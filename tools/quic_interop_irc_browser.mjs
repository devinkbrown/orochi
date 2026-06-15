// Zero-dependency browser IRC-over-WebTransport interop harness (Node built-ins
// only — no npm, no puppeteer).
//
// Proves a REAL browser (headless Chromium) registers as an IRC client against
// the REAL orochi daemon, end-to-end, over the from-scratch WebTransport stack:
//   1. Extended CONNECT (`:protocol=webtransport`) -> `await wt.ready`
//   2. open a WT bidi stream (the IRC byte channel the listener bridges to the
//      daemon's plaintext IRC port over a loopback TCP proxy)
//   3. write `NICK webuser\r\nUSER webuser 0 * :Web User\r\n`, read the stream
//      until a ` 001 ` (RPL_WELCOME) line arrives -> assert the real welcome
//   4. `JOIN #web\r\n`, assert the JOIN echo + `353`/`366` names
//   5. `PRIVMSG #web :hello from a browser\r\n`, assert no IRC error numeric
//      comes back (the message is accepted)
// then POST a JSON verdict (incl. the captured IRC lines) back to this server.
//
// WebTransport is only available in a SECURE CONTEXT. `http://127.0.0.1` counts
// as secure (localhost), so we serve the page over plain HTTP on 127.0.0.1 and
// the page connects to `https://127.0.0.1:<P>/wt`. Chrome accepts the self-signed
// server cert via `serverCertificateHashes` (ECDSA-P256, <=14-day validity, hash
// = SHA-256 of the cert DER) — the orochi WT interop server mints exactly that
// and prints PORT + CERTHASH; this harness is handed those.
//
// Usage:
//   node tools/quic_interop_irc_browser.mjs --port <UDP> --certhash <HEX>
//     [--http-port <N>] [--chromium <path>] [--timeout-ms <N>]
//   (or via env: OROCHI_WT_PORT / OROCHI_WT_CERTHASH / CHROMIUM)
//
// Exit 0 when the browser completed IRC registration (real 001) + JOIN + PRIVMSG
// against the live daemon; non-zero with detail otherwise.

import http from 'node:http';
import { spawn } from 'node:child_process';
import process from 'node:process';

// ---- argv / env -----------------------------------------------------------

function argOf(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined;
}

const udpPort = argOf('port') ?? process.env.OROCHI_WT_PORT;
const certHashHex = (argOf('certhash') ?? process.env.OROCHI_WT_CERTHASH ?? '').trim().toLowerCase();
const httpPort = parseInt(argOf('http-port') ?? '0', 10); // 0 -> ephemeral
const chromiumBin = argOf('chromium') ?? process.env.CHROMIUM ?? '/usr/bin/chromium';
const hardTimeoutMs = parseInt(argOf('timeout-ms') ?? '25000', 10);

function die(msg) {
  console.error(`[irc-browser-harness] FAIL: ${msg}`);
  process.exit(1);
}

if (!udpPort || !/^\d+$/.test(String(udpPort))) die('missing/invalid --port (server UDP port)');
if (!/^[0-9a-f]{64}$/.test(certHashHex)) die(`missing/invalid --certhash (need 64 hex chars), got '${certHashHex}'`);

// The IRC identity + channel the browser registers/joins/messages with.
const NICK = 'webuser';
const CHANNEL = '#web';
const MESSAGE = 'hello from a browser';

// ---- the test page --------------------------------------------------------

function pageHtml() {
  return `<!doctype html><meta charset="utf-8"><title>orochi irc-over-wt interop</title>
<body><pre id="log"></pre><script>
const UDP_PORT = ${JSON.stringify(String(udpPort))};
const CERT_HASH_HEX = ${JSON.stringify(certHashHex)};
const NICK = ${JSON.stringify(NICK)};
const CHANNEL = ${JSON.stringify(CHANNEL)};
const MESSAGE = ${JSON.stringify(MESSAGE)};

const logEl = document.getElementById('log');
function log(m) { logEl.textContent += m + "\\n"; }

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function report(ok, detail, lines) {
  try {
    await fetch('/result', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok, detail, lines: lines || [] }),
    });
  } catch (e) {
    log('report failed: ' + (e && e.message));
  }
}

// An IRC line reader over a WT bidi stream: it accumulates bytes, splits on
// CRLF/LF, and yields complete lines. IRC is a CRLF line protocol; the bridge
// proxies raw bytes, so a single stream chunk may carry several lines or a
// partial line — we must buffer across reads and split, NOT assume one line per
// chunk (the same framing rule the wss browser path documents).
class IrcLineReader {
  constructor(readable) {
    this.reader = readable.getReader();
    this.dec = new TextDecoder();
    this.buf = '';
    this.queue = [];
    this.closed = false;
  }
  _drain() {
    let idx;
    while ((idx = this.buf.search(/\\r?\\n/)) !== -1) {
      const line = this.buf.slice(0, idx);
      this.buf = this.buf.slice(this.buf[idx] === '\\r' ? idx + 2 : idx + 1);
      if (line.length) this.queue.push(line);
    }
  }
  // Read lines until \`pred(line)\` is true for one of them, or the deadline hits.
  // Returns { matched, lines } where \`lines\` is every line seen this call.
  async until(pred, deadlineMs) {
    const seen = [];
    // Flush any already-buffered lines first.
    this._drain();
    while (this.queue.length) {
      const l = this.queue.shift();
      seen.push(l);
      if (pred(l)) return { matched: l, lines: seen };
    }
    const end = Date.now() + deadlineMs;
    while (Date.now() < end) {
      const remaining = end - Date.now();
      const timeoutP = new Promise((res) => setTimeout(() => res({ timeout: true }), remaining));
      const r = await Promise.race([this.reader.read(), timeoutP]);
      if (r && r.timeout) break;
      if (r.done) { this.closed = true; break; }
      this.buf += this.dec.decode(r.value, { stream: true });
      this._drain();
      while (this.queue.length) {
        const l = this.queue.shift();
        seen.push(l);
        if (pred(l)) return { matched: l, lines: seen };
      }
    }
    return { matched: null, lines: seen };
  }
}

async function run() {
  const all = [];
  const record = (lines) => { for (const l of lines) all.push(l); };

  if (typeof WebTransport === 'undefined') {
    await report(false, 'WebTransport is undefined (not a secure context or unsupported)');
    return;
  }
  const enc = new TextEncoder();
  const url = 'https://127.0.0.1:' + UDP_PORT + '/wt';
  let wt;
  try {
    wt = new WebTransport(url, {
      serverCertificateHashes: [{ algorithm: 'sha-256', value: hexToBytes(CERT_HASH_HEX) }],
    });
  } catch (e) {
    await report(false, 'WebTransport constructor threw: ' + (e && (e.stack || e.message)));
    return;
  }

  wt.closed.then((info) => log('wt.closed resolved: ' + JSON.stringify(info)))
          .catch((e) => log('wt.closed rejected: ' + (e && (e.message || e))));

  try {
    await wt.ready;
  } catch (e) {
    await report(false, 'wt.ready rejected: ' + (e && (e.stack || e.message || String(e))));
    return;
  }

  let stream, writer, lineReader;
  try {
    stream = await wt.createBidirectionalStream();
    writer = stream.writable.getWriter();
    lineReader = new IrcLineReader(stream.readable);
  } catch (e) {
    await report(false, 'failed to open WT bidi stream: ' + (e && (e.stack || e.message || String(e))));
    return;
  }

  const send = (s) => writer.write(enc.encode(s));

  // ---- 1. register: NICK + USER, await RPL_WELCOME (001) ----
  try {
    await send('NICK ' + NICK + '\\r\\nUSER ' + NICK + ' 0 * :Web User\\r\\n');
    const r = await lineReader.until((l) => / 001 /.test(l), 12000);
    record(r.lines);
    if (!r.matched) {
      await report(false, 'no RPL_WELCOME (001) received before timeout', all);
      return;
    }
  } catch (e) {
    await report(false, 'registration leg failed: ' + (e && (e.stack || e.message || String(e))), all);
    return;
  }

  // ---- 2. JOIN #web, await the JOIN echo + 366 (End of NAMES) ----
  let names353 = null;
  try {
    await send('JOIN ' + CHANNEL + '\\r\\n');
    // Wait for the channel's End-of-NAMES (366). Capture any 353 (NAMES) on the way.
    const r = await lineReader.until((l) => {
      if (/ 353 /.test(l) && l.indexOf(CHANNEL) !== -1) names353 = l;
      return / 366 /.test(l) && l.indexOf(CHANNEL) !== -1;
    }, 8000);
    record(r.lines);
    const joinEcho = r.lines.find((l) => / JOIN /.test(l) && l.indexOf(CHANNEL) !== -1);
    if (!joinEcho) {
      await report(false, 'no JOIN echo for ' + CHANNEL + ' received', all);
      return;
    }
    if (!r.matched) {
      await report(false, 'no 366 (End of NAMES) for ' + CHANNEL + ' received', all);
      return;
    }
  } catch (e) {
    await report(false, 'JOIN leg failed: ' + (e && (e.stack || e.message || String(e))), all);
    return;
  }

  // ---- 3. PRIVMSG #web, assert no IRC error numeric comes back ----
  // The daemon does not echo your own PRIVMSG (no echo-message cap negotiated),
  // so "accepted" = no error numeric (4xx/5xx) arrives in a short window. We
  // probe with a PING afterwards: when its PONG returns with no preceding error
  // numeric, the PRIVMSG was accepted and processed in order.
  try {
    await send('PRIVMSG ' + CHANNEL + ' :' + MESSAGE + '\\r\\nPING :ircwtprobe\\r\\n');
    let sawError = null;
    const r = await lineReader.until((l) => {
      // An IRC error numeric is a 3-digit 4xx/5xx code in the " <code> " slot.
      const m = l.match(/^\\S+ (\\d{3}) /) || l.match(/ (\\d{3}) /);
      if (m && (m[1][0] === '4' || m[1][0] === '5')) { sawError = l; return true; }
      return /PONG/.test(l) && l.indexOf('ircwtprobe') !== -1;
    }, 6000);
    record(r.lines);
    if (sawError) {
      await report(false, 'PRIVMSG rejected with an error numeric: ' + sawError, all);
      return;
    }
    if (!r.matched) {
      await report(false, 'no PONG after PRIVMSG (could not confirm acceptance)', all);
      return;
    }
  } catch (e) {
    await report(false, 'PRIVMSG leg failed: ' + (e && (e.stack || e.message || String(e))), all);
    return;
  }

  await report(true, 'IRC registration (001) + JOIN ' + CHANNEL + ' + PRIVMSG accepted'
    + (names353 ? ' | names=' + JSON.stringify(names353) : ''), all);
}

window.addEventListener('error', (ev) => { report(false, 'window error: ' + (ev && ev.message)); });
window.addEventListener('unhandledrejection', (ev) => {
  report(false, 'unhandledrejection: ' + (ev && ev.reason && (ev.reason.message || String(ev.reason))));
});
run().catch((e) => report(false, 'run() threw: ' + (e && (e.stack || e.message || String(e)))));
</script></body>`;
}

// ---- HTTP server: serves the page + collects POST /result -----------------

let resolveResult;
const resultPromise = new Promise((res) => { resolveResult = res; });

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url.startsWith('/?'))) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(pageHtml());
    return;
  }
  if (req.method === 'POST' && req.url === '/result') {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 1 << 20) req.destroy(); });
    req.on('end', () => {
      res.writeHead(204);
      res.end();
      let parsed;
      try { parsed = JSON.parse(body); } catch { parsed = { ok: false, detail: 'unparseable result: ' + body }; }
      resolveResult(parsed);
    });
    return;
  }
  res.writeHead(404);
  res.end('not found');
});

server.on('error', (e) => die('http server error: ' + e.message));

server.listen(httpPort, '127.0.0.1', () => {
  const addr = server.address();
  const pageUrl = `http://127.0.0.1:${addr.port}/`;
  console.log(`[irc-browser-harness] page server at ${pageUrl}`);
  console.log(`[irc-browser-harness] target WebTransport server: https://127.0.0.1:${udpPort}/wt`);

  const args = [
    '--headless=new',
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    `--user-data-dir=${process.env.TMPDIR || '/tmp'}/orochi-irc-wt-chrome-${process.pid}`,
    pageUrl,
  ];
  console.log(`[irc-browser-harness] launching ${chromiumBin} ${args.join(' ')}`);
  const child = spawn(chromiumBin, args, { stdio: ['ignore', 'pipe', 'pipe'] });

  let chromeStderr = '';
  child.stdout.on('data', (d) => { process.stderr.write(`[chromium:out] ${d}`); });
  child.stderr.on('data', (d) => { chromeStderr += d; process.stderr.write(`[chromium:err] ${d}`); });
  child.on('error', (e) => die(`failed to launch chromium (${chromiumBin}): ${e.message}`));

  const hardTimer = setTimeout(() => {
    resolveResult({ ok: false, detail: `hard timeout (${hardTimeoutMs}ms): no /result POST from the page` });
  }, hardTimeoutMs);

  resultPromise.then((result) => {
    clearTimeout(hardTimer);
    try { child.kill('SIGKILL'); } catch {}
    server.close();
    if (Array.isArray(result.lines) && result.lines.length) {
      console.log('[irc-browser-harness] --- IRC lines the browser received ---');
      for (const l of result.lines) console.log('[irc] ' + l);
      console.log('[irc-browser-harness] --- end IRC lines ---');
    }
    if (result.ok) {
      console.log(`[irc-browser-harness] PASS: ${result.detail}`);
      process.exit(0);
    } else {
      console.error(`[irc-browser-harness] FAIL: ${result.detail}`);
      if (chromeStderr.trim()) {
        console.error('[irc-browser-harness] --- chromium stderr (tail) ---');
        console.error(chromeStderr.split('\n').slice(-40).join('\n'));
      }
      process.exit(2);
    }
  });
});
