// Zero-dependency browser WebTransport interop harness (Node built-ins only).
//
// Proves the Orochi from-scratch WebTransport server interoperates with a REAL
// browser (headless Chromium) speaking the actual WebTransport API:
//   1. Extended CONNECT (`:protocol=webtransport`) -> `await wt.ready`
//   2. a WT bidi stream: write a known payload, read the echo, assert byte-exact
//   3. a WT datagram: send a known payload, read the echo, assert byte-exact
//
// WebTransport is only available in a SECURE CONTEXT. `http://127.0.0.1` counts
// as secure (localhost), so we serve the test page over plain HTTP on 127.0.0.1
// and the page connects to `https://127.0.0.1:<P>/echo`. Chrome accepts the
// self-signed server cert via `serverCertificateHashes` (requires the cert be
// ECDSA-P256, <=14-day validity, hash = SHA-256 of the cert DER) -- the Orochi
// WT interop server mints exactly that and prints PORT + CERTHASH.
//
// Usage:
//   node tools/quic_interop_browser.mjs --port <UDP> --certhash <HEX>
//     [--http-port <N>] [--chromium <path>] [--timeout-ms <N>]
//   (or via env: OROCHI_WT_PORT / OROCHI_WT_CERTHASH / CHROMIUM)
//
// Exit 0 on a byte-exact bidi + datagram echo; non-zero with detail otherwise.

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
  console.error(`[browser-harness] FAIL: ${msg}`);
  process.exit(1);
}

if (!udpPort || !/^\d+$/.test(String(udpPort))) die('missing/invalid --port (server UDP port)');
if (!/^[0-9a-f]{64}$/.test(certHashHex)) die(`missing/invalid --certhash (need 64 hex chars), got '${certHashHex}'`);

// Known payloads asserted byte-exact on the round trip.
const BIDI_PAYLOAD = 'orochi-wt-ping';
const DGRAM_PAYLOAD = 'orochi-wt-datagram';

// ---- the test page --------------------------------------------------------

function pageHtml() {
  // The cert hash is injected as a hex string; the page rebuilds the Uint8Array.
  return `<!doctype html><meta charset="utf-8"><title>orochi wt interop</title>
<body><pre id="log"></pre><script>
const UDP_PORT = ${JSON.stringify(String(udpPort))};
const CERT_HASH_HEX = ${JSON.stringify(certHashHex)};
const BIDI_PAYLOAD = ${JSON.stringify(BIDI_PAYLOAD)};
const DGRAM_PAYLOAD = ${JSON.stringify(DGRAM_PAYLOAD)};

const logEl = document.getElementById('log');
function log(m) { logEl.textContent += m + "\\n"; }

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function bytesToStr(b) { return new TextDecoder().decode(b); }

// Read exactly n bytes from a ReadableStream reader (the echo may arrive split
// across multiple chunks).
async function readExactly(reader, n) {
  const acc = new Uint8Array(n);
  let off = 0;
  while (off < n) {
    const { value, done } = await reader.read();
    if (done) throw new Error('stream closed early after ' + off + '/' + n + ' bytes');
    acc.set(value.subarray(0, Math.min(value.length, n - off)), off);
    off += value.length;
  }
  return acc;
}

async function report(ok, detail) {
  try {
    await fetch('/result', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok, detail }),
    });
  } catch (e) {
    // last-ditch: still try to surface it in the page
    log('report failed: ' + (e && e.message));
  }
}

async function run() {
  const steps = [];
  if (typeof WebTransport === 'undefined') {
    await report(false, 'WebTransport is undefined (not a secure context or unsupported)');
    return;
  }
  const enc = new TextEncoder();
  const url = 'https://127.0.0.1:' + UDP_PORT + '/echo';
  let wt;
  try {
    wt = new WebTransport(url, {
      serverCertificateHashes: [{ algorithm: 'sha-256', value: hexToBytes(CERT_HASH_HEX) }],
    });
  } catch (e) {
    await report(false, 'WebTransport constructor threw: ' + (e && (e.stack || e.message)));
    return;
  }

  // Surface a close/abort reason if the session dies under us.
  wt.closed.then((info) => log('wt.closed resolved: ' + JSON.stringify(info)))
          .catch((e) => log('wt.closed rejected: ' + (e && (e.message || e))));

  try {
    await wt.ready;
    steps.push('ready');
  } catch (e) {
    await report(false, 'wt.ready rejected: ' + (e && (e.stack || e.message || String(e))));
    return;
  }

  // ---- bidi stream echo ----
  try {
    const stream = await wt.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    await writer.write(enc.encode(BIDI_PAYLOAD));
    // Do NOT close the writer: the echo target (loopback TCP) stays open; we
    // only need the reply for the known payload length.
    const reader = stream.readable.getReader();
    const got = await readExactly(reader, BIDI_PAYLOAD.length);
    const want = enc.encode(BIDI_PAYLOAD);
    if (!eq(got, want)) {
      await report(false, 'bidi echo mismatch: got ' + JSON.stringify(bytesToStr(got)) +
        ' want ' + JSON.stringify(BIDI_PAYLOAD) + ' (steps: ' + steps.join(',') + ')');
      return;
    }
    steps.push('bidi-echo');
  } catch (e) {
    await report(false, 'bidi stream failed: ' + (e && (e.stack || e.message || String(e))) +
      ' (steps: ' + steps.join(',') + ')');
    return;
  }

  // ---- datagram echo ----
  try {
    const dw = wt.datagrams.writable.getWriter();
    const dr = wt.datagrams.readable.getReader();
    const want = enc.encode(DGRAM_PAYLOAD);

    // Datagrams are unreliable: retry a few times, each with a short read window.
    let dgGot = null;
    for (let attempt = 0; attempt < 10 && !dgGot; attempt++) {
      await dw.write(want);
      const readP = dr.read();
      const timeoutP = new Promise((res) => setTimeout(() => res({ timeout: true }), 600));
      const r = await Promise.race([readP, timeoutP]);
      if (r && r.timeout) continue;
      if (r && !r.done && r.value && eq(r.value, want)) { dgGot = r.value; break; }
      if (r && !r.done && r.value) {
        // Got a datagram but it didn't match — report exactly what came back.
        await report(false, 'datagram echo mismatch: got ' + JSON.stringify(bytesToStr(r.value)) +
          ' want ' + JSON.stringify(DGRAM_PAYLOAD) + ' (steps: ' + steps.join(',') + ')');
        return;
      }
    }
    if (!dgGot) {
      await report(false, 'datagram echo not received after retries (steps: ' + steps.join(',') + ')');
      return;
    }
    steps.push('datagram-echo');
  } catch (e) {
    await report(false, 'datagram leg failed: ' + (e && (e.stack || e.message || String(e))) +
      ' (steps: ' + steps.join(',') + ')');
    return;
  }

  await report(true, 'all legs byte-exact: ' + steps.join(',') +
    ' | bidi=' + JSON.stringify(BIDI_PAYLOAD) + ' datagram=' + JSON.stringify(DGRAM_PAYLOAD));
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
  console.log(`[browser-harness] page server at ${pageUrl}`);
  console.log(`[browser-harness] target WebTransport server: https://127.0.0.1:${udpPort}/echo`);

  // Launch headless Chromium against the page.
  const args = [
    '--headless=new',
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    // A throwaway profile dir keeps runs hermetic.
    `--user-data-dir=${process.env.TMPDIR || '/tmp'}/orochi-wt-chrome-${process.pid}`,
    pageUrl,
  ];
  console.log(`[browser-harness] launching ${chromiumBin} ${args.join(' ')}`);
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
    if (result.ok) {
      console.log(`[browser-harness] PASS: ${result.detail}`);
      process.exit(0);
    } else {
      console.error(`[browser-harness] FAIL: ${result.detail}`);
      if (chromeStderr.trim()) {
        console.error('[browser-harness] --- chromium stderr (tail) ---');
        console.error(chromeStderr.split('\n').slice(-40).join('\n'));
      }
      process.exit(2);
    }
  });
});
