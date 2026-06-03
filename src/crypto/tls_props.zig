//! Deterministic property and fuzz-style tests for TLS handshake and record seams.
const std = @import("std");
const tls = @import("tls.zig");

const seed: u64 = 0x544c_535f_5052_4f50;
const handshake_iterations: usize = 192;
const handshake_steps: usize = 96;
const record_iterations: usize = 48;
const max_records_per_iteration: usize = 96;
const max_plaintext_len: usize = 256;

const roles = [_]tls.HandshakeRole{ .client, .server };
const states = [_]tls.HandshakeState{
    .start,
    .client_hello,
    .server_hello,
    .encrypted_extensions,
    .certificate,
    .certificate_verify,
    .finished,
    .connected,
};
const events = [_]tls.HandshakeEvent{
    .send_client_hello,
    .recv_client_hello,
    .send_server_hello,
    .recv_server_hello,
    .send_encrypted_extensions,
    .recv_encrypted_extensions,
    .send_certificate,
    .recv_certificate,
    .send_certificate_verify,
    .recv_certificate_verify,
    .send_finished,
    .recv_finished,
};
const content_types = [_]tls.ContentType{
    .change_cipher_spec,
    .alert,
    .handshake,
    .application_data,
};

test "canTransition is total and matches documented TLS handshake edges" {
    for (roles) |role| {
        for (states) |state| {
            for (events) |event| {
                const expected = expectedTransition(role, state, event) != null;
                try std.testing.expectEqual(expected, tls.canTransition(role, state, event));
            }
        }
    }
}

test "random runtime handshake event streams never panic or hide illegal transitions" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4841_4e44_5348_414b);
    const random = prng.random();

    for (roles) |role| {
        for (0..handshake_iterations) |_| {
            var runtime = tls.RuntimeHandshake{ .role = role };

            for (0..handshake_steps) |_| {
                const event = randomEvent(random);
                const before = runtime.state;
                if (expectedTransition(role, before, event)) |next| {
                    try runtime.step(event);
                    try std.testing.expectEqual(next, runtime.state);
                } else {
                    try std.testing.expectError(error.IllegalTransition, runtime.step(event));
                    try std.testing.expectEqual(before, runtime.state);
                }
            }
        }
    }
}

test "fuzzed TLS 1.2 record seal and open params keep AAD and nonce sequences aligned" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5245_434f_5244_5254);
    const random = prng.random();
    var plaintext: [max_plaintext_len]u8 = undefined;
    var ciphertext: [max_plaintext_len]u8 = undefined;
    var decrypted: [max_plaintext_len]u8 = undefined;

    for (0..record_iterations) |_| {
        var key: [Aes128Gcm.key_length]u8 = undefined;
        var iv: tls.Nonce96 = undefined;
        random.bytes(&key);
        random.bytes(&iv);

        var sender = try tls.RecordCipherState.init(.tls12, .tls_ecdhe_rsa_with_aes_128_gcm_sha256, iv);
        var receiver = try tls.RecordCipherState.init(.tls12, .tls_ecdhe_rsa_with_aes_128_gcm_sha256, iv);
        const record_count = random.intRangeAtMost(usize, 1, max_records_per_iteration);

        for (0..record_count) |expected_sequence| {
            const plaintext_len = random.intRangeAtMost(usize, 0, plaintext.len);
            random.bytes(plaintext[0..plaintext_len]);
            const content_type = randomContentType(random);
            const length: u16 = @intCast(plaintext_len);

            const seal = try sender.sealParams(content_type, tls.tls12_wire_version, length);
            try expectTls12SequenceAlignment(seal, expected_sequence);

            var tag: [Aes128Gcm.tag_length]u8 = undefined;
            Aes128Gcm.encrypt(ciphertext[0..plaintext_len], &tag, plaintext[0..plaintext_len], seal.aadSlice(), seal.nonce, key);

            const open = try receiver.openParams(content_type, tls.tls12_wire_version, length);
            try expectTls12SequenceAlignment(open, expected_sequence);
            try std.testing.expectEqual(seal.sequence, open.sequence);
            try std.testing.expectEqualSlices(u8, seal.aadSlice(), open.aadSlice());
            try std.testing.expectEqualSlices(u8, &seal.nonce, &open.nonce);

            try Aes128Gcm.decrypt(decrypted[0..plaintext_len], ciphertext[0..plaintext_len], tag, open.aadSlice(), open.nonce, key);
            try std.testing.expectEqualSlices(u8, plaintext[0..plaintext_len], decrypted[0..plaintext_len]);
        }
    }
}

test "tampered TLS 1.2 records fail closed" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5441_4d50_4552_4544);
    const random = prng.random();
    var plaintext: [max_plaintext_len]u8 = undefined;
    var ciphertext: [max_plaintext_len]u8 = undefined;
    var decrypted: [max_plaintext_len]u8 = undefined;

    var key: [Aes128Gcm.key_length]u8 = undefined;
    var iv: tls.Nonce96 = undefined;
    random.bytes(&key);
    random.bytes(&iv);

    var sender = try tls.RecordCipherState.init(.tls12, .tls_ecdhe_rsa_with_aes_128_gcm_sha256, iv);
    var receiver = try tls.RecordCipherState.init(.tls12, .tls_ecdhe_rsa_with_aes_128_gcm_sha256, iv);

    for (0..max_records_per_iteration) |_| {
        const plaintext_len = random.intRangeAtMost(usize, 1, plaintext.len);
        random.bytes(plaintext[0..plaintext_len]);
        const content_type = randomContentType(random);
        const length: u16 = @intCast(plaintext_len);
        const seal = try sender.sealParams(content_type, tls.tls12_wire_version, length);

        var tag: [Aes128Gcm.tag_length]u8 = undefined;
        Aes128Gcm.encrypt(ciphertext[0..plaintext_len], &tag, plaintext[0..plaintext_len], seal.aadSlice(), seal.nonce, key);

        const open = try receiver.openParams(content_type, tls.tls12_wire_version, length);
        var tampered_tag = tag;
        var tampered_aad = open.aad;
        var tampered_nonce = open.nonce;

        switch (random.intRangeAtMost(u8, 0, 3)) {
            0 => ciphertext[random.intRangeAtMost(usize, 0, plaintext_len - 1)] ^= 0x01,
            1 => tampered_tag[random.intRangeAtMost(usize, 0, tampered_tag.len - 1)] ^= 0x01,
            2 => tampered_aad[random.intRangeAtMost(usize, 0, open.aad_len - 1)] ^= 0x01,
            3 => tampered_nonce[random.intRangeAtMost(usize, 0, tampered_nonce.len - 1)] ^= 0x01,
            else => unreachable,
        }

        try std.testing.expectError(
            error.AuthenticationFailed,
            Aes128Gcm.decrypt(
                decrypted[0..plaintext_len],
                ciphertext[0..plaintext_len],
                tampered_tag,
                tampered_aad[0..open.aad_len],
                tampered_nonce,
                key,
            ),
        );
    }
}

fn expectedTransition(
    role: tls.HandshakeRole,
    state: tls.HandshakeState,
    event: tls.HandshakeEvent,
) ?tls.HandshakeState {
    return switch (role) {
        .client => switch (state) {
            .start => if (event == .send_client_hello) .client_hello else null,
            .client_hello => if (event == .recv_server_hello) .server_hello else null,
            .server_hello => if (event == .recv_encrypted_extensions) .encrypted_extensions else null,
            .encrypted_extensions => if (event == .recv_certificate) .certificate else null,
            .certificate => if (event == .recv_certificate_verify) .certificate_verify else null,
            .certificate_verify => if (event == .recv_finished) .finished else null,
            .finished => if (event == .send_finished) .connected else null,
            .connected => null,
        },
        .server => switch (state) {
            .start => if (event == .recv_client_hello) .client_hello else null,
            .client_hello => if (event == .send_server_hello) .server_hello else null,
            .server_hello => if (event == .send_encrypted_extensions) .encrypted_extensions else null,
            .encrypted_extensions => if (event == .send_certificate) .certificate else null,
            .certificate => if (event == .send_certificate_verify) .certificate_verify else null,
            .certificate_verify => if (event == .send_finished) .finished else null,
            .finished => if (event == .recv_finished) .connected else null,
            .connected => null,
        },
    };
}

fn randomEvent(random: std.Random) tls.HandshakeEvent {
    return events[random.intRangeAtMost(usize, 0, events.len - 1)];
}

fn randomContentType(random: std.Random) tls.ContentType {
    return content_types[random.intRangeAtMost(usize, 0, content_types.len - 1)];
}

fn expectTls12SequenceAlignment(params: tls.RecordCipherState.RecordParams, expected_sequence: usize) !void {
    const aad_sequence = std.mem.readInt(u64, params.aad[0..8], .big);
    const nonce_sequence = std.mem.readInt(u64, params.nonce[4..12], .big);
    const expected: u64 = @intCast(expected_sequence);
    try std.testing.expectEqual(expected, params.sequence);
    try std.testing.expectEqual(params.sequence, aad_sequence);
    try std.testing.expectEqual(params.sequence, nonce_sequence);
    try std.testing.expectEqual(@as(usize, 13), params.aad_len);
}

test {
    std.testing.refAllDecls(@This());
}
