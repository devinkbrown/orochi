// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Known-answer tests for Onyx Server's TLS 1.3 SHA-256 key schedule.
//!
//! The vectors are from RFC 8448, Section 3, "Simple 1-RTT Handshake".  The
//! public `Tls13Sha256` API reaches the zero-PSK early secret, the derived
//! handshake salt, the ECDHE handshake secret, the client/server handshake
//! traffic secrets, the master-secret transition, the client/server
//! application traffic secrets, and the HKDF-Expand-Label key/IV expansions
//! for TLS_AES_128_GCM_SHA256.
const std = @import("std");
const tls = @import("tls.zig");

const Schedule = tls.Tls13Sha256;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn expectSecret(expected: []const u8, actual: *const Schedule.SecretBytes) !void {
    try std.testing.expectEqualSlices(u8, expected, &actual.declassify());
}

test "RFC 8448 Simple 1-RTT TLS 1.3 SHA-256 key schedule" {
    const zero_psk = @as([Schedule.hash_len]u8, @splat(0));
    const empty_hash = Schedule.emptyTranscriptHash();
    const shared_secret = hex(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d" ++
            "35e6d63f537563efd46272900f89492d",
    );
    const hello_hash = hex(
        "860c06edc07858ee8e78f0e7428c58ed" ++
            "d6b43f2ca3e6e95f02ed063cf0e1cad8",
    );
    const server_finished_hash = hex(
        "9608102a0f1ccc6db6250b7b7e417b1a" ++
            "000eaada3daae4777a7686c9ff83df13",
    );

    var early = Schedule.earlySecret(&zero_psk);
    defer early.wipe();
    try expectSecret(
        &hex(
            "33ad0a1c607ec03b09e6cd9893680ce2" ++
                "10adf300aa1f2660e1b22e10f170f92a",
        ),
        &early,
    );

    var derived_handshake = try Schedule.deriveSecret(&early, "derived", &empty_hash);
    defer derived_handshake.wipe();
    try expectSecret(
        &hex(
            "6f2615a108c702c5678f54fc9dbab697" ++
                "16c076189c48250cebeac3576c3611ba",
        ),
        &derived_handshake,
    );

    var handshake = try Schedule.handshakeSecret(&early, &shared_secret);
    defer handshake.wipe();
    try expectSecret(
        &hex(
            "1dc826e93606aa6fdc0aadc12f741b01" ++
                "046aa6b99f691ed221a9f0ca043fbeac",
        ),
        &handshake,
    );

    var handshake_traffic = try Schedule.handshakeTrafficSecrets(&handshake, &hello_hash);
    defer handshake_traffic.wipe();
    try expectSecret(
        &hex(
            "b3eddb126e067f35a780b3abf45e2d8f" ++
                "3b1a950738f52e9600746a0e27a55a21",
        ),
        &handshake_traffic.client,
    );
    try expectSecret(
        &hex(
            "b67b7d690cc16c4e75e54213cb2d37b4" ++
                "e9c912bcded9105d42befd59d391ad38",
        ),
        &handshake_traffic.server,
    );

    var derived_master = try Schedule.deriveSecret(&handshake, "derived", &empty_hash);
    defer derived_master.wipe();
    try expectSecret(
        &hex(
            "43de77e0c77713859a944db9db2590b5" ++
                "3190a65b3ee2e4f12dd7a0bb7ce254b4",
        ),
        &derived_master,
    );

    var master = try Schedule.masterSecret(&handshake);
    defer master.wipe();
    try expectSecret(
        &hex(
            "18df06843d13a08bf2a449844c5f8a47" ++
                "8001bc4d4c627984d5a41da8d0402919",
        ),
        &master,
    );

    var application_traffic = try Schedule.applicationTrafficSecrets(&master, &server_finished_hash);
    defer application_traffic.wipe();
    try expectSecret(
        &hex(
            "9e40646ce79a7f9dc05af8889bce6552" ++
                "875afa0b06df0087f792ebb7c17504a5",
        ),
        &application_traffic.client,
    );
    try expectSecret(
        &hex(
            "a11af9f05531f856ad47116b45a95032" ++
                "8204b4f44bfb6b3a4b4f1f3fcb631643",
        ),
        &application_traffic.server,
    );
}

test "RFC 8448 Simple 1-RTT TLS_AES_128_GCM_SHA256 traffic key expansion" {
    var client_handshake_secret = Schedule.SecretBytes.init(hex(
        "b3eddb126e067f35a780b3abf45e2d8f" ++
            "3b1a950738f52e9600746a0e27a55a21",
    ));
    defer client_handshake_secret.wipe();
    var server_handshake_secret = Schedule.SecretBytes.init(hex(
        "b67b7d690cc16c4e75e54213cb2d37b4" ++
            "e9c912bcded9105d42befd59d391ad38",
    ));
    defer server_handshake_secret.wipe();
    var client_application_secret = Schedule.SecretBytes.init(hex(
        "9e40646ce79a7f9dc05af8889bce6552" ++
            "875afa0b06df0087f792ebb7c17504a5",
    ));
    defer client_application_secret.wipe();
    var server_application_secret = Schedule.SecretBytes.init(hex(
        "a11af9f05531f856ad47116b45a95032" ++
            "8204b4f44bfb6b3a4b4f1f3fcb631643",
    ));
    defer server_application_secret.wipe();

    var client_handshake_keys = try Schedule.trafficKeys(.tls_aes_128_gcm_sha256, &client_handshake_secret);
    defer client_handshake_keys.wipe();
    try std.testing.expectEqualSlices(u8, &hex("dbfaa693d1762c5b666af5d950258d01"), client_handshake_keys.keySlice());
    try std.testing.expectEqualSlices(u8, &hex("5bd3c71b836e0b76bb73265f"), &client_handshake_keys.iv);

    var server_handshake_keys = try Schedule.trafficKeys(.tls_aes_128_gcm_sha256, &server_handshake_secret);
    defer server_handshake_keys.wipe();
    try std.testing.expectEqualSlices(u8, &hex("3fce516009c21727d0f2e4e86ee403bc"), server_handshake_keys.keySlice());
    try std.testing.expectEqualSlices(u8, &hex("5d313eb2671276ee13000b30"), &server_handshake_keys.iv);

    var client_application_keys = try Schedule.trafficKeys(.tls_aes_128_gcm_sha256, &client_application_secret);
    defer client_application_keys.wipe();
    try std.testing.expectEqualSlices(u8, &hex("17422dda596ed5d9acd890e3c63f5051"), client_application_keys.keySlice());
    try std.testing.expectEqualSlices(u8, &hex("5b78923dee08579033e523d9"), &client_application_keys.iv);

    var server_application_keys = try Schedule.trafficKeys(.tls_aes_128_gcm_sha256, &server_application_secret);
    defer server_application_keys.wipe();
    try std.testing.expectEqualSlices(u8, &hex("9f02283b6c9c07efc26bb9f2ac92e356"), server_application_keys.keySlice());
    try std.testing.expectEqualSlices(u8, &hex("cf782b88dd83549aadf1e984"), &server_application_keys.iv);
}
