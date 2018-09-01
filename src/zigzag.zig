//
// ZigZag: Noise Framework implementation in Zig
// Copyright (c) MMXVIII kristopher tate & connectFree Corporation.
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
// This project may be licensed under the terms of the ConnectFree Reference
// Source License (CF-RSL). Corporate and Academic licensing terms are also
// available. Please contact <licensing@connectfree.co.jp> for details.
//
// connectFree, the connectFree logo, and EVER/IP are registered trademarks
// of connectFree Corporation in Japan and other countries. connectFree
// trademarks and branding may not be used without express writen permission
// of connectFree. Please remove all trademarks and branding before use.
//
// See the LICENSE file at the root of this project for complete information.
//
// 

const std = @import("std");

const NOISE_HASH_LEN = 32;
const blake2s = std.crypto.Blake2s256;

const g_hshake = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

// struct noise_engine
// struct noise_session_handshake
// struct noise_session
// struct noise_keypair
// struct noise_symmetric_key

pub const Engine = struct {

  hshake_hash: [NOISE_HASH_LEN]u8,
  hshake_chaining_key: [NOISE_HASH_LEN]u8,

  pub fn init(ident: []const u8, identkey: []const u8) Engine {
    var out = Engine{
      .hshake_hash = undefined,
      .hshake_chaining_key = undefined,
    };

    // calculate chaining keys
    blake2s.hash(g_hshake[0..], out.hshake_chaining_key[0..]);

    var b = blake2s.init();
    b.update( out.hshake_chaining_key[0..] );
    b.update( ident );
    b.update( identkey );
    b.final( out.hshake_hash[0..] );

    std.debug.warn("hshake_chaining_key {X}\n", out.hshake_chaining_key);
    std.debug.warn("hshake_hash {X}\n", out.hshake_hash);

    return out;
  }

  pub fn deinit(self: *Engine) void { }

};

