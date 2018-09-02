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
const mem = std.mem;
const fmt = std.fmt;
const debug = std.debug;
const Allocator = std.mem.Allocator;
const HashMap = std.hash_map.HashMap;

const mbuf = @import("mbuf.zig").mbuf;

const NOISE_HASH_LEN = 32;
const NOISE_PUBLIC_KEY_LEN = 32;
const NOISE_SECRET_KEY_LEN = 32;
const NOISE_SYMMETRIC_KEY_LEN = 32; //crypto_aead_chacha20poly1305_KEYBYTES

const blake2s = std.crypto.Blake2s256;

const g_hshake = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

// struct noise_engine
// struct noise_session_handshake
// struct noise_session
// struct noise_keypair
// struct noise_symmetric_key

pub const Engine = struct {

  allocator: *Allocator,
  session_map: SessionHashMap,

  hshake_hash: [NOISE_HASH_LEN]u8,
  hshake_chaining_key: [NOISE_HASH_LEN]u8,

  const SessionHashMap = HashMap([]const u8, Session, mem.hash_slice_u8, mem.eql_slice_u8);

  /// Noise Session
  pub const Session = struct {
    engine: *Engine,
    pub_key: [NOISE_PUBLIC_KEY_LEN]u8,

    fn getOrCreate( engine: *Engine
                  , public_key: [NOISE_PUBLIC_KEY_LEN]u8
                  , preshared_key: ?[NOISE_SYMMETRIC_KEY_LEN]u8) !*Session {

      const result = try engine.session_map.getOrPut( public_key );
      if (result.found_existing) {
        return &result.kv.value;
      }

      // init Session

      const session = &result.kv.value;

      session.engine = engine;
      session.pub_key = public_key;

      return session;
    }

  };

  pub fn init(allocator: *Allocator, ident: []const u8, identkey: []const u8) Engine {
    var out = Engine{
      .allocator = allocator,
      .session_map = SessionHashMap.init(allocator),
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

  pub fn deinit(self: *Engine) void {
    self.session_map.deinit();
  }

  pub fn sessionGetOrCreate(self: *Engine, public_key: var, preshared_key: ?[NOISE_SYMMETRIC_KEY_LEN] u8) !*Engine.Session {
    return Engine.Session.getOrCreate(self, public_key, preshared_key);
  }


};

test "default" {
  const g_ident = "ConnectFree(R) EVER/IP(R) v1 (c) kristopher tate and ConnectFree Corporation";
  const g_identkey = "BLANK KEY";

  var e = Engine.init(debug.global_allocator, g_ident, g_identkey);
  defer e.deinit();

  var pb: [NOISE_PUBLIC_KEY_LEN]u8 = undefined;
  try fmt.hexToBytes("909A312BB12ED1F819B3521AC4C1E896F2160507FFC1C8381E3B07BB16BD1706", pb[0..]);
  var a_session = try e.sessionGetOrCreate(pb, null);
  debug.warn("got a session: {}\n", a_session);

}
