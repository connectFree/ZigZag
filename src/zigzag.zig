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
const builtin = @import("builtin");
const mem = std.mem;
const fmt = std.fmt;
const debug = std.debug;
const Allocator = std.mem.Allocator;
const HashMap = std.hash_map.HashMap;

const mbuf = @import("mbuf.zig").mbuf;
const RFC6479 = @import("RFC6479.zig").RFC6479;

const NOISE_HASH_LEN = 32;
const NOISE_PUBLIC_KEY_LEN = 32;
const NOISE_SECRET_KEY_LEN = 32;
const NOISE_SYMMETRIC_KEY_LEN = 32; //crypto_aead_chacha20poly1305_KEYBYTES
const NOISE_TIMESTAMP_LEN = 12; //TAI64_N_LEN

const Isaac64 = std.rand.Isaac64;

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
  prng: Isaac64,
  static_identity: NoiseStaticIdent,

  const SessionHashMap = HashMap([]const u8, Session, mem.hash_slice_u8, mem.eql_slice_u8);

  pub const NoiseSessionEvent = enum {
      NULL = 0
    , INIT = 1
    , CLOSE = 2
    , ZERO = 3
    , HSHAKE = 4
    , HSXMIT = 5
    , CONNECTED = 6
    , REKEY = 7
    , BEGIN_PILOT = 8
    , BEGIN_COPILOT = 9
    , MAXIMUM // must be last!
  };

  const NoiseHandshakeState = enum {
      ZEROED
    , CREATED_INITIATION
    , CONSUMED_INITIATION
    , CREATED_RESPONSE
    , CONSUMED_RESPONSE
  };

  const NoiseSymmetricKey = struct {
    key: [NOISE_SYMMETRIC_KEY_LEN]u8,
    rfc6479_counter: RFC6479,
    birthdate: u64,
    is_valid: bool,

    fn setKey( self: *NoiseSymmetricKey
             , key: [NOISE_SYMMETRIC_KEY_LEN]u8) void {
      self.key = key;
    }

    fn reset(self: *NoiseSymmetricKey) void {
      rfc6479_counter.secureReset();
      self.birthdate = now;
      self.is_valid = true;
    }
  };

  const NoiseKeyPair = struct {
    session: *Session,
    tx: NoiseSymmetricKey,
    rx: NoiseSymmetricKey,
    remote_index: u32,
    its_my_plane: bool,

    //accounting
    rx_bytes: u64,
    tx_bytes: u64,
  };

  const NoiseStaticIdent = struct {
    has_identity: bool,
    pk: [NOISE_PUBLIC_KEY_LEN]u8,
    sk: [NOISE_SECRET_KEY_LEN]u8,
  };

  const NoiseSessionHandshake = struct {
    state: NoiseHandshakeState,
    last_initiation_consumption: u64,
    static_identity: NoiseStaticIdent,

    ephemeral_private: [NOISE_SECRET_KEY_LEN]u8,
    remote_static: [NOISE_PUBLIC_KEY_LEN]u8,
    remote_ephemeral: [NOISE_PUBLIC_KEY_LEN]u8,
    precomputed_static_static: [NOISE_PUBLIC_KEY_LEN]u8,

    preshared_key: [NOISE_SYMMETRIC_KEY_LEN]u8,

    hash: [NOISE_HASH_LEN]u8,
    chaining_key: [NOISE_HASH_LEN]u8,

    latest_timestamp: [NOISE_TIMESTAMP_LEN]u8,
    remote_index: u32,

  };

  /// Noise Session
  pub const Session = struct {
    engine: *Engine,
    pub_key: [NOISE_PUBLIC_KEY_LEN]u8,

    keypair_now: ?*NoiseKeyPair,
    keypair_then: ?*NoiseKeyPair,
    keypair_next: ?*NoiseKeyPair,

    event_last: NoiseSessionEvent,

    // timestamp of when we last sent a handshake
    last_sent_handshake: u64,
    handshake: NoiseSessionHandshake,

    //Accounting
    rx_last: u64,
    rx_bytes: usize,
    tx_last: u64,
    tx_bytes: usize,

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

    /// format function for std.fmt
    pub fn format(
        self: *const Session,
        comptime _fmt: []const u8,
        context: var,
        comptime FmtError: type,
        output: fn (@typeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
      return fmt.format(context, FmtError, output, "[SESSION pub:{X}]@0x{x}", self.pub_key, @ptrToInt(self));
    }
  };

  pub fn init(allocator: *Allocator, ident: []const u8, identkey: []const u8) !Engine {
    var rbuf: [8]u8 = undefined;
    try std.os.getRandomBytes(rbuf[0..]);
    const seed = mem.readInt(rbuf[0..8], u64, builtin.Endian.Little);

    var out = Engine{
      .allocator = allocator,
      .session_map = SessionHashMap.init(allocator),
      .hshake_hash = undefined,
      .hshake_chaining_key = undefined,
      .prng = Isaac64.init(seed),
      .static_identity = undefined,
    };

    // calculate chaining keys
    blake2s.hash(g_hshake[0..], out.hshake_chaining_key[0..]);

    var b = blake2s.init();
    b.update( out.hshake_chaining_key[0..] );
    b.update( ident );
    b.update( identkey );
    b.final( out.hshake_hash[0..] );

    //std.debug.warn("hshake_chaining_key {X}\n", out.hshake_chaining_key);
    //std.debug.warn("hshake_hash {X}\n", out.hshake_hash);

    return out;
  }

  pub fn deinit(self: *Engine) void {
    //TODO: secure wipe memory
    debug.warn("TODO: secure wipe memory\n");
    self.session_map.deinit();
  }

  pub fn sessionGetOrCreate(self: *Engine, public_key: var, preshared_key: ?[NOISE_SYMMETRIC_KEY_LEN] u8) !*Engine.Session {
    return Engine.Session.getOrCreate(self, public_key, preshared_key);
  }

  pub fn pubkey_get(self: *Engine) ![]const u8 {
    return error.NoKeyLoaded;
  }

  pub fn processIncoming(self: *Engine, mb: *mbuf) !void {
    var pkt_type: u32 = try mb.readIntLE(u32);
    switch (pkt_type) {
      1 => std.debug.warn("got type 1\n"),
      else => return error.BadMessage,
    }
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
