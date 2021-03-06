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

const X25519 = std.crypto.X25519;


const REKEY_TIMEOUT = 5000;
const REKEY_TIMEOUT_JITTER_MAX = 333;
const REKEY_AFTER_TIME = 120000;
const KEEPALIVE_TIMEOUT = 10000;
const REJECT_AFTER_TIME = 180000;

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

// X:S TOOLS

fn _mix_hash( hash: *[NOISE_HASH_LEN]u8, src: []const u8 ) void {
  var b = blake2s.init();
  b.update( hash[0..] );
  b.update( src[0..] );
  b.final( hash[0..] );
}


// X:E TOOLS

pub const Engine = struct.{

  allocator: *Allocator,
  session_map: SessionHashMap,
  hshake_hash: [NOISE_HASH_LEN]u8,
  hshake_chaining_key: [NOISE_HASH_LEN]u8,
  prng: Isaac64,
  static_identity: NoiseStaticIdent,
  sys_unixtime: fn () u64,

  const SessionHashMap = HashMap([]const u8, Session, mem.hash_slice_u8, mem.eql_slice_u8);

  pub const NoiseSessionEvent = enum.{
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

  const NoiseHandshakeState = enum.{
      UNINITIALIZED
    , ZEROED
    , CREATED_INITIATION
    , CONSUMED_INITIATION
    , CREATED_RESPONSE
    , CONSUMED_RESPONSE
  };

  const NoiseSymmetricKey = struct.{
    key: [NOISE_SYMMETRIC_KEY_LEN]u8,
    rfc6479_counter: RFC6479,
    birthdate: u64,
    is_valid: bool,

    fn setKey( self: *NoiseSymmetricKey
             , key: *const [NOISE_SYMMETRIC_KEY_LEN]u8
             ) void {
      self.key = key;
    }

    fn reset(self: *NoiseSymmetricKey) void {
      rfc6479_counter.secureReset();
      self.birthdate = now;
      self.is_valid = true;
    }
  };

  const NoiseKeyPair = struct.{
    session: *Session,
    tx: NoiseSymmetricKey,
    rx: NoiseSymmetricKey,
    remote_index: u32,
    its_my_plane: bool,

    //accounting
    rx_bytes: u64,
    tx_bytes: u64,
  };

  const NoiseStaticIdent = struct.{
    has_identity: bool,
    pk: [NOISE_PUBLIC_KEY_LEN]u8,
    sk: [NOISE_SECRET_KEY_LEN]u8,
  };

  const NoiseSessionHandshake = struct.{
    state: NoiseHandshakeState,
    last_initiation_consumption: u64,

    ephemeral_private: [NOISE_SECRET_KEY_LEN]u8,
    remote_static: [NOISE_PUBLIC_KEY_LEN]u8,
    remote_ephemeral: [NOISE_PUBLIC_KEY_LEN]u8,
    precomputed_static_static: [NOISE_PUBLIC_KEY_LEN]u8,

    preshared_key: [NOISE_SYMMETRIC_KEY_LEN]u8,

    hash: [NOISE_HASH_LEN]u8,
    chaining_key: [NOISE_HASH_LEN]u8,

    latest_timestamp: [NOISE_TIMESTAMP_LEN]u8,
    remote_index: u32,

    fn secureZero(self: *NoiseSessionHandshake) void {
      mem.secureZero(u8, @ptrCast([*]u8, self)[0..@sizeOf(NoiseSessionHandshake)]);
    }

    fn mix( self: *NoiseSessionHandshake
          , chaining_key: *const [NOISE_HASH_LEN] u8
          , hash: *const [NOISE_HASH_LEN] u8
          , remote_static: *const [NOISE_PUBLIC_KEY_LEN] u8
          ) void {
      std.mem.copy(u8, self.hash[0..], hash);
      std.mem.copy(u8, self.chaining_key[0..], chaining_key);
      _mix_hash(&self.hash, remote_static[0..]);
    }

  };

  /// Noise Session
  pub const Session = struct.{
    engine: *Engine,

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
                  , public_key: []const u8
                  , preshared_key: ?*const [NOISE_SYMMETRIC_KEY_LEN]u8) !*Session {

      const result = try engine.session_map.getOrPut( public_key );
      if (result.found_existing) {
        return &result.kv.value;
      }

      // init Session
      const session = &result.kv.value;

      session.engine = engine;

      //setup handshake information
      session.handshake.secureZero();

      //copy public key into memory
      std.mem.copy(u8, session.handshake.remote_static[0..], public_key);

      if (preshared_key) |psk| {
        std.mem.copy(u8, session.handshake.preshared_key[0..], psk);
      }

      if (session.engine.static_identity.has_identity) {
        debug.assert( X25519.create( session.handshake.precomputed_static_static[0..] // q
                                   , session.engine.static_identity.sk[0..] // n
                                   , session.handshake.remote_static[0..] )); // p
      }

      session.handshake.state = NoiseHandshakeState.ZEROED;

      session.run_event(NoiseSessionEvent.INIT);

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
      return fmt.format( context
                       , FmtError
                       , output
                       , "[SESSION pub:{X}]@0x{x}"
                       , self.handshake.remote_static
                       , @ptrToInt(self)
                       );
    }

    fn run_event(self: *Session, event: NoiseSessionEvent) void {
      //TODO: do timers, etc.
      self.event_last = event;
    }

    fn hs_step1_pilot(self: *Session) !void {
//      hs = &ns->handshake;
//
//      if (!hs->static_identity->has_identity)
//        goto out;

      if (!self.engine.static_identity.has_identity) {
        @panic("this session requires an engine identity to initiate step1!");
      }
//
//      if (!is_retry)
//        ns->tmr_hs_attempts = 0;

      debug.warn("event: {}\n", self.event_last);
      switch(self.event_last) {
          NoiseSessionEvent.NULL => unreachable
        , NoiseSessionEvent.INIT => {} // OK
        , NoiseSessionEvent.CLOSE
        , NoiseSessionEvent.ZERO
        , NoiseSessionEvent.HSHAKE
        , NoiseSessionEvent.HSXMIT
        , NoiseSessionEvent.CONNECTED
        , NoiseSessionEvent.REKEY
        , NoiseSessionEvent.BEGIN_PILOT
        , NoiseSessionEvent.BEGIN_COPILOT
        , NoiseSessionEvent.MAXIMUM => unreachable
      }

      if (self.last_sent_handshake + REKEY_TIMEOUT > self.engine.sys_unixtime())
        return error.Already;

      self.last_sent_handshake = self.engine.sys_unixtime();

      self.handshake.mix( &self.handshake.chaining_key
                        , &self.handshake.hash
                        , &self.handshake.remote_static );

//
//      lsock_install(lsock, &hs->lsock_le, ns);
//
//      /* e */
//      randombytes_buf(hs->ephemeral_private, 32);
//      if (0 != crypto_scalarmult_base(out_unencrypted_ephemeral, hs->ephemeral_private))
//        goto out;
//
//      _message_ephemeral( out_unencrypted_ephemeral
//                        , out_unencrypted_ephemeral
//                        , hs->chaining_key
//                        , hs->hash);
//
//      /* es */
//      if (!_mix_dh( hs->chaining_key
//                  , key
//                  , hs->ephemeral_private
//                  , hs->remote_static))
//        goto out;
//
//      /* s */
//      _mhash_message_encrypt( out_encrypted_static
//                            , hs->static_identity->public
//                            , NOISE_PUBLIC_KEY_LEN
//                            , key
//                            , hs->hash);
//
//      /* ss */
//      _kdf( hs->chaining_key
//          , key
//          , NULL
//          , hs->precomputed_static_static
//          , NOISE_HASH_LEN
//          , NOISE_SYMMETRIC_KEY_LEN
//          , 0
//          , NOISE_PUBLIC_KEY_LEN
//          , hs->chaining_key);
//
//      /* {t} */
//
//      tai64n_now( timestamp );
//
//      _mhash_message_encrypt( out_encrypted_timestamp
//                            , timestamp
//                            , NOISE_TIMESTAMP_LEN
//                            , key
//                            , hs->hash);
//
//      /* unlink if were linked */
//      hash_unlink(&ns->lookup.le);
//
//      /* reup */
//      ns->lookup.id = ns->ne->sessions_counter++;
//      hash_append( ns->ne->idlookup
//                 , ns->lookup.id
//                 , &ns->lookup.le
//                 , &ns->lookup);
//
//      out_sender_index = arch_htole32( ns->lookup.id );
//
//      hs->state = HANDSHAKE_CREATED_INITIATION;
//
//      /* write and send */
//
//      mb = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);
//      mb->pos = EVER_OUTWARD_MBE_POS;
//      mb->end = EVER_OUTWARD_MBE_POS;
//
//      mb_pos = mb->pos;
//
//      mbuf_write_u32(mb, arch_htole32( 1 ));
//      mbuf_write_u32(mb, out_sender_index);
//      mbuf_write_mem(mb, out_unencrypted_ephemeral, 32);
//      mbuf_write_mem(mb, out_encrypted_static, NOISE_ENCRYPTED_LEN(32));
//      mbuf_write_mem(mb, out_encrypted_timestamp, NOISE_ENCRYPTED_LEN(12));
//
//      mbuf_fill(mb, 0, 16); /* mac1 */
//      mbuf_fill(mb, 0, 16); /* mac2 */
//
//      /*debug("resetting position: %u\n", mb->pos - mb_pos);*/
//
//      mbuf_set_pos(mb, mb_pos);
//
//      noise_session_tmr_control(ns, NOISE_TIMER_ON_HAND_INIT);
//
//      (void)lsock_forward(&hs->lsock_le, SOCK_TYPE_DATA_MB, mb);
//
//    out:
//      sodium_memzero(key, NOISE_SYMMETRIC_KEY_LEN);
//      mb = mem_deref(mb);
    }

  }; //X:E Session

  pub fn init( allocator: *Allocator
             , ident: []const u8
             , identkey: []const u8
             , sys_unixtime: fn () u64) !Engine {
    var rbuf: [8]u8 = undefined;
    try std.os.getRandomBytes(rbuf[0..]);
    const seed = mem.readInt(rbuf[0..8], u64, builtin.Endian.Little);

    var out = Engine.{
      .allocator = allocator,
      .session_map = SessionHashMap.init(allocator),
      .hshake_hash = undefined,
      .hshake_chaining_key = undefined,
      .prng = Isaac64.init(seed),
      .static_identity = undefined,
      .sys_unixtime = sys_unixtime,
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

  pub fn genRandomIdentity(self: *Engine) void {
    if (self.static_identity.has_identity) {
      @panic("This engine already has static identity!");
    }
    self.prng.random.bytes(self.static_identity.sk[0..32]);
    std.debug.assert(X25519.createPublicKey(self.static_identity.pk[0..], self.static_identity.sk));
    self.static_identity.has_identity = true;
    debug.warn("SK: {X}\n", self.static_identity.sk);
    debug.warn("PK: {X}\n", self.static_identity.pk);
  }

  pub fn sessionGetOrCreate( self: *Engine
                           , public_key: var
                           , preshared_key: ?*const [NOISE_SYMMETRIC_KEY_LEN] u8) !*Engine.Session {
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

  //init engines
  var e1 = try Engine.init( debug.global_allocator
                          , g_ident
                          , g_identkey
                          , std.os.time.timestamp);
  defer e1.deinit();
  var e2 = try Engine.init( debug.global_allocator
                          , g_ident
                          , g_identkey
                          , std.os.time.timestamp);
  defer e2.deinit();

  //generate random identities
  e1.genRandomIdentity();
  e2.genRandomIdentity();

  var e1_e2_session = try e1.sessionGetOrCreate(e2.static_identity.pk, null);
  debug.warn("e1_e2_session: {}\n", e1_e2_session);
  _ = try e1_e2_session.hs_step1_pilot();

}
