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
const assert = std.debug.assert;
const math = std.math;

const RFC6479_BITS_TOTAL: u32 = 2048;
const RFC6479_REDUNDANT_BITS: u32 = u32.bit_count;
const RFC6479_REDUNDANT_BITS_SHIFTBY: u6 = (31 - @clz(u32(u32.bit_count)));
const RFC6479_WINDOW_SIZE: u32 = RFC6479_BITS_TOTAL - RFC6479_REDUNDANT_BITS;


comptime {
  assert( u32.bit_count == 32 );
  assert( RFC6479_REDUNDANT_BITS_SHIFTBY == 5 );  
}

pub const RFC6479 = struct {
  backtrack: [RFC6479_BITS_TOTAL / u32.bit_count]u32,
  counter: u64,


  pub fn new() RFC6479 {
    return RFC6479 {
      .backtrack = undefined,
      .counter = 0,
    };
  }

  pub fn count(self: *RFC6479, _their_counter: u64, distance: ?*u64) !void {
    var index_current: u64 = 0;
    var i: u32 = 1;
    var top: u64 = 0;

    var their_counter = _their_counter + 1;

    if ((RFC6479_WINDOW_SIZE + their_counter) < self.counter) {
      return error.OutsideWindow;
    }

    var index: u64 = their_counter >> RFC6479_REDUNDANT_BITS_SHIFTBY;

    if (their_counter > self.counter) {
      index_current = self.counter >> RFC6479_REDUNDANT_BITS_SHIFTBY;
      top = math.min(index - index_current, RFC6479_BITS_TOTAL / u32.bit_count);

      while (i <= top) : (i += 1) {
        self.backtrack[(i + index_current) & ((RFC6479_BITS_TOTAL / u32.bit_count) - 1)] = 0;
      }

      if (distance) |d| {
        d.* = (their_counter - self.counter);
      }

      self.counter = their_counter;
    } else {
      if (distance) |d| {
        d.* = 0;
      }
    }

    index &= (RFC6479_BITS_TOTAL / u32.bit_count) - 1;
    var bitloc: u5 = @truncate(u5, their_counter & (u32.bit_count - 1));

    if (self.backtrack[index] & (u32(1) << bitloc) != 0) {
      return error.AlreadyRecieved;// /* already received */
    }

    self.backtrack[index] |= (u32(1) << bitloc);
  }

};


test "rudimentary replay" {
  var i: u32 = 0;
  var counter = RFC6479.new();

  while (i <= 1000) : (i += 1) {
    try counter.count(i, null);
  }

  i = 0;
  while (i <= 1000) : (i += 1) {
    var ok = false;
    counter.count(i, null) catch |err| {
      switch (err) {
        error.AlreadyRecieved => {
          ok = true;
        },
        error.OutsideWindow => unreachable
      }
    };
    assert(ok);
  }

}

