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
// @file mbuf.zig Interface to message buffers
//

const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const Allocator = mem.Allocator;
const assert = debug.assert;
const ArrayList = std.ArrayList;

const DEFAULT_SIZE: usize = 1 << 9;

pub const mbuf = struct {
    buf: ArrayList(u8),
    size: usize, 
    pos: usize, 
    end: usize,

    pub fn alloc(allocator: *Allocator, size: usize) !mbuf {
        var self = allocEmpty(allocator);
        try self.resize(if (size > 0) size else DEFAULT_SIZE);
        return self;
    }

    pub fn allocEmpty(allocator: *Allocator) mbuf {
        return mbuf {
            .buf = ArrayList(u8).init(allocator),
            .size = 0,
            .pos = 0,
            .end = 0,
        };
    }

    pub fn deinit(self: *mbuf) void {
        self.buf.deinit();
    }

    pub fn resize(self: *mbuf, new_size: usize) !void {
        try self.buf.resize(new_size + 1);
        self.buf.items[self.len()] = 0;
        self.size = new_size;
    }

    pub fn len(self: *const mbuf) usize {
        return self.buf.len - 1;
    }

    /// Check that self.pos does not exceed self.end
    /// This function panics because message buffers should go over
    fn checkPos(self: *const mbuf) void {
      if (self.pos > self.end)
        @panic("Message Buffer position mark exceeds end mark");
    }

    /// Check that self.end does not exceed self.size
    /// This function panics because message buffers should go over
    fn checkEnd(self: *const mbuf) void {
      if (self.end > self.size)
        @panic("Message Buffer end mark exceeds buffer size");
    }

    pub fn write_mem(self: *mbuf, buf: []const u8) !void {
        var rsize: usize = self.pos + buf.len;
        if (rsize > self.size) {
          const dsize = if (self.size != 0) self.size * 2 else DEFAULT_SIZE;
          try self.resize( std.math.max(rsize, dsize) );
        }
        mem.copy(u8, self.buf.toSlice()[self.pos..], buf);
        self.pos += buf.len;
        self.end  = std.math.max(self.end, self.pos);
    }

    pub fn writeInt(self: *mbuf, value: var, endian: builtin.Endian) !void {
        const size = (@typeOf(value).bit_count / 8);
        var rsize: usize = self.pos + size;
        if (rsize > self.size) {
          const dsize = if (self.size != 0) self.size * 2 else DEFAULT_SIZE;
          try self.resize( std.math.max(rsize, dsize) );
        }
        mem.writeInt(self.buf.toSlice()[self.pos..], value, endian);
        self.pos += size;
        self.end  = std.math.max(self.end, self.pos);
    }

    pub fn toSlice(self: *const mbuf) []u8 {
        return self.buf.toSlice()[self.pos..self.end];
    }

    pub fn toSliceConst(self: *const mbuf) []const u8 {
        return self.buf.toSliceConst()[self.pos..self.end];
    }

    pub fn ptr(self: *const mbuf) [*]u8 {
        return self.buf.items.ptr + self.pos;
    }

    pub fn bytesLeft(self: *const mbuf) usize {
        return if (self.end > self.pos) self.end - self.pos else 0;
    }

    pub fn space(self: *const mbuf) usize {
        return if (self.size > self.pos) self.size - self.pos else 0;
    }

    pub fn setPos(self: *mbuf, pos: usize) void {
        self.pos = pos;
        self.checkPos();
    }

    pub fn setEnd(self: *mbuf, end: usize) void {
        self.end = end;
        self.checkEnd();
    }

    pub fn advance(self: *mbuf, n: isize) void {
        self.pos = @intCast(usize, @intCast(isize, self.pos) + n);
        self.checkPos();
    }

};
