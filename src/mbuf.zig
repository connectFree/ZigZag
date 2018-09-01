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

};
