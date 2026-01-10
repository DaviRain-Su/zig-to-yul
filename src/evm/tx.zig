//! Transaction encoding and signing (legacy/EIP-155).

const std = @import("std");
const types = @import("types.zig");
const rpc = @import("rpc.zig");

pub const Address = types.Address;
pub const U256 = types.U256;

const Scheme = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Scalar = Secp256k1.scalar.Scalar;

pub const LegacyTx = struct {
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: ?Address,
    value: U256,
    data: []const u8,
    chain_id: u64,
};

pub fn signLegacy(allocator: std.mem.Allocator, tx: LegacyTx, private_key_hex: []const u8) ![]u8 {
    const priv_bytes = try decodeHex32(private_key_hex);
    return try signLegacyWithKey(allocator, tx, priv_bytes);
}

fn signLegacyWithKey(allocator: std.mem.Allocator, tx: LegacyTx, priv_bytes: [32]u8) ![]u8 {
    const signing_rlp = try encodeLegacyForSign(allocator, tx);
    defer allocator.free(signing_rlp);

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(signing_rlp, &hash, .{});

    const secret = try Scheme.SecretKey.fromBytes(priv_bytes);
    const key_pair = try Scheme.KeyPair.fromSecretKey(secret);

    const sig = try key_pair.signPrehashed(hash, null);
    const sig_bytes = sig.toBytes();
    var r_bytes: [32]u8 = undefined;
    var s_bytes: [32]u8 = undefined;
    @memcpy(&r_bytes, sig_bytes[0..32]);
    @memcpy(&s_bytes, sig_bytes[32..64]);

    var recid = try recoverId(hash, r_bytes, s_bytes, key_pair.public_key.p);
    if (isHighS(s_bytes)) {
        s_bytes = subBytes32(SECP256K1_N, s_bytes);
        recid ^= 1;
    }

    const v = @as(u64, recid) + 35 + tx.chain_id * 2;
    const raw = try encodeLegacySigned(allocator, tx, v, r_bytes, s_bytes);
    defer allocator.free(raw);
    return try hexEncodeAlloc(allocator, raw);
}

pub fn sendLegacy(allocator: std.mem.Allocator, rpc_url: []const u8, tx: LegacyTx, private_key_hex: []const u8) ![]u8 {
    const raw = try signLegacy(allocator, tx, private_key_hex);
    defer allocator.free(raw);
    return try rpc.ethSendRawTransaction(allocator, rpc_url, raw);
}

pub const AccessListItem = struct {
    address: Address,
    storage_keys: []const [32]u8,
};

pub const Eip1559Tx = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u64,
    max_fee_per_gas: u64,
    gas_limit: u64,
    to: ?Address,
    value: U256,
    data: []const u8,
    access_list: []const AccessListItem = &.{},
};

pub fn signEip1559(allocator: std.mem.Allocator, tx: Eip1559Tx, private_key_hex: []const u8) ![]u8 {
    const priv_bytes = try decodeHex32(private_key_hex);
    return try signEip1559WithKey(allocator, tx, priv_bytes);
}

fn signEip1559WithKey(allocator: std.mem.Allocator, tx: Eip1559Tx, priv_bytes: [32]u8) ![]u8 {
    const signing_rlp = try encodeEip1559ForSign(allocator, tx);
    defer allocator.free(signing_rlp);

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.append(allocator, 0x02);
    try payload.appendSlice(allocator, signing_rlp);

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(payload.items, &hash, .{});

    const secret = try Scheme.SecretKey.fromBytes(priv_bytes);
    const key_pair = try Scheme.KeyPair.fromSecretKey(secret);

    const sig = try key_pair.signPrehashed(hash, null);
    const sig_bytes = sig.toBytes();
    var r_bytes: [32]u8 = undefined;
    var s_bytes: [32]u8 = undefined;
    @memcpy(&r_bytes, sig_bytes[0..32]);
    @memcpy(&s_bytes, sig_bytes[32..64]);

    var recid = try recoverId(hash, r_bytes, s_bytes, key_pair.public_key.p);
    if (isHighS(s_bytes)) {
        s_bytes = subBytes32(SECP256K1_N, s_bytes);
        recid ^= 1;
    }

    const raw_rlp = try encodeEip1559Signed(allocator, tx, recid, r_bytes, s_bytes);
    defer allocator.free(raw_rlp);

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try raw.append(allocator, 0x02);
    try raw.appendSlice(allocator, raw_rlp);

    return try hexEncodeAlloc(allocator, raw.items);
}

pub fn sendEip1559(allocator: std.mem.Allocator, rpc_url: []const u8, tx: Eip1559Tx, private_key_hex: []const u8) ![]u8 {
    const raw = try signEip1559(allocator, tx, private_key_hex);
    defer allocator.free(raw);
    return try rpc.ethSendRawTransaction(allocator, rpc_url, raw);
}

pub const KeystoreError = error{
    InvalidKeystore,
    UnsupportedCipher,
    UnsupportedKdf,
    InvalidMac,
    InvalidParams,
    InvalidCiphertext,
};

pub fn signLegacyKeystore(
    allocator: std.mem.Allocator,
    tx: LegacyTx,
    keystore_json: []const u8,
    password: []const u8,
) ![]u8 {
    const key = try decryptKeystore(allocator, keystore_json, password);
    return try signLegacyWithKey(allocator, tx, key);
}

pub fn sendLegacyKeystore(
    allocator: std.mem.Allocator,
    rpc_url: []const u8,
    tx: LegacyTx,
    keystore_json: []const u8,
    password: []const u8,
) ![]u8 {
    const raw = try signLegacyKeystore(allocator, tx, keystore_json, password);
    defer allocator.free(raw);
    return try rpc.ethSendRawTransaction(allocator, rpc_url, raw);
}

pub fn signEip1559Keystore(
    allocator: std.mem.Allocator,
    tx: Eip1559Tx,
    keystore_json: []const u8,
    password: []const u8,
) ![]u8 {
    const key = try decryptKeystore(allocator, keystore_json, password);
    return try signEip1559WithKey(allocator, tx, key);
}

pub fn sendEip1559Keystore(
    allocator: std.mem.Allocator,
    rpc_url: []const u8,
    tx: Eip1559Tx,
    keystore_json: []const u8,
    password: []const u8,
) ![]u8 {
    const raw = try signEip1559Keystore(allocator, tx, keystore_json, password);
    defer allocator.free(raw);
    return try rpc.ethSendRawTransaction(allocator, rpc_url, raw);
}

pub fn decryptKeystore(allocator: std.mem.Allocator, keystore_json: []const u8, password: []const u8) ![32]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, keystore_json, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return KeystoreError.InvalidKeystore;
    const root = parsed.value.object;

    const crypto_value = if (root.get("crypto")) |val| val else root.get("Crypto") orelse return KeystoreError.InvalidKeystore;
    if (crypto_value != .object) return KeystoreError.InvalidKeystore;
    const crypto_obj = crypto_value.object;

    const cipher = try getStringField(crypto_obj, "cipher");
    if (!std.mem.eql(u8, cipher, "aes-128-ctr")) return KeystoreError.UnsupportedCipher;

    const ciphertext_hex = try getStringField(crypto_obj, "ciphertext");
    const cipherparams_value = try getObjectField(crypto_obj, "cipherparams");
    const iv_hex = try getStringField(cipherparams_value, "iv");

    const kdf = try getStringField(crypto_obj, "kdf");
    const kdfparams = try getObjectField(crypto_obj, "kdfparams");
    const dklen = try getU32Field(kdfparams, "dklen");
    if (dklen < 32) return KeystoreError.InvalidParams;

    const salt_hex = try getStringField(kdfparams, "salt");
    const salt = try decodeHexAlloc(allocator, salt_hex);
    defer allocator.free(salt);

    var derived_key = try allocator.alloc(u8, dklen);
    defer allocator.free(derived_key);

    if (std.mem.eql(u8, kdf, "scrypt")) {
        const n = try getU64Field(kdfparams, "n");
        const r = try getU64Field(kdfparams, "r");
        const p = try getU64Field(kdfparams, "p");
        if (!std.math.isPowerOfTwo(n)) return KeystoreError.InvalidParams;
        const ln = std.math.log2_int(u64, n);
        const params: std.crypto.pwhash.scrypt.Params = .{
            .ln = @intCast(ln),
            .r = @intCast(r),
            .p = @intCast(p),
        };
        try std.crypto.pwhash.scrypt.kdf(allocator, derived_key, password, salt, params);
    } else if (std.mem.eql(u8, kdf, "pbkdf2")) {
        const prf = try getStringField(kdfparams, "prf");
        if (!std.mem.eql(u8, prf, "hmac-sha256")) return KeystoreError.UnsupportedKdf;
        const rounds = try getU32Field(kdfparams, "c");
        try std.crypto.pwhash.pbkdf2(derived_key, password, salt, rounds, std.crypto.auth.hmac.sha2.HmacSha256);
    } else {
        return KeystoreError.UnsupportedKdf;
    }

    const mac_hex = try getStringField(crypto_obj, "mac");
    const mac = try decodeHexFixed(32, mac_hex);

    const ciphertext = try decodeHexAlloc(allocator, ciphertext_hex);
    defer allocator.free(ciphertext);

    var mac_input = try allocator.alloc(u8, 16 + ciphertext.len);
    defer allocator.free(mac_input);
    @memcpy(mac_input[0..16], derived_key[16..32]);
    @memcpy(mac_input[16..], ciphertext);

    var mac_hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(mac_input, &mac_hash, .{});
    if (!std.mem.eql(u8, &mac_hash, &mac)) return KeystoreError.InvalidMac;

    const iv = try decodeHexFixed(16, iv_hex);
    var key_bytes: [16]u8 = undefined;
    @memcpy(&key_bytes, derived_key[0..16]);

    var plain = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(plain);

    const aes = std.crypto.core.aes.Aes128;
    const ctr = std.crypto.core.modes.ctr;
    const ctx = aes.initEnc(key_bytes);
    ctr(std.crypto.core.aes.AesEncryptCtx(aes), ctx, plain, ciphertext, iv, .big);

    if (plain.len != 32) return KeystoreError.InvalidCiphertext;
    var out: [32]u8 = undefined;
    @memcpy(&out, plain[0..32]);
    return out;
}

fn encodeLegacyForSign(allocator: std.mem.Allocator, tx: LegacyTx) ![]u8 {
    return try encodeLegacyList(allocator, tx, tx.chain_id, null, null);
}

fn encodeLegacySigned(allocator: std.mem.Allocator, tx: LegacyTx, v: u64, r: [32]u8, s: [32]u8) ![]u8 {
    return try encodeLegacyList(allocator, tx, v, r, s);
}

fn encodeLegacyList(allocator: std.mem.Allocator, tx: LegacyTx, v: u64, r: ?[32]u8, s: ?[32]u8) ![]u8 {
    var items: std.ArrayList([]u8) = .empty;
    defer {
        for (items.items) |item| allocator.free(item);
        items.deinit(allocator);
    }

    try items.append(allocator, try rlpEncodeInteger(allocator, tx.nonce));
    try items.append(allocator, try rlpEncodeInteger(allocator, tx.gas_price));
    try items.append(allocator, try rlpEncodeInteger(allocator, tx.gas_limit));
    try items.append(allocator, try rlpEncodeAddress(allocator, tx.to));
    try items.append(allocator, try rlpEncodeU256(allocator, tx.value));
    try items.append(allocator, try rlpEncodeBytes(allocator, tx.data));

    if (r == null or s == null) {
        try items.append(allocator, try rlpEncodeInteger(allocator, v));
        try items.append(allocator, try rlpEncodeBytes(allocator, &.{}));
        try items.append(allocator, try rlpEncodeBytes(allocator, &.{}));
    } else {
        try items.append(allocator, try rlpEncodeInteger(allocator, v));
        try items.append(allocator, try rlpEncodeScalar(allocator, r.?));
        try items.append(allocator, try rlpEncodeScalar(allocator, s.?));
    }

    return try rlpEncodeList(allocator, items.items);
}

fn encodeEip1559ForSign(allocator: std.mem.Allocator, tx: Eip1559Tx) ![]u8 {
    return try encodeEip1559List(allocator, tx, null, null, null);
}

fn encodeEip1559Signed(allocator: std.mem.Allocator, tx: Eip1559Tx, v: u8, r: [32]u8, s: [32]u8) ![]u8 {
    return try encodeEip1559List(allocator, tx, v, r, s);
}

fn encodeEip1559List(
    allocator: std.mem.Allocator,
    tx: Eip1559Tx,
    v: ?u8,
    r: ?[32]u8,
    s: ?[32]u8,
) ![]u8 {
    var items: std.ArrayList([]u8) = .empty;
    defer {
        for (items.items) |item| allocator.free(item);
        items.deinit(allocator);
    }

    try items.append(allocator, try rlpEncodeInteger(allocator, tx.chain_id));
    try items.append(allocator, try rlpEncodeInteger(allocator, tx.nonce));
    try items.append(allocator, try rlpEncodeInteger(allocator, tx.max_priority_fee_per_gas));
    try items.append(allocator, try rlpEncodeInteger(allocator, tx.max_fee_per_gas));
    try items.append(allocator, try rlpEncodeInteger(allocator, tx.gas_limit));
    try items.append(allocator, try rlpEncodeAddress(allocator, tx.to));
    try items.append(allocator, try rlpEncodeU256(allocator, tx.value));
    try items.append(allocator, try rlpEncodeBytes(allocator, tx.data));
    try items.append(allocator, try rlpEncodeAccessList(allocator, tx.access_list));

    if (v != null and r != null and s != null) {
        try items.append(allocator, try rlpEncodeInteger(allocator, v.?));
        try items.append(allocator, try rlpEncodeScalar(allocator, r.?));
        try items.append(allocator, try rlpEncodeScalar(allocator, s.?));
    }

    return try rlpEncodeList(allocator, items.items);
}

fn rlpEncodeList(allocator: std.mem.Allocator, items: []const []const u8) ![]u8 {
    var total_len: usize = 0;
    for (items) |item| total_len += item.len;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try appendListPrefix(&out, allocator, total_len);
    for (items) |item| {
        try out.appendSlice(allocator, item);
    }

    return try out.toOwnedSlice(allocator);
}

fn rlpEncodeBytes(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len == 1 and data[0] < 0x80) {
        return allocator.dupe(u8, data);
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try appendStringPrefix(&out, allocator, data.len);
    try out.appendSlice(allocator, data);

    return try out.toOwnedSlice(allocator);
}

fn rlpEncodeInteger(allocator: std.mem.Allocator, value: u64) ![]u8 {
    if (value == 0) return rlpEncodeBytes(allocator, &.{});

    var buf: [8]u8 = undefined;
    const len = writeU64Be(&buf, value);
    return rlpEncodeBytes(allocator, buf[8 - len ..]);
}

fn rlpEncodeU256(allocator: std.mem.Allocator, value: U256) ![]u8 {
    if (value == 0) return rlpEncodeBytes(allocator, &.{});

    var buf: [32]u8 = undefined;
    writeU256Be(&buf, value);
    const trimmed = trimLeadingZeros(&buf);
    return rlpEncodeBytes(allocator, trimmed);
}

fn rlpEncodeScalar(allocator: std.mem.Allocator, value: [32]u8) ![]u8 {
    const trimmed = trimLeadingZeros(&value);
    return rlpEncodeBytes(allocator, trimmed);
}

fn rlpEncodeAddress(allocator: std.mem.Allocator, addr: ?Address) ![]u8 {
    if (addr == null) return rlpEncodeBytes(allocator, &.{});
    var buf: [20]u8 = undefined;
    writeAddressBe(&buf, addr.?);
    return rlpEncodeBytes(allocator, &buf);
}

fn rlpEncodeAccessList(allocator: std.mem.Allocator, access_list: []const AccessListItem) ![]u8 {
    var item_rlps: std.ArrayList([]u8) = .empty;
    defer {
        for (item_rlps.items) |item| allocator.free(item);
        item_rlps.deinit(allocator);
    }

    for (access_list) |item| {
        const addr_rlp = try rlpEncodeAddress(allocator, item.address);
        errdefer allocator.free(addr_rlp);
        const keys_rlp = try rlpEncodeStorageKeys(allocator, item.storage_keys);
        errdefer allocator.free(keys_rlp);

        const pair_items = [_][]const u8{ addr_rlp, keys_rlp };
        const pair_rlp = try rlpEncodeList(allocator, &pair_items);
        allocator.free(addr_rlp);
        allocator.free(keys_rlp);

        try item_rlps.append(allocator, pair_rlp);
    }

    return try rlpEncodeList(allocator, item_rlps.items);
}

fn rlpEncodeStorageKeys(allocator: std.mem.Allocator, keys: []const [32]u8) ![]u8 {
    var key_rlps: std.ArrayList([]u8) = .empty;
    defer {
        for (key_rlps.items) |item| allocator.free(item);
        key_rlps.deinit(allocator);
    }

    for (keys) |key| {
        try key_rlps.append(allocator, try rlpEncodeBytes(allocator, key[0..]));
    }

    return try rlpEncodeList(allocator, key_rlps.items);
}

fn appendStringPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize) !void {
    if (len < 56) {
        try list.append(allocator, @intCast(0x80 + len));
        return;
    }
    var buf: [8]u8 = undefined;
    const len_len = writeUsizeBe(&buf, len);
    try list.append(allocator, @intCast(0xb7 + len_len));
    try list.appendSlice(allocator, buf[8 - len_len ..]);
}

fn appendListPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize) !void {
    if (len < 56) {
        try list.append(allocator, @intCast(0xc0 + len));
        return;
    }
    var buf: [8]u8 = undefined;
    const len_len = writeUsizeBe(&buf, len);
    try list.append(allocator, @intCast(0xf7 + len_len));
    try list.appendSlice(allocator, buf[8 - len_len ..]);
}

fn writeUsizeBe(buf: *[8]u8, value: usize) usize {
    var tmp = value;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        buf[7 - i] = @intCast(tmp & 0xff);
        tmp >>= 8;
    }
    return 8 - leadingZeroBytes(buf);
}

fn writeU64Be(buf: *[8]u8, value: u64) usize {
    var tmp = value;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        buf[7 - i] = @intCast(tmp & 0xff);
        tmp >>= 8;
    }
    return 8 - leadingZeroBytes(buf);
}

fn writeU256Be(buf: *[32]u8, value: U256) void {
    var tmp = value;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        buf[31 - i] = @intCast(tmp & 0xff);
        tmp >>= 8;
    }
}

fn writeAddressBe(buf: *[20]u8, addr: Address) void {
    var tmp = addr;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        buf[19 - i] = @intCast(tmp & 0xff);
        tmp >>= 8;
    }
}

fn leadingZeroBytes(buf: *const [8]u8) usize {
    var i: usize = 0;
    while (i < 8 and buf[i] == 0) : (i += 1) {}
    return i;
}

fn trimLeadingZeros(buf: []const u8) []const u8 {
    var i: usize = 0;
    while (i < buf.len and buf[i] == 0) : (i += 1) {}
    return buf[i..];
}

fn decodeHex32(text: []const u8) ![32]u8 {
    const hex = trimHexPrefix(text);
    if (hex.len != 64) return error.InvalidArgument;

    var out: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out[i] = try parseHexByte(hex[i * 2], hex[i * 2 + 1]);
    }
    return out;
}

fn decodeHexFixed(comptime N: usize, text: []const u8) ![N]u8 {
    const hex = trimHexPrefix(text);
    if (hex.len != N * 2) return KeystoreError.InvalidParams;

    var out: [N]u8 = undefined;
    var i: usize = 0;
    while (i < N) : (i += 1) {
        out[i] = try parseHexByte(hex[i * 2], hex[i * 2 + 1]);
    }
    return out;
}

fn decodeHexAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const hex = trimHexPrefix(text);
    if (hex.len % 2 != 0) return KeystoreError.InvalidParams;

    var out = try allocator.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try parseHexByte(hex[i], hex[i + 1]);
    }
    return out;
}

fn getObjectField(obj: std.json.ObjectMap, name: []const u8) !std.json.ObjectMap {
    const value = obj.get(name) orelse return KeystoreError.InvalidKeystore;
    if (value != .object) return KeystoreError.InvalidKeystore;
    return value.object;
}

fn getStringField(obj: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = obj.get(name) orelse return KeystoreError.InvalidKeystore;
    if (value != .string) return KeystoreError.InvalidKeystore;
    return value.string;
}

fn getU64Field(obj: std.json.ObjectMap, name: []const u8) !u64 {
    const value = obj.get(name) orelse return KeystoreError.InvalidKeystore;
    switch (value) {
        .integer => |num| {
            if (num < 0) return KeystoreError.InvalidParams;
            return @intCast(num);
        },
        .float => |num| {
            if (num < 0) return KeystoreError.InvalidParams;
            const rounded = std.math.floor(num);
            if (rounded != num) return KeystoreError.InvalidParams;
            return @intFromFloat(rounded);
        },
        else => return KeystoreError.InvalidParams,
    }
}

fn getU32Field(obj: std.json.ObjectMap, name: []const u8) !u32 {
    const value = try getU64Field(obj, name);
    if (value > std.math.maxInt(u32)) return KeystoreError.InvalidParams;
    return @intCast(value);
}

fn parseHexByte(a: u8, b: u8) !u8 {
    return (try hexNibble(a)) << 4 | try hexNibble(b);
}

fn hexNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidArgument,
    };
}

fn trimHexPrefix(text: []const u8) []const u8 {
    if (text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) {
        return text[2..];
    }
    return text;
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    var out = try allocator.alloc(u8, data.len * 2 + 2);
    out[0] = '0';
    out[1] = 'x';
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        const byte = data[i];
        out[2 + i * 2] = hex_chars[byte >> 4];
        out[2 + i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return out;
}

fn isHighS(s: [32]u8) bool {
    return std.mem.order(u8, &s, &SECP256K1_HALF_N) == .gt;
}

fn subBytes32(a: [32]u8, b: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    var borrow: u8 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const ai = a[31 - i];
        const bi = b[31 - i];
        const tmp: i16 = @as(i16, ai) - @as(i16, bi) - @as(i16, borrow);
        if (tmp < 0) {
            out[31 - i] = @intCast(tmp + 256);
            borrow = 1;
        } else {
            out[31 - i] = @intCast(tmp);
            borrow = 0;
        }
    }
    return out;
}

fn recoverId(hash: [32]u8, r_bytes: [32]u8, s_bytes: [32]u8, pubkey: Secp256k1) !u8 {
    const r_scalar = try Scalar.fromBytes(r_bytes, .big);
    const s_scalar = try Scalar.fromBytes(s_bytes, .big);

    var hash64: [64]u8 = [_]u8{0} ** 64;
    @memcpy(hash64[32..], &hash);
    const z_scalar = Scalar.fromBytes64(hash64, .big);

    const r_inv = Scalar.invert(r_scalar);

    const x_fe = try Secp256k1.Fe.fromBytes(r_bytes, .big);

    var recid: u8 = 0;
    while (recid < 2) : (recid += 1) {
        const y_fe = try Secp256k1.recoverY(x_fe, recid == 1);
        const r_point = try Secp256k1.fromAffineCoordinates(.{ .x = x_fe, .y = y_fe });

        const sR = try r_point.mul(s_scalar.toBytes(.big), .big);
        const zG = try Secp256k1.basePoint.mul(z_scalar.toBytes(.big), .big);
        const sR_minus_zG = Secp256k1.sub(sR, zG);
        const q = try sR_minus_zG.mul(r_inv.toBytes(.big), .big);

        if (q.equivalent(pubkey)) {
            return recid;
        }
    }

    return error.SignatureRecoveryFailed;
}

const SECP256K1_N: [32]u8 = .{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

const SECP256K1_HALF_N: [32]u8 = .{
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

test "anvil tx send (legacy + eip1559)" {
    const allocator = std.testing.allocator;

    var anvil = startAnvil(allocator) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer stopAnvil(&anvil);

    waitForAnvilReady(allocator) catch |err| switch (err) {
        error.ConnectionRefused => return,
        else => return err,
    };

    const rpc_url = "http://127.0.0.1:8545";
    const private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    const recipient: Address = @as(Address, 0x70997970c51812dc3a010c7d01b50e0d17dc79c8);
    const chain_id: u64 = 31337;
    const gas_limit: u64 = 21_000;
    const gas_price: u64 = 1_000_000_000;
    const max_priority_fee_per_gas: u64 = 1_000_000_000;
    const max_fee_per_gas: u64 = 2_000_000_000;

    const legacy_hash = sendLegacy(allocator, rpc_url, .{
        .nonce = 0,
        .gas_price = gas_price,
        .gas_limit = gas_limit,
        .to = recipient,
        .value = 0,
        .data = &.{},
        .chain_id = chain_id,
    }, private_key) catch |err| switch (err) {
        error.ConnectionRefused => return,
        else => return err,
    };
    defer allocator.free(legacy_hash);
    try std.testing.expect(legacy_hash.len > 2);

    const eip1559_hash = sendEip1559(allocator, rpc_url, .{
        .chain_id = chain_id,
        .nonce = 1,
        .max_priority_fee_per_gas = max_priority_fee_per_gas,
        .max_fee_per_gas = max_fee_per_gas,
        .gas_limit = gas_limit,
        .to = recipient,
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    }, private_key) catch |err| switch (err) {
        error.ConnectionRefused => return,
        else => return err,
    };
    defer allocator.free(eip1559_hash);
    try std.testing.expect(eip1559_hash.len > 2);
}

fn startAnvil(allocator: std.mem.Allocator) !std.process.Child {
    const anvil_path = std.process.getEnvVarOwned(allocator, "ANVIL_BIN") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (anvil_path) |path| allocator.free(path);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);

    try argv.append(allocator, if (anvil_path) |path| path else "anvil");
    try argv.appendSlice(allocator, &.{ "--host", "127.0.0.1", "--port", "8545" });

    var child = std.process.Child.init(argv.items, allocator);
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    return child;
}

fn waitForAnvilReady(allocator: std.mem.Allocator) !void {
    const max_attempts: usize = 50;
    var attempt: usize = 0;
    while (attempt < max_attempts) : (attempt += 1) {
        if (std.net.tcpConnectToHost(allocator, "127.0.0.1", 8545)) |stream| {
            stream.close();
            return;
        } else |err| switch (err) {
            error.ConnectionRefused => {
                std.Thread.sleep(100 * std.time.ns_per_ms);
            },
            else => return err,
        }
    }
    return error.ConnectionRefused;
}

fn stopAnvil(child: *std.process.Child) void {
    const term = child.kill() catch return;
    _ = term;
    _ = child.wait() catch {};
}
