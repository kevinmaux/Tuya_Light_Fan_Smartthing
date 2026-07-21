-- Pure Lua AES-128-GCM (NIST SP 800-38D), for Tuya protocol 3.5 framing.
-- Only supports the case Tuya actually uses: 12-byte (96-bit) IV, 16-byte tag.
local aes = require("aes")

local gcm = {}

local function bxor16(a, b)
  local out = {}
  for i = 1, 16 do
    out[i] = string.char(string.byte(a, i) ~ string.byte(b, i))
  end
  return table.concat(out)
end

-- GF(2^128) multiply, per the GCM spec's bit ordering (MSB-first within each
-- byte is the "low" end of the polynomial). X, Y are 16-byte strings.
local function gf_mul(x, y)
  local z = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
  local v = {string.byte(y, 1, 16)}

  for i = 1, 16 do
    local xbyte = string.byte(x, i)
    for bit = 7, 0, -1 do
      if ((xbyte >> bit) & 1) == 1 then
        for k = 1, 16 do z[k] = z[k] ~ v[k] end
      end
      local lsb = v[16] & 1
      for k = 16, 2, -1 do
        v[k] = ((v[k] >> 1) | ((v[k-1] & 1) << 7)) & 0xFF
      end
      v[1] = v[1] >> 1
      if lsb == 1 then
        v[1] = v[1] ~ 0xE1
      end
    end
  end

  local chars = {}
  for i = 1, 16 do chars[i] = string.char(z[i]) end
  return table.concat(chars)
end

-- GHASH(H, data) where #data is a multiple of 16.
local function ghash(h, data)
  local y = string.rep("\0", 16)
  for i = 1, #data, 16 do
    local block = data:sub(i, i + 15)
    y = gf_mul(bxor16(y, block), h)
  end
  return y
end

local function pad16(s)
  local rem = #s % 16
  if rem == 0 then return s end
  return s .. string.rep("\0", 16 - rem)
end

local function inc32(block)
  local prefix = block:sub(1, 12)
  local ctr = string.unpack(">I4", block, 13)
  ctr = (ctr + 1) & 0xFFFFFFFF
  return prefix .. string.pack(">I4", ctr)
end

-- CTR-mode keystream application starting at counter block `icb`.
local function gctr(w, icb, data)
  if #data == 0 then return "" end
  local out = {}
  local cb = icb
  local pos = 1
  while pos <= #data do
    local ks = aes.encrypt_block_str(cb, w)
    local chunk = data:sub(pos, pos + 15)
    local piece = {}
    for i = 1, #chunk do
      piece[i] = string.char(string.byte(chunk, i) ~ string.byte(ks, i))
    end
    out[#out+1] = table.concat(piece)
    cb = inc32(cb)
    pos = pos + 16
  end
  return table.concat(out)
end

local function j0_and_h(key, iv)
  if #key ~= 16 then error("GCM key must be 16 bytes") end
  if #iv ~= 12 then error("only 96-bit IVs are supported") end
  local w = aes.expand_key(key)
  local h = aes.encrypt_block_str(string.rep("\0", 16), w)
  local j0 = iv .. "\0\0\0\1"
  return w, h, j0
end

-- Returns ciphertext, 16-byte tag
function gcm.encrypt(key, iv, plaintext, aad)
  aad = aad or ""
  local w, h, j0 = j0_and_h(key, iv)
  local ciphertext = gctr(w, inc32(j0), plaintext)

  local s_input = pad16(aad) .. pad16(ciphertext)
    .. string.pack(">I4I4", 0, #aad * 8)
    .. string.pack(">I4I4", 0, #ciphertext * 8)
  local s = ghash(h, s_input)
  local tag = gctr(w, j0, s)

  return ciphertext, tag
end

-- Returns plaintext or nil, "auth failed"
function gcm.decrypt(key, iv, ciphertext, aad, tag)
  aad = aad or ""
  local w, h, j0 = j0_and_h(key, iv)

  local s_input = pad16(aad) .. pad16(ciphertext)
    .. string.pack(">I4I4", 0, #aad * 8)
    .. string.pack(">I4I4", 0, #ciphertext * 8)
  local s = ghash(h, s_input)
  local expected_tag = gctr(w, j0, s)

  if expected_tag ~= tag then
    return nil, "auth failed"
  end

  local plaintext = gctr(w, inc32(j0), ciphertext)
  return plaintext
end

return gcm
