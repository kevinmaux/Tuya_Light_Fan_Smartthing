-- Pure Lua HMAC-SHA256 (RFC 2104)
local sha256 = require("sha256")

local BLOCK_SIZE = 64

local function xor_bytes(s, pad)
  local out = {}
  for i = 1, #s do
    out[i] = string.char(string.byte(s, i) ~ pad)
  end
  return table.concat(out)
end

local function hmac_sha256(key, msg)
  if #key > BLOCK_SIZE then
    key = sha256.digest(key)
  end
  if #key < BLOCK_SIZE then
    key = key .. string.rep("\0", BLOCK_SIZE - #key)
  end

  local ipad = xor_bytes(key, 0x36)
  local opad = xor_bytes(key, 0x5c)

  local inner = sha256.digest(ipad .. msg)
  return sha256.digest(opad .. inner)
end

return hmac_sha256
