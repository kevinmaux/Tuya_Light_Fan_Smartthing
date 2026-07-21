-- Tuya LAN protocol 3.5 (and 3.4) framing: session-key negotiation and
-- 0x6699-prefixed AES-GCM messages. Protocol reverse-engineered/documented
-- publicly by the tinytuya project; this is an independent Lua implementation.
local gcm = require("gcm")
local hmac_sha256 = require("hmac_sha256")

local M = {}

local CMD = {
  SESS_KEY_NEG_START  = 3,
  SESS_KEY_NEG_RESP   = 4,
  SESS_KEY_NEG_FINISH = 5,
  CONTROL_NEW         = 0x0d,
  DP_QUERY_NEW        = 0x10,
}
M.CMD = CMD

local PREFIX_6699 = 0x00006699
local SUFFIX_6699 = "\0\0\153\102" -- 0x00 0x00 0x99 0x66

local NO_HEADER_CMDS = {
  [CMD.SESS_KEY_NEG_START] = true,
  [CMD.SESS_KEY_NEG_RESP] = true,
  [CMD.SESS_KEY_NEG_FINISH] = true,
  [0x0a] = true, -- DP_QUERY
  [CMD.DP_QUERY_NEW] = true,
  [0x12] = true, -- UPDATEDPS
  [9] = true,    -- HEART_BEAT
  [0x40] = true, -- LAN_EXT_STREAM
}

-- crude but adequate local randomness source for GCM nonces / client nonce.
-- Uniqueness (not unpredictability) is what matters for correctness on a
-- LAN control channel: mixes wall clock, a high-res tick and a counter.
local rng_counter = 0
local function random_bytes(n)
  rng_counter = (rng_counter + 1) % 0xFFFFFFFF
  local seed = (math.floor(os.time() * 1000) + math.floor(os.clock() * 1000000)) & 0x7FFFFFFF
  math.randomseed(seed ~ rng_counter)
  local out = {}
  for i = 1, n do
    out[i] = string.char(math.random(0, 255))
  end
  return table.concat(out)
end
M.random_bytes = random_bytes

-- Pack a 0x6699 message. key = current session key (real local key pre-negotiation).
-- version_header is prepended to the payload unless cmd is header-exempt.
function M.pack(seqno, cmd, payload, key, version_header)
  if not NO_HEADER_CMDS[cmd] and version_header then
    payload = version_header .. payload
  end
  local iv = random_bytes(12)
  local ciphertext, tag = gcm.encrypt(key, iv, payload, nil)
  local length = #ciphertext + #tag + #iv -- ciphertext + tag(16) + iv(12), suffix not counted
  local header = string.pack(">IHIII", PREFIX_6699, 0, seqno, cmd, length)
  local aad = header:sub(5) -- bytes 5.. (i.e. skip 4-byte prefix)
  -- NOTE: aad must be computed the same way encrypt used it; redo with real aad
  ciphertext, tag = gcm.encrypt(key, iv, payload, aad)
  return header .. iv .. ciphertext .. tag .. SUFFIX_6699
end

-- Unpack a 0x6699 message given the full raw bytes of exactly one frame.
-- Real device replies are wire-formatted as [4-byte retcode][actual payload]
-- before encryption (retcode 0 = success); strip_retcode (default true)
-- matches tinytuya's default behavior for messages received FROM the device.
-- Returns seqno, cmd, retcode, payload, consumed_bytes  OR  nil, error
function M.unpack(data, key, strip_retcode)
  if strip_retcode == nil then strip_retcode = true end
  if #data < 18 then return nil, "short header" end
  local prefix, unknown, seqno, cmd, length = string.unpack(">IHIII", data)
  if prefix ~= PREFIX_6699 then return nil, "bad prefix" end
  if #data < 18 + length then return nil, "short body" end
  local header = data:sub(1, 18)
  local aad = header:sub(5)
  local body = data:sub(19, 18 + length)
  local iv = body:sub(1, 12)
  local tag = body:sub(#body - 15, #body)
  local ciphertext = body:sub(13, #body - 16)
  local plaintext, err = gcm.decrypt(key, iv, ciphertext, aad, tag)
  if not plaintext then return nil, err end
  local retcode = 0
  if strip_retcode and #plaintext >= 4 then
    retcode = string.unpack(">I4", plaintext)
    plaintext = plaintext:sub(5)
  end
  return seqno, cmd, retcode, plaintext, 18 + length + 4
end

-- Session key negotiation, step 1: build the SESS_KEY_NEG_START packet.
-- Returns packet_bytes, local_nonce
function M.negotiate_step1(seqno, real_local_key)
  local local_nonce = random_bytes(16)
  local packet = M.pack(seqno, CMD.SESS_KEY_NEG_START, local_nonce, real_local_key, nil)
  return packet, local_nonce
end

-- Step 2: parse the device's SESS_KEY_NEG_RESP frame (payload already passed
-- through M.unpack, i.e. retcode already stripped) and build the
-- SESS_KEY_NEG_FINISH payload. Returns finish_payload, remote_nonce or nil, err
function M.negotiate_step3(resp_payload, local_nonce, real_local_key)
  if #resp_payload < 48 then return nil, nil, "short session response" end
  local remote_nonce = resp_payload:sub(1, 16)
  local got_hmac = resp_payload:sub(17, 48)
  local want_hmac = hmac_sha256(real_local_key, local_nonce)
  if got_hmac ~= want_hmac then
    return nil, nil, "session key HMAC check failed (wrong local key?)"
  end
  local finish_payload = hmac_sha256(real_local_key, remote_nonce)
  return finish_payload, remote_nonce
end

-- Step 4: derive the final session key from both nonces.
function M.negotiate_finalize(local_nonce, remote_nonce, real_local_key)
  local xored = {}
  for i = 1, 16 do
    xored[i] = string.char(string.byte(local_nonce, i) ~ string.byte(remote_nonce, i))
  end
  xored = table.concat(xored)
  local iv = local_nonce:sub(1, 12)
  local session_key = gcm.encrypt(real_local_key, iv, xored, nil)
  return session_key
end

return M
