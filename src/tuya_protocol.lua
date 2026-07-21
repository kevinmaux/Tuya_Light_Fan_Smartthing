local socket = require("cosock.socket")
local json = require("dkjson")
local aes = require("aes")
local tuya35 = require("tuya35")
local capabilities = require("st.capabilities")
local log = require("log")

local tuya_lan = {}
local sequence_num = 1

local function calculate_crc32(data)
  local crc = 0xFFFFFFFF
  for i = 1, #data do
    local byte = string.byte(data, i)
    crc = crc ~ byte
    for _ = 1, 8 do
      local mask = -(crc & 1)
      crc = (crc >> 1) ~ (0xEDB88320 & mask)
    end
  end
  return ~crc & 0xFFFFFFFF
end

local function pkcs7_pad(str)
  local block_size = 16
  local pad_len = block_size - (#str % block_size)
  return str .. string.rep(string.char(pad_len), pad_len)
end

local function encrypt_payload(payload_str, local_key)
  local padded = pkcs7_pad(payload_str)
  return aes.encrypt_ecb(padded, local_key)
end

function tuya_lan.process_incoming_dps(parent_device, dps)
  if not parent_device or not dps then return end

  local light_child, fan_child = nil, nil
  for _, child in ipairs(parent_device:get_child_list()) do
    local key = child.parent_assigned_child_key
    if key == "light" then light_child = child
    elseif key == "fan" then fan_child = child end
  end

  if dps["20"] ~= nil and light_child then
    light_child:emit_event(capabilities.switch.switch(dps["20"] and "on" or "off"))
  end
  if dps["22"] ~= nil and light_child then
    light_child:emit_event(capabilities.switchLevel.level(dps["22"]))
  end
  if dps["60"] ~= nil and fan_child then
    fan_child:emit_event(capabilities.switch.switch(dps["60"] and "on" or "off"))
  end
  if dps["62"] ~= nil and fan_child then
    fan_child:emit_event(capabilities.fanSpeed.fanSpeed(dps["62"]))
  end
end

--------------------------------------------------------------------------------
-- Protocol 3.3: plain AES-128-ECB, single fire-and-forget packet.
--------------------------------------------------------------------------------
local function pack_message_33(dev_id, local_key, dps)
  local payload_table = {
    devId = dev_id,
    gwId = dev_id,
    uid = dev_id,
    t = tostring(math.floor(os.time())),
    dps = dps
  }

  local payload_str = json.encode(payload_table)
  local ciphertext = encrypt_payload(payload_str, local_key)

  -- Protocol 3.3 header prefix for port 6668
  local protocol_header = "3.3" .. string.rep("\0", 12)
  local data_payload = protocol_header .. ciphertext

  local prefix = 0x000055AA
  local command = 0x00000007 -- CONTROL
  local length = #data_payload + 8

  local header = string.pack(">I4I4I4I4", prefix, sequence_num, command, length)
  sequence_num = (sequence_num + 1) % 0xFFFFFFFF

  local buffer_without_crc = header .. data_payload
  local crc = calculate_crc32(buffer_without_crc)
  local suffix = 0x0000AA55

  return buffer_without_crc .. string.pack(">I4I4", crc, suffix)
end

local function send_33(tcp, dev_id, key, dps)
  local packet = pack_message_33(dev_id, key, dps)
  tcp:send(packet)
  return true
end

--------------------------------------------------------------------------------
-- Protocol 3.5: session-key negotiation (HMAC-SHA256) + AES-128-GCM framed
-- messages (0x6699 prefix). See tuya35.lua for the wire-format details.
--------------------------------------------------------------------------------
local function recv_exact(tcp, n)
  local buf = {}
  local have = 0
  while have < n do
    local chunk, err = tcp:receive(n - have)
    if not chunk or #chunk == 0 then
      return nil, err or "connection closed"
    end
    buf[#buf + 1] = chunk
    have = have + #chunk
  end
  return table.concat(buf)
end

local function recv_6699_frame(tcp)
  local header, err = recv_exact(tcp, 18)
  if not header then return nil, err end
  local prefix, _unknown, _seqno, _cmd, length = string.unpack(">IHIII", header)
  if prefix ~= 0x00006699 then
    return nil, string.format("unexpected frame prefix 0x%08X", prefix)
  end
  local rest, err2 = recv_exact(tcp, length + 4) -- body (iv+ciphertext+tag) + suffix
  if not rest then return nil, err2 end
  return header .. rest
end

-- Negotiates a fresh session key on an already-connected socket and sends
-- one CONTROL_NEW command over it. A new negotiation is performed for every
-- command (matches the driver's existing "one connection per command"
-- design), which keeps the state machine simple at the cost of one extra
-- round-trip per command.
local function send_35(tcp, dev_id, key, dps)
  local pkt1, local_nonce = tuya35.negotiate_step1(0, key)
  tcp:send(pkt1)

  local frame2, err = recv_6699_frame(tcp)
  if not frame2 then
    return nil, "no session key response from device: " .. tostring(err)
  end

  local _seqno2, cmd2, _retcode2, payload2, uerr = tuya35.unpack(frame2, key)
  if not payload2 then
    return nil, "failed to decrypt session key response (wrong local key?): " .. tostring(uerr)
  end
  if cmd2 ~= tuya35.CMD.SESS_KEY_NEG_RESP then
    return nil, "unexpected response cmd " .. tostring(cmd2) .. " during session negotiation"
  end

  local finish_payload, remote_nonce, negerr = tuya35.negotiate_step3(payload2, local_nonce, key)
  if not finish_payload then
    return nil, "session key negotiation failed: " .. tostring(negerr)
  end

  local pkt3 = tuya35.pack(1, tuya35.CMD.SESS_KEY_NEG_FINISH, finish_payload, key, nil)
  tcp:send(pkt3)

  local session_key = tuya35.negotiate_finalize(local_nonce, remote_nonce, key)

  local payload_table = {
    devId = dev_id,
    uid = dev_id,
    t = tostring(math.floor(os.time())),
    dps = dps
  }
  local payload_str = json.encode(payload_table)
  local version_header = "3.5" .. string.rep("\0", 12)
  local cmd_packet = tuya35.pack(2, tuya35.CMD.CONTROL_NEW, payload_str, session_key, version_header)
  tcp:send(cmd_packet)

  return true
end

--------------------------------------------------------------------------------
-- Entry point. `version` is the device's Tuya protocol version string, e.g.
-- "3.3" or "3.5" (as reported by a tool like tinytuya's scan/version check).
-- Defaults to "3.3" for backward compatibility with existing installs.
--------------------------------------------------------------------------------
function tuya_lan.send_command(ip, dev_id, key, dps, version)
  version = version or "3.3"

  if #key ~= 16 then
    log.error(string.format(
      "Tuya Local Key must be exactly 16 characters (got %d). Check that Device ID and Local Key preferences aren't swapped.",
      #key))
    return false
  end

  local ok, err = pcall(function()
    local tcp = socket.tcp()
    tcp:settimeout(3)

    local success, connect_err = tcp:connect(ip, 6668)
    if not success then
      log.error(string.format("Tuya LAN Connection failed to %s: %s", ip, tostring(connect_err)))
      tcp:close()
      return false
    end

    local send_ok, send_err
    if version == "3.5" then
      send_ok, send_err = send_35(tcp, dev_id, key, dps)
    elseif version == "3.3" then
      send_ok, send_err = send_33(tcp, dev_id, key, dps)
    else
      tcp:close()
      error("Unsupported Tuya protocol version: " .. tostring(version) .. " (supported: 3.3, 3.5)")
    end

    tcp:close()

    if not send_ok then
      log.error("Tuya command failed: " .. tostring(send_err))
      return false
    end
    return true
  end)

  if not ok then
    log.error(string.format("Tuya socket execution error: %s", tostring(err)))
    return false
  end

  return ok
end

return tuya_lan
