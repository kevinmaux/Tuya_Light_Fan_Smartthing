local socket = require("cosock.socket")
local json = require("dkjson")
local aes = require("aes")
local tuya35 = require("tuya35")
local capabilities = require("st.capabilities")
local log = require("log")

local tuya_lan = {}
local sequence_num = 1

-- protocolVersion preference stores word-char-only keys (SmartThings enum
-- options can't contain "."); translate to the dotted version string used
-- internally. Mirrors the same map in command_handlers.lua.
local VERSION_MAP_FOR_CONNECT = { v33 = "3.3", v35 = "3.5" }

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
  local pkt1, local_nonce = tuya35.negotiate_step1(1, key)
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

  local pkt3 = tuya35.pack(2, tuya35.CMD.SESS_KEY_NEG_FINISH, finish_payload, key, nil)
  tcp:send(pkt3)

  local session_key = tuya35.negotiate_finalize(local_nonce, remote_nonce, key)

  -- IMPORTANT: v3.4/3.5 devices use a different payload schema for
  -- CONTROL_NEW than the old 3.3-style {devId,uid,t,dps} body — they expect
  -- {"protocol":5,"t":<int>,"data":{"dps":{...}}} with no devId/uid at all
  -- (the session-encrypted channel already authenticates the device).
  -- "t" must be a JSON *number*, not a string.
  local payload_table = {
    protocol = 5,
    t = math.floor(os.time()),
    data = { dps = dps }
  }
  local payload_str = json.encode(payload_table)
  local version_header = "3.5" .. string.rep("\0", 12)
  local cmd_packet = tuya35.pack(3, tuya35.CMD.CONTROL_NEW, payload_str, session_key, version_header)
  tcp:send(cmd_packet)

  -- Wait for the device's reply before closing the socket. Closing
  -- immediately after send() can cut the connection before a WiFi MCU has
  -- actually finished processing the packet, silently dropping the command
  -- even though send() itself reported success. This also tells us whether
  -- the device actually accepted the command (retcode 0) or rejected it.
  local frame4, recv_err = recv_6699_frame(tcp)
  if not frame4 then
    log.warn("Tuya command sent but no reply from device (command may not have been applied): " .. tostring(recv_err))
    return true
  end

  local _seqno4, _cmd4, retcode4, reply_payload = tuya35.unpack(frame4, session_key)
  if retcode4 and retcode4 ~= 0 then
    log.warn(string.format("Tuya device replied with non-zero retcode %d: %s", retcode4, tostring(reply_payload)))
  else
    log.info("Tuya command acknowledged by device (retcode 0).")
  end

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

--------------------------------------------------------------------------------
-- Connectivity/credential check, called from init.lua on device init and
-- infoChanged. Opens a socket to the device and, for protocol 3.5, runs the
-- full session-key negotiation (the strongest available proof the local key
-- is correct) — but never sends an actual DP command. Logs the result;
-- callers don't need the return value, but it's provided (true/false) in
-- case future code wants to react to it.
--------------------------------------------------------------------------------
function tuya_lan.connect(device)
  local prefs = device.preferences
  if not prefs then
    log.warn("Tuya connect check skipped: device has no preferences yet.")
    return false
  end

  local ip, dev_id, key = prefs.deviceIp, prefs.deviceId, prefs.localKey
  local version = VERSION_MAP_FOR_CONNECT[prefs.protocolVersion] or "3.3"

  if not (ip and dev_id and key) or #ip == 0 or #dev_id == 0 or #key == 0
     or ip == "iptochange" or dev_id == "idtochange" or key == "localkeytochange" then
    log.info("Tuya connect check skipped: credentials not yet configured.")
    return false
  end

  if #key ~= 16 then
    log.error(string.format(
      "Tuya connect check failed: Local Key must be exactly 16 characters (got %d) — check that Device ID and Local Key aren't swapped.",
      #key))
    return false
  end

  local ok, result = pcall(function()
    local tcp = socket.tcp()
    tcp:settimeout(3)

    local success, connect_err = tcp:connect(ip, 6668)
    if not success then
      log.error(string.format("Tuya connect check: failed to reach %s: %s", ip, tostring(connect_err)))
      tcp:close()
      return false
    end

    if version == "3.5" then
      local pkt1, local_nonce = tuya35.negotiate_step1(1, key)
      tcp:send(pkt1)
      local frame2, err = recv_6699_frame(tcp)
      if not frame2 then
        log.error("Tuya connect check: no session key response from device: " .. tostring(err))
        tcp:close()
        return false
      end
      local _seqno2, cmd2, _retcode2, payload2, uerr = tuya35.unpack(frame2, key)
      if not payload2 or cmd2 ~= tuya35.CMD.SESS_KEY_NEG_RESP then
        log.error("Tuya connect check: session key negotiation failed (wrong local key?): " .. tostring(uerr))
        tcp:close()
        return false
      end
      local finish_payload, _remote_nonce, negerr = tuya35.negotiate_step3(payload2, local_nonce, key)
      if not finish_payload then
        log.error("Tuya connect check: " .. tostring(negerr))
        tcp:close()
        return false
      end
      log.info(string.format("Tuya connect check: session key negotiated OK with %s (protocol 3.5).", ip))
    else
      log.info(string.format("Tuya connect check: TCP connection to %s OK (protocol 3.3).", ip))
    end

    tcp:close()
    return true
  end)

  if not ok then
    log.error("Tuya connect check error: " .. tostring(result))
    return false
  end
  return result
end

return tuya_lan