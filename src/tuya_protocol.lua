-- src/tuya_protocol.lua
local socket = require("cosock.socket")
local cosock = require("cosock")
local json = require("dkjson")
local aes = require("aes")
local capabilities = require("st.capabilities")
local log = require("log")

local tuya_lan = {}
local sequence_num = 1
local tcp_sockets = {}

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

local function decrypt_payload(payload_data, key)
  if payload_data:sub(1, 3) == "3.3" then
    payload_data = payload_data:sub(16)
  end
  
  local ok, decrypted = pcall(aes.decrypt_ecb, payload_data, key)
  if not ok or not decrypted then return nil end
  
  local pad = string.byte(decrypted, #decrypted)
  if pad and pad > 0 and pad <= 16 then
    return decrypted:sub(1, #decrypted - pad)
  end
  return decrypted
end

function tuya_lan.process_incoming_dps(parent_device, dps)
  if not parent_device or type(dps) ~= "table" then return end

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

function tuya_lan.send_command(parent_device, dps, cmd_override)
  local prefs = parent_device.preferences
  local cmd = cmd_override or 7
  
  local payload_str = ""
  if cmd == 7 then
    local payload_table = {
      devId = prefs.deviceId,
      gwId = prefs.deviceId,
      uid = prefs.deviceId,
      t = tostring(math.floor(os.time())),
      dps = dps
    }
    payload_str = json.encode(payload_table)
  elseif cmd == 10 then
    local payload_table = {
      devId = prefs.deviceId,
      gwId = prefs.deviceId,
      uid = prefs.deviceId,
      t = tostring(math.floor(os.time()))
    }
    payload_str = json.encode(payload_table)
  end

  local data_payload = ""
  if payload_str ~= "" then
    local ciphertext = aes.encrypt_ecb(payload_str, prefs.localKey)
    if cmd == 7 then
      -- FIX: the "3.3" + 12-null version header is only added for CONTROL
      -- (cmd 7). DP_QUERY (10) and HEART_BEAT (9) must NOT have it -- the
      -- previous version added it unconditionally to any non-empty
      -- payload, which corrupted every DP_QUERY (status refresh) request.
      local protocol_header = "3.3" .. string.rep("\0", 12)
      data_payload = protocol_header .. ciphertext
    else
      data_payload = ciphertext
    end
  end

  local prefix = 0x000055AA
  local length = #data_payload + 8
  
  local header = string.pack(">I4I4I4I4", prefix, sequence_num, cmd, length)
  sequence_num = (sequence_num + 1) % 0x100000000
  
  local buffer_without_crc = header .. data_payload
  local crc = calculate_crc32(buffer_without_crc)
  local suffix = 0x0000AA55
  local packet = buffer_without_crc .. string.pack(">I4I4", crc, suffix)
  
  local sock = tcp_sockets[parent_device.id]
  if sock then
    sock:send(packet)
  else
    log.error("Socket offline. Reconnecting to " .. tostring(prefs.deviceIp))
    tuya_lan.connect(parent_device)
  end
end

local function socket_listener(parent_device)
  local sock = tcp_sockets[parent_device.id]
  local prefs = parent_device.preferences
  
  while true do
    if not sock then break end
    
    local header, err = sock:receive(16)
    if err == "timeout" then
      tuya_lan.send_command(parent_device, nil, 9)
    elseif err then
      log.error("Socket error: " .. tostring(err))
      sock:close()
      tcp_sockets[parent_device.id] = nil
      cosock.socket.sleep(5)
      tuya_lan.connect(parent_device)
      break
    elseif header then
      local prefix, seq, cmd, length = string.unpack(">I4I4I4I4", header)
      if prefix == 0x000055AA then
        local remainder = sock:receive(length)
        if remainder and #remainder == length then
          local payload_data = remainder:sub(1, length - 8)
          
          if (cmd == 8 or cmd == 10) and #payload_data > 0 then
            local cleartext = decrypt_payload(payload_data, prefs.localKey)
            if cleartext then
              local parsed = json.decode(cleartext, 1, nil)
              if parsed and parsed.dps then
                tuya_lan.process_incoming_dps(parent_device, parsed.dps)
              end
            end
          end
        end
      end
    end
  end
end

function tuya_lan.connect(parent_device)
  local prefs = parent_device.preferences
  local ip = prefs.deviceIp
  if not ip or ip == "" or not prefs.deviceId then return end
  
  if tcp_sockets[parent_device.id] then
    tcp_sockets[parent_device.id]:close()
  end
  
  local tcp = socket.tcp()
  tcp:settimeout(5)
  
  local success, err = tcp:connect(ip, 6668)
  if success then
    tcp_sockets[parent_device.id] = tcp
    log.info("LAN Connection established to Tuya device: " .. ip)
    
    cosock.spawn(function() socket_listener(parent_device) end)
    tuya_lan.send_command(parent_device, nil, 10)
  else
    log.error("Failed to connect: " .. tostring(err))
    tcp:close()
  end
end

return tuya_lan