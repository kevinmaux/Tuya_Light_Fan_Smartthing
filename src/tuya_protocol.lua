local socket = require("cosock.socket")
local json = require("dkjson")
local aes = require("aes")
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

-- aes.encrypt_ecb already applies PKCS7 padding internally.
-- Padding here a second time would corrupt the payload (see explanation),
-- so this function now just delegates straight to the AES module.
local function encrypt_payload(payload_str, local_key)
  return aes.encrypt_ecb(payload_str, local_key)
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

local function pack_message(dev_id, local_key, dps)
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
  local command = 0x00000007 -- Reverted to Command 7
  local length = #data_payload + 8
  
  local header = string.pack(">I4I4I4I4", prefix, sequence_num, command, length)
  sequence_num = (sequence_num + 1) % 0xFFFFFFFF
  
  local buffer_without_crc = header .. data_payload
  local crc = calculate_crc32(buffer_without_crc)
  local suffix = 0x0000AA55
  
  return buffer_without_crc .. string.pack(">I4I4", crc, suffix)
end

function tuya_lan.send_command(ip, dev_id, key, dps)
  local ok, err = pcall(function()
    local tcp = socket.tcp()
    tcp:settimeout(2)
    
    local success, connect_err = tcp:connect(ip, 6668)
    if not success then
      log.error(string.format("Tuya LAN Connection failed to %s: %s", ip, tostring(connect_err)))
      tcp:close()
      return false
    end
    
    local packet = pack_message(dev_id, key, dps)
    tcp:send(packet)
    tcp:close()
    return true
  end)

  if not ok then
    log.error(string.format("Tuya socket execution error: %s", tostring(err)))
    return false
  end
  
  return ok
end

return tuya_lan