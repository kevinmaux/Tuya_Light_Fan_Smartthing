local socket = require("cosock.socket")
local json = require("dkjson")

-- Lockbox Pure-Lua Cryptography Imports
local Array = require("lockbox.util.array")
local String = require("lockbox.util.string")
local ECBMode = require("lockbox.cipher.mode.ecb")
local AES128 = require("lockbox.cipher.aes128")
local PKCS7 = require("lockbox.padding.pkcs7")

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

local function encrypt_payload(payload_str, local_key)
  local key_array = Array.fromString(local_key)
  local payload_array = Array.fromString(payload_str)
  
  local cipher = ECBMode()
                 .setBlockCipher(AES128)
                 .setPadding(PKCS7)
  
  local encrypted_array = cipher.encrypt(key_array, payload_array)
  return String.fromArray(encrypted_array)
end

local function pack_message(dev_id, local_key, dps)
  local payload_table = {
    devId = dev_id,
    uid = dev_id,
    t = os.time(),
    dps = dps
  }
  local payload_str = json.encode(payload_table)
  local ciphertext = encrypt_payload(payload_str, local_key)
  
  -- Tuya Protocol 3.3 Header prefix
  local protocol_header = "3.3" .. string.rep("\0", 12)
  local data_payload = protocol_header .. ciphertext
  
  local prefix = 0x000055AA
  local command = 0x00000007 -- Control Command
  local length = #data_payload + 8
  
  local header = string.pack(">I4I4I4I4", prefix, sequence_num, command, length)
  sequence_num = (sequence_num + 1) % 0xFFFFFFFF
  
  local buffer_without_crc = header .. data_payload
  local crc = calculate_crc32(buffer_without_crc)
  local suffix = 0x0000AA55
  
  return buffer_without_crc .. string.pack(">I4I4", crc, suffix)
end

function tuya_lan.send_command(ip, dev_id, key, dps)
  local tcp = socket.tcp()
  tcp:settimeout(3)
  
  local success, err = tcp:connect(ip, 6668)
  if not success then
    print(string.format("Tuya LAN Error connecting to %s: %s", ip, tostring(err)))
    return false
  end
  
  local packet = pack_message(dev_id, key, dps)
  tcp:send(packet)
  tcp:receive("*a")
  tcp:close()
  return true
end

return tuya_lan