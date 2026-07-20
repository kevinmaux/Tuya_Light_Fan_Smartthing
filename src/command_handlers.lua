local capabilities = require("st.capabilities")
local tuya_lan = require("tuya_lan")

local command_handlers = {}

local function send_to_parent(device, dp_payload)
  local parent = device:get_parent_device()
  if parent then
    local ip = parent.preferences.deviceIp
    local devId = parent.preferences.deviceId
    local key = parent.preferences.localKey
    
    if ip and devId and key and #ip > 0 and #devId > 0 and #key > 0 then
      tuya_lan.send_command(ip, devId, key, dp_payload)
    else
      device.log.warn("Parent device missing Tuya IP, Device ID, or Local Key in settings.")
    end
  end
end

function command_handlers.handle_switch_on(driver, device, command)
  if device.network_id:match(":light") then
    send_to_parent(device, { ["20"] = true })
  elseif device.network_id:match(":fan") then
    send_to_parent(device, { ["60"] = true })
  end
  device:emit_event(capabilities.switch.switch.on())
end

function command_handlers.handle_switch_off(driver, device, command)
  if device.network_id:match(":light") then
    send_to_parent(device, { ["20"] = false })
  elseif device.network_id:match(":fan") then
    send_to_parent(device, { ["60"] = false })
  end
  device:emit_event(capabilities.switch.switch.off())
end

function command_handlers.handle_light_level(driver, device, command)
  local level = math.max(1, math.min(100, command.args.level))
  send_to_parent(device, { ["22"] = level })
  device:emit_event(capabilities.switchLevel.level(level))
end

function command_handlers.handle_color_temp(driver, device, command)
  local k_temp = command.args.temperature
  -- Convert SmartThings Kelvin (2700K - 6500K) to Tuya DP 23 scale (0 - 1000)
  local tuya_temp = math.floor(((k_temp - 2700) / (6500 - 2700)) * 1000)
  tuya_temp = math.max(0, math.min(1000, tuya_temp))
  
  send_to_parent(device, { ["23"] = tuya_temp })
  device:emit_event(capabilities.colorTemperature.colorTemperature(k_temp))
end

function command_handlers.handle_fan_speed(driver, device, command)
  local st_speed = command.args.speed
  if st_speed == 0 then
    send_to_parent(device, { ["60"] = false })
    device:emit_event(capabilities.switch.switch.off())
  else
    -- Map ST speeds (1-4) to Tuya speeds (1-6)
    local tuya_speed_map = { [1] = 1, [2] = 3, [3] = 4, [4] = 6 }
    local tuya_speed = tuya_speed_map[st_speed] or 1
    
    send_to_parent(device, { ["60"] = true, ["62"] = tuya_speed })
    device:emit_event(capabilities.switch.switch.on())
  end
  device:emit_event(capabilities.fanSpeed.fanSpeed(st_speed))
end

return command_handlers