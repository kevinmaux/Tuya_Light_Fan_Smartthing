-- src/command_handlers.lua
local log = require("log")
local capabilities = require("st.capabilities")
local tuya = require("tuya_protocol") 

local handlers = {}

local function get_parent(device)
  local parent = device
  if device.parent_assigned_child_key ~= nil then
    parent = device:get_parent_device()
  end
  if not parent then
    log.error("Failed to acquire parent device!")
    return nil
  end
  return parent
end

function handlers.handle_switch_on(driver, device, command)
  local parent = get_parent(device)
  if not parent then return end

  local key = device.parent_assigned_child_key or "light"
  local dp_id = (key == "fan") and 60 or 20

  log.info(string.format("--> Sending ON to [%s] via DP %d", device.label, dp_id))
  tuya.send_command(parent, { [tostring(dp_id)] = true }, 7)
end

function handlers.handle_switch_off(driver, device, command)
  local parent = get_parent(device)
  if not parent then return end

  local key = device.parent_assigned_child_key or "light"
  local dp_id = (key == "fan") and 60 or 20

  log.info(string.format("--> Sending OFF to [%s] via DP %d", device.label, dp_id))
  tuya.send_command(parent, { [tostring(dp_id)] = false }, 7)
end

function handlers.handle_light_level(driver, device, command)
  local parent = get_parent(device)
  if not parent then return end

  local level = math.max(1, math.min(100, command.args.level))
  log.info(string.format("--> Setting Brightness [%d%%] (DP 22)", level))
  tuya.send_command(parent, { ["22"] = level }, 7)
end

function handlers.handle_color_temp(driver, device, command)
  local parent = get_parent(device)
  if not parent then return end

  local st_temp = command.args.temperature
  local tuya_val = math.floor(((st_temp - 2700) / (6500 - 2700)) * 1000)
  tuya_val = math.max(0, math.min(1000, tuya_val))

  log.info(string.format("--> Setting Color Temp [%dK -> Tuya: %d] (DP 23)", st_temp, tuya_val))
  tuya.send_command(parent, { ["23"] = tuya_val }, 7)
end

function handlers.handle_fan_speed(driver, device, command)
  local parent = get_parent(device)
  if not parent then return end

  local raw_speed = command.args.speed
  local tuya_speed = math.max(1, math.min(6, raw_speed))

  log.info(string.format("--> Setting Fan Speed [%d] (DP 62)", tuya_speed))
  tuya.send_command(parent, { ["62"] = tuya_speed }, 7)
end

return handlers