local log = require("log")
local capabilities = require("st.capabilities")
-- Assuming you have a local tuya socket/protocol helper module
local tuya = require("tuya_protocol")

local handlers = {}

-- Helper to retrieve parent device reference and Tuya settings
local function get_parent_and_config(device)
  local parent = device
  if device.parent_assigned_child_key ~= nil then
    parent = device:get_parent_device()
  end

  if not parent then
    log.error("Failed to acquire parent device!")
    return nil, nil
  end

  local prefs = parent.preferences
  if not (prefs.deviceIp and prefs.deviceId and prefs.localKey) then
    log.error("Missing Tuya credentials in parent device preferences!")
    return nil, nil
  end

  return parent, prefs
end

--------------------------------------------------------------------------------
-- SWITCH COMMANDS (DP 20 for Light, DP 60 for Fan)
--------------------------------------------------------------------------------
function handlers.handle_switch_on(driver, device, command)
  local parent, prefs = get_parent_and_config(device)
  if not parent then return end

  local key = device.parent_assigned_child_key or "light"
  local dp_id = (key == "fan") and 60 or 20

  log.info(string.format("--> Sending ON to [%s] via DP %d at IP %s", device.label, dp_id, prefs.deviceIp))

  -- Construct and send Tuya Local Command (DP = true)
  local payload = { [tostring(dp_id)] = true }
  tuya.send_command(prefs.deviceIp, prefs.deviceId, prefs.localKey, payload)

  -- Update tile state
  device:emit_event(capabilities.switch.switch.on())
end

function handlers.handle_switch_off(driver, device, command)
  local parent, prefs = get_parent_and_config(device)
  if not parent then return end

  local key = device.parent_assigned_child_key or "light"
  local dp_id = (key == "fan") and 60 or 20

  log.info(string.format("--> Sending OFF to [%s] via DP %d at IP %s", device.label, dp_id, prefs.deviceIp))

  -- Construct and send Tuya Local Command (DP = false)
  local payload = { [tostring(dp_id)] = false }
  tuya.send_command(prefs.deviceIp, prefs.deviceId, prefs.localKey, payload)

  -- Update tile state
  device:emit_event(capabilities.switch.switch.off())
end

--------------------------------------------------------------------------------
-- LIGHT LEVEL / BRIGHTNESS (DP 22: Range 1 - 100)
--------------------------------------------------------------------------------
function handlers.handle_light_level(driver, device, command)
  local parent, prefs = get_parent_and_config(device)
  if not parent then return end

  -- math.floor() also normalizes a float arg (e.g. 50.0) to Lua's integer
  -- subtype, so dkjson emits a clean JSON integer (50) instead of 50.0 --
  -- DP 22 is typed as an integer "value" and some Tuya firmware parsers
  -- are strict about this.
  local level = math.floor(math.max(1, math.min(100, command.args.level)))
  log.info(string.format("--> Setting Brightness [%d%%] on [%s] (DP 22)", level, device.label))

  local payload = { ["22"] = level }
  tuya.send_command(prefs.deviceIp, prefs.deviceId, prefs.localKey, payload)

  device:emit_event(capabilities.switchLevel.level(level))
end

--------------------------------------------------------------------------------
-- COLOR TEMPERATURE (DP 23: Range 0 - 1000)
--------------------------------------------------------------------------------
function handlers.handle_color_temp(driver, device, command)
  local parent, prefs = get_parent_and_config(device)
  if not parent then return end

  -- Scale SmartThings Kelvin (e.g. 2700K - 6500K) or % to Tuya's 0-1000 range
  local st_temp = command.args.temperature
  local tuya_val = math.floor(((st_temp - 2700) / (6500 - 2700)) * 1000)
  tuya_val = math.max(0, math.min(1000, tuya_val))

  log.info(string.format("--> Setting Color Temp [%dK -> Tuya: %d] (DP 23)", st_temp, tuya_val))

  local payload = { ["23"] = tuya_val }
  tuya.send_command(prefs.deviceIp, prefs.deviceId, prefs.localKey, payload)

  device:emit_event(capabilities.colorTemperature.colorTemperature(st_temp))
end

--------------------------------------------------------------------------------
-- FAN SPEED (DP 62: Range 1 - 6)
--------------------------------------------------------------------------------
function handlers.handle_fan_speed(driver, device, command)
  local parent, prefs = get_parent_and_config(device)
  if not parent then return end

  -- SmartThings fan speed range -> Tuya DP 62 range (1 to 6)
  local raw_speed = command.args.speed
  local tuya_speed = math.floor(math.max(1, math.min(6, raw_speed)))

  log.info(string.format("--> Setting Fan Speed [%d] on [%s] (DP 62)", tuya_speed, device.label))

  local payload = { ["62"] = tuya_speed }
  tuya.send_command(prefs.deviceIp, prefs.deviceId, prefs.localKey, payload)

  device:emit_event(capabilities.fanSpeed.fanSpeed(tuya_speed))
end

return handlers
