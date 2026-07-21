local Driver = require("st.driver")
local capabilities = require("st.capabilities")
local handlers = require("command_handlers")
local log = require("log")

-- 1. Discovery Handler
local function discovery_handler(driver, _, should_continue)
  log.info("--> LAN Discovery triggered by SmartThings App scan.")
  
  local unique_dni = "tuya_parent_" .. os.time()

  local parent_metadata = {
    type = "LAN",
    device_network_id = unique_dni,
    label = "Tuya Light & Fan Controller",
    vendor_provided_label = "Tuya Light & Fan Controller",
    profile = "tuya-parent",
    manufacturer = "Tuya Custom",
    model = "WMC500-LV"
  }

  log.info("Creating Parent container device...")
  driver:try_create_device(parent_metadata)
end

-- 2. Device Init Handler (Emits default states so tiles become active immediately)
local function device_init(driver, device)
  if device.parent_assigned_child_key == "light" then
    device:emit_event(capabilities.switch.switch.off())
    device:emit_event(capabilities.switchLevel.level(100))
    device:emit_event(capabilities.colorTemperature.colorTemperature(2700))
  elseif device.parent_assigned_child_key == "fan" then
    device:emit_event(capabilities.switch.switch.off())
    device:emit_event(capabilities.fanSpeed.fanSpeed(1))
  end
end

-- 3. Lifecycle Handler: Triggered when IP/ID/Key settings are saved
local function info_changed(driver, device, event, args)
  log.info("--> Settings updated on device: " .. tostring(device.label))

  if device.parent_assigned_child_key == nil then
    local ip = device.preferences.deviceIp
    local devId = device.preferences.deviceId
    local key = device.preferences.localKey

    if ip and devId and key and #ip > 0 and #devId > 0 and #key > 0 then
      log.info("Tuya credentials detected! Spawning child endpoints...")

      local child_list = device:get_child_list()
      if #child_list == 0 then
        driver:try_create_device({
          type = "EDGE_CHILD",
          parent_assigned_child_key = "light",
          parent_device_id = device.id,
          profile = "tuya-child-light",
          manufacturer = "Tuya Custom",
          model = "WMC500-Light",
          label = "Ceiling Light"
        })

        driver:try_create_device({
          type = "EDGE_CHILD",
          parent_assigned_child_key = "fan",
          parent_device_id = device.id,
          profile = "tuya-child-fan",
          manufacturer = "Tuya Custom",
          model = "WMC500-Fan",
          label = "Ceiling Fan"
        })
      else
        log.info("Child endpoints already exist. Settings saved successfully.")
      end
    else
      log.warn("Parent settings incomplete. Please fill in Device IP, Device ID, and Local Key.")
    end
  end
end

local tuya_driver = Driver("Tuya_Light_Fan_Smartthing", {
  discovery = discovery_handler,
  lifecycle_handlers = {
    init = device_init,
    infoChanged = info_changed
  },
  capability_handlers = {
    [capabilities.switch.ID] = {
      [capabilities.switch.commands.on.NAME] = handlers.handle_switch_on,
      [capabilities.switch.commands.off.NAME] = handlers.handle_switch_off,
    },
    [capabilities.switchLevel.ID] = {
      [capabilities.switchLevel.commands.setLevel.NAME] = handlers.handle_light_level,
    },
    [capabilities.colorTemperature.ID] = {
      [capabilities.colorTemperature.commands.setColorTemperature.NAME] = handlers.handle_color_temp,
    },
    [capabilities.fanSpeed.ID] = {
      [capabilities.fanSpeed.commands.setFanSpeed.NAME] = handlers.handle_fan_speed,
    }
  }
})

tuya_driver:run()