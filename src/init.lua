-- src/init.lua
local Driver = require("st.driver")
local capabilities = require("st.capabilities")
local handlers = require("command_handlers")
local tuya = require("tuya_protocol")
local log = require("log")

local PARENT_DNI = "tuya_parent_controller"

local function discovery_handler(driver, _, should_continue)
  log.info("--> LAN Discovery triggered by SmartThings App scan.")
  for _, dev in ipairs(driver:get_devices()) do
    if dev.parent_assigned_child_key == nil then
      log.info("Parent device already exists. Skipping creation.")
      return
    end
  end

  local parent_metadata = {
    type = "LAN",
    device_network_id = PARENT_DNI,
    label = "Tuya Light & Fan Controller",
    vendor_provided_label = "Tuya Light & Fan Controller",
    profile = "tuya-parent",
    manufacturer = "Tuya Custom",
    model = "WMC500-LV"
  }
  driver:try_create_device(parent_metadata)
end

local function device_init(driver, device)
  if device.parent_assigned_child_key == nil then
    local connected = tuya.connect(device)
    if connected then
      handlers.handle_refresh(driver, device, {})
    end
  end
end

local function info_changed(driver, device, event, args)
  log.info("--> Settings updated on device: " .. tostring(device.label))

  if device.parent_assigned_child_key == nil then
    local ip = device.preferences.deviceIp
    local devId = device.preferences.deviceId
    local key = device.preferences.localKey

    if ip and devId and key and #ip > 0 and #devId > 0 and #key > 0 then
      local child_list = device:get_child_list()
      if #child_list == 0 then
        log.info("Tuya credentials detected! Spawning child endpoints...")
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
      end
      local connected = tuya.connect(device)
      if connected then
        -- Pull real current state instead of leaving the hardcoded
        -- off/100/2700K defaults from device_init in place.
        handlers.handle_refresh(driver, device, {})
      end
    else
      log.warn("Parent settings incomplete. Check Device IP, ID, and Key.")
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
    },
    [capabilities.refresh.ID] = {
      [capabilities.refresh.commands.refresh.NAME] = handlers.handle_refresh,
    }
  }
})

tuya_driver:run()