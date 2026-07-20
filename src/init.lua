local Driver = require("st.driver")
local capabilities = require("st.capabilities")
local handlers = require("command_handlers")

-- Lifecycle handler: spawns child devices automatically when the parent is created
local function device_added(driver, device)
  if not device.network_id:match(":") then
    device.log.info("Parent device added. Spawning child endpoints...")

    driver:try_create_device({
      type = "EDGE_CHILD",
      device_network_id = device.device_network_id .. ":light",
      parent_device_id = device.id,
      profile = "tuya-child-light",
      manufacturer = "Tuya Custom",
      model = "WMC500-Light",
      label = "Ceiling Light"
    })

    driver:try_create_device({
      type = "EDGE_CHILD",
      device_network_id = device.device_network_id .. ":fan",
      parent_device_id = device.id,
      profile = "tuya-child-fan",
      manufacturer = "Tuya Custom",
      model = "WMC500-Fan",
      label = "Ceiling Fan"
    })
  end
end

local tuya_driver = Driver("Tuya_Light_Fan_Smartthing", {
  lifecycle_handlers = {
    added = device_added
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