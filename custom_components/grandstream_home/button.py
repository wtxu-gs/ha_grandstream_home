"""Button platform for Grandstream Home integration."""

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import DOMAIN, GrandstreamConfigEntry
from .const import DEVICE_TYPE_GDS, DEVICE_TYPE_GNS_NAS

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: GrandstreamConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the Grandstream button platform."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    device = hass.data[DOMAIN][config_entry.entry_id]["device"]

    # Build entities by device type to avoid duplicates
    if getattr(device, "device_type", None) == DEVICE_TYPE_GNS_NAS:
        entities = [
            GrandstreamRebootButton(coordinator, device),
            GnsSleepButton(coordinator, device),
            GnsWakeButton(coordinator, device),
            GnsShutdownButton(coordinator, device),
        ]
    elif getattr(device, "device_type", None) == DEVICE_TYPE_GDS:
        entities = [
            GrandstreamRebootButton(coordinator, device),
            GdsResetTamperButton(coordinator, device),
        ]
    else:
        entities = [
            GrandstreamRebootButton(coordinator, device),
        ]

    async_add_entities(entities)


class GrandstreamBaseButton(CoordinatorEntity, ButtonEntity):
    """Representation of a Grandstream button."""

    def __init__(self, coordinator, device) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self.coordinator = coordinator
        self.device = device

    def _get_api_instance(self):
        """Get API instance from hass.data."""
        if DOMAIN in self.hass.data and hasattr(self.device, "config_entry_id"):
            entry_data = self.hass.data[DOMAIN].get(self.device.config_entry_id)
            if entry_data and "api" in entry_data:
                return entry_data["api"]
        return None

    def _call_service(self, service_name, service_data=None):
        """Call Home Assistant service."""
        if service_data is None:
            service_data = {}
        return self.hass.services.async_call(DOMAIN, service_name, service_data)

    def _get_device_id(self):
        """Get device ID from device registry."""
        try:
            device_info = self._attr_device_info
            if not device_info or not hasattr(device_info, "get"):
                return None

            identifiers = device_info.get("identifiers")
            if not identifiers:
                return None

            for identifier in identifiers:
                if identifier[0] != DOMAIN:
                    continue

                # Get device registry
                device_registry = dr.async_get(self.hass)
                device = device_registry.async_get_device(
                    identifiers={(DOMAIN, identifier[1])}
                )
                if device:
                    return device.id
        except (AttributeError, TypeError, KeyError) as _:
            pass
        return None

    def press(self) -> None:
        """Press the button (base implementation)."""

    async def _safe_api_call(self, api_method, operation_name: str):
        """Safely call API method with unified error handling.

        Args:
            api_method: API method to call
            operation_name: Operation name for logging

        Returns:
            True if successful, False otherwise

        """
        try:
            await self.hass.async_add_executor_job(api_method)
        except (ConnectionError, TimeoutError, ValueError, RuntimeError) as err:
            _LOGGER.error("Failed to %s: %s", operation_name, err)
            return False
        else:
            return True

    def _check_api_availability(self, api, check_admin: bool = False) -> bool:
        """Check if API is available for operations.

        Args:
            api: API instance to check
            check_admin: Whether to check admin status

        Returns:
            True if API is available and ready

        """
        if not api:
            return False

        # Check if device is online
        if hasattr(api, "is_online") and not api.is_online:
            return False

        # Check if account is locked (for GDS devices)
        if hasattr(api, "is_account_locked") and api.is_account_locked:
            return False

        # Check if device is authenticated (for GDS devices)
        if hasattr(api, "is_authenticated") and not api.is_authenticated:
            return False

        # Check if HA control is disabled on device (for GDS devices)
        if hasattr(api, "is_ha_control_enabled") and not api.is_ha_control_enabled:
            return False

        # Check if user is admin (for GNS devices)
        if check_admin and hasattr(api, "is_admin") and not api.is_admin:
            return False

        return True


class GrandstreamRebootButton(GrandstreamBaseButton):
    """Representation of a Grandstream reboot button."""

    def __init__(self, coordinator, device) -> None:
        """Initialize the reboot button."""
        super().__init__(coordinator, device)
        self._attr_unique_id = f"{device.unique_id}_reboot"
        self._attr_has_entity_name = True
        self._attr_translation_key = "reboot"
        self._attr_entity_category = EntityCategory.CONFIG
        self._attr_device_info = device.device_info
        self._attr_icon = "mdi:restart"

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        api = self._get_api_instance()
        return self._check_api_availability(api)

    async def async_press(self) -> None:
        """Handle the button press - reboot device."""
        api = self._get_api_instance()
        if api and hasattr(api, "reboot_device"):
            _LOGGER.info(
                "Rebooting device: %s (type: %s)",
                self.device.name,
                getattr(api, "device_type", "unknown"),
            )
            await self._safe_api_call(api.reboot_device, "reboot device")
            return

        # Fallback: get device_id and call service
        _LOGGER.warning("Direct API call failed, using service call with device_id")
        device_id = self._get_device_id()
        service_data = {}
        if device_id:
            service_data["device_id"] = device_id
            _LOGGER.info("Calling reboot_device service with device_id: %s", device_id)

        await self._call_service("reboot_device", service_data)


class GnsSpecializedButton(GrandstreamBaseButton):
    """Base class for GNS NAS specialized buttons."""

    def __init__(
        self, coordinator, device, unique_id_suffix, translation_key, icon
    ) -> None:
        """Initialize the GNS button."""
        super().__init__(coordinator, device)
        self._attr_unique_id = f"{device.unique_id}_{unique_id_suffix}"
        self._attr_has_entity_name = True
        self._attr_translation_key = translation_key
        self._attr_entity_category = EntityCategory.CONFIG
        self._attr_device_info = device.device_info
        self._attr_icon = icon
        self._service_name: str | None = None  # To be set by subclasses
        self._api_method_name: str | None = None  # To be set by subclasses

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        api = self._get_api_instance()
        return self._check_api_availability(api, check_admin=True)

    async def async_press(self) -> None:
        """Handle button press - directly call API."""
        api = self._get_api_instance()
        if api and self._api_method_name and hasattr(api, self._api_method_name):
            await self._safe_api_call(
                getattr(api, self._api_method_name), self._api_method_name
            )
            return

        # Fallback to service call
        await self._call_service(self._service_name, {})


class GnsSleepButton(GnsSpecializedButton):
    """GNS NAS sleep button."""

    def __init__(self, coordinator, device) -> None:
        """Initialize the sleep button."""
        super().__init__(coordinator, device, "sleep", "sleep", "mdi:sleep")
        self._service_name = "sleep_device"
        self._api_method_name = "sleep_device"


class GnsWakeButton(GnsSpecializedButton):
    """GNS NAS wake button."""

    def __init__(self, coordinator, device) -> None:
        """Initialize the wake button."""
        super().__init__(coordinator, device, "wake", "wake", "mdi:eye")
        self._service_name = "wake_device"
        self._api_method_name = "wake_device"

    @property
    def available(self) -> bool:
        """Return if entity is available - wake button availability based on MAC address."""
        api = self._get_api_instance()
        if not api:
            return False

        # Check if device has MAC address
        if hasattr(api, "device_mac") and api.device_mac:
            return True

        return False


class GnsShutdownButton(GnsSpecializedButton):
    """GNS NAS shutdown button."""

    def __init__(self, coordinator, device) -> None:
        """Initialize the shutdown button."""
        super().__init__(coordinator, device, "shutdown", "shutdown", "mdi:power")
        self._service_name = "shutdown_device"
        self._api_method_name = "shutdown_device"


class GdsResetTamperButton(GrandstreamBaseButton):
    """GDS reset all alarms button."""

    def __init__(self, coordinator, device) -> None:
        """Initialize the reset all alarms button."""
        super().__init__(coordinator, device)
        self._attr_unique_id = f"{device.unique_id}_reset_all_alarms"
        self._attr_has_entity_name = True
        self._attr_translation_key = "reset_all_alarms"
        self._attr_entity_category = EntityCategory.CONFIG
        self._attr_device_info = device.device_info
        self._attr_icon = "mdi:alarm-light-off"

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        api = self._get_api_instance()
        return self._check_api_availability(api)

    async def async_press(self) -> None:
        """Handle the button press - reset all alarms."""
        api = self._get_api_instance()
        if api and hasattr(api, "reset_all_alarms"):
            _LOGGER.info("Resetting all alarms for device: %s", self.device.name)
            await self._safe_api_call(api.reset_all_alarms, "reset alarms")
