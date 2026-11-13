"""Binary sensor platform for Grandstream integration."""

from __future__ import annotations

from datetime import datetime
import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import GrandstreamConfigEntry
from .const import (
    DEFAULT_DEVICE_FEATURES,
    DEVICE_FEATURES,
    DEVICE_TYPE_GDS,
    DI_ACTIVE_LEVEL,
    DI_MODE_ALARM,
    DI_MODE_DOORBELL_CALL,
    DI_MODE_DOOR_STATE,
    DI_MODE_NAMES,
    DI_MODE_OPEN_SIGNAL,
    DOMAIN,
)
from .coordinator import GrandstreamCoordinator, GrandstreamDIState
from .device import GrandstreamDevice

_LOGGER = logging.getLogger(__name__)

# The device reports the digital input state only through biz events, so the
# configured mode decides both the icon semantics and the active level
DI_MODE_DEVICE_CLASSES: dict[int, BinarySensorDeviceClass] = {
    DI_MODE_ALARM: BinarySensorDeviceClass.PROBLEM,
    DI_MODE_OPEN_SIGNAL: BinarySensorDeviceClass.OPENING,
    DI_MODE_DOOR_STATE: BinarySensorDeviceClass.DOOR,
    DI_MODE_DOORBELL_CALL: BinarySensorDeviceClass.SOUND,
}


class GrandstreamDIBinarySensor(CoordinatorEntity[GrandstreamCoordinator], BinarySensorEntity):
    """Representation of a Grandstream DI binary sensor."""

    _attr_has_entity_name = True
    _attr_translation_key = "di"

    def __init__(
        self,
        coordinator: GrandstreamCoordinator,
        device: GrandstreamDevice,
        di_index: int,
    ) -> None:
        """Initialize the DI binary sensor.

        Args:
            coordinator: Data update coordinator
            device: Grandstream device instance
            di_index: DI port index (1, 2, or 3)

        """
        super().__init__(coordinator)
        self._device = device
        self._di_index = di_index
        self._attr_unique_id = f"{device.unique_id}_di_{di_index}"
        self._attr_translation_placeholders = {"index": str(di_index)}
        self._attr_device_info = device.device_info

        # Duration tracking
        self._trigger_start: datetime | None = None
        self._last_duration: float | None = None
        self._last_trigger_start: datetime | None = None

    @property
    def _di_state(self) -> GrandstreamDIState | None:
        """Return the last reported state of this DI port."""
        return self.coordinator.di_states.get(str(self._di_index))

    @property
    def is_on(self) -> bool | None:
        """Return true if the DI is active, None until the device reported once."""
        state = self._di_state
        if state is None:
            return None
        return state.level == DI_ACTIVE_LEVEL.get(state.mode)

    @property
    def device_class(self) -> BinarySensorDeviceClass | None:
        """Return the device class matching the configured DI mode."""
        state = self._di_state
        if state is None:
            return None
        return DI_MODE_DEVICE_CLASSES.get(state.mode)

    @property
    def icon(self) -> str:
        """Return the icon of the DI sensor."""
        return "mdi:electric-switch-closed" if self.is_on else "mdi:electric-switch"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes of the DI sensor."""
        attrs: dict[str, Any] = {}

        state = self._di_state
        if state is not None:
            attrs["di_mode"] = state.mode
            attrs["di_mode_name"] = DI_MODE_NAMES.get(state.mode, "unknown")
            attrs["di_trigger_mode"] = state.trigger_mode
            attrs["di_event_state"] = state.level
            attrs["last_event_time"] = state.changed_at.isoformat()

        if self.is_on and self._trigger_start:
            attrs["duration"] = (datetime.now() - self._trigger_start).total_seconds()
            attrs["trigger_start"] = self._trigger_start.isoformat()
        elif not self.is_on and self._last_duration is not None:
            attrs["last_duration"] = self._last_duration
            if self._last_trigger_start:
                attrs["last_trigger_start"] = self._last_trigger_start.isoformat()

        return attrs

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        was_on = self.is_on
        super()._handle_coordinator_update()
        now_on = self.is_on

        if now_on and not was_on:
            # DI became active, prefer the device reported timestamp
            state = self._di_state
            self._trigger_start = (
                state.changed_at if state else datetime.now()
            )
            self._last_duration = None
            self._last_trigger_start = None
        elif was_on and not now_on:
            # DI became inactive
            if self._trigger_start:
                self._last_duration = (datetime.now() - self._trigger_start).total_seconds()
                self._last_trigger_start = self._trigger_start
            self._trigger_start = None

        self.async_write_ha_state()


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: GrandstreamConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up DI binary sensors from a config entry."""
    device_data = hass.data[DOMAIN][config_entry.entry_id]
    device = device_data.get("device")
    coordinator = device_data.get("coordinator")
    device_type = device_data.get("device_type", "")

    # Only GDS/GSC devices support DI
    if DEVICE_TYPE_GDS.lower() not in device_type.lower():
        _LOGGER.debug("Skipping DI binary sensor setup for device type: %s", device_type)
        return

    if not device or not coordinator:
        _LOGGER.warning("Missing device or coordinator, skipping DI binary sensor setup")
        return

    # Determine DI count from product model
    product_model = device_data.get("product_model")
    di_count = 2  # Default to 2 DI ports

    if product_model:
        features = DEVICE_FEATURES.get(product_model, DEFAULT_DEVICE_FEATURES)
        has_di_3 = features.get("has_di_3", False)
        di_count = 3 if has_di_3 else 2

    _LOGGER.info(
        "Setting up %d DI binary sensors for %s", di_count, product_model or "unknown model"
    )

    entities = [
        GrandstreamDIBinarySensor(coordinator, device, di_index)
        for di_index in range(1, di_count + 1)
    ]

    async_add_entities(entities)
