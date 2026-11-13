"""Event platform for Grandstream Home integration.

Physical key presses reach Home Assistant as biz events. Each supported key is
exposed as an EventEntity, using HA's standard event type for the chosen device
class (ring for doorbell, press for buttons).
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.event import (
    DoorbellEventType,
    EventDeviceClass,
    EventEntity,
)
from homeassistant.core import Event as HASSEvent, HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import GrandstreamConfigEntry
from .const import (
    BIZ_EVENT_NAME,
    DEFAULT_DEVICE_FEATURES,
    DEVICE_FEATURES,
    DEVICE_TYPE_GDS,
    DEVICE_TYPE_GSC,
    DOMAIN,
)
from .coordinator import GrandstreamCoordinator
from .device import GrandstreamDevice
from .receiver import BIZ_TYPE_ADMIN_KEY, BIZ_TYPE_DOORBELL, BIZ_TYPE_QUICK_KEY

_LOGGER = logging.getLogger(__name__)

EVENT_TYPE_PRESS = "press"


class GrandstreamKeyEventEntity(
    CoordinatorEntity[GrandstreamCoordinator], EventEntity
):
    """A physical key press reported through biz events."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: GrandstreamCoordinator,
        device: GrandstreamDevice,
        key: str,
        translation_key: str,
        biz_type: str,
        device_class: EventDeviceClass,
        event_type: str,
        key_filter: tuple[str, str] | None = None,
        translation_placeholders: dict[str, str] | None = None,
    ) -> None:
        """Initialize the key press entity.

        Args:
            coordinator: Data update coordinator, provides availability.
            device: Grandstream device the key belongs to.
            key: Suffix making the unique id stable across renames.
            translation_key: i18n key under entity.event in strings.json.
            biz_type: bizType value this entity listens for.
            device_class: DOORBELL for ring keys, BUTTON for the other keys.
            event_type: Event type reported on each press; the doorbell device
                class requires DoorbellEventType.RING.
            key_filter: Additional (detailMap field, value) to match.
            translation_placeholders: Placeholders used by the entity name.

        """
        super().__init__(coordinator)
        self._entry_id = coordinator.entry_id
        self._biz_type = biz_type
        self._key_filter = key_filter
        self._event_type = event_type
        self._attr_unique_id = f"{device.unique_id}_{key}"
        self._attr_device_info = device.device_info
        self._attr_translation_key = translation_key
        self._attr_device_class = device_class
        self._attr_event_types = [event_type]
        if translation_placeholders is not None:
            self._attr_translation_placeholders = translation_placeholders

    async def async_added_to_hass(self) -> None:
        """Subscribe to biz events once the entity is added."""
        await super().async_added_to_hass()
        self.async_on_remove(
            self.hass.bus.async_listen(BIZ_EVENT_NAME, self._handle_biz_event)
        )

    @callback
    def _handle_biz_event(self, event: HASSEvent) -> None:
        """Fire the entity event when the matching key is reported."""
        data: dict[str, Any] = event.data or {}

        # The biz event carries the entry that owns the receiving webhook
        if data.get("config_entry_id") != self._entry_id:
            return

        if data.get("bizType") != self._biz_type:
            return

        if self._key_filter is not None:
            field, value = self._key_filter
            if str(data.get(field)) != value:
                return

        self._trigger_event(
            self._event_type,
            {"timestamp": data.get("timestamp"), "datetime": data.get("datetime")},
        )
        self.async_write_ha_state()


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: GrandstreamConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up key press event entities from a config entry."""
    device_data = hass.data[DOMAIN][config_entry.entry_id]
    device: GrandstreamDevice | None = device_data.get("device")
    coordinator: GrandstreamCoordinator | None = device_data.get("coordinator")
    device_type: str = device_data.get("device_type", "")
    product_model: str | None = device_data.get("product_model")

    # GNS devices have no keys, GDS door stations and GSC cameras report presses
    is_gds = DEVICE_TYPE_GDS.lower() in device_type.lower()
    is_gsc = DEVICE_TYPE_GSC.lower() in device_type.lower()
    if not (is_gds or is_gsc):
        _LOGGER.debug("Skipping event entity setup for device type: %s", device_type)
        return

    if not device or not coordinator:
        _LOGGER.warning("Missing device or coordinator, skipping event entity setup")
        return

    features = DEVICE_FEATURES.get(product_model or "", DEFAULT_DEVICE_FEATURES)

    entities: list[GrandstreamKeyEventEntity] = []

    if features.get("has_doorbell_key"):
        entities.append(
            GrandstreamKeyEventEntity(
                coordinator=coordinator,
                device=device,
                key="doorbell",
                translation_key="doorbell",
                biz_type=BIZ_TYPE_DOORBELL,
                device_class=EventDeviceClass.DOORBELL,
                event_type=DoorbellEventType.RING,
            )
        )

    # GSC356X call button, reported as bizType 1 like the GDS doorbell key
    if is_gsc:
        entities.append(
            GrandstreamKeyEventEntity(
                coordinator=coordinator,
                device=device,
                key="call_key",
                translation_key="call_key",
                biz_type=BIZ_TYPE_DOORBELL,
                device_class=EventDeviceClass.DOORBELL,
                event_type=DoorbellEventType.RING,
            )
        )

    if features.get("has_admin_key"):
        entities.append(
            GrandstreamKeyEventEntity(
                coordinator=coordinator,
                device=device,
                key="admin_key",
                translation_key="admin_key",
                biz_type=BIZ_TYPE_ADMIN_KEY,
                device_class=EventDeviceClass.BUTTON,
                event_type=EVENT_TYPE_PRESS,
            )
        )

    if features.get("has_quick_key"):
        entities.extend(
            GrandstreamKeyEventEntity(
                coordinator=coordinator,
                device=device,
                key=f"quick_key_{key_id}",
                translation_key="quick_key",
                biz_type=BIZ_TYPE_QUICK_KEY,
                device_class=EventDeviceClass.BUTTON,
                event_type=EVENT_TYPE_PRESS,
                key_filter=("quickKeyId", str(key_id)),
                translation_placeholders={"index": str(key_id)},
            )
            for key_id in (1, 2, 3, 4)
        )

    async_add_entities(entities)
