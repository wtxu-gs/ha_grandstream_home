"""Support for Grandstream GXV and GDS door locks."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.const import ATTR_DEVICE_CLASS
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import GrandstreamConfigEntry
from .const import (
    CONF_DOOR_ID,
    CONF_KEEP_UNLOCKED,
    CONF_UNLOCK_DURATION,
    DEVICE_TYPE_GDS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

# Service call schema (removed - now using unlock_door service)
# SERVICE_SET_KEEP_DOOR_OPEN = "set_keep_door_open"
# SERVICE_OPEN_DOOR_WITH_DELAY = "open_door_with_delay"


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: GrandstreamConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Grandstream lock."""
    device_data = hass.data[DOMAIN][config_entry.entry_id]
    api = device_data.get("api")
    device = device_data.get("device")
    device_type = device_data.get("device_type", "").lower()

    entities = []

    # GDS devices add locks for two doors
    if device and DEVICE_TYPE_GDS.lower() in device_type:
        entities.extend(
            [
                GrandstreamGDSLock(
                    hass,
                    device,
                    api,
                    config_entry.title,
                    door_id,
                    config_entry.options.get(CONF_KEEP_UNLOCKED, False),
                    config_entry.options.get(CONF_UNLOCK_DURATION, 5),
                )
                for door_id in (1, 2)
            ]
        )
        _LOGGER.info("Added GDS lock entity: %s Door 1 & 2", device.name)
    else:
        _LOGGER.info(
            "No lock entity added: device type %s not supported or device does not exist",
            device_type,
        )
        return

    async_add_entities(entities)

    # Services removed - now using unlock_door service from services.py

class GrandstreamGDSLock(LockEntity):
    """Representation of a Grandstream GDS lock."""

    _attr_has_entity_name = True

    def __init__(
        self,
        hass: HomeAssistant,
        device,
        api,
        title,
        door_id,
        keep_unlocked=False,
        unlock_duration=5,
    ) -> None:
        """Initialize the lock."""
        self.hass = hass
        self._device = device
        self._api = api
        self._attr_unique_id = f"{device.unique_id}-door{door_id}"
        self._attr_name = f"Door {door_id}"
        self._door_id = door_id
        self._keep_unlocked = keep_unlocked
        self._attr_device_info = device.device_info
        self._attr_extra_state_attributes = {
            ATTR_DEVICE_CLASS: "door",
            CONF_DOOR_ID: door_id,
        }
        self._unlock_task: asyncio.Task[None] | None = None
        _LOGGER.info(
            "Initialized GDS lock for door %s: device=%s, api=%s",
            door_id,
            device.name if device else "None",
            "Available" if api else "None",
        )

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        if not self._api:
            return False

        # Check if device is online
        if hasattr(self._api, "is_online") and not self._api.is_online:
            _LOGGER.debug("Lock unavailable: GDS device offline")
            return False

        # Check if account is locked
        if hasattr(self._api, "is_account_locked") and self._api.is_account_locked:
            _LOGGER.debug("Lock unavailable: GDS account locked")
            return False

        # Check if device is authenticated
        if hasattr(self._api, "is_authenticated") and not self._api.is_authenticated:
            _LOGGER.debug("Lock unavailable: GDS device not authenticated")
            return False

        return True

    @property
    def is_locked(self) -> bool | None:
        """Return true if the lock is locked."""
        return not self._keep_unlocked

    async def async_will_remove_from_hass(self) -> None:
        """Remove entity from Home Assistant."""
        if self._unlock_task is not None:
            self._unlock_task.cancel()
            self._unlock_task = None

    async def _delayed_lock(self, delay: int) -> None:
        """Lock after specified delay."""
        try:
            _LOGGER.debug(
                "Starting delayed lock for door %s with delay %s seconds",
                self._door_id,
                delay,
            )
            await asyncio.sleep(delay)
            # Auto-lock by updating state
            self._keep_unlocked = False
            self.async_write_ha_state()
            _LOGGER.info(
                "Door %s auto-locked after %s seconds", self._door_id, delay
            )
        except asyncio.CancelledError:
            _LOGGER.info("Delayed lock cancelled for door %s", self._door_id)

    async def _execute_door_operation(
        self, operation: str, api_method, target_state: bool
    ) -> None:
        """Execute door operation (lock/unlock) with unified logic.

        Args:
            operation: Operation name ("lock" or "unlock")
            api_method: API method to call (lock_door or unlock_door)
            target_state: Target state for _keep_unlocked (False for lock, True for unlock)

        """
        _LOGGER.info("Executing %s door operation: door_id=%s", operation, self._door_id)

        # Cancel any existing delayed lock task
        if self._unlock_task is not None:
            self._unlock_task.cancel()
            self._unlock_task = None
            _LOGGER.debug(
                "Cancelled existing delayed lock task for door %s", self._door_id
            )

        # Call secure API (three-step HMAC authentication)
        result = await self.hass.async_add_executor_job(api_method, self._door_id)

        _LOGGER.debug(
            "%s API response for door %s: %s",
            operation.capitalize(),
            self._door_id,
            result,
        )

        # Check APIResponse format: {"response": "success"/"error", "body": ...}
        if result.get("response") == "success":
            body = result.get("body", {})

            # For unlock operation: extract timing parameters
            if operation == "unlock":
                delay_resp_time = self._safe_int_convert(body.get("delay_resp_time"), 0)
                hold_time = self._safe_int_convert(body.get("hold_time"), 5)

                _LOGGER.info(
                    "Door %s unlocked successfully: delay=%s, hold_time=%s",
                    self._door_id,
                    delay_resp_time,
                    hold_time,
                )

                # If there's a delay before door opens, wait for it
                if delay_resp_time > 0:
                    _LOGGER.info(
                        "Door %s will open after %s seconds delay",
                        self._door_id,
                        delay_resp_time,
                    )
                    await asyncio.sleep(delay_resp_time)

                # Update state
                self._keep_unlocked = target_state
                self.async_write_ha_state()

                # Create delayed lock task for auto-close
                self._unlock_task = self.hass.async_create_task(
                    self._delayed_lock(hold_time)
                )
                _LOGGER.info(
                    "Door %s will auto-lock after %s seconds",
                    self._door_id,
                    hold_time,
                )
            else:
                # For lock operation: no delay handling needed
                _LOGGER.info(
                    "Door %s locked successfully",
                    self._door_id,
                )

                # Update state
                self._keep_unlocked = target_state
                self.async_write_ha_state()
        else:
            error_msg = result.get("body", "Unknown error")
            _LOGGER.error(
                "Failed to %s door %s: %s",
                operation,
                self._door_id,
                error_msg,
            )

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the lock using secure three-step authentication."""
        await self._execute_door_operation("lock", self._api.lock_door, False)

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the lock using secure three-step authentication."""
        await self._execute_door_operation("unlock", self._api.unlock_door, True)

    @staticmethod
    def _safe_int_convert(value: Any, default: int) -> int:
        """Safely convert value to int with fallback.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            Converted integer or default value

        """
        try:
            return int(value) if value else default
        except (ValueError, TypeError):
            return default

