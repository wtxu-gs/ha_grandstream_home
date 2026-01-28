"""Support for Grandstream GXV and GDS door locks."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import GrandstreamConfigEntry
from .const import (
    CONF_DOOR_ID,
    CONF_KEEP_UNLOCKED,
    CONF_PRODUCT_MODEL,
    CONF_UNLOCK_DURATION,
    DEFAULT_DEVICE_FEATURES,
    DEVICE_FEATURES,
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
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the Grandstream lock."""
    device_data = hass.data[DOMAIN][config_entry.entry_id]
    api = device_data.get("api")
    device = device_data.get("device")
    coordinator = device_data.get("coordinator")
    device_type = device_data.get("device_type", "").lower()

    entities = []

    # Check if device supports locks
    if not device or DEVICE_TYPE_GDS.lower() not in device_type:
        _LOGGER.info(
            "No lock entity added: device type %s not supported or device does not exist",
            device_type,
        )
        return

    # Get product model to determine door count
    product_model = config_entry.data.get(CONF_PRODUCT_MODEL)
    door_count = 2  # Default to 2 doors

    if product_model:
        features = DEVICE_FEATURES.get(product_model, DEFAULT_DEVICE_FEATURES)
        door_count = features.get("door_count", 2)
        _LOGGER.info("Product model %s has %d door(s)", product_model, door_count)

    # Create lock entities based on door count
    if door_count > 0:
        entities.extend(
            [
                GrandstreamGDSLock(
                    hass,
                    device,
                    api,
                    config_entry.title,
                    door_id,
                    coordinator,
                    config_entry.options.get(CONF_KEEP_UNLOCKED, False),
                    config_entry.options.get(CONF_UNLOCK_DURATION, 5),
                )
                for door_id in range(1, door_count + 1)
            ]
        )
        _LOGGER.info("Added GDS lock entity: %s Door 1-%d", device.name, door_count)
    else:
        _LOGGER.info(
            "No lock entities added: product model %s has no doors",
            product_model,
        )
        return

    async_add_entities(entities)

    # Services removed - now using unlock_door service from services.py


class GrandstreamGDSLock(CoordinatorEntity, LockEntity):
    """Representation of a Grandstream GDS lock."""

    _attr_has_entity_name = True

    def __init__(
        self,
        hass: HomeAssistant,
        device,
        api,
        title,
        door_id,
        coordinator,
        keep_unlocked=False,
        unlock_duration=5,
    ) -> None:
        """Initialize the lock."""
        super().__init__(coordinator)
        self.hass = hass
        self._device = device
        self._api = api
        self._attr_unique_id = f"{device.unique_id}-door{door_id}"
        self._attr_name = f"Door {door_id}"
        self._door_id = door_id
        self._keep_unlocked = keep_unlocked
        self._attr_device_info = device.device_info
        self._attr_extra_state_attributes = {
            CONF_DOOR_ID: door_id,
        }
        self._unlock_task: asyncio.Task[None] | None = None
        self._is_locking = False
        self._is_unlocking = False
        self._is_opening = False
        self._is_open = False
        self._is_jammed = False  # Track if lock is jammed
        self._consecutive_failures = 0  # Track consecutive operation failures
        self._operation_cancelled = (
            False  # Track if current operation was cancelled by user
        )
        self._operation_lock = asyncio.Lock()  # Prevent concurrent operations
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
            return False

        # Check if account is locked
        if hasattr(self._api, "is_account_locked") and self._api.is_account_locked:
            return False

        # Check if device is authenticated
        if hasattr(self._api, "is_authenticated") and not self._api.is_authenticated:
            return False

        # Check if HA control is disabled on device
        if (
            hasattr(self._api, "is_ha_control_enabled")
            and not self._api.is_ha_control_enabled
        ):
            return False

        return True

    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        # Only write state if not in a transitional state (unlocking/opening)
        # This prevents coordinator from overwriting our door operation states
        if self._is_unlocking or self._is_opening or self._is_open:
            _LOGGER.debug(
                "Door %s [%s] coordinator update SKIPPED (in transitional state: unlocking=%s, opening=%s, open=%s)",
                self._door_id,
                self._device.name[:12] if self._device else "?",
                self._is_unlocking,
                self._is_opening,
                self._is_open,
            )
            return
        _LOGGER.debug(
            "Door %s [%s] coordinator update - is_locked=%s",
            self._door_id,
            self._device.name[:12] if self._device else "?",
            self.is_locked,
        )
        self.async_write_ha_state()

    @property
    def is_locked(self) -> bool | None:
        """Return true if the lock is locked."""
        # Unlocked when: unlocking, opening, open, keep_unlocked mode,
        # OR when we're in the "unlocked but not yet opening" state
        # The "unlocked" state happens after API success but before physical door opens
        result = not (
            self._is_unlocking
            or self._is_opening
            or self._is_open
            or self._keep_unlocked
        )
        _LOGGER.debug(
            "Door %s [%s] is_locked=%s (unlocking=%s, opening=%s, open=%s, keep_unlocked=%s)",
            self._door_id,
            self._device.name[:12] if self._device else "?",
            result,
            self._is_unlocking,
            self._is_opening,
            self._is_open,
            self._keep_unlocked,
        )
        return result

    def _set_unlocked_state(self) -> None:
        """Set the lock to unlocked state (after API success, before door opens).

        This creates a proper 'unlocked' state that HA can detect for automations.
        """
        # Clear unlocking flag, set keep_unlocked to ensure is_locked=False
        self._is_unlocking = False
        self._keep_unlocked = True  # This ensures is_locked returns False
        _LOGGER.info(
            "Door %s [%s] now UNLOCKED: is_locked=%s (waiting for automation trigger)",
            self._door_id,
            self._device.name[:12] if self._device else "?",
            self.is_locked,
        )
        self.async_write_ha_state()

    @property
    def is_locking(self) -> bool:
        """Return true if the lock is locking."""
        return self._is_locking

    @property
    def is_unlocking(self) -> bool:
        """Return true if the lock is unlocking."""
        return self._is_unlocking

    @property
    def is_opening(self) -> bool:
        """Return true if the lock is opening."""
        return self._is_opening

    @property
    def is_open(self) -> bool:
        """Return true if the lock is open."""
        return self._is_open

    @property
    def is_jammed(self) -> bool:
        """Return true if the lock is jammed."""
        return self._is_jammed

    async def async_will_remove_from_hass(self) -> None:
        """Remove entity from Home Assistant."""
        if self._unlock_task is not None:
            self._unlock_task.cancel()
            self._unlock_task = None

    async def _delayed_lock(self, delay: int) -> None:
        """Lock after specified delay."""
        try:
            _LOGGER.debug(
                "Starting delayed lock for door %s [%s] with delay %s seconds",
                self._door_id,
                self._device.name[:12] if self._device else "?",
                delay,
            )
            await asyncio.sleep(delay)
            # Transition from open to locked
            self._is_open = False
            self._keep_unlocked = False
            _LOGGER.info(
                "Door %s [%s] auto-locking: is_locked=%s",
                self._door_id,
                self._device.name[:12] if self._device else "?",
                self.is_locked,
            )
            self.async_write_ha_state()
            _LOGGER.info(
                "Door %s [%s] auto-locked after %s seconds",
                self._door_id,
                self._device.name[:12] if self._device else "?",
                delay,
            )
        except asyncio.CancelledError:
            _LOGGER.info(
                "Delayed lock cancelled for door %s [%s]",
                self._door_id,
                self._device.name[:12] if self._device else "?",
            )

    async def _execute_door_operation(
        self, operation: str, api_method, target_state: bool
    ) -> None:
        """Execute door operation (lock/unlock) with unified logic.

        Args:
            operation: Operation name ("lock" or "unlock")
            api_method: API method to call (lock_door or unlock_door)
            target_state: Target state for _keep_unlocked (False for lock, True for unlock)

        """
        # Acquire lock to prevent concurrent operations
        async with self._operation_lock:
            await self._do_execute_door_operation(operation, api_method, target_state)

    async def _do_execute_door_operation(
        self, operation: str, api_method, target_state: bool
    ) -> None:
        """Internal method to execute door operation (called with lock held)."""
        _LOGGER.info(
            "Executing %s door operation: door_id=%s", operation, self._door_id
        )

        # Cancel any ongoing operation from previous unlock/lock
        self._operation_cancelled = False

        # Store previous state for comparison
        previous_is_locked = self.is_locked

        # Set transitional state
        if operation == "lock":
            self._is_locking = True
            self._is_unlocking = False
            self._is_opening = False
            self._is_open = False
            self._keep_unlocked = False
        else:
            # For unlock: set unlocking state, but DON'T set keep_unlocked yet
            # keep_unlocked will be set after API confirms success
            self._is_unlocking = True
            self._is_locking = False
            # Note: _keep_unlocked is NOT set here to ensure proper state transition

        new_is_locked = self.is_locked
        _LOGGER.info(
            "Door %s [%s] state transition: %s -> %s (unlocking=%s, opening=%s, open=%s, keep_unlocked=%s)",
            self._door_id,
            self._device.name[:12] if self._device else "?",
            "locked" if previous_is_locked else "unlocked",
            "locked" if new_is_locked else "unlocked",
            self._is_unlocking,
            self._is_opening,
            self._is_open,
            self._keep_unlocked,
        )

        # Always write state for transitional states (unlocking/locking/opening)
        # This ensures HA UI shows the "waiting" icon immediately
        state_changed = previous_is_locked != new_is_locked
        is_transitional = self._is_unlocking or self._is_locking or self._is_opening

        if state_changed or is_transitional:
            _LOGGER.info(
                "Door %s [%s] state CHANGED: locked=%s -> locked=%s (transitional=%s), writing to HA",
                self._door_id,
                self._device.name[:12] if self._device else "?",
                previous_is_locked,
                new_is_locked,
                is_transitional,
            )
            self.async_write_ha_state()

        try:
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

                # Reset failure counter and jammed state on success
                self._consecutive_failures = 0
                self._is_jammed = False

                # For unlock operation: extract timing parameters
                if operation == "unlock":
                    delay_resp_time = self._safe_int_convert(
                        body.get("delay_resp_time"), 0
                    )
                    hold_time = self._safe_int_convert(body.get("hold_time"), 5)

                    _LOGGER.info(
                        "Door %s [%s] unlocked successfully: delay=%s, hold_time=%s",
                        self._door_id,
                        self._device.name[:12] if self._device else "?",
                        delay_resp_time,
                        hold_time,
                    )

                    # If there's a delay before door opens, wait for it
                    if delay_resp_time > 0:
                        _LOGGER.info(
                            "Door %s [%s] will open after %s seconds delay",
                            self._door_id,
                            self._device.name[:12] if self._device else "?",
                            delay_resp_time,
                        )
                        await asyncio.sleep(delay_resp_time)

                    # Check if user manually locked during the delay
                    if self._is_locking or self._operation_cancelled:
                        _LOGGER.info(
                            "Door %s [%s] unlock sequence cancelled - user manually locked",
                            self._door_id,
                            self._device.name[:12] if self._device else "?",
                        )
                        return

                    # First transition: unlocking -> unlocked
                    # This is CRITICAL for HA automations - the state must actually be "unlocked"
                    # HA state priority: jammed > locking > unlocking > opening > open > unlocked/locked
                    # When _is_unlocking=True, HA state is "unlocking", NOT "unlocked"!
                    self._set_unlocked_state()

                    # Check again if user manually locked during state transition
                    if self._is_locking or self._operation_cancelled:
                        _LOGGER.info(
                            "Door %s [%s] opening sequence cancelled - user manually locked",
                            self._door_id,
                            self._device.name[:12] if self._device else "?",
                        )
                        return

                    # Second transition: unlocked -> opening -> open
                    self._is_opening = True
                    _LOGGER.info(
                        "Door %s [%s] transitioning to opening: is_locked=%s",
                        self._door_id,
                        self._device.name[:12] if self._device else "?",
                        self.is_locked,
                    )
                    self.async_write_ha_state()

                    # Brief opening transition
                    await asyncio.sleep(0.5)

                    # Check again before final open state
                    if self._is_locking or self._operation_cancelled:
                        _LOGGER.info(
                            "Door %s [%s] open sequence cancelled - user manually locked",
                            self._door_id,
                            self._device.name[:12] if self._device else "?",
                        )
                        return

                    # Now fully open
                    self._is_opening = False
                    self._is_open = True
                    # _keep_unlocked is already True from _set_unlocked_state()
                    _LOGGER.info(
                        "Door %s [%s] now open: is_locked=%s",
                        self._door_id,
                        self._device.name[:12] if self._device else "?",
                        self.is_locked,
                    )
                    self.async_write_ha_state()

                    # Create delayed lock task for auto-close
                    self._unlock_task = self.hass.async_create_task(
                        self._delayed_lock(hold_time)
                    )
                    _LOGGER.info(
                        "Door %s [%s] will auto-lock after %s seconds",
                        self._door_id,
                        self._device.name[:12] if self._device else "?",
                        hold_time,
                    )
                else:
                    # For lock operation: no delay handling needed
                    _LOGGER.info(
                        "Door %s locked successfully",
                        self._door_id,
                    )

                    # Update state
                    self._is_locking = False
                    self.async_write_ha_state()
            else:
                error_msg = result.get("body", "Unknown error")
                _LOGGER.error(
                    "Failed to %s door %s: %s",
                    operation,
                    self._door_id,
                    error_msg,
                )

                # Increment failure counter
                self._consecutive_failures += 1

                # If we have multiple consecutive failures, mark as jammed
                if self._consecutive_failures >= 3:
                    _LOGGER.warning(
                        "Door %s marked as jammed after %d consecutive failures",
                        self._door_id,
                        self._consecutive_failures,
                    )
                    self._is_jammed = True

                # Reset transitional state on error
                self._is_locking = False
                self._is_unlocking = False
                self._is_opening = False
                self.async_write_ha_state()
        except Exception:
            _LOGGER.exception(
                "Error during %s operation for door %s", operation, self._door_id
            )

            # Increment failure counter
            self._consecutive_failures += 1

            # If we have multiple consecutive failures, mark as jammed
            if self._consecutive_failures >= 3:
                _LOGGER.warning(
                    "Door %s marked as jammed after %d consecutive failures",
                    self._door_id,
                    self._consecutive_failures,
                )
                self._is_jammed = True

            # Reset transitional state on exception
            self._is_locking = False
            self._is_unlocking = False
            self._is_opening = False
            self.async_write_ha_state()
            raise

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the lock using secure three-step authentication."""
        # Mark that user manually triggered lock - this cancels any ongoing unlock sequence
        self._operation_cancelled = True
        _LOGGER.info(
            "Door %s [%s] manual lock triggered - cancelling any ongoing unlock sequence",
            self._door_id,
            self._device.name[:12] if self._device else "?",
        )
        await self._execute_door_operation("lock", self._api.lock_door, False)

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the lock using secure three-step authentication."""
        # Mark that user manually triggered unlock - this cancels any ongoing lock sequence
        self._is_unlocking = True
        self._operation_cancelled = True
        _LOGGER.info(
            "Door %s unlock called - current state: unlocking=%s, opening=%s, open=%s, keep_unlocked=%s, is_locked=%s (cancelling any ongoing operation)",
            self._door_id,
            self._is_unlocking,
            self._is_opening,
            self._is_open,
            self._keep_unlocked,
            self.is_locked,
        )
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
        except (ValueError, TypeError) as _:
            return default
