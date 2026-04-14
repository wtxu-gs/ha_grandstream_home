"""Provides device automations for Grandstream Home."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

import voluptuous as vol

from homeassistant.components.device_automation import DEVICE_TRIGGER_BASE_SCHEMA
from homeassistant.const import CONF_DEVICE_ID, CONF_DOMAIN, CONF_PLATFORM, CONF_TYPE
from homeassistant.core import CALLBACK_TYPE, Context, Event, HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.trigger import TriggerActionType, TriggerInfo
from homeassistant.helpers.typing import ConfigType

from .automation_patterns import (
    GDS_ONLY_TRIGGER_TYPES,
    GDS_TRIGGER_TYPES,
    GNS_TRIGGER_TYPES,
    GSC_TRIGGER_TYPES,
    TRIGGER_TYPES,
    AutomationConditionChecker,
    AutomationTypeClassifier,
    EntityMatcher,
    IndexCalculator,
)
from .const import (
    DEFAULT_DEVICE_FEATURES,
    DEVICE_FEATURES,
    DEVICE_TYPE_GDS,
    DEVICE_TYPE_GNS_NAS,
    DEVICE_TYPE_GSC,
    DOMAIN,
)
from .utils import DeviceMatcher, DeviceTypeResolver, extract_mac_from_name

_LOGGER = logging.getLogger(__name__)

# Additional configuration constants
CONF_THRESHOLD = "threshold"
CONF_INDEX = "index"


# Trigger schema
TRIGGER_SCHEMA = DEVICE_TRIGGER_BASE_SCHEMA.extend(
    {
        vol.Required(CONF_TYPE): vol.In(TRIGGER_TYPES),
        vol.Optional(CONF_THRESHOLD): vol.Coerce(float),
        vol.Optional(CONF_INDEX): vol.Coerce(int),
    }
)


async def async_get_triggers(
    hass: HomeAssistant, device_id: str
) -> list[dict[str, Any]]:
    """Return list of device triggers.

    Args:
        hass: Home Assistant instance
        device_id: Device identifier

    Returns:
        List of trigger configurations for GDS, GSC and GNS devices, empty list otherwise

    """

    resolver = DeviceTypeResolver(hass)

    # Determine device type and valid triggers
    if resolver.is_gsc_device(device_id):
        # GSC devices: GDS triggers (excluding GDS-only) + GSC specific triggers
        valid_triggers = {
            k: v
            for k, v in GDS_TRIGGER_TYPES.items()
            if k not in GDS_ONLY_TRIGGER_TYPES
        }
        valid_triggers.update(GSC_TRIGGER_TYPES)
        device_type = DEVICE_TYPE_GSC
    elif resolver.is_gds_device(device_id):
        # GDS devices: all GDS triggers (including GDS-only)
        valid_triggers = dict(GDS_TRIGGER_TYPES)
        device_type = DEVICE_TYPE_GDS
    elif resolver.is_gns_device(device_id):
        valid_triggers = dict(GNS_TRIGGER_TYPES)
        device_type = DEVICE_TYPE_GNS_NAS
    else:
        _LOGGER.debug(
            "Skipping trigger setup for non-supported device: %s",
            device_id,
        )
        return []

    # Filter triggers based on product model features
    product_model = resolver.get_product_model(device_id)
    if product_model:
        features = DEVICE_FEATURES.get(product_model, DEFAULT_DEVICE_FEATURES)
    else:
        # Use default features for unknown models
        features = DEFAULT_DEVICE_FEATURES

    has_di_3 = features.get("has_di_3", False)
    has_qr_code_unlock = features.get("has_qr_code_unlock", False)
    has_bluetooth = features.get("has_bluetooth", False)
    has_nfc = features.get("has_nfc", False)
    has_rfid = features.get("has_rfid", False)
    has_duress_alarm = features.get("has_duress_alarm", False)
    has_anti_tamper = features.get("has_anti_tamper", False)
    has_person_stay_alarm = features.get("has_person_stay_alarm", False)
    has_security_mode = features.get("has_security_mode", False)
    has_password_unlock = features.get("has_password_unlock", False)

    # Remove triggers not supported by device
    triggers_to_remove = []

    if not has_di_3:
        triggers_to_remove.append("di_3")

    if not has_qr_code_unlock:
        triggers_to_remove.extend(["door_opened_qrcode", "door_opened_guest_qrcode"])

    if not has_bluetooth:
        triggers_to_remove.append("door_opened_ble")

    if not has_nfc:
        triggers_to_remove.append("door_opened_nfc")

    if not has_rfid:
        triggers_to_remove.extend(["door_opened_rfid", "unauthorized_rfid"])

    if not has_duress_alarm:
        triggers_to_remove.append("hostage")

    if not has_anti_tamper:
        triggers_to_remove.append("tamper")

    if not has_person_stay_alarm:
        triggers_to_remove.append("personnel_intrusion")

    if not has_security_mode:
        triggers_to_remove.append("safe_room_alarm")

    if not has_password_unlock:
        triggers_to_remove.extend(
            [
                "door_opened_common_password",
                "door_opened_personal_password",
                "door_opened_temp_password",
                "door_opened_card_password",
                "keypad_error",
            ]
        )

    for trigger in triggers_to_remove:
        if trigger in valid_triggers:
            _LOGGER.debug(
                "Removing %s trigger for product model %s (not supported)",
                trigger,
                product_model or "unknown",
            )
            del valid_triggers[trigger]

    _LOGGER.debug(
        "Creating triggers for %s device: %s (product: %s, valid triggers: %d)",
        device_type,
        device_id,
        product_model or "unknown",
        len(valid_triggers),
    )

    # Build trigger list using list comprehension for better performance
    return [
        {
            CONF_PLATFORM: "device",
            CONF_DOMAIN: DOMAIN,
            CONF_DEVICE_ID: device_id,
            CONF_TYPE: trigger_type,
        }
        for trigger_type in valid_triggers
    ]


def _validate_trigger_config(config: ConfigType) -> tuple[str, str]:
    """Validate trigger configuration and return type and device_id.

    Args:
        config: Trigger configuration dictionary

    Returns:
        Tuple of (trigger_type, device_id)

    Raises:
        ValueError: If required fields are missing

    """
    if CONF_TYPE not in config:
        _LOGGER.error("Trigger config missing type field")
        raise ValueError("Trigger configuration missing type field")

    if CONF_DEVICE_ID not in config:
        _LOGGER.error("Trigger config missing device ID field")
        raise ValueError("Trigger configuration missing device_id field")

    return config[CONF_TYPE], config[CONF_DEVICE_ID]


def _build_trigger_data(
    device_id: str,
    trigger_type: str,
    entity_id: str,
    state_value: str,
    threshold: float | None = None,
    index: int | None = None,
) -> dict[str, Any]:
    """Build trigger data dictionary from sensor state.

    Args:
        device_id: Device identifier
        trigger_type: Trigger type identifier
        entity_id: Sensor entity ID
        state_value: Current sensor state value
        threshold: Optional threshold value for numeric triggers
        index: Optional index value for multi-component triggers

    Returns:
        Formatted trigger data dictionary

    """
    trigger_data: dict[str, Any] = {
        "trigger": {
            "platform": "device",
            "domain": DOMAIN,
            "device_id": device_id,
            "entity_id": entity_id,
            "type": trigger_type,
            "description": TRIGGER_TYPES[trigger_type],
            "value": state_value,
        }
    }

    # Add threshold and index if provided
    if threshold is not None:
        trigger_data["trigger"][CONF_THRESHOLD] = threshold
    if index is not None:
        trigger_data["trigger"][CONF_INDEX] = index

    return trigger_data


def _get_expected_mac(hass: HomeAssistant, device_id: str) -> str | None:
    """Get expected MAC address for device filtering.

    Args:
        hass: Home Assistant instance
        device_id: Device identifier

    Returns:
        Normalized MAC address or None if not found

    """
    matcher = DeviceMatcher(hass)
    device = matcher.get_device_by_id(device_id)
    if not device:
        return None

    expected_mac = None
    # Try to get MAC from device connections (HA standard format)
    for conn_type, conn_value in device.connections:
        if conn_type == "mac":
            expected_mac = conn_value.lower()
            break

    # Fallback: try to extract from device name
    if not expected_mac and device.name:
        try:
            # Check if device.name is a real string (not a Mock object)
            if type(device.name).__name__ == "str":
                expected_mac = extract_mac_from_name(device.name)
        except (TypeError, ValueError, AttributeError) as _:
            pass

    _LOGGER.info(
        "Trigger registered for device %s (name: %s, MAC: %s)",
        device_id,
        device.name,
        expected_mac,
    )
    return expected_mac


def _validate_event_mac(
    event_data: Mapping[str, Any], expected_mac: str | None
) -> bool:
    """Validate event MAC address matches expected device.

    Args:
        event_data: Event data dictionary
        expected_mac: Expected MAC address

    Returns:
        True if MAC matches or no filtering needed, False otherwise

    """
    if not expected_mac:
        return True

    event_mac = event_data.get("mac")
    _LOGGER.debug("Expected MAC: %s, Event MAC: %s", expected_mac, event_mac)

    if not event_mac:
        _LOGGER.warning("Event missing MAC address, cannot verify device")
        return False

    # Normalize MAC for comparison (remove colons, lowercase)
    event_mac_normalized = event_mac.replace(":", "").lower()
    expected_mac_normalized = expected_mac.replace(":", "").lower()

    if event_mac_normalized != expected_mac_normalized:
        _LOGGER.debug(
            "Event MAC %s does not match expected MAC %s, skipping",
            event_mac,
            expected_mac,
        )
        return False

    return True


def _get_access_type_from_event(
    event_data: Mapping[str, Any], trigger_access_type: str | None
) -> str | None:
    """Extract and validate access type from event data.

    Args:
        event_data: Event data dictionary
        trigger_access_type: Expected access type from trigger config

    Returns:
        Validated access type or None if validation fails

    """
    event_access_type = event_data.get("accessType")

    if event_access_type is None:
        _LOGGER.warning(
            "Door access event missing 'accessType' field in event data: %s",
            event_data,
        )
        # Specific access type trigger requires valid accessType
        if trigger_access_type is not None:
            _LOGGER.debug(
                "Skipping specific access type trigger due to missing accessType"
            )
            return None
        # For "any" trigger, use unknown access type
        return "unknown"

    # Validate accessType is a string
    try:
        event_access_type = str(event_access_type)
    except (ValueError, TypeError) as e:
        _LOGGER.warning(
            "Invalid accessType value in event data: %s (error: %s)",
            event_access_type,
            e,
        )
        if trigger_access_type is not None:
            return None
        return "unknown"

    return event_access_type


def _build_gds_trigger_data(
    device_id: str,
    trigger_type: str,
    event_data: Mapping[str, Any],
    is_door_access: bool,
) -> dict[str, Any]:
    """Build trigger data dictionary for GDS events.

    Args:
        device_id: Device identifier
        trigger_type: Trigger type identifier
        event_data: Event data from the GDS device
        is_door_access: Whether this is a door access event

    Returns:
        Formatted trigger data dictionary

    """
    trigger_data: dict[str, Any] = {
        "trigger": {
            "platform": "device",
            "domain": DOMAIN,
            "device_id": device_id,
            "type": trigger_type,
            "description": TRIGGER_TYPES[trigger_type],
            "timestamp": event_data.get("timestamp"),
            "datetime": event_data.get("datetime"),
            "info": event_data.get("info"),
            "event_type": event_data.get("type"),
        }
    }

    # Add door access specific fields
    if is_door_access:
        trigger_data["trigger"]["access_type"] = event_data.get("accessType")
    else:
        trigger_data["trigger"]["alert_type"] = event_data.get("alertType")

    # Add optional fields if present
    for field in ("sound_type", "temperature"):
        if field in event_data:
            trigger_data["trigger"][field] = event_data[field]

    return trigger_data


async def _attach_gds_event_trigger(
    hass: HomeAssistant,
    config: ConfigType,
    action: TriggerActionType,
    device_id: str,
    trigger_type: str,
) -> CALLBACK_TYPE:
    """Attach GDS event-based trigger."""
    _LOGGER.debug("Attaching GDS event trigger: %s", trigger_type)

    # Check if this is a door access trigger
    is_door_access = AutomationTypeClassifier.is_door_access_trigger(trigger_type)

    # Get access type or event code based on trigger type
    if is_door_access:
        access_type = AutomationTypeClassifier.get_door_access_type(trigger_type)
        event_code = None
        _LOGGER.debug(
            "Door access trigger: %s, access_type: %s",
            trigger_type,
            access_type,
        )
    else:
        access_type = None
        event_code = AutomationTypeClassifier.get_gds_event_code(trigger_type)
        _LOGGER.debug(
            "Alarm trigger: %s, event_code: %s",
            trigger_type,
            event_code,
        )

    # Get expected MAC for device filtering
    expected_mac = _get_expected_mac(hass, device_id)

    async def handle_gds_alarm_event(event: Event) -> None:
        """Handle GDS alarm events."""
        try:
            # Validate event data
            if not event.data:
                _LOGGER.warning("Received empty event data: %s", event)
                return

            _LOGGER.debug(
                "Processing event for trigger %s (device %s): %s",
                trigger_type,
                device_id,
                event.data,
            )

            # Validate MAC address
            if not _validate_event_mac(event.data, expected_mac):
                return

            # Get event type
            event_type = event.data.get("type")
            if not event_type:
                _LOGGER.warning("Missing type in event data: %s", event.data)
                return

            # Handle door access events
            if is_door_access:
                if event_type != "access":
                    return

                event_access_type = _get_access_type_from_event(event.data, access_type)
                if event_access_type is None:
                    return

                # Match specific access type if required
                if access_type is not None and event_access_type != access_type:
                    _LOGGER.debug(
                        "Access type mismatch: expected %s, got %s",
                        access_type,
                        event_access_type,
                    )
                    return

                _LOGGER.debug(
                    "Door access event matched for trigger %s: accessType=%s",
                    trigger_type,
                    event_access_type,
                )
            else:
                # Handle regular alarm events
                if event_type == "access":
                    return

                alert_type = event.data.get("alertType")
                if not alert_type:
                    _LOGGER.warning("Missing alertType in event data: %s", event.data)
                    return

                if alert_type != event_code:
                    return

                _LOGGER.debug(
                    "Alarm event matched for trigger %s: alertType=%s",
                    trigger_type,
                    alert_type,
                )

            # Build and execute trigger data
            trigger_data = _build_gds_trigger_data(
                device_id, trigger_type, event.data, is_door_access
            )

            _LOGGER.debug("Executing GDS trigger action with data: %s", trigger_data)

            context = Context()
            result = action(trigger_data, context=context)

            if result is not None:
                hass.async_create_task(result)

            _LOGGER.debug("GDS trigger action submitted: %s", trigger_type)

        except (ValueError, KeyError, RuntimeError) as e:
            _LOGGER.exception(
                "Error executing GDS trigger action for type %s",
                trigger_type,
                exc_info=e,
            )

    # Log registration
    if is_door_access:
        _LOGGER.info(
            "Registered door access trigger: %s -> access_type %s",
            trigger_type,
            access_type or "any",
        )
    else:
        _LOGGER.info(
            "Registered GDS alarm trigger: %s -> alert_type %s",
            trigger_type,
            event_code,
        )

    return hass.bus.async_listen("grandstream_alarm", handle_gds_alarm_event)


async def _attach_sensor_trigger(
    hass: HomeAssistant,
    config: ConfigType,
    action: TriggerActionType,
    device_id: str,
    trigger_type: str,
) -> CALLBACK_TYPE:
    """Attach sensor-based trigger."""
    threshold = config.get(CONF_THRESHOLD)
    index = config.get(CONF_INDEX)

    # Get entity registry
    registry = er.async_get(hass)

    # Find matching entity for this trigger
    entity_matcher = EntityMatcher(registry)
    entity_id = entity_matcher.find_matching_entity(device_id, trigger_type, index)

    if not entity_id:
        _LOGGER.error(
            "No matching entity found for trigger type %s on device %s",
            trigger_type,
            device_id,
        )
        raise ValueError(f"No matching entity found for trigger type {trigger_type}")

    # Handle sensor-based triggers
    _LOGGER.debug("Attaching sensor-based trigger: %s -> %s", trigger_type, entity_id)

    async def check_and_trigger(state_value: str | None = None) -> None:
        """Check if conditions are met and trigger if so."""
        try:
            # If no state value provided, get current state
            if state_value is None:
                state_obj = hass.states.get(entity_id)
                if not state_obj:
                    _LOGGER.debug("Entity not found: %s", entity_id)
                    return
                state_value = state_obj.state

            # Check if trigger conditions are met
            if not AutomationConditionChecker.should_trigger_fire(
                state_value, trigger_type, threshold
            ):
                _LOGGER.debug(
                    "Trigger conditions not met: type=%s, value=%s, threshold=%s, index=%s",
                    trigger_type,
                    state_value,
                    threshold,
                    index,
                )
                return

            # Build trigger data
            trigger_data = _build_trigger_data(
                device_id, trigger_type, entity_id, state_value, threshold, index
            )

            _LOGGER.debug("Executing trigger action with data: %s", trigger_data)

            # Execute action
            context = Context()
            result = action(trigger_data, context=context)

            # Check if result is a coroutine and create task if so
            if result is not None:
                hass.async_create_task(result)

            _LOGGER.debug("Trigger action submitted: %s", trigger_type)

        except (ValueError, KeyError, RuntimeError) as e:
            _LOGGER.exception(
                "Error executing trigger action for type %s", trigger_type, exc_info=e
            )

    async def handle_state_change(event: Event) -> None:
        """Handle sensor state change event."""
        try:
            # Get the new state
            new_state = event.data.get("new_state")
            if not new_state:
                return

            # Check if this is the correct entity
            if new_state.entity_id != entity_id:
                return

            # Check and trigger with new state value
            await check_and_trigger(new_state.state)

        except (ValueError, KeyError, RuntimeError) as e:
            _LOGGER.exception(
                "Error handling state change for type %s", trigger_type, exc_info=e
            )

    # Check current state on trigger registration
    hass.async_create_task(check_and_trigger())

    _LOGGER.info("Registered sensor-based trigger: %s -> %s", trigger_type, entity_id)

    # Listen for state changes on the specific entity
    return hass.bus.async_listen("state_changed", handle_state_change)


async def async_attach_trigger(
    hass: HomeAssistant,
    config: ConfigType,
    action: TriggerActionType,
    _trigger_info: TriggerInfo,
) -> CALLBACK_TYPE:
    """Attach device trigger based on sensor state changes or GDS events.

    Args:
        hass: Home Assistant instance
        config: Trigger configuration
        action: Action to execute when triggered
        _trigger_info: Additional trigger information

    Returns:
        Callback function to remove the trigger listener

    Raises:
        ValueError: If configuration is invalid or device not found

    """
    _LOGGER.debug("Attaching trigger, config: %s", config)

    # Validate action
    if not action or not callable(action):
        _LOGGER.error("Trigger action function is invalid")
        raise ValueError("Action must be a valid callable")

    # Validate and extract config
    trigger_type, device_id = _validate_trigger_config(config)

    # Find device
    matcher = DeviceMatcher(hass)
    device = matcher.get_device_by_id(device_id)

    if device is None:
        _LOGGER.error("Device not found: %s", device_id)
        raise ValueError(f"Device not found: {device_id}")

    # Check if this is a GDS event-based trigger
    if AutomationTypeClassifier.is_gds_event_trigger(trigger_type):
        return await _attach_gds_event_trigger(
            hass, config, action, device_id, trigger_type
        )

    return await _attach_sensor_trigger(hass, config, action, device_id, trigger_type)


async def async_get_trigger_capabilities(
    hass: HomeAssistant, config: ConfigType
) -> dict[str, vol.Schema]:
    """List trigger capabilities for configuration UI.

    Args:
        hass: Home Assistant instance
        config: Trigger configuration

    Returns:
        Dictionary with extra fields schema for UI configuration

    """
    trigger_type = config[CONF_TYPE]
    device_id = config.get(CONF_DEVICE_ID)

    # Check if this is a GDS event-based trigger
    if AutomationTypeClassifier.is_gds_event_trigger(trigger_type):
        # GDS event triggers don't require additional configuration
        return {}

    # Get entity registry for dynamic index calculation
    registry = er.async_get(hass)
    index_calculator = IndexCalculator(registry)

    # Calculate actual entity count for this device and trigger type
    max_index = (
        index_calculator.get_max_index_for_device(device_id, trigger_type)
        if device_id
        else 1
    )

    _LOGGER.debug(
        "Using max_index=%d for device %s trigger %s",
        max_index,
        device_id,
        trigger_type,
    )

    # Numeric threshold triggers (CPU, Memory, Pool usage)
    if AutomationTypeClassifier.is_threshold_trigger(trigger_type):
        # CPU/Memory usage - only threshold (no index needed)
        if trigger_type in ["cpu_usage_above", "memory_usage_above"]:
            return {
                "extra_fields": vol.Schema(
                    {
                        vol.Required(CONF_THRESHOLD, default=80): vol.All(
                            vol.Coerce(float), vol.Range(min=0, max=100)
                        )
                    }
                )
            }

        # Temperature thresholds
        if trigger_type in ["system_temperature_above", "cpu_temperature_above"]:
            return {
                "extra_fields": vol.Schema(
                    {
                        vol.Required(CONF_THRESHOLD, default=60): vol.All(
                            vol.Coerce(float), vol.Range(min=0, max=100)
                        )
                    }
                )
            }

        # Indexed threshold triggers (disk temperature, pool usage)
        if trigger_type in ["disk_temperature_above", "pool_usage_above"]:
            schema_fields = {
                vol.Required(
                    CONF_THRESHOLD,
                    default=60 if trigger_type == "disk_temperature_above" else 80,
                ): vol.All(vol.Coerce(float), vol.Range(min=0, max=100))
            }

            # Add index field only if multiple entities exist
            if max_index > 1:
                schema_fields[vol.Required(CONF_INDEX, default=1)] = vol.All(
                    vol.Coerce(int), vol.Range(min=1, max=max_index)
                )

            return {"extra_fields": vol.Schema(schema_fields)}

    # Status-based triggers that need index only when multiple entities exist
    if trigger_type in ["fan_abnormal", "disk_abnormal", "pool_abnormal"]:
        if max_index > 1:
            # Show index selector as required field when multiple entities exist
            return {
                "extra_fields": vol.Schema(
                    {
                        vol.Required(CONF_INDEX, default=1): vol.All(
                            vol.Coerce(int), vol.Range(min=1, max=max_index)
                        )
                    }
                )
            }

    return {}
