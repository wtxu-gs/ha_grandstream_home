"""Grandstream Home Webhook receivers."""

from datetime import datetime
import json
import logging
from typing import Any

from aiohttp import web
from requests.exceptions import RequestException

from homeassistant.components import webhook
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .automation_patterns import parse_di_report
from .const import BIZ_EVENT_NAME, DEVICE_TYPE_GDS, DI_MODE_DOORBELL_CALL
from .coordinator import GrandstreamCoordinator

_LOGGER = logging.getLogger(__name__)

__all__ = ["GsWebhookCommandReceiver", "GsWebhookStatusReceiver"]

# Define alarm event types
ALARM_EVENTS = {
    "0": "Personnel stay/intrusion alarm",
    "1": "Hostage Alarm",
    "2": "Tamper Alarm",
    "3": "Keypad Input Error Alarm",
    "4": "Non-scheduled Access Alarm",
    "5": "Non-authorized RFID Card Access Alarm",
    "6": "Abnormal Sound Alarm",
    "7": "High Temperature Alarm",
    "8": "DI 1",
    "9": "DI 2",
    "10": "DI 3",
    "21": "Backend Admin Continuous Authentication Failure Alarm",
}

# Business event types reported with type="biz"
BIZ_TYPE_SD_CARD = "0"
BIZ_TYPE_DOORBELL = "1"
BIZ_TYPE_ADMIN_KEY = "2"
BIZ_TYPE_QUICK_KEY = "3"
BIZ_TYPE_DI_STATE = "4"

BIZ_EVENTS = {
    BIZ_TYPE_SD_CARD: "SD Card Status",
    BIZ_TYPE_DOORBELL: "Doorbell/Call Key Pressed",
    BIZ_TYPE_ADMIN_KEY: "Admin Key Pressed",
    BIZ_TYPE_QUICK_KEY: "Quick Key Pressed",
    BIZ_TYPE_DI_STATE: "Digital Input State",
}


def normalize_status(status: Any) -> str:
    """Normalize status value.

    Args:
        status: Raw status value

    Returns:
        str: Normalized status string

    """
    if not status:
        return "unknown"

    status_str = str(status).lower().strip()

    # Handle common error states
    if "error" in status_str or "timeout" in status_str or "failed" in status_str:
        return "unavailable"

    return status_str


async def _parse_request_data(request: web.Request) -> dict[str, Any]:
    """Parse request data from either JSON or form data.

    Args:
        request: Web request object

    Returns:
        dict: Parsed request data

    """
    try:
        if request.headers.get("Content-Type", "").startswith("application/json"):
            # Try to parse JSON
            if request.content_length and request.content_length > 0:
                json_data = await request.json()
                # Ensure json_data is a dictionary
                if isinstance(json_data, dict):
                    return json_data
                _LOGGER.warning(
                    "JSON data is not a dictionary, got type: %s", type(json_data)
                )
                return {}
            return {}
        # Try to parse form data
        data = await request.post()
        # Convert MultiDict to regular dict, ensuring all values are strings
        return {k: str(v) for k, v in data.items()}
    except json.JSONDecodeError as e:
        _LOGGER.warning("JSON parsing error: %s", e)
        return {}
    except (ValueError, KeyError, RequestException) as e:
        _LOGGER.error("Error parsing request data: %s", e)
        return {}


async def _handle_status_data(
    coordinator: DataUpdateCoordinator, data: dict[str, Any]
) -> dict[str, Any]:
    """Handle status data.

    Args:
        coordinator: Data update coordinator
        data: Status data

    Returns:
        dict: Response data

    """
    try:
        # Get device type, default to 'gds'
        device_type = data.get("type", DEVICE_TYPE_GDS.lower())
        _LOGGER.info("Received status update (device type: %s): %s", device_type, data)
        result_success: dict[str, Any] | None = None

        # Get status data, support multiple possible key names
        status = data.get("status") or data.get("state") or data.get("value")

        if not status:
            return {
                "success": False,
                "error": "No status data found in request",
                "code": 400,
            }

        # Normalize status value
        status = normalize_status(status)

        # Add device type to status data
        formatted_status = {
            "type": device_type,
            "status": status,
            "data": data,  # Save complete data for subsequent processing
        }

        # Call coordinator method
        if hasattr(coordinator, "handle_push_data"):
            coordinator.handle_push_data(formatted_status)
        else:
            # If no handle_push_data method, use async_set_updated_data
            coordinator.async_set_updated_data(formatted_status)

        result_success = {
            "success": True,
            "message": "Status update successful",
            "code": 200,
            "data": formatted_status,
        }

    except (ValueError, KeyError, json.JSONDecodeError, RequestException) as e:
        _LOGGER.error("Status update error: %s", e)
        return {"success": False, "error": str(e), "code": 500}

    return result_success


async def _handle_alarm_event(hass: HomeAssistant, data: dict[str, Any]) -> None:
    """Handle alarm events.

    Args:
        hass: Home Assistant instance
        data: Alarm event data

    """
    try:
        # Get event type (new format)
        event_type = data.get("type")

        if not event_type:
            _LOGGER.warning("Missing 'type' in event data: %s", data)
            return

        # Get event details
        event_details = data.get("eventDetails", [])
        if not event_details:
            _LOGGER.warning("Missing 'eventDetails' in event data: %s", data)
            return

        # Process first event detail
        event_detail = event_details[0]
        event_time_ms = event_detail.get("eventTime")
        event_code = event_detail.get("eventCode")
        event_message = event_detail.get("eventMessage", "")
        event_data = event_detail.get("data", {})

        # Convert timestamp to readable time (milliseconds to seconds)
        if event_time_ms:
            event_time = datetime.fromtimestamp(int(event_time_ms) / 1000)
        else:
            event_time = datetime.now()

        # Get MAC address from the incoming data (for device matching in automations)
        mac_address = data.get("mac")

        # Prepare base event data
        base_event_data = {
            "type": event_type,
            "timestamp": event_time_ms,
            "datetime": event_time.isoformat(),
            "info": event_message,
            "event_id": event_detail.get("eventId"),
            "mac": mac_address,  # Include MAC for device-specific automation matching
        }

        # Handle different event types
        if event_type == "access":
            # Door access event
            access_type = event_data.get("accessType")
            access_user_id = event_data.get("accessUserId")
            access_user_name = event_data.get("accessUserName")
            relay = event_data.get("relay")

            event_data_to_fire = {
                **base_event_data,
                "accessType": str(access_type) if access_type is not None else None,
                "accessUserId": access_user_id,
                "accessUserName": access_user_name,
                "relay": relay,
            }

            _LOGGER.info(
                "Door access event: type=%s, user=%s, accessType=%s",
                event_type,
                access_user_name,
                access_type,
            )

        elif event_type == "alert":
            # Alarm event
            # alertType is in data.alertType, not eventCode
            alert_type_from_data = event_data.get("alertType")
            alert_type = (
                str(alert_type_from_data)
                if alert_type_from_data is not None
                else str(event_code)
            )

            # Get alarm type description
            event_description = ALARM_EVENTS.get(alert_type, "Unknown Alarm")

            event_data_to_fire = {
                **base_event_data,
                "alertType": alert_type,
                "event_description": event_description,
            }

            _LOGGER.info(
                "Alarm event: type=%s, alertType=%s, description=%s",
                event_type,
                alert_type,
                event_description,
            )

        else:
            # Unknown event type
            _LOGGER.warning("Unknown event type: %s", event_type)
            event_data_to_fire = base_event_data

        # Trigger Home Assistant event
        hass.bus.async_fire("grandstream_alarm", event_data_to_fire)

        _LOGGER.debug("Event fired: %s", event_data_to_fire)

    except (ValueError, KeyError, json.JSONDecodeError, RequestException) as e:
        _LOGGER.error("Error handling alarm event: %s", e)
    except Exception:
        _LOGGER.exception("Unexpected error handling alarm event")


def _update_di_state(
    coordinator: GrandstreamCoordinator,
    detail_map: dict[str, Any],
    event_time: datetime,
) -> None:
    """Cache the logical digital input state so binary sensors can reflect it."""
    port = detail_map.get("diInputId")
    try:
        mode = int(detail_map["diMode"])
    except (KeyError, TypeError, ValueError) as e:
        _LOGGER.warning("Ignoring incomplete digital input event: %s (%s)", detail_map, e)
        return

    parsed = parse_di_report(detail_map)
    if parsed is None:
        _LOGGER.warning(
            "Ignoring digital input event without usable diEventState: %s", detail_map
        )
        return

    if port is None:
        _LOGGER.warning("Ignoring digital input event without diInputId: %s", detail_map)
        return

    trigger_mode, level = parsed
    coordinator.update_di_state(port, mode, level, event_time, trigger_mode)


def _as_int(value: Any) -> int | None:
    """Parse an int from detailMap values, which may arrive as strings."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


async def _handle_biz_event(
    hass: HomeAssistant,
    coordinator: GrandstreamCoordinator | None,
    data: dict[str, Any],
) -> int:
    """Handle business events reported with type="biz".

    Devices wrap each biz event in eventDetails like access/alert events, with
    bizType and detailMap nested in the element's data; the flat form is also
    accepted. The detailMap payload is forwarded unchanged and its fields are
    exposed at the top level so automations can read them without extra nesting.

    Args:
        hass: Home Assistant instance
        coordinator: Data update coordinator owning the webhook
        data: Business event data

    Returns:
        int: Number of biz events processed

    """
    event_details = data.get("eventDetails")
    if isinstance(event_details, list) and event_details:
        items = [item for item in event_details if isinstance(item, dict)]
    else:
        items = [data]

    processed = 0
    for item in items:
        # Wrapped payloads nest bizType/detailMap under data, flat ones keep them at top level
        payload = item.get("data") if isinstance(item.get("data"), dict) else item

        biz_type = payload.get("bizType")
        if biz_type is None:
            _LOGGER.warning("Missing 'bizType' in biz event data: %s", item)
            continue

        biz_type = str(biz_type)
        detail_map = payload.get("detailMap") or {}
        if not isinstance(detail_map, dict):
            _LOGGER.warning("Ignoring non-dict 'detailMap' in biz event data: %s", item)
            detail_map = {}

        # Devices may report the event time; fall back to the receiving time
        event_time_ms = item.get("eventTime")
        if event_time_ms:
            event_time = datetime.fromtimestamp(int(event_time_ms) / 1000)
        else:
            event_time = datetime.now()
            event_time_ms = int(event_time.timestamp() * 1000)

        event_data = {
            "type": "biz",
            "bizType": biz_type,
            "description": BIZ_EVENTS.get(biz_type, "Unknown Biz Event"),
            "timestamp": event_time_ms,
            "datetime": event_time.isoformat(),
            "event_id": item.get("eventId"),
            "mac": data.get("mac"),  # Include MAC for device-specific automation matching
            "config_entry_id": coordinator.entry_id if coordinator else None,
            "detailMap": detail_map,
            **detail_map,
        }

        if biz_type == BIZ_TYPE_DI_STATE and coordinator is not None:
            _update_di_state(coordinator, detail_map, event_time)

        hass.bus.async_fire(BIZ_EVENT_NAME, event_data)
        processed += 1

        # A DI configured as doorbell call simulates a doorbell press, so
        # doorbell automations and the doorbell event entity also react
        di_report = parse_di_report(detail_map) if biz_type == BIZ_TYPE_DI_STATE else None
        if (
            di_report is not None
            and di_report[1] == 1
            and _as_int(detail_map.get("diMode")) == DI_MODE_DOORBELL_CALL
        ):
            press_data = {
                **event_data,
                "bizType": BIZ_TYPE_DOORBELL,
                "description": BIZ_EVENTS[BIZ_TYPE_DOORBELL],
            }
            hass.bus.async_fire(BIZ_EVENT_NAME, press_data)
            processed += 1

        _LOGGER.info(
            "Biz event reported: bizType=%s (%s), details=%s",
            biz_type,
            BIZ_EVENTS.get(biz_type, "Unknown"),
            detail_map,
        )

    return processed


async def _handle_command_data(
    hass: HomeAssistant,
    coordinator: GrandstreamCoordinator | None,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Handle command data.

    Args:
        hass: Home Assistant instance
        coordinator: Data update coordinator owning the webhook
        data: Command data

    Returns:
        dict: Response data

    """
    try:
        _LOGGER.info("Command received: %s", data)

        # Validate data is a dictionary
        if not isinstance(data, dict):
            _LOGGER.error("Invalid data type received: %s (expected dict)", type(data))
            return {
                "success": False,
                "error": f"Invalid data type: expected dict, got {type(data).__name__}",
                "code": 400,
            }

        # Check if this is a new format event (has "type" and "eventDetails")
        event_type = data.get("type")

        # Business events report bizType/detailMap, wrapped in eventDetails or flat
        if event_type == "biz" or "bizType" in data:
            processed = await _handle_biz_event(hass, coordinator, data)
            return {
                "success": processed > 0,
                "message": f"Processed {processed} biz event(s)",
                "code": 200 if processed else 400,
                "data": {"type": "biz", "processed": processed},
            }

        if event_type and "eventDetails" in data:
            # This is a new format event (access or alert)
            await _handle_alarm_event(hass, data)
            return {
                "success": True,
                "message": f"Event processed: {event_type}",
                "code": 200,
                "data": {"type": event_type},
            }

        # No valid event format found
        return {  # noqa: TRY300
            "success": False,
            "error": "Invalid event format: missing 'type' or 'eventDetails'",
            "code": 400,
        }

    except (ValueError, KeyError, json.JSONDecodeError, RequestException) as e:
        _LOGGER.error("Command error: %s", e)
        return {"success": False, "error": str(e), "code": 500}


# ----------------------------------------------------------
# Webhook receivers
# ----------------------------------------------------------
class GsWebhookStatusReceiver:
    """Handle Webhook status updates."""

    def __init__(
        self, hass: HomeAssistant, coordinator: DataUpdateCoordinator, webhook_id: str
    ) -> None:
        """Initialize the webhook status receiver.

        Args:
            hass: Home Assistant instance
            coordinator: Data update coordinator
            webhook_id: Webhook ID

        """
        self.hass = hass
        self.coordinator = coordinator
        self.webhook_id = webhook_id

    async def async_setup(self) -> None:
        """Set up Webhook."""
        # Try to register webhook, catch if already exists
        try:
            webhook.async_register(
                self.hass,
                "grandstream_home",
                "Grandstream Status",
                self.webhook_id,
                self.handle_webhook,
                local_only=True,  # Restrict to local access only
            )
            _LOGGER.info("Registered status Webhook: %s", self.webhook_id)
        except ValueError as e:
            if "Handler is already defined" in str(e):
                _LOGGER.debug(
                    "Status webhook %s already registered, skipping", self.webhook_id
                )
            else:
                raise

    async def handle_webhook(
        self, _hass: HomeAssistant, _webhook_id: str, request: web.Request
    ) -> web.Response:
        """Handle Webhook requests.

        Args:
            _hass: Home Assistant instance (unused)
            _webhook_id: Webhook ID (unused)
            request: Web request object

        Returns:
            web.Response: JSON response

        """
        try:
            # Parse request data
            data = await _parse_request_data(request)

            if not data:
                # If no data, try to get from query parameters
                data = dict(request.query)

            if not data:
                return web.json_response(
                    {
                        "success": False,
                        "error": "No data provided in request",
                        "code": 400,
                    },
                    status=400,
                )

            result = await _handle_status_data(self.coordinator, data)
            return web.json_response(result, status=result["code"])

        except (ValueError, KeyError, json.JSONDecodeError, RequestException) as e:
            _LOGGER.error("Webhook status update error: %s", e)
            return web.json_response(
                {"success": False, "error": str(e), "code": 500}, status=500
            )


class GsWebhookCommandReceiver:
    """Handle Webhook commands."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: GrandstreamCoordinator | None,
        webhook_id: str,
    ) -> None:
        """Initialize the webhook command receiver.

        Args:
            hass: Home Assistant instance
            coordinator: Data update coordinator used to cache pushed states
            webhook_id: Webhook ID

        """
        self.hass = hass
        self.coordinator = coordinator
        self.webhook_id = webhook_id

    async def async_setup(self) -> None:
        """Set up Webhook."""
        # Try to register webhook, catch if already exists
        try:
            webhook.async_register(
                self.hass,
                "grandstream_home",
                "Grandstream Command",
                self.webhook_id,
                self.handle_webhook,
                local_only=True,  # Restrict to local access only
            )
            _LOGGER.info("Registered command Webhook: %s", self.webhook_id)
        except ValueError as e:
            if "Handler is already defined" in str(e):
                _LOGGER.debug(
                    "Command webhook %s already registered, skipping", self.webhook_id
                )
            else:
                raise

    async def handle_webhook(
        self, _hass: HomeAssistant, _webhook_id: str, request: web.Request
    ) -> web.Response:
        """Handle Webhook requests.

        Args:
            _hass: Home Assistant instance (unused)
            _webhook_id: Webhook ID (unused)
            request: Web request object

        Returns:
            web.Response: JSON response

        """
        try:
            # Parse request data
            data = await _parse_request_data(request)

            if not data:
                # If no data, try to get from query parameters
                data = dict(request.query)

            if not data:
                return web.json_response(
                    {
                        "success": False,
                        "error": "No data provided in request body or query parameters",
                        "code": 400,
                    },
                    status=400,
                )

            result = await _handle_command_data(self.hass, self.coordinator, data)
            return web.json_response(result, status=result["code"])

        except (ValueError, KeyError, json.JSONDecodeError, RequestException) as e:
            _LOGGER.error("Webhook command error: %s", e)
            return web.json_response(
                {"success": False, "error": str(e), "code": 500}, status=500
            )
