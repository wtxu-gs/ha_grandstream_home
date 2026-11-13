"""Constants for the Grandstream Home integration."""

from typing import Any

DOMAIN = "grandstream_home"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_PORT = "port"

# Webhook configuration items
CONF_STATUS_WEBHOOK_ID = "status_webhook_id"
CONF_COMMAND_WEBHOOK_ID = "command_webhook_id"

# Lock related constants
CONF_DOOR_ID = "door_id"
CONF_KEEP_UNLOCKED = "keep_unlocked"
CONF_UNLOCK_DURATION = "unlock_duration"

# RTSP configuration items
CONF_RTSP_ENABLE = "rtsp_enable"
CONF_RTSP_USERNAME = "rtsp_username"
CONF_RTSP_PASSWORD = "rtsp_password"

# Protocol configuration
CONF_USE_HTTPS = "use_https"
CONF_VERIFY_SSL = "verify_ssl"  # SSL certificate verification

DEFAULT_PORT = 443  # Default HTTPS port for GDS devices
DEFAULT_USERNAME = "gdsha"
DEFAULT_USERNAME_GNS = "admin"

# Device Types
CONF_DEVICE_TYPE = "device_type"
CONF_DEVICE_MODEL = "device_model"  # Original device model (GDS/GSC/GNS)
CONF_PRODUCT_MODEL = (
    "product_model"  # Specific product model (e.g., GDS3725, GDS3727, GSC3560)
)
CONF_FIRMWARE_VERSION = "firmware_version"  # Firmware version from discovery
DEVICE_TYPE_GDS = "GDS"
DEVICE_TYPE_GSC = "GSC"
DEVICE_TYPE_GNS_NAS = "GNS"

# Device Product Models
PRODUCT_GDS3725 = "GDS3725"
PRODUCT_GDS3726 = "GDS3726"
PRODUCT_GDS3726Q = "GDS3726Q"
PRODUCT_GDS3727 = "GDS3727"
PRODUCT_GDS3730 = "GDS3730"
PRODUCT_GDS3732 = "GDS3732"
PRODUCT_GSC3560 = "GSC3560"
PRODUCT_GSC3565 = "GSC3565"

# Bus events fired from device pushes
BIZ_EVENT_NAME = "grandstream_biz"

# Digital input biz events (bizType 4) carry diInputId + diTriggerMode + diMode
# + diEventState
DI_MODE_ALARM = 1  # Alarm input
DI_MODE_OPEN_SIGNAL = 2  # Open door signal
DI_MODE_DOOR_STATE = 4  # Door state sensor
DI_MODE_DOORBELL_CALL = 5  # Doorbell call signal, a momentary press event

# Wiring of the digital input; a normally closed port reports level 1 while
# idle, so its reported level has to be flipped to get the logical state
DI_TRIGGER_MODE_NORMALLY_OPEN = 0  # Normally open wiring
DI_TRIGGER_MODE_NORMALLY_CLOSED = 1  # Normally closed wiring

DI_MODE_NAMES = {
    DI_MODE_ALARM: "alarm",
    DI_MODE_OPEN_SIGNAL: "open_signal",
    DI_MODE_DOOR_STATE: "door_state",
    DI_MODE_DOORBELL_CALL: "doorbell_call",
}

# Level that reads as "active" for each mode; the door state sensor reports the
# opposite polarity, where 1 means the door is closed
DI_ACTIVE_LEVEL = {
    DI_MODE_ALARM: 1,
    DI_MODE_OPEN_SIGNAL: 1,
    DI_MODE_DOOR_STATE: 0,
    DI_MODE_DOORBELL_CALL: 1,
}

# Device Feature Capabilities
# Each device model has specific features:
# - door_count: Number of doors/locks supported
# - has_rtsp: Whether device supports RTSP streaming
# - has_di_3: Whether device has Digital Input 3 (do3)
# - has_password_unlock: Password unlock support
# - has_face_recognition: Face recognition support
# - has_touch_pass: Touch Pass support
# - has_security_mode: Security mode
# - has_power_alert: Power supply alert
# - has_qr_code_unlock: QR-code unlock support (GSC3565 supports, GSC3560 does not)
# - has_bluetooth: Bluetooth support
# - has_nfc: NFC support
# - has_rfid: RFID unlock support
# - has_duress_alarm: Duress password alarm
# - has_anti_tamper: Anti-tamper alarm
# - has_person_stay_alarm: Person stay alarm
# - has_doorbell_key: Doorbell key press, reported as biz event bizType 1
# - has_admin_key: Admin key press, reported as biz event bizType 2
# - has_quick_key: Four quick keys, reported as biz event bizType 3 with quickKeyId
# GSC356X report their call button as bizType 1 too, but expose it through a
# dedicated GSC trigger, so they carry none of the GDS key flags below.
DEVICE_FEATURES: dict[str, dict[str, Any]] = {
    PRODUCT_GDS3725: {
        "has_doorbell_key": True,
        "has_admin_key": True,
        "has_quick_key": False,
        "door_count": 2,
        "has_rtsp": True,
        "has_di_3": True,
        "has_password_unlock": True,
        "has_face_recognition": False,
        "has_touch_pass": True,
        "has_security_mode": True,
        "has_power_alert": False,
        "has_qr_code_unlock": True,
        "has_bluetooth": True,
        "has_nfc": True,
        "has_rfid": True,
        "has_duress_alarm": True,
        "has_anti_tamper": True,
        "has_person_stay_alarm": True,
    },
    PRODUCT_GDS3726: {
        "has_doorbell_key": True,
        "has_admin_key": False,
        "has_quick_key": False,
        "door_count": 2,
        "has_rtsp": True,
        "has_di_3": True,
        "has_password_unlock": False,
        "has_face_recognition": False,
        "has_touch_pass": True,
        "has_security_mode": True,
        "has_power_alert": False,
        "has_qr_code_unlock": True,
        "has_bluetooth": True,
        "has_nfc": True,
        "has_rfid": True,
        "has_duress_alarm": False,
        "has_anti_tamper": True,
        "has_person_stay_alarm": True,
    },
    PRODUCT_GDS3726Q: {
        "has_doorbell_key": False,
        "has_admin_key": False,
        "has_quick_key": True,
        "door_count": 2,
        "has_rtsp": True,
        "has_di_3": True,
        "has_password_unlock": False,
        "has_face_recognition": False,
        "has_touch_pass": True,
        "has_security_mode": True,
        "has_power_alert": False,
        "has_qr_code_unlock": True,
        "has_bluetooth": True,
        "has_nfc": True,
        "has_rfid": True,
        "has_duress_alarm": False,
        "has_anti_tamper": True,
        "has_person_stay_alarm": True,
    },
    PRODUCT_GDS3727: {
        "has_doorbell_key": True,
        "has_admin_key": False,
        "has_quick_key": False,
        "door_count": 1,
        "has_rtsp": True,
        "has_di_3": False,
        "has_password_unlock": False,
        "has_face_recognition": False,
        "has_touch_pass": True,
        "has_security_mode": True,
        "has_power_alert": False,
        "has_qr_code_unlock": True,
        "has_bluetooth": True,
        "has_nfc": True,
        "has_rfid": True,
        "has_duress_alarm": False,
        "has_anti_tamper": True,
        "has_person_stay_alarm": True,
    },
    PRODUCT_GDS3730: {
        "has_doorbell_key": True,
        "has_admin_key": True,
        "has_quick_key": False,
        "door_count": 2,
        "has_rtsp": True,
        "has_di_3": True,
        "has_password_unlock": True,
        "has_face_recognition": True,
        "has_touch_pass": True,
        "has_security_mode": True,
        "has_power_alert": False,
        "has_qr_code_unlock": True,
        "has_bluetooth": True,
        "has_nfc": True,
        "has_rfid": True,
        "has_duress_alarm": True,
        "has_anti_tamper": True,
        "has_person_stay_alarm": True,
        "has_admin_auth_failure_alarm": True,
    },
    PRODUCT_GDS3732: {
        "has_doorbell_key": True,
        "has_admin_key": True,
        "has_quick_key": False,
        "door_count": 2,
        "has_rtsp": True,
        "has_di_3": True,
        "has_password_unlock": True,
        "has_face_recognition": True,
        "has_touch_pass": True,
        "has_security_mode": True,
        "has_power_alert": False,
        "has_qr_code_unlock": True,
        "has_bluetooth": True,
        "has_nfc": True,
        "has_rfid": True,
        "has_duress_alarm": True,
        "has_anti_tamper": True,
        "has_person_stay_alarm": True,
        "has_admin_auth_failure_alarm": True,
    },
    PRODUCT_GSC3560: {
        "has_doorbell_key": False,
        "has_admin_key": False,
        "has_quick_key": False,
        "door_count": 2,
        "has_rtsp": False,
        "has_di_3": False,
        "has_password_unlock": False,
        "has_face_recognition": False,
        "has_touch_pass": False,
        "has_security_mode": False,
        "has_power_alert": True,
        "has_qr_code_unlock": False,
        "has_bluetooth": True,
        "has_nfc": False,
        "has_rfid": False,
        "has_duress_alarm": False,
        "has_anti_tamper": True,
        "has_person_stay_alarm": False,
    },
    PRODUCT_GSC3565: {
        "has_doorbell_key": False,
        "has_admin_key": False,
        "has_quick_key": False,
        "door_count": 2,
        "has_rtsp": False,
        "has_di_3": False,
        "has_password_unlock": False,
        "has_face_recognition": False,
        "has_touch_pass": False,
        "has_security_mode": False,
        "has_power_alert": True,
        "has_qr_code_unlock": True,
        "has_bluetooth": False,
        "has_nfc": False,
        "has_rfid": False,
        "has_duress_alarm": False,
        "has_anti_tamper": True,
        "has_person_stay_alarm": True,
    },
}

# Default features for unknown models
DEFAULT_DEVICE_FEATURES = {
    "has_doorbell_key": True,
    "has_admin_key": True,
    "has_quick_key": False,
    "door_count": 2,
    "has_rtsp": True,
    "has_di_3": True,
    "has_password_unlock": True,
    "has_face_recognition": True,
    "has_touch_pass": True,
    "has_security_mode": True,
    "has_power_alert": True,
    "has_qr_code_unlock": True,
    "has_bluetooth": True,
    "has_nfc": True,
    "has_rfid": True,
    "has_duress_alarm": True,
    "has_anti_tamper": True,
    "has_person_stay_alarm": True,
    "has_admin_auth_failure_alarm": True,
}

# Device type to available actions mapping
DEVICE_ACTIONS_MAP = {
    "GDS": ["reboot_device"],
    "GNS": ["reboot_device", "sleep_device", "wake_device", "shutdown_device"],
}

# SIP registration status mapping
SIP_STATUS_MAP = {
    0: "unregistered",
    1: "registered",
}

# Default Port Settings
DEFAULT_HTTP_PORT = 5000
DEFAULT_HTTPS_PORT = 5001

# Version information
INTEGRATION_VERSION = "1.0.0"

# Coordinator settings
COORDINATOR_UPDATE_INTERVAL = 10  # seconds - How often to poll device status
COORDINATOR_ERROR_THRESHOLD = 3  # Max consecutive errors before marking unavailable
