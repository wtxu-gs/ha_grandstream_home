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

# Door unlock API constants
ACCESS_TOKEN_TTL = 3300  # 55 minutes in seconds

# Door unlock API error codes
UNLOCK_CODE_SUCCESS = "0"
UNLOCK_CODE_AUTH_FAILED = "-100"  # Invalid password or signature verification failed
UNLOCK_CODE_MATERIAL_EMPTY = "-200"  # Material for generating token is empty
UNLOCK_CODE_TIMESTAMP_EXPIRED = "-300"  # Timestamp expired
UNLOCK_CODE_PERMISSION_DENIED = "-400"  # User has no permission
UNLOCK_CODE_CHALLENGE_INVALID = "-500"  # Challenge code is invalid

# Door action types
DOOR_ACTION_UNLOCK = "1"  # Unlock/open door
DOOR_ACTION_LOCK = "2"  # Lock/close door

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
PRODUCT_GDS3727 = "GDS3727"
PRODUCT_GSC3560 = "GSC3560"

# Device Feature Capabilities
# Each device model has specific features:
# - door_count: Number of doors/locks supported
# - has_rtsp: Whether device supports RTSP streaming
# - has_di_3: Whether device has Digital Input 3 (do3)
DEVICE_FEATURES: dict[str, dict[str, Any]] = {
    # GDS3725: 2 doors, has RTSP, has di_3 (do3)
    PRODUCT_GDS3725: {
        "door_count": 2,
        "has_rtsp": True,
        "has_di_3": True,
    },
    # GDS3727: 1 door only, has RTSP, no di_3
    PRODUCT_GDS3727: {
        "door_count": 1,
        "has_rtsp": True,
        "has_di_3": False,
    },
    # GSC3560: 2 doors, no RTSP, no di_3
    PRODUCT_GSC3560: {
        "door_count": 2,
        "has_rtsp": False,
        "has_di_3": False,
    },
}

# Default features for unknown models
DEFAULT_DEVICE_FEATURES = {
    "door_count": 2,  # Default to 2 doors for unknown GDS models
    "has_rtsp": True,  # Default to having RTSP
    "has_di_3": False,  # Default to no di_3
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

# API Content Types
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"
ACCEPT_JSON = "application/json, text/plain, */*"

# API Header Names
HEADER_AUTHORIZATION = "Authorization"
HEADER_CONTENT_TYPE = "Content-Type"

# HTTP Methods
HTTP_METHOD_GET = "GET"
HTTP_METHOD_POST = "POST"

# API Timeout Settings (seconds)
GDS_TIMEOUT_CONNECT = 5
GDS_TIMEOUT_READ = 30  # Increased for unlock operations
GDS_TIMEOUT_SOCKET_CHECK = 2

GNS_DEFAULT_TIMEOUT = 20

# Default Port Settings
DEFAULT_HTTP_PORT = 5000
DEFAULT_HTTPS_PORT = 5001

# Version information
INTEGRATION_VERSION = "1.0.0"

# Coordinator settings
COORDINATOR_UPDATE_INTERVAL = 10  # seconds - How often to poll device status
COORDINATOR_ERROR_THRESHOLD = 3  # Max consecutive errors before marking unavailable
