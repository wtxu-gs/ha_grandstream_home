"""Constants for the Grandstream Home integration."""

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

DEFAULT_PORT = 80
DEFAULT_USERNAME = "gdsha"
DEFAULT_USERNAME_GNS = "admin"

# Device Types
CONF_DEVICE_TYPE = "device_type"
CONF_DEVICE_MODEL = "device_model"  # Original device model (GDS/GSC/GNS)
DEVICE_TYPE_GDS = "GDS"
DEVICE_TYPE_GSC = "GSC"
DEVICE_TYPE_GNS_NAS = "GNS"

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
