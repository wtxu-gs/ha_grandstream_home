"""Custom exceptions for Grandstream Home integration."""


class GrandstreamError(Exception):
    """Base exception for Grandstream Home integration."""


class GrandstreamLoginError(GrandstreamError):
    """Exception raised when login fails."""


class GrandstreamCallError(GrandstreamError):
    """Exception raised when making a call fails."""


class GrandstreamRebootError(GrandstreamError):
    """Exception raised when rebooting device fails."""


class GrandstreamConfigError(GrandstreamError):
    """Exception raised when configuration fails."""


class GrandstreamStatusError(GrandstreamError):
    """Exception raised when getting device status fails."""


class GrandstreamRTSPError(GrandstreamError):
    """Exception raised when RTSP operations fail."""


class GrandstreamNotificationError(GrandstreamError):
    """Exception raised when setting event notification fails."""
