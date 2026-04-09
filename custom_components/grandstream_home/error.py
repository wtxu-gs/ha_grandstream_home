"""Custom exceptions for Grandstream Home integration - re-exported from library."""

from grandstream_home_api.error import (
    GrandstreamAuthTokenError,
    GrandstreamChallengeError,
    GrandstreamError,
    GrandstreamHAControlDisabledError,
    GrandstreamRTSPError,
    GrandstreamSignatureError,
    GrandstreamUnlockError,
)

__all__ = [
    "GrandstreamAuthTokenError",
    "GrandstreamChallengeError",
    "GrandstreamError",
    "GrandstreamHAControlDisabledError",
    "GrandstreamRTSPError",
    "GrandstreamSignatureError",
    "GrandstreamUnlockError",
]
