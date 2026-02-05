"""Typed application errors with user-facing messages."""

from __future__ import annotations


class AppError(Exception):
    """Base application error."""

    def __init__(self, message: str, user_message: str | None = None) -> None:
        super().__init__(message)
        self.user_message = user_message or message


class InvalidLinkError(AppError):
    pass


class UnsupportedSchemeError(AppError):
    pass


class ConfigBuildError(AppError):
    pass


class BinaryMissingError(AppError):
    pass


class PortInUseError(AppError):
    pass


class ProxyApplyError(AppError):
    pass


class PermissionDeniedError(AppError):
    pass
