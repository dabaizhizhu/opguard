"""Errors raised by the guard. None of these carry exploit instructions."""


class OpGuardError(Exception):
    """Base error for the protection layer."""


class GuardAttachmentError(OpGuardError):
    """A main or child agent was created without the guard chain."""


class BareCallRejected(OpGuardError):
    """The execution layer refused a tool call that did not carry a gateway permit."""


class GatewayRejected(OpGuardError):
    """The gateway rejected a verdict or permit."""


class TicketRejected(OpGuardError):
    """A ticket could not be issued or failed structural checks."""


class JevTimeout(OpGuardError):
    """The L2 auditor did not answer before the deadline."""

    def __init__(self, message: str, *, latency_ms: float) -> None:
        super().__init__(message)
        self.latency_ms = latency_ms


class JevParseError(OpGuardError):
    """The L2 auditor answered with a body that is not a usable decision."""

    def __init__(self, message: str, *, http_status: int | None, latency_ms: float) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.latency_ms = latency_ms


class JevTransportError(OpGuardError):
    """The L2 auditor could not be reached."""

    def __init__(self, message: str, *, latency_ms: float) -> None:
        super().__init__(message)
        self.latency_ms = latency_ms
