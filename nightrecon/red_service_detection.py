"""Red Night ownership facade for existing service detection."""

from nightrecon.service_detection import (
    COMMON_TCP_SERVICES,
    HttpResponseMetadata,
    ServiceDetectionResult,
    detect_service,
    detect_services,
    identify_service,
    identify_service_from_banner,
    parse_http_response,
    probe_http_service,
)

__all__ = [
    "COMMON_TCP_SERVICES", "HttpResponseMetadata", "ServiceDetectionResult",
    "detect_service", "detect_services", "identify_service",
    "identify_service_from_banner", "parse_http_response", "probe_http_service",
]
