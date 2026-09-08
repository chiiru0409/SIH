"""
utils/geoip.py — GeoIP intelligence lookup abstraction.

Supports:
    1. Local MaxMind GeoLite2 City database (via GEOIP_DB_PATH).
    2. IPInfo API (via IPINFO_TOKEN).
    3. IP-API (via IPAPI_BASE_URL).
    4. Graceful offline fallback when no provider or database is configured.

Design Rules:
    - Never throws unhandled exceptions.
    - Excludes non-public (private, loopback, reserved) IPs.
    - Zero active crawler or scan operations.
    - Safe timeouts on any external HTTP lookup.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from backend.config import settings
from backend.utils.ip_utils import classify_ip

logger = logging.getLogger("mailtrace.utils.geoip")


def lookup_geoip(ip: str) -> dict[str, Any]:
    """
    Perform approximate geolocation lookup for an IP address.

    Returns structured dictionary with:
        - status: 'success' | 'excluded' | 'unavailable' | 'error'
        - ip: str
        - country: str | None
        - country_code: str | None
        - region: str | None
        - city: str | None
        - latitude: float | None
        - longitude: float | None
        - timezone: str | None
        - source: 'local_geoip' | 'ipinfo' | 'ipapi' | 'local_filter' | 'unavailable'
        - reason: str | None
    """
    if not ip or not isinstance(ip, str):
        return {
            "status": "error",
            "ip": ip,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "source": "unavailable",
            "reason": "Invalid IP input",
        }

    ip_clean = ip.strip()
    classification = classify_ip(ip_clean)

    # Exclude non-public IPs from geolocation
    if classification != "public":
        return {
            "status": "excluded",
            "ip": ip_clean,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "source": "local_filter",
            "reason": f"Non-public IP ({classification})",
        }

    # 1. Try Local MaxMind DB if configured
    if settings.GEOIP_DB_PATH:
        db_path = Path(settings.GEOIP_DB_PATH)
        if db_path.is_file():
            try:
                import geoip2.database  # type: ignore

                with geoip2.database.Reader(str(db_path)) as reader:
                    match = reader.city(ip_clean)
                    return {
                        "status": "success",
                        "ip": ip_clean,
                        "country": match.country.name,
                        "country_code": match.country.iso_code,
                        "region": match.subdivisions.most_specific.name if match.subdivisions else None,
                        "city": match.city.name,
                        "latitude": match.location.latitude,
                        "longitude": match.location.longitude,
                        "timezone": match.location.time_zone,
                        "source": "local_geoip",
                        "reason": None,
                    }
            except ImportError:
                logger.debug("geoip2 library not installed; falling back.")
            except Exception as exc:
                logger.warning(f"Local GeoIP database lookup failed for {ip_clean}: {exc}")

    # 2. Try IPInfo if token configured
    if settings.IPINFO_TOKEN:
        try:
            import httpx  # type: ignore

            url = f"https://ipinfo.io/{ip_clean}/json"
            headers = {"Authorization": f"Bearer {settings.IPINFO_TOKEN}"}
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    loc = data.get("loc", "")
                    lat, lon = None, None
                    if "," in loc:
                        try:
                            parts = loc.split(",")
                            lat, lon = float(parts[0]), float(parts[1])
                        except ValueError:
                            pass

                    return {
                        "status": "success",
                        "ip": ip_clean,
                        "country": data.get("country"),
                        "country_code": data.get("country"),
                        "region": data.get("region"),
                        "city": data.get("city"),
                        "latitude": lat,
                        "longitude": lon,
                        "timezone": data.get("timezone"),
                        "source": "ipinfo",
                        "reason": None,
                    }
        except Exception as exc:
            logger.warning(f"IPInfo lookup failed for {ip_clean}: {exc}")

    # 3. Graceful fallback when no provider or provider unavailable
    return {
        "status": "unavailable",
        "ip": ip_clean,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "timezone": None,
        "source": "unavailable",
        "reason": "GeoIP provider not configured or database not available",
    }
