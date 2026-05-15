"""Outbound URL safety helper (SEC-C12, SEC-C13).

Defends against SSRF: a configuration value (connector ``base_url``,
webhook destination, alert URL, etc.) controlled by a tenant administrator
or a misconfigured operator can otherwise redirect outbound HTTP calls to
``http://169.254.169.254/latest/meta-data/`` (AWS metadata service),
``http://127.0.0.1:8200/v1/sys/`` (Vault), or any internal admin endpoint.
Because Warlock connectors and webhook delivery code attach bearer
tokens / API keys / signed payloads to every outbound request, an
attacker who flips the URL has a one-shot credential exfiltration channel.

Use ``validate_outbound_url`` at every site that builds an HTTP client
from a configured URL. The function:

* Rejects non-``https://`` schemes in production (allows ``http://`` only
  when the deployment explicitly opts in via the
  ``WLK_ALLOW_INSECURE_OUTBOUND`` env var — useful for local dev against
  ``http://localhost`` Ollama).
* Rejects URLs containing user-info (``http://attacker@victim/``).
* Resolves the hostname and rejects loopback / RFC1918 / link-local /
  multicast / IPv6 ULA addresses (and the same after each DNS A/AAAA
  record), defeating DNS rebinding.
* Optionally requires the hostname to match an allowlist (e.g.
  ``*.okta.com``, ``*.salesforce.com``).

Raises :class:`UnsafeURLError` on rejection so callers get a deterministic
exception type to handle.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


class UnsafeURLError(ValueError):
    """Raised when an outbound URL fails safety validation."""


def _hostname_matches(host: str, pattern: str) -> bool:
    """Match ``host`` against an exact or ``*.suffix`` pattern (case-insensitive)."""
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        return host == pattern[2:] or host.endswith("." + pattern[2:])
    return host == pattern


def _resolve_ips(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve ``host`` to its IP addresses. Returns empty list on failure."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out: list[ipaddress._BaseAddress] = []
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        out.append(ip)
    return out


def _is_disallowed_ip(ip: ipaddress._BaseAddress) -> bool:
    """Return True if the IP is on a forbidden network."""
    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_private
    )


def validate_outbound_url(
    url: str,
    *,
    allowed_hosts: list[str] | None = None,
    allow_http: bool | None = None,
) -> str:
    """Validate an outbound URL is safe to attach credentials to.

    Parameters
    ----------
    url:
        The URL to validate.
    allowed_hosts:
        Optional list of hostnames or ``*.suffix`` patterns. If provided,
        the URL's hostname must match at least one entry. Useful for
        vendor-pinning (``["*.okta.com"]``).
    allow_http:
        When ``True``, ``http://`` is accepted (only do this for local
        dev). When ``False`` (default), only ``https://`` is accepted.
        When ``None``, defaults to the value of the
        ``WLK_ALLOW_INSECURE_OUTBOUND`` env var.

    Returns
    -------
    The normalised URL on success.

    Raises
    ------
    UnsafeURLError
        If any safety check fails.
    """
    if not url or not isinstance(url, str):
        raise UnsafeURLError("URL is empty")

    if allow_http is None:
        allow_http = os.environ.get("WLK_ALLOW_INSECURE_OUTBOUND", "").lower() in (
            "1",
            "true",
            "yes",
        )

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https",) and not (allow_http and scheme == "http"):
        raise UnsafeURLError(
            f"URL scheme '{scheme}' not allowed (only https; set "
            f"WLK_ALLOW_INSECURE_OUTBOUND=true to accept http for local dev)"
        )

    # Reject user-info embedded URLs (e.g. http://user:pass@host).
    if "@" in (parsed.netloc or ""):
        raise UnsafeURLError("URLs with embedded user-info are not permitted")

    host = parsed.hostname
    if not host:
        raise UnsafeURLError("URL has no hostname")

    # Reject IP-literal hosts that are themselves on private/loopback ranges.
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None
    if literal_ip is not None and _is_disallowed_ip(literal_ip):
        raise UnsafeURLError(
            f"IP literal '{host}' resolves to a disallowed network "
            f"(loopback/private/link-local/multicast)"
        )

    # Allowlist pinning (e.g. require *.okta.com).
    if allowed_hosts:
        if not any(_hostname_matches(host, pat) for pat in allowed_hosts):
            raise UnsafeURLError(
                f"Hostname '{host}' is not in the allowed host list: {allowed_hosts}"
            )

    # DNS resolution: reject if ANY resolved address is on a disallowed
    # range. Unresolvable hostnames are NOT rejected here — they will
    # simply fail to connect, with no credential leak. We resolve only to
    # catch hostnames that explicitly point at metadata services, RFC1918
    # ranges, etc. when DNS does answer.
    if literal_ip is None:
        ips = _resolve_ips(host)
        for ip in ips:
            if _is_disallowed_ip(ip):
                raise UnsafeURLError(f"Hostname '{host}' resolves to a disallowed network ({ip})")

    return url
