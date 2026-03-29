"""Regulatory change feed integration.

Stub connectors for regulatory RSS/API feeds (Federal Register, NIST
updates, CISA advisories). Parses and classifies regulatory changes by
affected frameworks.

Feed sources are configurable but default to well-known public endpoints.
Actual HTTP fetching requires ``httpx`` (optional dependency).
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree

log = logging.getLogger(__name__)

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False
    log.info("httpx not installed -- regulatory feed refresh requires httpx")


# ---------------------------------------------------------------------------
# Feed source definitions
# ---------------------------------------------------------------------------


@dataclass
class FeedSource:
    """Definition of a regulatory feed source."""

    name: str
    url: str
    feed_type: str = "rss"  # "rss", "atom", "json"
    enabled: bool = True
    description: str = ""
    frameworks: list[str] = field(default_factory=list)


# Default feed sources — well-known regulatory update endpoints
DEFAULT_FEEDS: list[FeedSource] = [
    FeedSource(
        name="federal_register_cyber",
        url="https://www.federalregister.gov/api/v1/articles.rss"
        "?conditions[topics][]=cybersecurity",
        feed_type="rss",
        description="Federal Register -- Cybersecurity regulations",
        frameworks=["nist_800_53", "fedramp", "cmmc_l2"],
    ),
    FeedSource(
        name="nist_publications",
        url="https://csrc.nist.gov/CSRC/media/feeds/publications/rss",
        feed_type="rss",
        description="NIST CSRC publications feed",
        frameworks=["nist_800_53", "nist_csf_2", "cmmc_l2"],
    ),
    FeedSource(
        name="cisa_advisories",
        url="https://www.cisa.gov/news.xml",
        feed_type="rss",
        description="CISA cybersecurity advisories",
        frameworks=["nist_800_53", "fedramp", "cmmc_l2"],
    ),
    FeedSource(
        name="eu_official_journal",
        url="https://eur-lex.europa.eu/rss/search-results.xml?qid=cybersecurity&type=act",
        feed_type="rss",
        description="EU Official Journal -- cybersecurity and data protection",
        frameworks=["gdpr", "eu_ai_act", "iso_27001"],
    ),
    FeedSource(
        name="pci_ssc_news",
        url="https://blog.pcisecuritystandards.org/rss.xml",
        feed_type="rss",
        description="PCI SSC blog and announcements",
        frameworks=["pci_dss_v4"],
    ),
    FeedSource(
        name="hipaa_hhs",
        url="https://www.hhs.gov/rss/hipaa.xml",
        feed_type="rss",
        description="HHS HIPAA regulatory updates",
        frameworks=["hipaa"],
    ),
]


# ---------------------------------------------------------------------------
# Framework classification heuristics
# ---------------------------------------------------------------------------

_FRAMEWORK_KEYWORDS: dict[str, list[str]] = {
    "nist_800_53": ["nist", "800-53", "sp 800", "special publication"],
    "nist_csf_2": ["csf", "cybersecurity framework", "nist csf"],
    "fedramp": ["fedramp", "federal risk", "authorization"],
    "cmmc_l2": ["cmmc", "cybersecurity maturity", "dfars", "cui"],
    "soc2": ["soc 2", "soc2", "trust services", "aicpa"],
    "iso_27001": ["iso 27001", "iso/iec 27001", "isms"],
    "hipaa": ["hipaa", "hitech", "phi", "protected health"],
    "gdpr": ["gdpr", "data protection", "eu regulation 2016/679"],
    "pci_dss_v4": ["pci dss", "pci-dss", "payment card"],
    "eu_ai_act": ["ai act", "artificial intelligence act", "eu ai"],
    "sec_cyber": ["sec cyber", "securities", "sec disclosure"],
}


@dataclass
class RegulatoryItem:
    """A parsed regulatory change item from a feed."""

    id: str
    title: str
    description: str = ""
    url: str = ""
    published: str = ""
    source: str = ""
    affected_frameworks: list[str] = field(default_factory=list)
    severity: str = "medium"  # critical, high, medium, low
    raw: dict[str, Any] = field(default_factory=dict)


def classify_frameworks(title: str, description: str) -> list[str]:
    """Classify which frameworks a regulatory item affects.

    Uses keyword matching against title and description text.
    """
    text = f"{title} {description}".lower()
    matched: list[str] = []
    for framework, keywords in _FRAMEWORK_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in text:
                matched.append(framework)
                break
    return matched


def _estimate_severity(title: str, description: str) -> str:
    """Heuristically estimate the severity of a regulatory change."""
    text = f"{title} {description}".lower()
    if any(w in text for w in ["final rule", "enforcement", "penalty", "breach", "mandatory"]):
        return "high"
    if any(w in text for w in ["proposed rule", "draft", "comment period", "guidance"]):
        return "medium"
    if any(w in text for w in ["update", "revision", "amendment", "new requirement"]):
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Feed parsing
# ---------------------------------------------------------------------------


def parse_rss(xml_content: str, source_name: str) -> list[RegulatoryItem]:
    """Parse an RSS/Atom feed into RegulatoryItem objects."""
    items: list[RegulatoryItem] = []
    try:
        root = ElementTree.fromstring(xml_content)
    except ElementTree.ParseError as exc:
        log.warning("Failed to parse RSS from %s: %s", source_name, exc)
        return items

    # Handle RSS 2.0
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        desc = (item.findtext("description") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        guid = (item.findtext("guid") or "").strip()

        item_id = guid or hashlib.sha256(f"{title}{link}".encode()).hexdigest()[:16]
        frameworks = classify_frameworks(title, desc)

        items.append(
            RegulatoryItem(
                id=item_id,
                title=title,
                description=desc[:500],
                url=link,
                published=pub_date,
                source=source_name,
                affected_frameworks=frameworks,
                severity=_estimate_severity(title, desc),
            )
        )

    # Handle Atom feeds
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.iter("{http://www.w3.org/2005/Atom}entry"):
        title_el = entry.find("atom:title", ns) or entry.find("{http://www.w3.org/2005/Atom}title")
        title = (title_el.text or "").strip() if title_el is not None else ""
        summary_el = entry.find("atom:summary", ns) or entry.find(
            "{http://www.w3.org/2005/Atom}summary"
        )
        desc = (summary_el.text or "").strip() if summary_el is not None else ""
        link_el = entry.find("atom:link", ns) or entry.find("{http://www.w3.org/2005/Atom}link")
        link = link_el.get("href", "") if link_el is not None else ""
        pub_el = entry.find("atom:updated", ns) or entry.find(
            "{http://www.w3.org/2005/Atom}updated"
        )
        pub_date = (pub_el.text or "").strip() if pub_el is not None else ""
        id_el = entry.find("atom:id", ns) or entry.find("{http://www.w3.org/2005/Atom}id")
        item_id = (
            (id_el.text or "").strip()
            if id_el is not None
            else hashlib.sha256(f"{title}{link}".encode()).hexdigest()[:16]
        )

        frameworks = classify_frameworks(title, desc)
        items.append(
            RegulatoryItem(
                id=item_id,
                title=title,
                description=desc[:500],
                url=link,
                published=pub_date,
                source=source_name,
                affected_frameworks=frameworks,
                severity=_estimate_severity(title, desc),
            )
        )

    return items


def refresh_feed(source: FeedSource) -> list[RegulatoryItem]:
    """Fetch and parse a single feed source.

    Requires httpx. Returns empty list if httpx is not installed
    or if the fetch fails.
    """
    if not _HAS_HTTPX:
        log.warning(
            "httpx not installed -- cannot refresh feed %s. Install with: pip install httpx",
            source.name,
        )
        return []

    try:
        resp = httpx.get(source.url, timeout=30.0, follow_redirects=True)
        resp.raise_for_status()
    except Exception as exc:
        log.warning("Failed to fetch feed %s: %s", source.name, exc)
        return []

    if source.feed_type in ("rss", "atom"):
        items = parse_rss(resp.text, source.name)
    else:
        log.warning("Unsupported feed type %s for %s", source.feed_type, source.name)
        return []

    # Supplement framework classification from source defaults
    for item in items:
        if not item.affected_frameworks and source.frameworks:
            item.affected_frameworks = list(source.frameworks)

    log.info("Refreshed feed %s: %d items", source.name, len(items))
    return items


def refresh_all_feeds(
    feeds: list[FeedSource] | None = None,
) -> list[RegulatoryItem]:
    """Refresh all configured feed sources.

    Returns combined list of regulatory items from all feeds.
    """
    sources = feeds or DEFAULT_FEEDS
    all_items: list[RegulatoryItem] = []

    for source in sources:
        if not source.enabled:
            continue
        items = refresh_feed(source)
        all_items.extend(items)

    # Deduplicate by ID
    seen: set[str] = set()
    unique: list[RegulatoryItem] = []
    for item in all_items:
        if item.id not in seen:
            seen.add(item.id)
            unique.append(item)

    return unique


def list_feeds(feeds: list[FeedSource] | None = None) -> list[dict[str, Any]]:
    """List configured feed sources with their status."""
    sources = feeds or DEFAULT_FEEDS
    return [
        {
            "name": s.name,
            "url": s.url,
            "type": s.feed_type,
            "enabled": s.enabled,
            "description": s.description,
            "frameworks": s.frameworks,
        }
        for s in sources
    ]
