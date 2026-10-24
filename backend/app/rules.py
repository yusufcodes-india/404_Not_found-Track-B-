"""
rules.py — Pure-function rules engine for look-alike website detection.

Given a URL and optional page signals (from a browser content script),
this module computes a phishing / typosquat risk assessment.

All functions are pure: no side effects, no database access, no network I/O.
The only inputs are the URL string, a brand registry (list of dicts loaded
from brands.json), and optional page-signal dicts collected by the extension.

Output
------
A ``CheckResult`` dict::

    {
        "score":        int,           # 0–100 composite risk score
        "level":        str,           # "safe" | "careful" | "danger"
        "triggered":    list[dict],    # [{"code": …, "weight": …, "detail": …}, …]
        "official_site": dict | None,  # {"brand": "SBI", "domain": "onlinesbi.sbi"} or None
        "matched_brand": str | None,
    }
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any
from urllib.parse import urlparse

import tldextract
from rapidfuzz.distance import Levenshtein

# ---------------------------------------------------------------------------
# Homoglyph / confusable mappings
# ---------------------------------------------------------------------------

# ASCII multi-char sequences that visually resemble a single char
_ASCII_CONFUSABLES: list[tuple[str, str]] = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
]

# Single-char look-alikes (digit ↔ letter)
_CHAR_CONFUSABLES: dict[str, str] = {
    "0": "o",
    "1": "l",
}

# Cyrillic → Latin look-alikes (lowercase)
_CYRILLIC_TO_LATIN: dict[str, str] = {
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "p",  # р → p
    "\u0441": "c",  # с → c
    "\u0443": "y",  # у → y
    "\u0445": "x",  # х → x
}

# Build the reverse mapping too (Latin → Cyrillic) for completeness,
# though the primary direction for attack detection is Cyrillic→Latin.
_LATIN_TO_CYRILLIC: dict[str, str] = {v: k for k, v in _CYRILLIC_TO_LATIN.items()}

# Risky / free TLDs frequently abused for phishing
_RISKY_TLDS: set[str] = {
    "xyz", "top", "click", "tk", "ml", "gq", "cf", "ga", "buzz", "rest", "icu",
}

# Keywords that imply government association
_GOV_KEYWORDS: set[str] = {"gov", "nic", "govt"}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _parse_url(url: str) -> dict[str, Any]:
    """
    Parse *url* into a dict with both ``urllib`` and ``tldextract`` results.

    Returns
    -------
    dict with keys:
        scheme, netloc, path, query, fragment  — from ``urlparse``
        subdomain, domain, suffix              — from ``tldextract``
        fqdn                                   — fully-qualified domain name
        registered_domain                      — domain + suffix
        labels                                 — list of all hostname labels
    """
    # Ensure a scheme so urlparse works predictably
    if "://" not in url and not url.startswith("//"):
        url = "https://" + url

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    hostname = parsed.hostname or ""
    labels = [lbl for lbl in hostname.split(".") if lbl]

    return {
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "full_url": url,
        "hostname": hostname,
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "fqdn": ext.fqdn,
        "registered_domain": getattr(ext, "top_domain_under_public_suffix", None) or (f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain),
        "labels": labels,
    }


def _triggered(code: str, weight: int, detail: str) -> dict:
    """Convenience builder for a single triggered-rule dict."""
    return {"code": code, "weight": weight, "detail": detail}


def _domain_without_tld(registered_domain: str) -> str:
    """
    Return the domain label (everything before the TLD).

    Example: ``"hdfcbank.com"`` → ``"hdfcbank"``
    """
    ext = tldextract.extract(registered_domain)
    return ext.domain


def _normalize_homoglyphs(text: str) -> str:
    """
    Apply all homoglyph / confusable normalizations to *text*.

    1. Replace Cyrillic look-alikes with their Latin equivalents.
    2. Replace digit look-alikes (0→o, 1→l).
    3. Replace multi-char ASCII sequences (rn→m, vv→w, etc.).
    """
    # Step 1 — Cyrillic → Latin
    for cyrillic_char, latin_char in _CYRILLIC_TO_LATIN.items():
        text = text.replace(cyrillic_char, latin_char)

    # Step 2 — digit → letter
    for digit, letter in _CHAR_CONFUSABLES.items():
        text = text.replace(digit, letter)

    # Step 3 — multi-char ASCII
    for seq, replacement in _ASCII_CONFUSABLES:
        text = text.replace(seq, replacement)

    return text


def _is_ip_address(hostname: str) -> bool:
    """Return True if *hostname* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Brand Registry Helpers
# ---------------------------------------------------------------------------

def _get_brand_name(brand_entry: dict) -> str:
    """Extract brand name from either 'brand' or 'name' key."""
    return brand_entry.get("brand") or brand_entry.get("name", "")


def _get_brand_keywords(brand_entry: dict) -> list[str]:
    """
    Return all lowercase keywords/aliases associated with a brand entry.
    Combines explicit keywords, brand name tokens, and official domain labels.
    """
    keywords: set[str] = set()

    # Explicit keywords if present
    for kw in brand_entry.get("keywords", []):
        if kw and len(kw.strip()) >= 3:
            keywords.add(kw.strip().lower())

    # Tokens from brand name
    brand_name = _get_brand_name(brand_entry)
    if brand_name:
        for token in re.findall(r"[A-Za-z0-9]+", brand_name):
            token_lower = token.lower()
            if len(token_lower) >= 3 and token_lower not in {
                "bank", "india", "portal", "the", "and", "services", "online", "ltd", "limited"
            }:
                keywords.add(token_lower)

    # Domain labels from official domains
    for official in brand_entry.get("official_domains", []):
        lbl = _domain_without_tld(official).lower()
        if len(lbl) >= 3:
            keywords.add(lbl)
            # Add known core acronyms if substring of label
            for sub in ("sbi", "hdfc", "icici", "kotak", "axis", "pnb", "bob", "uidai", "gst", "epfo", "irctc", "paytm", "lic"):
                if sub in lbl:
                    keywords.add(sub)

    return list(keywords)


# ---------------------------------------------------------------------------
# Individual rule checkers
# ---------------------------------------------------------------------------


def check_official_match(
    domain_info: dict[str, Any],
    brand_registry: list[dict],
) -> tuple[bool, dict | None]:
    """
    Check if the URL's domain is an *official* domain for any registered brand.

    An official match occurs when the URL's registered domain exactly matches
    one of the brand's ``official_domains``, **or** is a subdomain of one.

    Parameters
    ----------
    domain_info : dict
        Parsed URL info from :func:`_parse_url`.
    brand_registry : list[dict]
        List of brand dicts, each containing at least ``brand`` (str) and
        ``official_domains`` (list[str]).

    Returns
    -------
    (is_official, brand_info)
        ``is_official`` is True when the domain is legitimate.
        ``brand_info`` is a dict ``{"brand": …, "domain": …}`` or None.
    """
    hostname = domain_info.get("hostname", "").lower()
    registered_domain = domain_info.get("registered_domain", "").lower()

    for brand_entry in brand_registry:
        brand_name = _get_brand_name(brand_entry)
        for official in brand_entry.get("official_domains", []):
            official_lower = official.lower()
            # Exact match on registered domain
            if registered_domain == official_lower:
                return True, {"brand": brand_name, "domain": official}
            # Subdomain match: hostname ends with .official_domain
            if hostname == official_lower or hostname.endswith("." + official_lower):
                return True, {"brand": brand_name, "domain": official}
    return False, None


def check_typosquat(
    domain_info: dict[str, Any],
    brand_registry: list[dict],
) -> tuple[list[dict], str | None, dict | None]:
    """
    Detect typosquatting by comparing the input domain against every brand's
    official domains using Levenshtein edit distance.

    A match with distance ≤ 2 triggers ``TYPOSQUAT_BRAND`` (weight 25).

    Returns
    -------
    (triggered_list, matched_brand_name, brand_site_info)
    """
    triggered: list[dict] = []
    input_domain_label = domain_info.get("domain", "").lower()
    best_distance = float("inf")
    best_brand: str | None = None
    best_brand_info: dict | None = None

    for brand_entry in brand_registry:
        brand_name = _get_brand_name(brand_entry)
        for official in brand_entry.get("official_domains", []):
            official_label = _domain_without_tld(official).lower()
            dist = Levenshtein.distance(input_domain_label, official_label)
            if dist <= 2 and dist > 0 and dist < best_distance:
                best_distance = dist
                best_brand = brand_name
                best_brand_info = {"brand": brand_name, "domain": official}

    if best_brand is not None:
        triggered.append(
            _triggered(
                "TYPOSQUAT_BRAND",
                25,
                f"Domain '{input_domain_label}' is {best_distance} edit(s) away "
                f"from {best_brand} official domain",
            )
        )
    return triggered, best_brand, best_brand_info


def check_homoglyphs(
    domain_info: dict[str, Any],
    brand_registry: list[dict],
) -> tuple[list[dict], str | None, dict | None]:
    """
    Detect homoglyph / confusable-character attacks.

    Normalizes the input domain (Cyrillic→Latin, digit→letter, rn→m, etc.)
    and checks whether the normalized form differs from the original.  If so,
    the normalized form is re-checked against the brand registry.

    Also flags punycode domains (``xn--`` prefix).

    Returns
    -------
    (triggered_list, matched_brand_name, brand_site_info)
    """
    triggered: list[dict] = []
    hostname = domain_info.get("hostname", "").lower()
    input_domain_label = domain_info.get("domain", "").lower()

    # Check for punycode (internationalized domain names in ASCII form)
    is_punycode = any(lbl.startswith("xn--") for lbl in domain_info.get("labels", []))

    # Normalize the domain label
    normalized = _normalize_homoglyphs(input_domain_label)

    if normalized != input_domain_label or is_punycode:
        detail_parts: list[str] = []
        if normalized != input_domain_label:
            detail_parts.append(
                f"Domain '{input_domain_label}' normalizes to '{normalized}'"
            )
        if is_punycode:
            detail_parts.append(f"Punycode domain detected: {hostname}")

        triggered.append(
            _triggered("HOMOGLYPH_DOMAIN", 30, "; ".join(detail_parts))
        )

        # Re-check the normalized domain against the registry
        for brand_entry in brand_registry:
            brand_name = brand_entry.get("brand", "")
            for official in brand_entry.get("official_domains", []):
                official_label = _domain_without_tld(official).lower()
                if normalized == official_label:
                    return triggered, brand_name, {"brand": brand_name, "domain": official}
                # Also try Levenshtein on the normalized form
                dist = Levenshtein.distance(normalized, official_label)
                if dist <= 1:
                    return triggered, brand_name, {"brand": brand_name, "domain": official}

    return triggered, None, None


def check_brand_in_wrong_place(
    domain_info: dict[str, Any],
    brand_registry: list[dict],
) -> tuple[list[dict], str | None, dict | None]:
    """
    Flag URLs where a brand name appears in a subdomain or path of an
    *unrelated* domain.

    - ``BRAND_IN_SUBDOMAIN`` (weight 20): brand in subdomain, registered
      domain doesn't belong to the brand.
    - ``BRAND_IN_PATH`` (weight 10): brand keyword appears in the URL path.

    Returns
    -------
    (triggered_list, matched_brand_name, brand_site_info)
    """
    triggered: list[dict] = []
    subdomain = domain_info.get("subdomain", "").lower()
    registered_domain = domain_info.get("registered_domain", "").lower()
    path = domain_info.get("path", "").lower()
    best_brand: str | None = None
    best_brand_info: dict | None = None

    path_flagged = False

    for brand_entry in brand_registry:
        brand_name = _get_brand_name(brand_entry)
        official_domains = [d.lower() for d in brand_entry.get("official_domains", [])]
        keywords = _get_brand_keywords(brand_entry)

        # Skip if the registered domain is actually official for this brand
        is_official = any(registered_domain == od for od in official_domains)
        if is_official:
            continue

        for kw in keywords:
            if len(kw) < 3:
                # Skip very short keywords to avoid false positives
                continue

            # Check subdomain: whole word match or exact label
            subdomain_labels = subdomain.split(".")
            if kw in subdomain_labels or kw in subdomain:
                triggered.append(
                    _triggered(
                        "BRAND_IN_SUBDOMAIN",
                        20,
                        f"Brand '{brand_name}' appears in subdomain "
                        f"of unrelated domain '{registered_domain}'",
                    )
                )
                best_brand = brand_name
                best_brand_info = {
                    "brand": brand_name,
                    "domain": official_domains[0] if official_domains else "",
                }
                break  # one match per brand is enough

            # Check path (capped at weight 10 once across all brands to prevent news false positives)
            if not path_flagged and kw in path:
                triggered.append(
                    _triggered(
                        "BRAND_IN_PATH",
                        10,
                        f"Brand '{brand_name}' keyword found in URL path",
                    )
                )
                path_flagged = True
                if best_brand is None:
                    best_brand = brand_name
                    best_brand_info = {
                        "brand": brand_name,
                        "domain": official_domains[0] if official_domains else "",
                    }
                break

    return triggered, best_brand, best_brand_info


def check_structural_flags(
    url: str,
    domain_info: dict[str, Any],
) -> list[dict]:
    """
    Detect structural red flags in the URL itself (no brand knowledge needed).

    Flags checked
    -------------
    - ``NO_HTTPS`` (10)          — scheme is ``http``
    - ``RAW_IP_ADDRESS`` (25)    — hostname is a numeric IP
    - ``AT_IN_URL`` (20)         — ``@`` present in the URL (credential trick)
    - ``EXCESSIVE_HYPHENS`` (15) — more than 3 hyphens in the domain label
    - ``EXCESSIVE_SUBDOMAINS`` (15) — more than 4 labels in hostname
    - ``RISKY_TLD`` (15)         — TLD is in the known-risky set
    - ``GOV_CLAIM_WRONG_TLD`` (30) — domain contains "gov"/"nic"/"govt"
      but TLD is not ``.gov.in`` or ``.nic.in``
    """
    triggered: list[dict] = []
    scheme = domain_info.get("scheme", "").lower()
    hostname = domain_info.get("hostname", "")
    domain_label = domain_info.get("domain", "").lower()
    suffix = domain_info.get("suffix", "").lower()
    labels = domain_info.get("labels", [])
    full_url = domain_info.get("full_url", url)

    # NO_HTTPS
    if scheme == "http":
        triggered.append(_triggered("NO_HTTPS", 10, "Connection is not encrypted (HTTP)"))

    # RAW_IP_ADDRESS
    if _is_ip_address(hostname):
        triggered.append(
            _triggered("RAW_IP_ADDRESS", 25, f"Domain is a raw IP address: {hostname}")
        )

    # AT_IN_URL — the @ sign can trick browsers into treating everything
    # before it as credentials, navigating to the host *after* the @.
    if "@" in full_url:
        triggered.append(
            _triggered("AT_IN_URL", 20, "URL contains '@' (possible credential trick)")
        )

    # EXCESSIVE_HYPHENS — more than 3 hyphens in the domain label
    if domain_label.count("-") > 3:
        triggered.append(
            _triggered(
                "EXCESSIVE_HYPHENS",
                15,
                f"Domain '{domain_label}' has {domain_label.count('-')} hyphens",
            )
        )

    # EXCESSIVE_SUBDOMAINS — more than 4 labels in the hostname
    if len(labels) > 4:
        triggered.append(
            _triggered(
                "EXCESSIVE_SUBDOMAINS",
                15,
                f"Hostname has {len(labels)} labels (suspicious depth)",
            )
        )

    # RISKY_TLD
    # The suffix from tldextract may be compound (e.g. "co.in"), so check
    # the *rightmost* part as well as the full suffix.
    tld_parts = suffix.split(".") if suffix else []
    rightmost_tld = tld_parts[-1] if tld_parts else ""
    if rightmost_tld in _RISKY_TLDS or suffix in _RISKY_TLDS:
        triggered.append(
            _triggered("RISKY_TLD", 15, f"TLD '.{suffix}' is commonly abused")
        )

    # GOV_CLAIM_WRONG_TLD
    # If the domain label or any subdomain label contains a gov-like keyword
    # but the TLD isn't a legitimate government suffix, it's suspicious.
    all_labels_text = ".".join(labels).lower()
    has_gov_keyword = any(kw in all_labels_text for kw in _GOV_KEYWORDS)
    legitimate_gov_suffixes = {"gov.in", "nic.in"}
    if has_gov_keyword and suffix not in legitimate_gov_suffixes:
        triggered.append(
            _triggered(
                "GOV_CLAIM_WRONG_TLD",
                30,
                f"Domain implies government affiliation but TLD is '.{suffix}'",
            )
        )

    return triggered


def check_hyphen_variants(
    domain_info: dict[str, Any],
    brand_registry: list[dict],
) -> tuple[list[dict], str | None, dict | None]:
    """
    Check whether removing hyphens from the input domain creates a match
    against any brand's official domains.

    Trigger: ``HYPHEN_INSERTED`` (weight 20).

    Returns
    -------
    (triggered_list, matched_brand_name, brand_site_info)
    """
    triggered: list[dict] = []
    input_domain_label = domain_info.get("domain", "").lower()

    # Only relevant if the domain actually contains hyphens
    if "-" not in input_domain_label:
        return triggered, None, None

    dehyphenated = input_domain_label.replace("-", "")

    for brand_entry in brand_registry:
        brand_name = _get_brand_name(brand_entry)
        for official in brand_entry.get("official_domains", []):
            official_label = _domain_without_tld(official).lower()
            if dehyphenated == official_label:
                triggered.append(
                    _triggered(
                        "HYPHEN_INSERTED",
                        20,
                        f"Removing hyphens from '{input_domain_label}' yields "
                        f"'{dehyphenated}', matching {brand_name}",
                    )
                )
                return triggered, brand_name, {"brand": brand_name, "domain": official}

        # Check if any hyphen-separated part matches an official domain label or brand keyword
        hyphen_parts = input_domain_label.split("-")
        keywords = _get_brand_keywords(brand_entry)
        for part in hyphen_parts:
            if part in keywords and len(part) >= 3:
                triggered.append(
                    _triggered(
                        "HYPHEN_INSERTED",
                        20,
                        f"Hyphenated domain contains brand keyword '{part}' for {brand_name}",
                    )
                )
                first_official = brand_entry.get("official_domains", [""])[0]
                return triggered, brand_name, {"brand": brand_name, "domain": first_official}

    return triggered, None, None


def check_page_signals(signals: dict | None) -> list[dict]:
    """
    Evaluate page-level signals collected by the browser content script.

    Signals dict keys
    -----------------
    - ``form_targets_other_domain`` (bool)  → ``FORM_TO_OTHER_DOMAIN`` (25)
    - ``asks_card_and_otp`` (bool)          → ``ASKS_CARD_PIN_OTP`` (30)
    - ``urgency_phrases`` (list[str])       → ``URGENCY_LANGUAGE`` (10 each, max 20)
    - ``logo_from_other_domain`` (str|None) → ``LOGO_FROM_OTHER_DOMAIN`` (15)

    Parameters
    ----------
    signals : dict or None
        Page signals from the content script.  ``None`` or empty dict is
        handled gracefully (returns no triggered rules).

    Returns
    -------
    list[dict]
        Triggered rules.
    """
    if not signals:
        return []

    triggered: list[dict] = []

    if signals.get("form_targets_other_domain"):
        triggered.append(
            _triggered(
                "FORM_TO_OTHER_DOMAIN",
                25,
                "Login/payment form submits data to a different domain",
            )
        )

    if signals.get("asks_card_and_otp"):
        triggered.append(
            _triggered(
                "ASKS_CARD_PIN_OTP",
                30,
                "Page asks for card details AND OTP/PIN simultaneously",
            )
        )

    urgency_phrases = signals.get("urgency_phrases", [])
    if urgency_phrases:
        urgency_weight_total = 0
        for phrase in urgency_phrases:
            if urgency_weight_total >= 20:
                break
            weight = min(10, 20 - urgency_weight_total)
            triggered.append(
                _triggered(
                    "URGENCY_LANGUAGE",
                    weight,
                    f"Urgency phrase detected: \"{phrase}\"",
                )
            )
            urgency_weight_total += weight

    if signals.get("logo_from_other_domain"):
        logo_domain = signals["logo_from_other_domain"]
        triggered.append(
            _triggered(
                "LOGO_FROM_OTHER_DOMAIN",
                15,
                f"Page loads logo/branding from external domain: {logo_domain}",
            )
        )

    return triggered


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def analyze_url(
    url: str,
    brand_registry: list[dict],
    signals: dict | None = None,
) -> dict:
    """
    Analyse a URL for phishing / look-alike risk.

    This is the main entry point of the rules engine.  It parses the URL,
    runs every check in sequence, aggregates the triggered rules, and
    returns a ``CheckResult`` dict.

    Parameters
    ----------
    url : str
        The URL to analyse (may or may not include a scheme).
    brand_registry : list[dict]
        Brand registry loaded from ``brands.json``.  Each entry must contain
        at least ``"brand"`` (str) and ``"official_domains"`` (list[str]).
        Optional: ``"keywords"`` (list[str]).
    signals : dict or None
        Optional page-level signals from the browser content script.

    Returns
    -------
    dict
        A ``CheckResult`` dict with keys:
        ``score``, ``level``, ``triggered``, ``official_site``, ``matched_brand``.

    Examples
    --------
    >>> result = analyze_url("https://onlinesbi.sbi", registry)
    >>> result["level"]
    'safe'

    >>> result = analyze_url("https://onlinesbl.sbi", registry)
    >>> result["level"] in ('careful', 'danger')
    True
    """
    # 1. Parse URL
    domain_info = _parse_url(url)

    # 2. Check official match — return safe immediately if the domain is legit
    is_official, brand_info = check_official_match(domain_info, brand_registry)
    if is_official:
        return {
            "score": 0,
            "level": "safe",
            "triggered": [],
            "official_site": brand_info,
            "matched_brand": brand_info["brand"] if brand_info else None,
        }

    # 3. Run all other checks and collect triggered rules
    all_triggered: list[dict] = []
    matched_brand: str | None = None
    official_site: dict | None = None

    # Helper to update matched brand from check results
    def _update_match(brand: str | None, info: dict | None) -> None:
        nonlocal matched_brand, official_site
        if brand is not None and matched_brand is None:
            matched_brand = brand
            official_site = info

    # Typosquat check
    typo_triggers, typo_brand, typo_info = check_typosquat(domain_info, brand_registry)
    all_triggered.extend(typo_triggers)
    _update_match(typo_brand, typo_info)

    # Homoglyph check
    homo_triggers, homo_brand, homo_info = check_homoglyphs(domain_info, brand_registry)
    all_triggered.extend(homo_triggers)
    _update_match(homo_brand, homo_info)

    # Brand in wrong place
    bwp_triggers, bwp_brand, bwp_info = check_brand_in_wrong_place(
        domain_info, brand_registry
    )
    all_triggered.extend(bwp_triggers)
    _update_match(bwp_brand, bwp_info)

    # Structural flags (no brand match from these)
    struct_triggers = check_structural_flags(url, domain_info)
    all_triggered.extend(struct_triggers)

    # Hyphen variants
    hyph_triggers, hyph_brand, hyph_info = check_hyphen_variants(
        domain_info, brand_registry
    )
    all_triggered.extend(hyph_triggers)
    _update_match(hyph_brand, hyph_info)

    # Page signals
    signal_triggers = check_page_signals(signals)
    all_triggered.extend(signal_triggers)

    # 4. Compute composite score (sum of weights, capped at 100)
    raw_score = sum(t["weight"] for t in all_triggered)
    score = min(raw_score, 100)

    # 5. Determine risk level
    if score < 20:
        level = "safe"
    elif score < 50:
        level = "careful"
    else:
        level = "danger"

    # 6. Build and return result
    return {
        "score": score,
        "level": level,
        "triggered": all_triggered,
        "official_site": official_site,
        "matched_brand": matched_brand,
    }
