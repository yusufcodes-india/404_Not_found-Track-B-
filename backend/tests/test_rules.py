"""
test_rules.py — Comprehensive pytest tests for the look-alike website
detection rules engine.

Tests are grouped by rule category.  A small inline brand registry is used
as a fixture so that tests are self-contained and don't depend on
data/brands.json existing on disk.
"""

from __future__ import annotations

import pytest

from app.rules import (
    analyze_url,
    check_official_match,
    check_typosquat,
    check_homoglyphs,
    check_brand_in_wrong_place,
    check_structural_flags,
    check_hyphen_variants,
    check_page_signals,
    _parse_url,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def brand_registry() -> list[dict]:
    """
    A compact inline brand registry that covers enough brands for thorough
    testing without requiring the full brands.json file.
    """
    return [
        {
            "brand": "SBI",
            "official_domains": ["onlinesbi.sbi", "sbi.co.in"],
            "keywords": ["sbi", "onlinesbi"],
        },
        {
            "brand": "HDFC Bank",
            "official_domains": ["hdfcbank.com"],
            "keywords": ["hdfc", "hdfcbank"],
        },
        {
            "brand": "ICICI Bank",
            "official_domains": ["icicibank.com"],
            "keywords": ["icici", "icicibank"],
        },
        {
            "brand": "Axis Bank",
            "official_domains": ["axisbank.com"],
            "keywords": ["axis", "axisbank"],
        },
        {
            "brand": "Paytm",
            "official_domains": ["paytm.com"],
            "keywords": ["paytm"],
        },
        {
            "brand": "Kotak",
            "official_domains": ["kotak.com"],
            "keywords": ["kotak"],
        },
        {
            "brand": "UIDAI",
            "official_domains": ["uidai.gov.in"],
            "keywords": ["uidai", "aadhaar"],
        },
        {
            "brand": "Income Tax",
            "official_domains": ["incometax.gov.in"],
            "keywords": ["incometax"],
        },
        {
            "brand": "IRCTC",
            "official_domains": ["irctc.co.in"],
            "keywords": ["irctc"],
        },
    ]


# ---------------------------------------------------------------------------
# TestOfficialMatch
# ---------------------------------------------------------------------------


class TestOfficialMatch:
    """Genuine / official domains must return safe with score 0."""

    def test_sbi_official(self, brand_registry):
        """onlinesbi.sbi is a known SBI domain."""
        result = analyze_url("https://onlinesbi.sbi", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"
        assert result["triggered"] == []
        assert result["official_site"]["brand"] == "SBI"

    def test_sbi_subdomain(self, brand_registry):
        """Subdomains of official domains (e.g., netbanking.onlinesbi.sbi) should be safe."""
        result = analyze_url("https://netbanking.onlinesbi.sbi", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_sbi_co_in(self, brand_registry):
        """sbi.co.in is official."""
        result = analyze_url("https://www.sbi.co.in", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_hdfc_official(self, brand_registry):
        """hdfcbank.com is official."""
        result = analyze_url("https://hdfcbank.com", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"
        assert result["official_site"]["brand"] == "HDFC Bank"

    def test_hdfc_subdomain(self, brand_registry):
        """netbanking.hdfcbank.com must be safe."""
        result = analyze_url("https://netbanking.hdfcbank.com/login", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_uidai_official(self, brand_registry):
        """uidai.gov.in is official."""
        result = analyze_url("https://uidai.gov.in", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_incometax_official(self, brand_registry):
        """incometax.gov.in is official."""
        result = analyze_url("https://incometax.gov.in", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_irctc_official(self, brand_registry):
        """irctc.co.in is official."""
        result = analyze_url("https://www.irctc.co.in", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_paytm_official(self, brand_registry):
        """paytm.com is official."""
        result = analyze_url("https://paytm.com", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_icici_official(self, brand_registry):
        """icicibank.com is official."""
        result = analyze_url("https://icicibank.com/netbanking", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_axis_official(self, brand_registry):
        """axisbank.com is official."""
        result = analyze_url("https://axisbank.com", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"


# ---------------------------------------------------------------------------
# TestTyposquat
# ---------------------------------------------------------------------------


class TestTyposquat:
    """Typosquatting domains (Levenshtein distance ≤ 2) must be flagged."""

    def test_sbi_typo_onlinesbl(self, brand_registry):
        """onlinesbl.sbi — l instead of i at the end."""
        result = analyze_url("https://onlinesbl.sbi", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes
        assert result["level"] in ("careful", "danger")
        assert result["matched_brand"] == "SBI"

    def test_hdfc_typo_hdfcbamk(self, brand_registry):
        """hdfcbamk.com — 'a' and 'm' instead of 'an' transposition."""
        result = analyze_url("https://hdfcbamk.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes

    def test_icici_typo_icicl(self, brand_registry):
        """icicl.com — missing 'bank', but icicl vs icicibank distance may be > 2.
        Testing iciclbank.com instead (1 edit from icicibank)."""
        result = analyze_url("https://iciclbank.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes

    def test_paytm_typo_paytn(self, brand_registry):
        """paytn.com — n instead of m."""
        result = analyze_url("https://paytn.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes
        assert result["matched_brand"] == "Paytm"

    def test_axis_typo_axls(self, brand_registry):
        """axlsbank.com — l instead of i."""
        result = analyze_url("https://axlsbank.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes

    def test_sbi_typo_onlinesbj(self, brand_registry):
        """onlinesbj.sbi — j instead of i."""
        result = analyze_url("https://onlinesbj.sbi", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes

    def test_hdfc_typo_hdfcbenk(self, brand_registry):
        """hdfcbenk.com — e instead of a."""
        result = analyze_url("https://hdfcbenk.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes

    def test_paytm_typo_paytm_extra_letter(self, brand_registry):
        """paytms.com — one extra letter."""
        result = analyze_url("https://paytms.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes

    def test_kotak_typo_kotakk(self, brand_registry):
        """kotakk.com — doubled last letter."""
        result = analyze_url("https://kotakk.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes

    def test_irctc_typo_irctcc(self, brand_registry):
        """irctcc.co.in — extra c."""
        result = analyze_url("https://irctcc.co.in", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes

    def test_sbi_typo_score_at_least_25(self, brand_registry):
        """A typosquat alone should score at least 25 (the weight)."""
        result = analyze_url("https://onlinesbl.sbi", brand_registry)
        assert result["score"] >= 25

    def test_typosquat_returns_official_site_info(self, brand_registry):
        """When a typosquat is detected, official_site should be populated."""
        result = analyze_url("https://paytn.com", brand_registry)
        assert result["official_site"] is not None
        assert result["official_site"]["brand"] == "Paytm"


# ---------------------------------------------------------------------------
# TestHomoglyph
# ---------------------------------------------------------------------------


class TestHomoglyph:
    """Homoglyph and punycode attacks must be caught."""

    def test_rn_to_m(self, brand_registry):
        """paytrn.com — 'rn' looks like 'm' → normalizes to paytm."""
        result = analyze_url("https://paytrn.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "HOMOGLYPH_DOMAIN" in codes
        assert result["matched_brand"] == "Paytm"

    def test_zero_for_o(self, brand_registry):
        """k0tak.com — '0' looks like 'o' → normalizes to kotak."""
        result = analyze_url("https://k0tak.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "HOMOGLYPH_DOMAIN" in codes
        assert result["matched_brand"] == "Kotak"

    def test_cyrillic_a(self, brand_registry):
        """Domain with Cyrillic 'а' (U+0430) instead of Latin 'a'."""
        # "p\u0430ytm" — the 'а' is Cyrillic
        result = analyze_url("https://p\u0430ytm.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "HOMOGLYPH_DOMAIN" in codes

    def test_punycode(self, brand_registry):
        """xn-- domains should be flagged as homoglyph attacks."""
        result = analyze_url("https://xn--pytm-1na.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "HOMOGLYPH_DOMAIN" in codes

    def test_one_for_l(self, brand_registry):
        """on1inesbi.sbi — '1' looks like 'l' → normalizes closer to onlinesbi."""
        result = analyze_url("https://on1inesbi.sbi", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "HOMOGLYPH_DOMAIN" in codes

    def test_homoglyph_weight(self, brand_registry):
        """HOMOGLYPH_DOMAIN should have weight 30."""
        result = analyze_url("https://paytrn.com", brand_registry)
        homo_rules = [t for t in result["triggered"] if t["code"] == "HOMOGLYPH_DOMAIN"]
        assert len(homo_rules) == 1
        assert homo_rules[0]["weight"] == 30


# ---------------------------------------------------------------------------
# TestBrandInSubdomain
# ---------------------------------------------------------------------------


class TestBrandInSubdomain:
    """Brand name in subdomain of an unrelated domain should be flagged."""

    def test_sbi_in_subdomain(self, brand_registry):
        """sbi.phishing.com — SBI keyword in subdomain of unrelated domain."""
        result = analyze_url("https://sbi.phishing.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "BRAND_IN_SUBDOMAIN" in codes

    def test_hdfc_in_subdomain(self, brand_registry):
        """hdfcbank.evil.xyz — HDFC keyword in subdomain."""
        result = analyze_url("https://hdfcbank.evil.xyz", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "BRAND_IN_SUBDOMAIN" in codes

    def test_paytm_in_subdomain(self, brand_registry):
        """paytm.scam-site.com — Paytm in subdomain."""
        result = analyze_url("https://paytm.scam-site.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "BRAND_IN_SUBDOMAIN" in codes

    def test_brand_in_path(self, brand_registry):
        """evilsite.com/sbi/login — brand in path only."""
        result = analyze_url("https://evilsite.com/sbi/login", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "BRAND_IN_PATH" in codes

    def test_official_subdomain_not_flagged(self, brand_registry):
        """netbanking.hdfcbank.com should NOT trigger BRAND_IN_SUBDOMAIN."""
        result = analyze_url("https://netbanking.hdfcbank.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "BRAND_IN_SUBDOMAIN" not in codes
        assert result["level"] == "safe"


# ---------------------------------------------------------------------------
# TestStructuralFlags
# ---------------------------------------------------------------------------


class TestStructuralFlags:
    """Structural URL red flags must be detected."""

    def test_raw_ip(self, brand_registry):
        """http://192.168.1.1/login — raw IP address."""
        result = analyze_url("http://192.168.1.1/login", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "RAW_IP_ADDRESS" in codes
        assert "NO_HTTPS" in codes

    def test_no_https(self, brand_registry):
        """http://example.com — no encryption."""
        result = analyze_url("http://example.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "NO_HTTPS" in codes

    def test_at_in_url(self, brand_registry):
        """http://good.com@evil.com — @ credential trick."""
        result = analyze_url("http://good.com@evil.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "AT_IN_URL" in codes

    def test_excessive_hyphens(self, brand_registry):
        """sbi-online-banking-login-page.com — too many hyphens."""
        result = analyze_url("https://sbi-online-banking-login-page.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "EXCESSIVE_HYPHENS" in codes

    def test_excessive_subdomains(self, brand_registry):
        """a.b.c.d.e.example.com — more than 4 labels."""
        result = analyze_url("https://a.b.c.d.e.example.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "EXCESSIVE_SUBDOMAINS" in codes

    def test_risky_tld(self, brand_registry):
        """sbibank.xyz — risky TLD."""
        result = analyze_url("https://sbibank.xyz", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "RISKY_TLD" in codes

    def test_risky_tld_top(self, brand_registry):
        """example.top — another risky TLD."""
        result = analyze_url("https://example.top", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "RISKY_TLD" in codes

    def test_gov_wrong_tld(self, brand_registry):
        """incometax-gov.com — pretends to be government."""
        result = analyze_url("https://incometax-gov.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "GOV_CLAIM_WRONG_TLD" in codes

    def test_gov_correct_tld_not_flagged(self, brand_registry):
        """uidai.gov.in — legitimate government site."""
        result = analyze_url("https://uidai.gov.in", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "GOV_CLAIM_WRONG_TLD" not in codes

    def test_raw_ip_weight(self, brand_registry):
        """RAW_IP_ADDRESS should have weight 25."""
        result = analyze_url("https://192.168.1.1/login", brand_registry)
        ip_rules = [t for t in result["triggered"] if t["code"] == "RAW_IP_ADDRESS"]
        assert len(ip_rules) == 1
        assert ip_rules[0]["weight"] == 25


# ---------------------------------------------------------------------------
# TestHyphenVariants
# ---------------------------------------------------------------------------


class TestHyphenVariants:
    """Removing hyphens from a domain and matching a brand should be caught."""

    def test_hdfc_hyphen(self, brand_registry):
        """hdfc-bank.com → hdfcbank → matches HDFC Bank."""
        result = analyze_url("https://hdfc-bank.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "HYPHEN_INSERTED" in codes
        assert result["matched_brand"] == "HDFC Bank"

    def test_axis_hyphen(self, brand_registry):
        """axis-bank.com → axisbank → matches Axis Bank."""
        result = analyze_url("https://axis-bank.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "HYPHEN_INSERTED" in codes

    def test_icici_hyphen(self, brand_registry):
        """icici-bank.com → icicibank → matches ICICI Bank."""
        result = analyze_url("https://icici-bank.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "HYPHEN_INSERTED" in codes

    def test_no_hyphen_no_trigger(self, brand_registry):
        """Domain without hyphens should not trigger HYPHEN_INSERTED."""
        result = analyze_url("https://example.com", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "HYPHEN_INSERTED" not in codes


# ---------------------------------------------------------------------------
# TestPageSignals
# ---------------------------------------------------------------------------


class TestPageSignals:
    """Content-script page signals must produce the correct triggered rules."""

    def test_form_to_other_domain(self, brand_registry):
        """Form submitting to another domain → FORM_TO_OTHER_DOMAIN weight 25."""
        signals = {
            "form_targets_other_domain": True,
            "asks_card_and_otp": False,
            "urgency_phrases": [],
            "logo_from_other_domain": None,
            "has_password_field": False,
            "external_form_action": "https://evil.com/collect",
        }
        result = analyze_url("https://example.com", brand_registry, signals=signals)
        codes = [t["code"] for t in result["triggered"]]
        assert "FORM_TO_OTHER_DOMAIN" in codes
        form_rule = [t for t in result["triggered"] if t["code"] == "FORM_TO_OTHER_DOMAIN"][0]
        assert form_rule["weight"] == 25

    def test_asks_card_and_otp(self, brand_registry):
        """Asking for card AND OTP → ASKS_CARD_PIN_OTP weight 30."""
        signals = {
            "form_targets_other_domain": False,
            "asks_card_and_otp": True,
            "urgency_phrases": [],
            "logo_from_other_domain": None,
            "has_password_field": False,
            "external_form_action": None,
        }
        result = analyze_url("https://example.com", brand_registry, signals=signals)
        codes = [t["code"] for t in result["triggered"]]
        assert "ASKS_CARD_PIN_OTP" in codes
        card_rule = [t for t in result["triggered"] if t["code"] == "ASKS_CARD_PIN_OTP"][0]
        assert card_rule["weight"] == 30

    def test_urgency_phrases(self, brand_registry):
        """Urgency phrases produce URGENCY_LANGUAGE, capped at 20 total weight."""
        signals = {
            "form_targets_other_domain": False,
            "asks_card_and_otp": False,
            "urgency_phrases": [
                "your account will be blocked",
                "act now or lose access",
                "final warning",
            ],
            "logo_from_other_domain": None,
            "has_password_field": False,
            "external_form_action": None,
        }
        result = analyze_url("https://example.com", brand_registry, signals=signals)
        urgency_rules = [t for t in result["triggered"] if t["code"] == "URGENCY_LANGUAGE"]
        assert len(urgency_rules) >= 2
        total_urgency = sum(t["weight"] for t in urgency_rules)
        assert total_urgency == 20  # capped at 20

    def test_logo_from_other_domain(self, brand_registry):
        """External logo → LOGO_FROM_OTHER_DOMAIN weight 15."""
        signals = {
            "form_targets_other_domain": False,
            "asks_card_and_otp": False,
            "urgency_phrases": [],
            "logo_from_other_domain": "hdfcbank.com",
            "has_password_field": False,
            "external_form_action": None,
        }
        result = analyze_url("https://example.com", brand_registry, signals=signals)
        codes = [t["code"] for t in result["triggered"]]
        assert "LOGO_FROM_OTHER_DOMAIN" in codes
        logo_rule = [t for t in result["triggered"] if t["code"] == "LOGO_FROM_OTHER_DOMAIN"][0]
        assert logo_rule["weight"] == 15

    def test_no_signals_no_crash(self, brand_registry):
        """Passing signals=None should not raise."""
        result = analyze_url("https://example.com", brand_registry, signals=None)
        assert result["level"] in ("safe", "careful", "danger")

    def test_empty_signals_dict(self, brand_registry):
        """Empty signals dict should not produce signal-based triggers."""
        result = analyze_url("https://example.com", brand_registry, signals={})
        signal_codes = {"FORM_TO_OTHER_DOMAIN", "ASKS_CARD_PIN_OTP",
                        "URGENCY_LANGUAGE", "LOGO_FROM_OTHER_DOMAIN"}
        triggered_codes = {t["code"] for t in result["triggered"]}
        assert signal_codes.isdisjoint(triggered_codes)


# ---------------------------------------------------------------------------
# TestFalsePositives
# ---------------------------------------------------------------------------


class TestFalsePositives:
    """Legitimate sites must NOT be flagged as danger."""

    def test_news_mentioning_sbi(self, brand_registry):
        """
        ndtv.com/business/sbi-results — a news article mentioning SBI in
        the path should NOT score as danger.  BRAND_IN_PATH alone is weight
        10, which is "safe" territory.
        """
        result = analyze_url(
            "https://ndtv.com/business/sbi-results", brand_registry
        )
        assert result["level"] != "danger"
        # Score should be low — at most 10 for BRAND_IN_PATH
        assert result["score"] <= 19

    def test_news_economictimes_sbi(self, brand_registry):
        """economictimes.com/sbi-share-price — same false-positive guard."""
        result = analyze_url(
            "https://economictimes.com/banking/sbi-share-price", brand_registry
        )
        assert result["level"] != "danger"

    def test_unrelated_safe_site(self, brand_registry):
        """google.com should be safe (no brand overlap)."""
        result = analyze_url("https://google.com", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_legitimate_fintech(self, brand_registry):
        """zerodha.com should not be flagged."""
        result = analyze_url("https://zerodha.com", brand_registry)
        assert result["level"] == "safe"

    def test_wikipedia(self, brand_registry):
        """en.wikipedia.org — no false positives."""
        result = analyze_url("https://en.wikipedia.org/wiki/SBI", brand_registry)
        assert result["level"] != "danger"

    def test_github(self, brand_registry):
        """github.com — must be safe."""
        result = analyze_url("https://github.com", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"


# ---------------------------------------------------------------------------
# TestScoreThresholds
# ---------------------------------------------------------------------------


class TestScoreThresholds:
    """Verify that score → level mapping is correct."""

    def test_safe_threshold(self, brand_registry):
        """Score 0–19 → safe."""
        result = analyze_url("https://google.com", brand_registry)
        assert result["score"] < 20
        assert result["level"] == "safe"

    def test_careful_threshold(self, brand_registry):
        """
        A domain with only a RISKY_TLD (15) + NO_HTTPS (10) = 25 → careful.
        """
        result = analyze_url("http://some-random-site.xyz", brand_registry)
        assert result["score"] >= 20
        assert result["score"] < 50
        assert result["level"] == "careful"

    def test_danger_threshold(self, brand_registry):
        """
        A convincing phishing domain should score ≥ 50 → danger.
        sbi.evil.xyz triggers:
          BRAND_IN_SUBDOMAIN (20) + RISKY_TLD (15) + possibly others ≥ 35
        Adding page signals to push over 50.
        """
        signals = {
            "form_targets_other_domain": True,
            "asks_card_and_otp": False,
            "urgency_phrases": [],
            "logo_from_other_domain": None,
            "has_password_field": True,
            "external_form_action": None,
        }
        result = analyze_url("https://sbi.evil.xyz", brand_registry, signals=signals)
        # BRAND_IN_SUBDOMAIN(20) + RISKY_TLD(15) + FORM_TO_OTHER_DOMAIN(25) = 60
        assert result["score"] >= 50
        assert result["level"] == "danger"

    def test_score_capped_at_100(self, brand_registry):
        """Score must never exceed 100 even with many triggers."""
        signals = {
            "form_targets_other_domain": True,
            "asks_card_and_otp": True,
            "urgency_phrases": ["act now", "final warning"],
            "logo_from_other_domain": "sbi.co.in",
            "has_password_field": True,
            "external_form_action": "https://evil.com",
        }
        # Use a domain that stacks many rules
        result = analyze_url(
            "http://sbi-online-banking-login-page.evil.xyz/sbi/login",
            brand_registry,
            signals=signals,
        )
        assert result["score"] <= 100

    def test_official_match_overrides_everything(self, brand_registry):
        """Official domain should be safe regardless of other signals."""
        signals = {
            "form_targets_other_domain": True,
            "asks_card_and_otp": True,
            "urgency_phrases": ["urgent"],
            "logo_from_other_domain": None,
            "has_password_field": True,
            "external_form_action": None,
        }
        result = analyze_url("https://onlinesbi.sbi", brand_registry, signals=signals)
        assert result["score"] == 0
        assert result["level"] == "safe"


# ---------------------------------------------------------------------------
# TestCombinedScenarios
# ---------------------------------------------------------------------------


class TestCombinedScenarios:
    """End-to-end scenarios combining multiple rule triggers."""

    def test_typosquat_plus_risky_tld(self, brand_registry):
        """Typosquat + risky TLD should push to danger."""
        result = analyze_url("https://paytn.xyz", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "TYPOSQUAT_BRAND" in codes
        assert "RISKY_TLD" in codes
        assert result["score"] >= 40  # 25 + 15

    def test_homoglyph_plus_page_signals(self, brand_registry):
        """Homoglyph domain + suspicious page signals → danger."""
        signals = {
            "form_targets_other_domain": True,
            "asks_card_and_otp": True,
            "urgency_phrases": [],
            "logo_from_other_domain": None,
            "has_password_field": True,
            "external_form_action": None,
        }
        result = analyze_url("https://paytrn.com", brand_registry, signals=signals)
        assert result["level"] == "danger"
        assert result["score"] >= 50

    def test_brand_subdomain_plus_http_plus_risky_tld(self, brand_registry):
        """Brand in subdomain + HTTP + risky TLD = danger."""
        result = analyze_url("http://sbi.evil.xyz", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "BRAND_IN_SUBDOMAIN" in codes
        assert "NO_HTTPS" in codes
        assert "RISKY_TLD" in codes
        # 20 + 10 + 15 = 45 → careful (just under danger)
        assert result["level"] in ("careful", "danger")

    def test_gov_fraud_with_ip(self, brand_registry):
        """http://192.168.1.1/incometax — IP + HTTP + brand-in-path."""
        result = analyze_url("http://192.168.1.1/incometax", brand_registry)
        codes = [t["code"] for t in result["triggered"]]
        assert "RAW_IP_ADDRESS" in codes
        assert "NO_HTTPS" in codes
        # 25 + 10 + 10 (brand in path) = 45 → careful or higher
        assert result["score"] >= 35


# ---------------------------------------------------------------------------
# TestEdgeCases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_url_without_scheme(self, brand_registry):
        """URL without scheme should still be parsed correctly."""
        result = analyze_url("onlinesbi.sbi", brand_registry)
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_url_with_query_params(self, brand_registry):
        """URL with query params should still be analysed."""
        result = analyze_url(
            "https://onlinesbi.sbi/login?ref=google&lang=en", brand_registry
        )
        assert result["score"] == 0
        assert result["level"] == "safe"

    def test_empty_brand_registry(self):
        """Empty registry should not crash; everything is 'safe' by default."""
        result = analyze_url("https://example.com", [])
        assert result["level"] in ("safe", "careful", "danger")
        assert isinstance(result["triggered"], list)

    def test_result_dict_shape(self, brand_registry):
        """Result dict must contain all expected keys."""
        result = analyze_url("https://example.com", brand_registry)
        assert "score" in result
        assert "level" in result
        assert "triggered" in result
        assert "official_site" in result
        assert "matched_brand" in result
