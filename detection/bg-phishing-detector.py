#!/usr/bin/env python3
"""
Bulgarian Phishing Domain Detector
==================================

Detects phishing domains that impersonate Bulgarian institutions, banks,
payment providers, couriers, toll/vignette services and marketplaces.

Design goals
------------
1. HIGH PRECISION FOR BULGARIA. A domain only reaches the feed if it
   impersonates a protected brand *and* the impersonation is plausibly
   aimed at Bulgarian users. Global brand abuse with no Bulgarian angle
   (e.g. German Postbank, Greek NBG, Ukrainian OLX, Russian marketplace
   chains) is out of scope and is filtered out explicitly.
2. NO SUBSTRING GUESSING. Brand and geo matching operate on DNS labels /
   hyphen-separated tokens, never on raw substrings. This is what stops
   "webgl" from looking like Bulgaria and "content" from looking like Econt.
3. EVERY EXCLUSION IS NAMED. When a domain is rejected the reason is
   logged and (for feed pruning) recorded, so the rules stay auditable.

Features
--------
- Strict, token-boundary brand matching
- Homoglyph detection (ec0nt, sρeedy, есоnt)
- Typosquatting detection with generic-word suppression
- Bulgarian-context requirement for globally ambiguous brands
- Foreign-market exclusion lists (RU/UA/ID/TR/GR/DE/IN + gambling)
- Gibberish / subdomain-chain rejection
- URLScan.io integration with targeted queries

CT Log Support: REMOVED (yielded 0 results, URLScan provides better coverage)
"""

import json
import logging
import datetime
from datetime import timezone
import os
import sys
import time
import requests
import re
import urllib.parse
from typing import List, Dict, Tuple, Set, Optional

# ==================== CONFIGURATION ====================

# Score threshold for flagging domains
SCORE_THRESHOLD = 70

# Maximum number of DNS labels before a hostname is treated as a
# subdomain-stuffing chain (e.g. yandex.avito.cdek.kwid9.bg-speedyx.top)
MAX_DNS_LABELS = 5

# Hostnames longer than this with 4+ labels are treated as gibberish chains
MAX_HOSTNAME_LENGTH = 60

# API Keys from environment
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY")

if not URLSCAN_API_KEY:
    logging.warning("⚠️ URLSCAN_API_KEY not set. URLScan.io queries will be skipped.")

# ==================== MANUAL DOMAIN LIST ====================
# Add suspicious domains here for direct checking. Manual domains skip the
# "must be on a suspicious platform" filter but still go through scoring.
MANUAL_CHECK_DOMAINS = [
    # MVR (Министерство на вътрешните работи / Bulgarian Ministry of Interior)
    # phishing / typosquatting domains — identified manually
    'mvrgovbg.lol',
    'mvr-bggov.top',
    'mvrbg.cyou',          # www.mvrbg.cyou (www. stripped automatically)
    'e-uslugimvrbga.top',
    'e-uslugimvrbgb.top',
    'e-uslugimvrbgc.top',
    'mvr-bg.top',
    'mvr.govbg.work',
    'mvr-bg.cfd',
    'gav.mvrbg.cam',
    'mvrbg.sbs',
    'mvrbg.ink',
    'mvrbg.life',
    'mvr.govbg.one',
    'mvr-bg.sbs',
    'mvr-bg.shop',
    'mvr-bg.autos',
    'mvr.bggov.cam',
    'mvrx.lat',
    'e-uslugivrl.top',
    'mvr.qdoz.cam',
    'e-uslugi.mvrbgc.top',
    'mvr.niaj.cam',
]

# ==================== WHITELISTED DOMAINS ====================
# Legitimate domains. A hostname equal to, or a subdomain of, any entry
# here is never scored. Bank/online-banking subdomains of an already
# whitelisted apex (e.g. ebb.ubb.bg under ubb.bg) are covered automatically
# and are listed only where the apex itself is not whitelisted.
WHITELISTED_DOMAINS = [
    # --- Courier & logistics ---
    'econt.com',
    'econt.bg',
    'speedy.bg',
    'intime.bg',
    'interlogistica.bg',
    'bgpost.bg',
    'bulgariapost.bg',
    'samedaybg.com',
    'sameday.bg',
    'boxnow.bg',
    'cityexpress.bg',
    'expressone.bg',
    'evropat.bg',
    'dhl.bg',
    'dpd.bg',
    'gls-bulgaria.com',
    # --- Marketplaces ---
    'olx.bg',
    'bazar.bg',
    'emag.bg',
    # --- Payment / postal financial services ---
    'easypay.bg',
    'epay.bg',
    'borica.bg',
    'fastpay.bg',
    'mypos.com',
    'paysera.bg',
    'revolut.com',
    'paypal.com',
    'skrill.com',
    # --- Bulgarian banks (apex domains; subdomains inherit) ---
    'ubb.bg',
    'dskbank.bg',
    'unicreditbulbank.bg',
    'fibank.bg',
    'postbank.bg',
    'ccbank.bg',
    'ibank.bg',
    'procreditbank.bg',
    'tbibank.bg',
    'iabank.bg',
    'bacb.bg',
    'municipalbank.bg',
    'teximbank.bg',
    'tokudabank.bg',
    'allianz.bg',
    'bbr.bg',
    # --- Bank online-banking apps on their own apex domains ---
    'dskdirect.bg',        # DSK Bank online banking
    'dskmobile.bg',        # DSK Bank mobile banking
    'e-postbank.bg',       # Postbank (Eurobank) online banking
    'bulbankonline.bg',    # UniCredit Bulbank online banking
    'bdbank.bg',           # Bulgarian Development Bank online banking
    # --- Toll & vignette services (Национално ТОЛ управление + resellers) ---
    'bgtoll.bg',           # Official national toll/e-vignette portal (RIA)
    'tollpass.bg',         # Authorised e-vignette / toll reseller
    'vinetki.bg',          # Authorised e-vignette reseller
    'digitoll.bg',         # Authorised e-vignette reseller
    'api.bg',              # Агенция "Пътна инфраструктура" (Road Infrastructure Agency)
    'boleron.bg',          # Authorised e-vignette reseller
    'spotins.bg',          # Authorised e-vignette reseller
    'grabo.bg',            # Authorised e-vignette reseller
    'amarantbg.com',       # Authorised e-vignette reseller
    # --- Telecoms (also authorised vignette resellers, common phish targets) ---
    'a1.bg',
    'yettel.bg',
    'vivacom.bg',
    # --- Bulgarian government / public services ---
    'mvr.bg',
    'gov.bg',
    'egov.bg',
    'government.bg',
    'nra.bg',              # НАП / National Revenue Agency
    'nap.bg',
    'nssi.bg',             # НОИ / National Social Security Institute
    'noi.bg',
    'customs.bg',          # Агенция "Митници"
    'registryagency.bg',
    # --- Other ---
    # ABV mail is NOT a protected brand: it is a free webmail provider, not a
    # Bulgarian institution, bank or payment service, and bulk ABV campaigns
    # (abv-bgNNN.top, abvbg-NNNNNN.weeblysite.com) were crowding out the
    # institutional findings this feed exists for. The apex stays whitelisted
    # so nothing else can ever flag it.
    'abv.bg',
]

# ==================== BRAND KEYWORDS ====================
# Brands are split into two groups:
#
#   BG_EXCLUSIVE_BRANDS  — the brand only exists in / is only meaningful for
#                          Bulgaria. Matching one of these IS Bulgarian
#                          context on its own.
#   AMBIGUOUS_BRANDS     — the brand is global or shared with other markets
#                          (DHL, OLX, PayPal, Postbank, Allianz, iBank...).
#                          These only count when the domain also carries an
#                          independent Bulgarian signal.
#
# This split is what keeps German Postbank, Greek NBG and Ukrainian OLX
# phishing out of a feed that is meant to protect Bulgarian users.

BG_EXCLUSIVE_BRANDS = [
    # Couriers / logistics
    'econt',
    'speedy',
    'bgpost',
    'bulgariapost',
    'bg-post',
    'evropat',
    'cityexpress',
    'cityexpressbg',
    'expressone',
    'expressonebg',
    'interlogistica',
    # Marketplaces
    'bazar',
    'emag',
    # Payment services
    'easypay',
    'borica',
    'mypos',
    'paysera',
    # Banks
    'ubb',
    'dsk',
    'dskbank',
    'unicreditbulbank',
    'bulbank',
    'fibank',
    'firstinvestmentbank',
    'ccbank',
    'centralcooperativebank',
    'investbank',
    'procredit',
    'procreditbank',
    'tbibank',
    'iabank',
    'internationalassetbank',
    'bacb',
    'bulgarianamericancreditbank',
    'municipalbank',
    'teximbank',
    'tokudabank',
    'bbr',
    'bulgariandevelopmentbank',
    # Online banking web apps
    'dskdirect',
    'dskmobile',
    'dsk-direct',
    'dsk-mobile',
    'epostbank',
    'e-postbank',
    'bulbankonline',
    'bdbank',
    # Government / public services (MVR — Ministry of Interior, e-services)
    'mvr',
    'mvrbg',
    'mvrgovbg',
    'mvrgov',
    'euslugi',
    'e-uslugi',
    'euslugivrl',
    'egov',
    'nssi',
    # Toll & vignette (new)
    'bgtoll',
    'bg-toll',
    'tollpass',
    'toll-pass',
    'vinetki',
    'vinetka',
    'evinetka',
    'e-vinetka',
    'evinetki',
    'e-vinetki',
    'digitoll',
    # Telecoms
    'vivacom',
    'yettel',
]

AMBIGUOUS_BRANDS = [
    # Global couriers — huge phishing volume worldwide, only in scope with BG context
    'dhl',
    'dpd',
    'gls',
    'fedex',
    'ups',
    'sameday',
    'samedaybg',
    'boxnow',
    'boxnowbg',
    'intime',
    # Marketplaces present in many countries
    'olx',
    # Payment services used across Europe
    'epay',
    'fastpay',
    'revolut',
    'paypal',
    'skrill',
    'westernunion',
    # Banking groups shared with other markets
    'unicredit',
    'postbank',
    'eurobank',
    'allianz',
    'allianzbank',
    'ibank',
    'ibanking',
    'assetonline',
]

# Combined list — order matters only for reporting, not for matching
BRAND_KEYWORDS = BG_EXCLUSIVE_BRANDS + AMBIGUOUS_BRANDS

# Brands that are too short or too word-like to run edit-distance matching on
TYPOSQUAT_MIN_BRAND_LENGTH = 5

# Parts that must never be treated as a typo of a brand — ordinary English /
# transliterated words that happen to sit 1-2 edits from a brand name.
TYPOSQUAT_STOPWORDS = {
    'pay', 'post', 'bank', 'banks', 'card', 'cards', 'mail', 'link', 'live',
    'shop', 'shops', 'site', 'sites', 'page', 'pages', 'login', 'logins',
    'direct', 'mobile', 'online', 'secure', 'server', 'email', 'index',
    'admin', 'panel', 'store', 'order', 'orders', 'track', 'money', 'cash',
    'speed', 'speedtest', 'content', 'account', 'accounts', 'support',
    'service', 'services', 'delivery', 'deliver', 'transfer', 'invoice',
    'banking', 'ebanking', 'netbanking', 'dashboard', 'payment', 'payments',
    'security', 'verify', 'confirm', 'wallet', 'profile', 'passport',
}

# ==================== SECONDARY KEYWORDS ====================
TRANSACTION_KEYWORDS = [
    'tracking',
    'delivery',
    'shipment',
    'parcel',
    'payment',
    'secure-pay',
    'pay-now',
    'invoice',
    'confirm',
    'verify',
    'account',
    'login',
    'update',
    'suspended',
    'tax',
    'fee',
    'customer-center',
    # Banking-specific
    'banking',
    'ebanking',
    'e-banking',
    'netbanking',
    'onlinebanking',
    'mobilebanking',
    'authentication',
    'secure',
    'securepay',
    'transfer',
    'transaction',
    'balance',
    'credit',
    'debit',
    'card',
]

# Bulgarian-language words used in phishing lures. These are transliterated
# Bulgarian, so they are also a strong *geographic* signal, not just a
# transactional one.
BULGARIAN_LURE_WORDS = [
    'klient',
    'pratka',
    'pratki',
    'dostavka',
    'dostavki',
    'usluga',
    'uslugi',
    'plashtane',
    'plashtania',
    'parite',
    'smetka',
    'smetki',
    'banka',
    'vinetka',
    'vinetki',
    'tol',
    'potrebitel',
    'poshta',
    'nalozhen',
    'nalozhenplatezh',
    'krediti',
    'kredit',
    'danak',
    'danaci',
    'globa',
    'globi',
]

# ==================== GEOGRAPHIC INDICATORS ====================
# Token-exact Bulgarian markers. Matched against DNS labels and
# hyphen-separated tokens — never as raw substrings.
BG_GEO_TOKENS = {
    'bg', 'bgr', 'bulgaria', 'bulgarian', 'bulgarien', 'balgaria',
    'sofia', 'plovdiv', 'varna', 'burgas', 'bourgas', 'ruse', 'stara-zagora',
}

# ==================== FOREIGN-TARGET EXCLUSIONS ====================
# If any of these appear as a token, the domain is targeting a market other
# than Bulgaria and is dropped regardless of score. Grouped by market so the
# rejection reason is meaningful.
FOREIGN_MARKET_TOKENS = {
    # Russia / CIS marketplaces, banks and couriers. These drive the
    # "yandex.cdek.youla.blablacar.pochta.kwid9.bg-speedyx.top" chains.
    'ru': {
        'yandex', 'avito', 'sber', 'sberbank', 'sbermarket', 'sbermegamarket',
        'megamarket', 'ozon', 'cdek', 'sdek', 'blablacar', 'pochta',
        'pochtabank', 'youla', 'nalozhka', 'wildberries', 'gosuslugi',
        'tinkoff', 'alfabank', 'vtb', 'rutube', 'kwid9', 'dns-shop',
        'mailru', 'vkontakte',
    },
    # Ukraine
    'ua': {
        'ua', 'uah', 'otrymka', 'ukrposhta', 'novaposhta', 'nova-poshta',
        'privatbank', 'monobank', 'rozetka', 'prom', 'ukrnet', 'oschadbank',
        'diia',
    },
    # Indonesia — "MBG" (Makan Bergizi Gratis) and OLX Indonesia campaigns
    # are the single biggest source of accidental "bg" matches.
    'id': {
        'mbg', 'mbgl', 'bgst', 'prabowo', 'gibran', 'koperasi', 'diskominfo',
        'bahlil', 'sepak', 'bola', 'dunia', 'akses', 'cepat', 'gaes', 'bini',
        'beby', 'dukung', 'muka', 'dua', 'ganteng', 'makan', 'bergizi',
        'gratis', 'blay', 'depan', 'makin', 'lag', 'bolsasnt', 'izin',
    },
    # Türkiye
    'tr': {
        'trbg', 'turkiye', 'tckimlik', 'edevlet', 'ptt', 'ziraat',
        'garanti-tr', 'isbank-tr',
    },
    # Greece — NBG is the National Bank of Greece, not a Bulgarian bank
    'gr': {
        'nbg', 'ethniki', 'piraeus', 'alphabank', 'winbank',
    },
    # Germany / Austria — "meine-postbank", "-de-", Ausbildung… campaigns
    'de': {
        'de', 'meine', 'ausbildungsnavi', 'auswertungszentrum',
        'pakettracking', 'sparkasse', 'volksbank', 'commerzbank', 'postbank-de',
    },
    # India / South Asia
    'in': {
        'airtel', 'paytm', 'phonepe', 'bglsh', 'baji', 'bkash', 'nagad',
    },
    # Gambling / casino affiliate spam — not institutional phishing
    'gambling': {
        'casino', 'casinologin', 'playfastcasinologin', 'toto', '1xbet',
        'betano', 'melbet', 'parimatch', 'mostbet', 'bet365', 'pinup',
    },
}

# Long, distinctive foreign tokens that are also matched as substrings,
# because attackers glue them onto other words (e.g. "lyjbgozon").
FOREIGN_SUBSTRING_TOKENS = (
    'yandex', 'sberbank', 'sbermegamarket', 'sbermarket', 'blablacar',
    'pochtabank', 'wildberries', 'gosuslugi', 'novaposhta', 'ukrposhta',
    'privatbank', 'monobank', 'ausbildungsnavi', 'auswertungszentrum',
    'pakettracking', 'prabowo', 'diskominfo', 'wildcardprobe',
)

# ==================== SUSPICIOUS TLDs ====================
SUSPICIOUS_TLDS = (
    '.cfd', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz',
    '.club', '.online', '.site', '.space', '.click', '.link',
    '.live', '.icu', '.buzz', '.cam', '.rest', '.store', '.tech',
    '.website', '.world', '.pw', '.cc', '.sbs',
    '.lol', '.cyou', '.work', '.one', '.autos', '.ink', '.life',
    '.shop', '.lat', '.quest', '.mom', '.bond', '.support', '.help',
)

# ==================== FREE HOSTING PLATFORMS ====================
FREE_HOSTING_SUFFIXES = (
    '.web.app', '.firebaseapp.com', '.herokuapp.com', '.pages.dev',
    '.netlify.app', '.vercel.app', '.onrender.com', '.render.com',
    '.fly.dev', '.surge.sh', '.gitlab.io', '.github.io',
    '.repl.co', '.replit.dev', '.replit.app', '.glitch.me',
    '.cyclic.app', '.railway.app', '.deta.dev', '.workers.dev',
    '.azurestaticapps.net', '.amplifyapp.com', '.r2.dev',
    '.weeblysite.com', '.wixsite.com', '.blogspot.com',
)

TARGET_SUFFIXES = FREE_HOSTING_SUFFIXES + SUSPICIOUS_TLDS

# ==================== INFRASTRUCTURE / SCANNER-ARTEFACT EXCLUSIONS ====================
# Cloud infrastructure plus artefacts of other people's scanners that keep
# landing in URLScan results (wildcard DNS probes, IoT sinkholes, …).
INFRASTRUCTURE_PATTERNS = (
    '.postgres.render.com', '.redis.render.com', '.internal.render.com',
    'replica-', '.rds.amazonaws.com', '.elb.amazonaws.com',
    '.elasticache.amazonaws.com', '.drive.amazonaws.com',
    'kms.amazonaws.com', 's3.amazonaws.com', 's3-deprecated',
    'content-eu.drive', 'content-jp.drive',
    '.database.windows.net', '.redis.cache.windows.net',
    '--deploy-preview-', 'preview.vercel.app',
    'bgptools',            # BGP monitoring tools (not phishing)
    'wildcardprobe',       # third-party wildcard-DNS probing
    '.10iot.xyz',          # IoT scanning sinkhole
    'mageyportal',         # scanner artefact
    'bigobigo',            # scanner artefact
    'localhost',
    '.local',
    '.arpa',
)

# ==================== OUTPUT CONFIGURATION ====================
OUTPUT_FILE = 'feed/phishing_feed.json'
STATS_FILE = 'feed/stats.json'

# ==================== LOGGING SETUP ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# ==================== NORMALISATION HELPERS ====================

# Cloudflare/ISP mirror prefixes that carry no meaning (ww17., ww25., ww38.)
_MIRROR_PREFIX_RE = re.compile(r'^ww\d+\.')


def normalize_domain(domain: str) -> str:
    """Lowercase a hostname and strip www./wwNN. mirror prefixes and dots."""
    d = domain.strip().lower().rstrip('.')
    d = _MIRROR_PREFIX_RE.sub('', d)
    if d.startswith('www.'):
        d = d[4:]
    return d


def domain_tokens(domain: str) -> List[str]:
    """
    Split a hostname into comparable tokens.

    Tokens are the DNS labels *and* the hyphen/underscore separated parts of
    each label. Token matching is what prevents substring accidents such as
    "webgl" containing "bg" or "content" containing "econt".
    """
    d = normalize_domain(domain)
    tokens = []
    for label in d.split('.'):
        if not label:
            continue
        tokens.append(label)
        for part in re.split(r'[-_]', label):
            if part and part != label:
                tokens.append(part)
    return tokens


def domain_labels(domain: str) -> List[str]:
    """Return the DNS labels of a hostname, after normalisation."""
    return [lbl for lbl in normalize_domain(domain).split('.') if lbl]


# ==================== WHITELIST ====================

def is_whitelisted(domain: str) -> bool:
    """True if the hostname is a legitimate domain or a subdomain of one."""
    domain_lower = normalize_domain(domain)

    for whitelisted in WHITELISTED_DOMAINS:
        if domain_lower == whitelisted:
            return True
        if domain_lower.endswith('.' + whitelisted):
            return True

    return False


# ==================== FOREIGN-TARGET DETECTION ====================

def foreign_market_match(domain: str) -> Optional[Tuple[str, str]]:
    """
    Detect domains aimed at a market other than Bulgaria.

    Returns (market_code, matched_token) or None.

    Examples:
        yandex.cdek.youla.blablacar.pochta.kwid9.bg-speedyx.top -> ('ru', 'yandex')
        8guild-izin-trbg-gaes.pages.dev                          -> ('tr', 'izin')
        ww17.nbg-bank-login.fluxio.cfd                           -> ('gr', 'nbg')
        meine-postbank.online                                    -> ('de', 'meine')
        olx-ua-safedeal-payment25121.pages.dev                   -> ('ua', 'ua')
    """
    tokens = set(domain_tokens(domain))
    normalized = normalize_domain(domain)

    for market, markers in FOREIGN_MARKET_TOKENS.items():
        hit = tokens & markers
        if hit:
            return (market, sorted(hit)[0])

    for marker in FOREIGN_SUBSTRING_TOKENS:
        if marker in normalized:
            for market, markers in FOREIGN_MARKET_TOKENS.items():
                if marker in markers:
                    return (market, marker)
            return ('other', marker)

    return None


# ==================== GIBBERISH / CHAIN DETECTION ====================

def gibberish_chain_reason(domain: str) -> Optional[str]:
    """
    Reject over-long, stacked or repeated-label hostnames.

    Attackers building bulk marketplace-phishing infrastructure stuff many
    brand names into one hostname, producing entries that are unreadable and
    useless as a Bulgarian threat feed:

        yandex.cdek.youla.blablacar.pochta.kwid9.bg-speedyx.top
        ozon.yandex.nalozhka.avito.cdek.avito.sbermarket.kwid9.bg-speedyz.top

    Returns a human-readable reason, or None if the hostname looks sane.
    """
    normalized = normalize_domain(domain)
    labels = domain_labels(domain)

    if len(labels) > MAX_DNS_LABELS:
        return f'subdomain chain ({len(labels)} labels)'

    if len(normalized) > MAX_HOSTNAME_LENGTH and len(labels) >= 4:
        return f'over-long hostname ({len(normalized)} chars, {len(labels)} labels)'

    # Repeated labels: avito.avito.avito… is bulk infrastructure, not a lure
    meaningful = [lbl for lbl in labels[:-1] if len(lbl) > 2]
    if len(meaningful) != len(set(meaningful)):
        return 'repeated subdomain labels'

    # A single label that is a long run of random-looking characters
    for label in labels:
        if len(label) >= 24 and not re.search(r'[aeiou]{1}', label[:12]):
            return f'random label ({label[:24]}…)'

    return None


# ==================== BRAND MATCHING ====================

def _brand_patterns(brand: str) -> List[str]:
    """Word-boundary regex patterns for a brand inside a hostname."""
    b = re.escape(brand)
    return [
        rf'^{b}\.',      # speedy.bg-pv.cfd    (start, before dot)
        rf'^{b}-',       # speedy-bg.cfd       (start, before hyphen)
        rf'^{b}$',       # speedy              (whole hostname)
        rf'\.{b}\.',     # www.speedy.com      (between dots)
        rf'\.{b}-',      # info.speedy-bg.cfd  (after dot, before hyphen)
        rf'\.{b}$',      # domain.speedy       (after dot, at end)
        rf'-{b}\.',      # bg-speedy.cfd       (after hyphen, before dot)
        rf'-{b}-',       # x-speedy-bg         (between hyphens)
        rf'-{b}$',       # domain-speedy       (after hyphen, at end)
    ]


def _bg_glued_variants(brand: str) -> List[str]:
    """
    "brand+bg" spellings that attackers use to compress "econt.bg" into a
    single label: econtbg, bgecont, olxbg, mvrbg, epostbankbg…

    These are matched separately from the bare brand because they are also a
    Bulgarian *geographic* signal, not just a brand hit.
    """
    stem = brand.replace('-', '')
    variants = {brand + 'bg', 'bg' + brand}
    if stem != brand:
        variants |= {stem + 'bg', 'bg' + stem}
    return sorted(v for v in variants if not v.startswith('bgbg'))


def deobfuscated_forms(domain: str) -> List[str]:
    """
    Return the hostname plus, when it uses punycode, its decoded and
    homoglyph-normalised form — so xn--econtbg-6gg is matched as econtbg.
    """
    normalized = normalize_domain(domain)
    forms = [normalized]

    if 'xn--' in normalized:
        decoded = '.'.join(_punycode_decode(lbl) for lbl in normalized.split('.'))
        forms.append(decoded)
        forms.append(normalize_homoglyphs(decoded))

    return list(dict.fromkeys(forms))


def contains_brand_impersonation(domain: str) -> Tuple[bool, List[str], List[str]]:
    """
    Strict, boundary-anchored brand matching.

    Prevents false positives such as:
      - "econt" inside "content"       → NOT a match
      - "olx"   inside a random string → NOT a match
      - "speedy" in "speedytest"       → NOT a match

    Returns (has_brand, matched_brands, brands_matched_in_a_bg_glued_form).
    The third element feeds Bulgarian-context detection: seeing "econtbg"
    proves both the brand and the Bulgarian target in one token.
    """
    forms = deobfuscated_forms(domain)
    matched_brands: List[str] = []
    bg_glued: List[str] = []

    for brand in BRAND_KEYWORDS:
        hit = False
        for pattern in _brand_patterns(brand):
            if any(re.search(pattern, form) for form in forms):
                hit = True
                break

        glued_hit = False
        for variant in _bg_glued_variants(brand):
            for pattern in _brand_patterns(variant):
                if any(re.search(pattern, form) for form in forms):
                    glued_hit = True
                    break
            if glued_hit:
                break

        if hit or glued_hit:
            matched_brands.append(brand)
        if glued_hit:
            bg_glued.append(brand)

    return (len(matched_brands) > 0, matched_brands, bg_glued)


def classify_brands(brands: List[str]) -> Tuple[List[str], List[str]]:
    """Split matched brands into (bg_exclusive, ambiguous)."""
    bg_only = [b for b in brands if b in BG_EXCLUSIVE_BRANDS]
    ambiguous = [b for b in brands if b in AMBIGUOUS_BRANDS]
    return bg_only, ambiguous


# ==================== BULGARIAN CONTEXT ====================

def bulgarian_context(domain: str, matched_brands: List[str]) -> Tuple[bool, List[str]]:
    """
    Decide whether a hostname is plausibly aimed at Bulgarian users.

    Signals (any one is enough):
      1. A ``bg`` / ``bulgaria`` / Bulgarian-city token, matched on token
         boundaries — NOT as a substring. This is the fix for false positives
         like "inntelt-webgl-play" and "olx.plsd2bgflstagf39027".
      2. A ``.bg`` effective TLD anywhere in the hostname (speedy.bg-pv.cfd).
      3. A Bulgarian-exclusive brand (econt, dskdirect, mvr, vinetki, …).
      4. A transliterated Bulgarian lure word (dostavka, parite, vinetka, …).

    Returns (has_context, list_of_signals).
    """
    signals: List[str] = []
    normalized = normalize_domain(domain)
    tokens = set(domain_tokens(domain))

    geo_hits = tokens & BG_GEO_TOKENS
    if geo_hits:
        signals.extend(f'geo:{t}' for t in sorted(geo_hits))

    # ".bg" appearing as a label anywhere (speedy.bg-pv.cfd, dskdirect.bg.x.online)
    if re.search(r'(^|\.)bg(\.|$)', normalized):
        signals.append('geo:.bg-label')

    bg_only, _ = classify_brands(matched_brands)
    if bg_only:
        signals.extend(f'brand:{b}' for b in bg_only)

    for word in BULGARIAN_LURE_WORDS:
        if word in tokens:
            signals.append(f'lure:{word}')

    return (len(signals) > 0, signals)


# ==================== HOMOGLYPH DETECTION ====================

# Common homoglyphs for Latin characters (Cyrillic and similar-looking chars)
HOMOGLYPH_MAP = {
    'a': ['а', 'ạ', 'ą', 'ά', 'α'],       # Cyrillic 'а', various accented
    'c': ['с', 'ϲ', 'ć', 'ċ'],            # Cyrillic 'с', Greek
    'e': ['е', 'ė', 'ę', 'ё', 'έ', 'ε'],  # Cyrillic 'е', 'ё', Greek
    'i': ['і', 'ı', 'í', 'ì', 'ï', 'ι'],  # Cyrillic 'і', Turkish, Greek
    'o': ['о', 'ο', 'ọ', 'ó', 'ò', '0'],  # Cyrillic 'о', Greek, zero
    'p': ['р', 'ρ', 'þ'],                 # Cyrillic 'р', Greek 'ρ'
    's': ['ѕ', 'ś', 'ş'],                 # Cyrillic 'ѕ'
    't': ['т', 'τ'],                      # Cyrillic 'т', Greek 'τ'
    'u': ['υ', 'ú', 'ù'],                 # Greek 'υ'
    'x': ['х', 'χ'],                      # Cyrillic 'х', Greek 'χ'
    'y': ['у', 'ү', 'ý'],                 # Cyrillic 'у', 'ү'
}


def normalize_homoglyphs(text: str) -> str:
    """Normalize homoglyphs to their Latin equivalents"""
    result = []
    for char in text:
        found = False
        for latin, homoglyphs in HOMOGLYPH_MAP.items():
            if char in homoglyphs:
                result.append(latin)
                found = True
                break

        if not found:
            if char == '0':
                result.append('o')
            else:
                result.append(char)

    return ''.join(result)


def _punycode_decode(label: str) -> str:
    """Best-effort decode of an xn-- label so homoglyphs become visible."""
    if not label.startswith('xn--'):
        return label
    try:
        return label.encode('ascii').decode('idna')
    except Exception:
        return label


def detect_homoglyphs(domain: str, brands: List[str]) -> Tuple[bool, List[str]]:
    """
    Detect homoglyph attacks where similar-looking characters replace Latin
    letters.

    Examples:
      - econt  → ec0nt   (zero instead of o)
      - speedy → sρeedy  (Greek ρ instead of p)
      - econt  → есоnt   (Cyrillic е, с, о)
      - econt  → xn--econtbg-6gg (punycode wrapper, decoded first)
    """
    domain_lower = normalize_domain(domain)
    homoglyphs_found = []

    raw_parts = re.split(r'[.\-]', domain_lower)
    parts = [_punycode_decode(p) for p in raw_parts]

    for brand in brands:
        for part in parts:
            if len(part) < 3 or abs(len(part) - len(brand)) > 2:
                continue

            has_non_ascii = not all(ord(c) < 128 for c in part)

            if has_non_ascii:
                normalized = normalize_homoglyphs(part)
                if normalized == brand or (len(normalized) >= 4 and normalized in brand):
                    homoglyphs_found.append(part)
                    break

            if '0' in part and part.replace('0', 'o') == brand:
                homoglyphs_found.append(part)
                break

    return (len(homoglyphs_found) > 0, homoglyphs_found)


# ==================== TYPOSQUATTING DETECTION ====================

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein (edit) distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def classify_typo_type(original: str, typo: str) -> str:
    """Classify the type of typo for better analysis"""
    if len(typo) < len(original):
        return 'missing_char'
    elif len(typo) > len(original):
        return 'extra_char'
    else:
        differences = sum(1 for a, b in zip(original, typo) if a != b)
        if differences == 2:
            for i in range(len(original) - 1):
                if original[i] == typo[i + 1] and original[i + 1] == typo[i]:
                    return 'swapped_chars'
        return 'substitution'


def detect_typosquatting(domain: str, brands: List[str]) -> Tuple[bool, List[Dict]]:
    """
    Detect typosquatting patterns (spedy, econnt, spedey, …).

    Tightened against the noise the previous version produced:
      - brands shorter than TYPOSQUAT_MIN_BRAND_LENGTH are skipped, so "pay"
        is no longer reported as a typo of "epay"
      - ordinary words (login, secure, direct, …) are never treated as typos
      - 5-6 character brands allow at most one edit; only longer brands allow two
    """
    domain_lower = normalize_domain(domain)
    detected_typos = []

    parts = re.split(r'[.\-]', domain_lower)

    for brand in brands:
        if len(brand) < TYPOSQUAT_MIN_BRAND_LENGTH:
            continue

        max_distance = 1 if len(brand) <= 6 else 2

        for part in parts:
            if len(part) < 4 or part in TYPOSQUAT_STOPWORDS or part == brand:
                continue

            if abs(len(part) - len(brand)) > 2:
                continue

            distance = levenshtein_distance(part, brand)

            if 0 < distance <= max_distance:
                detected_typos.append({
                    'brand': brand,
                    'typo': part,
                    'distance': distance,
                    'type': classify_typo_type(brand, part)
                })

    return (len(detected_typos) > 0, detected_typos)


# ==================== DIRECT IMPERSONATION PATTERNS ====================
# Hostname shapes that are unambiguous Bulgarian brand impersonation even
# when the brand token itself is mangled. A match here both scores points
# and establishes Bulgarian context on its own.
DIRECT_IMPERSONATION_PATTERNS = [
    # Couriers / marketplaces
    r'econt-?bg',
    r'bg-?econt',
    r'speedy-?bg',
    r'bg-?speedy',
    r'bgpost-?bg',
    r'bg-?post',
    r'olx-?bg',
    r'bg-?olx',
    r'sameday-?bg',
    r'boxnow-?bg',
    # Payment services
    r'easypay-?bg',
    r'epay-?bg',
    r'borica-?bg',
    r'mypos-?bg',
    r'revolut-?bg',
    # Online banking
    r'dsk-?direct',
    r'dsk-?mobile',
    r'e-?postbank',
    r'bulbank-?online',
    r'uac-?procredit',
    r'ubb-?bg',
    r'fibank-?bg',
    r'postbank-?bg',
    # MVR (Ministry of Interior) and e-government
    r'mvr-?bg',
    r'mvrbg',
    r'mvrgovbg',
    r'mvr-?gov',
    r'e-?uslugi-?mvr',
    r'bg-?mvr',
    r'e-?gov-?bg',
    r'egov-?bg',
    # National Revenue Agency / social security / customs
    r'nap-?bg',
    r'nra-?bg',
    r'noi-?bg',
    r'nssi-?bg',
    r'mitnici-?bg',
    # Toll & vignette (Национално ТОЛ управление, e-vignette resellers)
    r'bg-?toll',
    r'toll-?pass',
    r'toll-?bg',
    r'e-?vinetka',
    r'e-?vinetki',
    r'vinetki-?bg',
    r'vinetka-?bg',
    r'digi-?toll',
]


# ==================== SCORING SYSTEM ====================

def calculate_score(domain: str) -> Tuple[int, Dict]:
    """
    Calculate a 0-100 phishing suspicion score for a hostname.

    The score answers "how strongly does this look like brand impersonation";
    whether the impersonation is aimed at Bulgaria is decided separately by
    :func:`evaluate_domain`, which is what actually gates the feed.
    """
    score = 0
    details = {
        'brand_keywords': [],
        'bg_exclusive_brands': [],
        'ambiguous_brands': [],
        'transaction_keywords': [],
        'geo_indicators': [],
        'bg_context_signals': [],
        'suspicious_tld': None,
        'free_hosting': None,
        'multiple_hyphens': False,
        'numeric_suffix': False,
        'subdomain_stacking': False,
        'high_entropy': False,
        'homoglyphs_detected': False,
        'homoglyphs_used': [],
        'typosquatting_detected': False,
        'typosquatting_details': [],
        'direct_impersonation': False,
    }

    domain_lower = normalize_domain(domain)

    # 1. BRAND KEYWORD DETECTION (+40) — strict, boundary-anchored
    has_brand, matched_brands, bg_glued = contains_brand_impersonation(domain)
    if has_brand:
        score += 40
        details['brand_keywords'] = matched_brands
        bg_only, ambiguous = classify_brands(matched_brands)
        details['bg_exclusive_brands'] = bg_only
        details['ambiguous_brands'] = ambiguous

    # 2. HOMOGLYPH DETECTION (+30)
    has_homoglyphs, homoglyphs_list = detect_homoglyphs(domain, BRAND_KEYWORDS)
    if has_homoglyphs:
        score += 30
        details['homoglyphs_detected'] = True
        details['homoglyphs_used'] = homoglyphs_list

    # 3. TYPOSQUATTING DETECTION (+25)
    has_typos, typos_list = detect_typosquatting(domain, BRAND_KEYWORDS)
    if has_typos:
        score += 25
        details['typosquatting_detected'] = True
        details['typosquatting_details'] = typos_list

    # 4. FREE HOSTING DETECTION (+25)
    for suffix in FREE_HOSTING_SUFFIXES:
        if domain_lower.endswith(suffix):
            score += 25
            details['free_hosting'] = suffix
            break

    # 5. SUSPICIOUS TLD DETECTION (+20)
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            score += 20
            details['suspicious_tld'] = tld
            break

    # 6. DIRECT IMPERSONATION (+15)
    for pattern in DIRECT_IMPERSONATION_PATTERNS:
        if re.search(pattern, domain_lower):
            score += 15
            details['direct_impersonation'] = True
            break

    # 7. BULGARIAN CONTEXT (+15) — token-based, never substring
    has_bg_context, bg_signals = bulgarian_context(domain, matched_brands)
    if bg_glued:
        has_bg_context = True
        bg_signals.extend(f'brand+bg:{b}' for b in bg_glued)
    if details['direct_impersonation']:
        has_bg_context = True
        bg_signals.append('direct-impersonation')
    if has_bg_context:
        score += 15
        details['bg_context_signals'] = bg_signals
        details['geo_indicators'] = [s.split(':', 1)[1] for s in bg_signals
                                     if s.startswith('geo:')]

    # 8. TRANSACTION KEYWORDS (+10)
    for keyword in TRANSACTION_KEYWORDS + BULGARIAN_LURE_WORDS:
        if keyword in domain_lower:
            score += 10
            details['transaction_keywords'].append(keyword)
            break

    # 9. MULTIPLE HYPHENS (+10)
    if domain_lower.count('-') >= 2:
        score += 10
        details['multiple_hyphens'] = True

    # 10. NUMERIC SUFFIX (+10)
    if re.search(r'-\d{3,}\.', domain_lower) or re.search(r'\d{4,}\.', domain_lower):
        score += 10
        details['numeric_suffix'] = True

    # 11. SUBDOMAIN STACKING (+10)
    if len(domain_labels(domain)) >= 4:
        score += 10
        details['subdomain_stacking'] = True

    # 12. HIGH ENTROPY / RANDOMNESS (+10)
    domain_name = domain_lower.split('.')[0]
    if len(domain_name) > 10:
        consonant_clusters = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{3,}', domain_name))
        mixed_alphanum = len(re.findall(r'[a-z]+\d+[a-z]+|\d+[a-z]+\d+', domain_name))

        if consonant_clusters >= 2 or mixed_alphanum >= 2:
            score += 10
            details['high_entropy'] = True

    # 13. BONUS: .bg-XX.TLD pattern (+10) — Bulgaria-specific abuse shape
    if re.search(r'\.bg-[a-z]{1,6}\.(cfd|tk|ml|ga|cf|gq|xyz|online|site|click|icu|top|live|shop)',
                 domain_lower):
        score += 10
        details['bg_tld_abuse'] = True

    score = min(max(score, 0), 100)

    return score, details


# ==================== VERDICT ====================

# Verdict codes
VERDICT_PHISHING = 'phishing'
VERDICT_BELOW_THRESHOLD = 'below_threshold'
VERDICT_EXCLUDED = 'excluded'


def evaluate_domain(domain: str, is_manual: bool = False) -> Dict:
    """
    Single source of truth for "does this hostname belong in the feed?".

    Used by both the live scanner and ``detection/prune_feed.py`` so that a
    stored feed entry is always judged by exactly the rules that are in force
    today.

    Returns a dict with:
        verdict  — one of VERDICT_*
        reason   — short machine-readable rejection reason ('' when accepted)
        detail   — human-readable explanation
        score    — 0-100
        details  — full scoring breakdown (None when rejected before scoring)
    """
    def reject(reason: str, detail: str, score: int = 0, details: Dict = None) -> Dict:
        return {'verdict': VERDICT_EXCLUDED, 'reason': reason, 'detail': detail,
                'score': score, 'details': details}

    normalized = normalize_domain(domain)

    if not normalized or normalized.startswith('*'):
        return reject('invalid', 'not a hostname')

    # 1. Infrastructure and third-party scanner artefacts
    if is_infrastructure_domain(normalized):
        return reject('infrastructure', 'cloud infrastructure or scanner artefact')

    # 2. Legitimate domains
    if is_whitelisted(normalized):
        return reject('whitelisted', 'legitimate Bulgarian service')

    # 3. Domains aimed at another market
    foreign = foreign_market_match(normalized)
    if foreign:
        market, token = foreign
        return reject(f'foreign-market:{market}',
                      f'targets the {market.upper()} market (token "{token}")')

    # 4. Gibberish / stacked subdomain chains
    chain_reason = gibberish_chain_reason(normalized)
    if chain_reason:
        return reject('gibberish-chain', chain_reason)

    # 5. Must live somewhere phishing actually lives (manual entries exempt)
    if not is_manual:
        if not any(normalized.endswith(suffix) for suffix in TARGET_SUFFIXES):
            return reject('not-suspicious-platform',
                          'neither a suspicious TLD nor free hosting')

    score, details = calculate_score(normalized)

    # Entries on the manual watchlist were verified by a human before being
    # added, so they are accepted on that authority. Heuristics exist to find
    # domains nobody has looked at yet; they should not overrule someone who
    # has. The rule-based score is still recorded, and is often low for these
    # (e.g. mvrx.lat, e-uslugivrl.top) precisely because they are the mangled
    # spellings automated matching is worst at.
    if is_manual:
        details['manual_watchlist'] = True
        return {'verdict': VERDICT_PHISHING, 'reason': '',
                'detail': 'human-verified manual watchlist entry',
                'score': score, 'details': details}

    # 6. Must actually impersonate a protected brand. A transaction keyword
    #    on its own ("banking-dashboard-march-2026.pages.dev") is not enough.
    impersonates = (
        bool(details['brand_keywords'])
        or details['homoglyphs_detected']
        or details['typosquatting_detected']
        or details['direct_impersonation']
    )
    if not impersonates:
        return reject('no-brand', 'no protected brand impersonated', score, details)

    # 7. Globally ambiguous brands (DHL, OLX, PayPal, Postbank, Allianz…)
    #    only count when there is an independent Bulgarian signal.
    if not details['bg_context_signals']:
        brands = ', '.join(details['brand_keywords']) or 'brand-like pattern'
        return reject('no-bg-context',
                      f'{brands} abused, but nothing ties it to Bulgaria',
                      score, details)

    if score < SCORE_THRESHOLD:
        return {'verdict': VERDICT_BELOW_THRESHOLD, 'reason': 'below-threshold',
                'detail': f'score {score} < {SCORE_THRESHOLD}',
                'score': score, 'details': details}

    return {'verdict': VERDICT_PHISHING, 'reason': '', 'detail': 'flagged',
            'score': score, 'details': details}


# ==================== DOMAIN VALIDATION ====================

def is_infrastructure_domain(domain: str) -> bool:
    """Check if domain is infrastructure/internal (should be excluded)"""
    domain_lower = domain.lower()
    return any(pattern in domain_lower for pattern in INFRASTRUCTURE_PATTERNS)


def contains_courier_keyword(domain: str) -> Tuple[bool, List[str]]:
    """Backwards-compatible wrapper around strict brand matching"""
    has_brand, brands, _ = contains_brand_impersonation(domain)
    return has_brand, brands


# ==================== FEED MANAGEMENT ====================

def load_existing_feed() -> List[Dict]:
    """Load existing phishing feed from JSON"""
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.warning("⚠️ Feed file corrupted, starting fresh")
            return []
    return []


def save_feed(feed_data: List[Dict]):
    """Save phishing feed to JSON"""
    try:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(feed_data, f, indent=2)
        logging.info(f"✅ Feed saved with {len(feed_data)} entries")
    except Exception as e:
        logging.error(f"❌ Error saving feed: {e}")


def add_to_feed(feed_data: List[Dict], domain: str, score: int, details: Dict,
                source: str) -> bool:
    """
    Append a domain to an in-memory feed list (no duplicates).

    The feed list is passed in and saved once per run by the caller — the old
    implementation reloaded and rewrote the whole file for every single
    detection, which was O(n²) writes per scan.
    """
    for entry in feed_data:
        if entry['domain'] == domain:
            logging.debug(f"Domain {domain} already in feed")
            return False

    feed_data.append({
        'domain': domain,
        'score': score,
        'details': details,
        'detected_at': datetime.datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'source': source
    })
    logging.info(f"➕ Added to feed: {domain} (score: {score})")
    return True


def save_run_stats(scanned_domains: set, phishing_domains: set, elapsed_time: float,
                   excluded_counts: Dict[str, int] = None):
    """Save run statistics with unique phishing domain tracking"""
    existing_stats = {}
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, 'r') as f:
                existing_stats = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            existing_stats = {}

    all_phishing = set(existing_stats.get('all_phishing_domains', []))
    new_phishing = phishing_domains - all_phishing
    all_phishing.update(phishing_domains)

    prev_cumulative = existing_stats.get('cumulative_stats', {})
    prev_total_scanned = prev_cumulative.get('total_domains_scanned',
                                             prev_cumulative.get('total_unique_domains_scanned', 0))
    total_runs = prev_cumulative.get('total_runs', 0) + 1
    total_scanned = prev_total_scanned + len(scanned_domains)

    phishing_rate = (len(all_phishing) / total_scanned * 100) if total_scanned > 0 else 0

    stats = {
        'last_run': datetime.datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'last_run_stats': {
            'domains_processed': len(scanned_domains),
            'phishing_detected': len(phishing_domains),
            'new_unique_phishing': len(new_phishing),
            'elapsed_time': round(elapsed_time, 2),
            'excluded_by_reason': excluded_counts or {}
        },
        'cumulative_stats': {
            # Sum of per-run processed counts. Not deduplicated across runs —
            # the same domain reappearing in URLScan results counts again.
            'total_domains_scanned': total_scanned,
            'total_unique_phishing_found': len(all_phishing),
            'total_runs': total_runs,
            'phishing_detection_rate': round(phishing_rate, 2)
        },
        'all_phishing_domains': sorted(all_phishing)
    }

    try:
        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2)
        logging.info(f"📊 Stats saved: {len(scanned_domains)} scanned, "
                     f"{len(phishing_domains)} phishing ({len(new_phishing)} new) | "
                     f"Totals: {total_scanned} scanned, {len(all_phishing)} phishing")
    except Exception as e:
        logging.error(f"❌ Error saving stats: {e}")


# ==================== MANUAL DOMAIN CHECKER ====================

def check_manual_domains() -> Set[str]:
    """Check manually specified domains directly"""
    if not MANUAL_CHECK_DOMAINS:
        return set()

    logging.info("🔍 Checking manually specified domains...")
    results = {d.strip().lower() for d in MANUAL_CHECK_DOMAINS if d.strip()}
    logging.info(f"   Total manual domains: {len(results)}")
    return results


# ==================== URLSCAN.IO INTEGRATION ====================

# Targeted URLScan queries, highest signal first. Each query is a hostname
# pattern that only a Bulgarian-targeted campaign would produce.
URLSCAN_QUERIES = [
    # --- Direct impersonation of Bulgarian couriers / marketplaces ---
    'page.domain:*econt-bg*',
    'page.domain:*econtbg*',
    'page.domain:*speedy-bg*',
    'page.domain:*speedybg*',
    'page.domain:*bgpost-bg*',
    'page.domain:*bgpost*',
    'page.domain:*olx-bg*',
    'page.domain:*olxbg*',

    # --- .bg-XX.TLD abuse shape (speedy.bg-pv.cfd style) ---
    'page.domain:speedy.bg-* AND page.domain:*.cfd*',
    'page.domain:speedy.bg-* AND page.domain:*.tk*',
    'page.domain:econt.bg-* AND page.domain:*.cfd*',
    'page.domain:econt.bg-* AND page.domain:*.tk*',
    'page.domain:econt.bg-* AND page.domain:*.icu*',
    'page.domain:econt.bg-* AND page.domain:*.click*',
    'page.domain:bgpost.bg-* AND page.domain:*.cfd*',
    'page.domain:olx.bg-* AND page.domain:*.cfd*',

    # --- Online banking brands ---
    'page.domain:*dskdirect*',
    'page.domain:*dsk-direct*',
    'page.domain:*dskmobile*',
    'page.domain:*dsk-mobile*',
    'page.domain:*epostbank*',
    'page.domain:*e-postbank*',
    'page.domain:*bulbankonline*',
    'page.domain:*uac-procredit*',
    'page.domain:*ibanking* AND page.domain:*bg*',
    'page.domain:*fibank* AND page.domain:*bg*',
    'page.domain:*ubb* AND page.domain:*bg*',
    'page.domain:*bdbank*',

    # --- Toll & vignette services (Национално ТОЛ управление + resellers) ---
    'page.domain:*bgtoll*',
    'page.domain:*bg-toll*',
    'page.domain:*tollpass*',
    'page.domain:*toll-pass*',
    'page.domain:*vinetki*',
    'page.domain:*vinetka*',
    'page.domain:*e-vinetka*',
    'page.domain:*evinetka*',
    'page.domain:*digitoll*',
    'page.domain:*toll* AND page.domain:*bg*',

    # --- Bulgarian government / public administration ---
    'page.domain:*mvrbg*',
    'page.domain:*mvr-bg*',
    'page.domain:*mvrgovbg*',
    'page.domain:*mvr* AND page.domain:*bg*',
    'page.domain:*e-uslugi* AND page.domain:*mvr*',
    'page.domain:*euslugi*',
    'page.domain:*egov* AND page.domain:*bg*',
    'page.domain:*nap-bg*',
    'page.domain:*nra-bg*',

    # --- Payment services with a Bulgarian angle ---
    'page.domain:*easypay* AND page.domain:*bg*',
    'page.domain:*epay* AND page.domain:*bg*',
    'page.domain:*borica* AND page.domain:*bg*',
    'page.domain:*mypos* AND page.domain:*bg*',
    'page.domain:*revolut* AND page.domain:*bg*',

    # --- Telecoms ---
    'page.domain:*vivacom*',
    'page.domain:*yettel*',

    # --- Brands on high-risk TLDs ---
    'page.domain:*econt* AND page.domain:*.cfd*',
    'page.domain:*econt* AND page.domain:*.tk*',
    'page.domain:*econt* AND page.domain:*.icu*',
    'page.domain:*speedy* AND page.domain:*.cfd*',
    'page.domain:*speedy* AND page.domain:*.tk*',
    'page.domain:*bgpost* AND page.domain:*.cfd*',
    'page.domain:*olx* AND page.domain:*.cfd*',

    # --- Broad BG catch-all on high-risk TLDs ---
    'page.domain:*bg* AND page.domain:*.cfd*',
    'page.domain:*bg* AND page.domain:*.tk*',
    'page.domain:*bg* AND page.domain:*.icu*',
    'page.domain:*bg* AND page.domain:*.click*',
]

# Recent-submission sweep (last 24h) on the platforms attackers reach for
URLSCAN_RECENT_QUERIES = [
    'page.domain:*.cfd* AND date:>now-24h',
    'page.domain:*.tk* AND date:>now-24h',
    'page.domain:*.xyz* AND date:>now-24h',
    'page.domain:*pages.dev* AND date:>now-24h',
]


def _urlscan_search(query: str) -> Set[str]:
    """Run one URLScan.io search and return the hostnames it reports."""
    domains: Set[str] = set()
    encoded_query = urllib.parse.quote(query)
    url = f"https://urlscan.io/api/v1/search/?q={encoded_query}&size=100"
    headers = {'API-Key': URLSCAN_API_KEY}

    response = requests.get(url, headers=headers, timeout=30)

    if response.status_code == 200:
        for result in response.json().get('results', []):
            domain = result.get('page', {}).get('domain', '')
            if domain:
                domains.add(domain.lower())
    elif response.status_code == 429:
        logging.warning("⚠️ Rate limit hit, waiting 60s...")
        time.sleep(60)
    else:
        logging.warning(f"⚠️ URLScan error {response.status_code}")

    return domains


def fetch_urlscan_targeted() -> Set[str]:
    """Fetch domains from URLScan.io using targeted Bulgarian queries"""
    if not URLSCAN_API_KEY:
        logging.warning("⚠️ Skipping URLScan.io (no API key)")
        return set()

    seen_domains: Set[str] = set()

    for query in URLSCAN_QUERIES:
        try:
            logging.info(f"🔍 URLScan query: {query[:70]}...")
            found = _urlscan_search(query)
            new_count = len(found - seen_domains)
            seen_domains |= found
            logging.info(f"  → {new_count} new domains (total: {len(seen_domains)})")
            time.sleep(2)
        except Exception as e:
            logging.error(f"❌ Query error: {e}")
            continue

    logging.info(f"📊 URLScan.io total: {len(seen_domains)} unique domains")
    return seen_domains


def fetch_urlscan_recent() -> Set[str]:
    """Fetch recent domains from URLScan.io (last 24h)"""
    if not URLSCAN_API_KEY:
        return set()

    seen_domains: Set[str] = set()

    for query in URLSCAN_RECENT_QUERIES:
        try:
            logging.info(f"🔍 Recent: {query[:50]}...")
            seen_domains |= _urlscan_search(query)
            time.sleep(2)
        except Exception as e:
            logging.warning(f"⚠️ Recent query error: {e}")
            continue

    logging.info(f"📊 Recent submissions: {len(seen_domains)} domains")
    return seen_domains


# ==================== MAIN SCANNING LOGIC ====================

def scan_domains(duration: int = None, sources: List[str] = None) -> None:
    """Main scanning function"""
    sources = sources or ['urlscan', 'manual']
    start_time = datetime.datetime.now(timezone.utc)
    processed_domains: Set[str] = set()
    phishing_domains: Set[str] = set()
    excluded_counts: Dict[str, int] = {}

    logging.info("=" * 60)
    logging.info("🚨 Bulgarian Phishing Domain Scanner")
    logging.info("=" * 60)
    logging.info(f"Sources: {', '.join(sources)}")
    logging.info(f"Score threshold: {SCORE_THRESHOLD}")
    logging.info(f"Whitelisted domains: {len(WHITELISTED_DOMAINS)}")
    logging.info(f"Brand keywords: {len(BRAND_KEYWORDS)} "
                 f"({len(BG_EXCLUSIVE_BRANDS)} BG-exclusive, "
                 f"{len(AMBIGUOUS_BRANDS)} ambiguous)")
    logging.info("=" * 60)

    all_domains: Set[str] = set()
    manual_set: Set[str] = set()

    if 'manual' in sources:
        manual_set = check_manual_domains()
        all_domains |= manual_set

    if 'urlscan' in sources:
        logging.info("🔍 Querying URLScan.io...")
        all_domains |= fetch_urlscan_targeted()
        all_domains |= fetch_urlscan_recent()

    logging.info("=" * 60)
    logging.info(f"📊 Processing {len(all_domains)} total domains...")
    logging.info("=" * 60)

    feed_data = load_existing_feed()
    added = 0

    for domain in sorted(all_domains):
        if duration:
            elapsed = (datetime.datetime.now(timezone.utc) - start_time).total_seconds()
            if elapsed > duration:
                logging.info(f"⏱️ Duration limit reached. Processed {len(processed_domains)} domains")
                break

        # Normalise before anything else, so www.x, ww38.x and x are one
        # domain rather than three separate feed entries. Scoring already
        # normalised internally, but the raw hostname was what got stored —
        # which is how mirror duplicates kept accumulating in the feed.
        raw = domain.strip().lower()
        domain = normalize_domain(raw)
        if not domain or domain in processed_domains:
            continue

        processed_domains.add(domain)

        result = evaluate_domain(domain, is_manual=domain in manual_set)
        verdict = result['verdict']

        if verdict == VERDICT_EXCLUDED:
            reason = result['reason']
            excluded_counts[reason] = excluded_counts.get(reason, 0) + 1
            logging.debug(f"[SKIP:{reason}] {domain} — {result['detail']}")
            continue

        if verdict == VERDICT_BELOW_THRESHOLD:
            logging.info(f"[SUSPICIOUS] {domain} (score: {result['score']}) - below threshold")
            continue

        details = result['details']
        phishing_domains.add(domain)

        triggers = []
        if details['brand_keywords']:
            triggers.append(f"Brand: {', '.join(details['brand_keywords'])}")
        if details['bg_context_signals']:
            triggers.append(f"BG: {', '.join(details['bg_context_signals'][:3])}")
        if details['free_hosting']:
            triggers.append(f"Hosting: {details['free_hosting']}")
        if details['suspicious_tld']:
            triggers.append(f"TLD: {details['suspicious_tld']}")
        if details['transaction_keywords']:
            triggers.append(f"Keywords: {', '.join(details['transaction_keywords'])}")
        if details.get('bg_tld_abuse'):
            triggers.append("Pattern: .bg-XX.TLD")

        logging.warning(
            f"🚨 PHISHING DETECTED: {domain} | Score: {result['score']}/100 | "
            f"{' | '.join(triggers)}"
        )

        if add_to_feed(feed_data, domain, result['score'], details,
                       'manual' if domain in manual_set else 'scanner'):
            added += 1

    if added:
        save_feed(feed_data)
    else:
        logging.info("No new domains to write to the feed")

    elapsed = (datetime.datetime.now(timezone.utc) - start_time).total_seconds()
    save_run_stats(processed_domains, phishing_domains, elapsed, excluded_counts)

    logging.info("=" * 60)
    logging.info("✅ Scan Complete!")
    logging.info("=" * 60)
    logging.info(f"Domains processed: {len(processed_domains)}")
    logging.info(f"Phishing domains detected: {len(phishing_domains)} ({added} new)")
    if excluded_counts:
        summary = ', '.join(f'{k}={v}' for k, v in sorted(excluded_counts.items()))
        logging.info(f"Excluded: {summary}")
    logging.info(f"Elapsed time: {elapsed:.1f}s")
    logging.info("=" * 60)


# ==================== MAIN ====================

def explain_domain(domain: str) -> int:
    """Print a full explanation for one hostname. Returns a shell exit code."""
    domain = domain.strip().lower()
    result = evaluate_domain(domain, is_manual=domain in MANUAL_CHECK_DOMAINS)

    print("=" * 60)
    print(f"Domain:    {domain}")
    print(f"Verdict:   {result['verdict'].upper()}")
    print(f"Reason:    {result['reason'] or 'n/a'} — {result['detail']}")
    print(f"Score:     {result['score']}/100 (threshold {SCORE_THRESHOLD})")
    print("=" * 60)

    details = result['details']
    if details:
        print(f"Brands matched:      {details['brand_keywords'] or '—'}")
        print(f"  BG-exclusive:      {details['bg_exclusive_brands'] or '—'}")
        print(f"  Ambiguous/global:  {details['ambiguous_brands'] or '—'}")
        print(f"Bulgarian signals:   {details['bg_context_signals'] or '—'}")
        print(f"Direct impersonation:{details['direct_impersonation']}")
        print(f"Homoglyphs:          {details['homoglyphs_used'] or '—'}")
        print(f"Typosquatting:       {details['typosquatting_details'] or '—'}")
        print(f"Suspicious TLD:      {details['suspicious_tld'] or '—'}")
        print(f"Free hosting:        {details['free_hosting'] or '—'}")
        print(f"Transaction words:   {details['transaction_keywords'] or '—'}")
        print(f"Multiple hyphens:    {details['multiple_hyphens']}")
        print(f"Subdomain stacking:  {details['subdomain_stacking']}")
        print(f"High entropy:        {details['high_entropy']}")
        print(f".bg-XX.TLD pattern:  {details.get('bg_tld_abuse', False)}")
        print("=" * 60)

    if result['verdict'] == VERDICT_PHISHING:
        print("🚨 PHISHING — would be added to the feed")
        return 0
    print("ℹ️ Not added to the feed")
    return 0


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Bulgarian Phishing Domain Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--duration', type=int, default=None,
                        help='Maximum runtime in seconds')
    parser.add_argument('--sources', nargs='+', choices=['urlscan', 'manual'],
                        default=['urlscan', 'manual'],
                        help='Data sources to use (default: urlscan manual)')
    parser.add_argument('--check-domain', type=str,
                        help='Explain the verdict for one hostname and exit')

    args = parser.parse_args()

    if args.check_domain:
        sys.exit(explain_domain(args.check_domain))

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    if not os.path.exists(OUTPUT_FILE):
        save_feed([])

    scan_domains(duration=args.duration, sources=args.sources)


if __name__ == "__main__":
    try:
        main()
        sys.exit(0)
    except KeyboardInterrupt:
        logging.info("\n⚠️ Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
