#!/usr/bin/env python3
"""
Bulgarian Phishing Domain Detector - REFINED VERSION
=======================================================

Features:
- Strict brand keyword matching (prevents false positives)
- Homoglyph detection (catches ec0nt, sρeedy, есоnt)
- Typosquatting detection (catches spedy, econnt)
- Direct impersonation bonus (econt-bg, econtbg patterns)
- Smart Bulgarian context detection
- 7 new whitelisted Bulgarian services (sameday.bg, easypay.bg, etc.)
- URLScan.io integration with 40 optimized queries
- Focus on Bulgarian-targeted phishing

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
from typing import List, Dict, Tuple, Set

# ==================== CONFIGURATION ====================

# Score threshold for flagging domains
SCORE_THRESHOLD = 70

# API Keys from environment
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY")

if not URLSCAN_API_KEY:
    logging.warning("⚠️ URLSCAN_API_KEY not set. URLScan.io queries will be skipped.")

# ==================== MANUAL DOMAIN LIST ====================
# Add suspicious domains here for direct checking
MANUAL_CHECK_DOMAINS = [
    # Add domains here as you discover them
    # 'speedy.bg-pv.cfd',
]

# ==================== WHITELISTED DOMAINS ====================
WHITELISTED_DOMAINS = [
    # Courier services
    'econt.com',
    'econt.bg',
    'speedy.bg',
    'intime.bg',
    'interlogistica.bg',
    'olx.bg',
    'bgpost.bg',
    'bulgariapost.bg',
    'samedaybg.com',
    'boxnow.bg',
    'cityexpress.bg',
    'expressone.bg',
    # Additional Bulgarian couriers
    'sameday.bg',
    'evropat.bg',
    'dhl.bg',
    # Bulgarian payment/postal services
    'easypay.bg',
    'epay.bg',
    'borica.bg',
    'fastpay.bg'
]

# ==================== BRAND KEYWORDS ====================
# These are the core brands we protect
BRAND_KEYWORDS = [
    # Main couriers
    'econt',
    'speedy',
    'bulgariapost',
    'bgpost',
    'bg-post',
    'olx',
    'dhl',
    # Additional couriers
    'sameday',
    'samedaybg',
    'evropat',
    'boxnow',
    'boxnowbg',
    'cityexpress',
    'cityexpressbg',
    'expressone',
    'expressonebg',
    'intime',
    'interlogistica',
    # Payment services
    'easypay',
    'epay',
    'borica',
    'fastpay'
]

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
    'klient',
    'pratka',
    'dostavka',
    'usluga'
]

# ==================== GEOGRAPHIC INDICATORS ====================
GEO_INDICATORS = ['.bg', 'bulgaria', 'bg-', '-bg']

# ==================== SUSPICIOUS TLDs ====================
SUSPICIOUS_TLDS = (
    '.cfd', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz',
    '.club', '.online', '.site', '.space', '.click', '.link',
    '.live', '.icu', '.buzz', '.cam', '.rest', '.store', '.tech',
    '.website', '.world', '.pw', '.cc', '.sbs'  # Added .sbs
)

# ==================== FREE HOSTING PLATFORMS ====================
FREE_HOSTING_SUFFIXES = (
    '.web.app', '.firebaseapp.com', '.herokuapp.com', '.pages.dev',
    '.netlify.app', '.vercel.app', '.onrender.com', '.render.com',
    '.fly.dev', '.surge.sh', '.gitlab.io', '.github.io',
    '.repl.co', '.replit.dev', '.replit.app', '.glitch.me',
    '.cyclic.app', '.railway.app', '.deta.dev',
    '.azurestaticapps.net', '.amplifyapp.com', '.cloudflare.com'
)

TARGET_SUFFIXES = FREE_HOSTING_SUFFIXES + SUSPICIOUS_TLDS

# ==================== INFRASTRUCTURE EXCLUSIONS ====================
INFRASTRUCTURE_PATTERNS = (
    '.postgres.render.com', '.redis.render.com', '.internal.render.com',
    'replica-', '.rds.amazonaws.com', '.elb.amazonaws.com',
    '.elasticache.amazonaws.com', '.drive.amazonaws.com',
    'kms.amazonaws.com', 's3.amazonaws.com', 's3-deprecated',
    'content-eu.drive', 'content-jp.drive',
    '.database.windows.net', '.redis.cache.windows.net',
    '.workers.dev', '--deploy-preview-', 'preview.vercel.app',
    'bgptools',  # BGP monitoring tools (not phishing)
)

# ==================== OUTPUT CONFIGURATION ====================
OUTPUT_FILE = 'feed/phishing_feed.json'
STATS_FILE = 'feed/stats.json'

# ==================== LOGGING SETUP ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# ==================== WHITELIST HELPER FUNCTIONS ====================

def is_whitelisted(domain: str) -> bool:
    """Check if domain is legitimate (whitelisted) and should be excluded"""
    domain_lower = domain.lower()
    
    if domain_lower.startswith('www.'):
        domain_lower = domain_lower[4:]
    
    for whitelisted in WHITELISTED_DOMAINS:
        if domain_lower == whitelisted:
            return True
        if domain_lower.endswith('.' + whitelisted):
            return True
    
    return False


def contains_brand_impersonation(domain: str) -> Tuple[bool, List[str]]:
    """
    Check if domain contains brand keywords with STRICT matching
    
    Prevents false positives like:
    - "econt" inside "content" → NOT a match
    - "olx" inside random strings → NOT a match
    - "speedy" in "speedytest" → NOT a match
    
    Only matches when brand appears as:
    - Start of domain: speedy.bg-pv.cfd ✓
    - After separator: www.speedy.com ✓, bg-speedy.cfd ✓
    - Before separator: speedy-bg.cfd ✓, econt.com ✓
    - Standalone: domain-speedy, speedy ✓
    """
    domain_lower = domain.lower()
    matched_brands = []
    
    # Remove www. prefix
    check_domain = domain_lower
    if check_domain.startswith('www.'):
        check_domain = check_domain[4:]
    
    for brand in BRAND_KEYWORDS:
        # STRICT patterns - brand must be at word boundary
        patterns = [
            f'^{brand}\\.',           # speedy.bg-pv.cfd (start, before dot)
            f'^{brand}-',              # speedy-bg.cfd (start, before hyphen)
            f'^{brand}$',              # speedy (entire domain name part)
            f'\\.{brand}\\.',          # www.speedy.com (between dots)
            f'\\.{brand}-',            # info.speedy-bg.cfd (after dot, before hyphen)
            f'\\.{brand}$',            # domain.speedy (after dot, at end)
            f'-{brand}\\.',            # bg-speedy.cfd (after hyphen, before dot)
            f'-{brand}-',              # x-speedy-bg (between hyphens)
            f'-{brand}$',              # domain-speedy (after hyphen, at end)
        ]
        
        # Check all patterns
        for pattern in patterns:
            if re.search(pattern, check_domain):
                matched_brands.append(brand)
                break  # Only count each brand once
    
    return (len(matched_brands) > 0, matched_brands)


# ==================== HOMOGLYPH DETECTION ====================

# Common homoglyphs for Latin characters (Cyrillic and similar-looking chars)
HOMOGLYPH_MAP = {
    'a': ['а', 'ạ', 'ą', 'ά', 'α'],  # Cyrillic 'а', various accented
    'c': ['с', 'ϲ', 'ć', 'ċ'],        # Cyrillic 'с', Greek
    'e': ['е', 'ė', 'ę', 'ё', 'έ', 'ε'],  # Cyrillic 'е', 'ё', Greek
    'i': ['і', 'ı', 'í', 'ì', 'ï', 'ι'],  # Cyrillic 'і', Turkish, Greek
    'o': ['о', 'ο', 'ọ', 'ó', 'ò', '0'],  # Cyrillic 'о', Greek, zero
    'p': ['р', 'ρ', 'þ'],              # Cyrillic 'р', Greek 'ρ'
    's': ['ѕ', 'ś', 'ş'],              # Cyrillic 'ѕ'
    't': ['т', 'τ'],                   # Cyrillic 'т', Greek 'τ'
    'u': ['υ', 'ú', 'ù'],              # Greek 'υ'
    'x': ['х', 'χ'],                   # Cyrillic 'х', Greek 'χ'
    'y': ['у', 'ү', 'ý'],              # Cyrillic 'у', 'ү'
}

def detect_homoglyphs(domain: str, brands: List[str]) -> Tuple[bool, List[str]]:
    """
    Detect homoglyph attacks where similar-looking characters replace Latin letters.
    
    Examples:
    - econt → ec0nt (0 instead of o)
    - speedy → sρeedy (Greek ρ instead of p)
    - econt → есоnt (Cyrillic е, с, о instead of Latin e, c, o)
    
    Returns:
        (has_homoglyphs, list_of_homoglyphs_found)
    """
    domain_lower = domain.lower()
    
    # Remove www. prefix
    if domain_lower.startswith('www.'):
        domain_lower = domain_lower[4:]
    
    homoglyphs_found = []
    
    # Check each brand
    for brand in brands:
        # Extract domain parts
        parts = re.split(r'[.\-]', domain_lower)
        
        for part in parts:
            # Skip if too short or too different in length
            if len(part) < 3 or abs(len(part) - len(brand)) > 2:
                continue
            
            # Check if this part contains homoglyphs of the brand
            # Convert part to ASCII-only to detect non-ASCII chars
            has_non_ascii = not all(ord(c) < 128 for c in part)
            
            if has_non_ascii:
                # Normalize homoglyphs to their Latin equivalents
                normalized = normalize_homoglyphs(part)
                
                # Check if normalized version matches brand
                if normalized == brand or (len(normalized) >= 4 and normalized in brand):
                    homoglyphs_found.append(part)
                    break
            
            # Also check for zero instead of 'o' (ec0nt)
            if '0' in part:
                part_with_o = part.replace('0', 'o')
                if part_with_o == brand:
                    homoglyphs_found.append(part)
                    break
    
    return (len(homoglyphs_found) > 0, homoglyphs_found)


def normalize_homoglyphs(text: str) -> str:
    """Normalize homoglyphs to their Latin equivalents"""
    result = []
    for char in text:
        # Try to find this char in homoglyph map
        found = False
        for latin, homoglyphs in HOMOGLYPH_MAP.items():
            if char in homoglyphs:
                result.append(latin)
                found = True
                break
        
        if not found:
            # Keep special case: 0 → o
            if char == '0':
                result.append('o')
            else:
                result.append(char)
    
    return ''.join(result)


# ==================== TYPOSQUATTING DETECTION ====================

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein (edit) distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Cost of insertions, deletions, or substitutions
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def detect_typosquatting(domain: str, brands: List[str]) -> Tuple[bool, List[Dict]]:
    """
    Detect typosquatting patterns:
    - Missing character: speedy → spedy, econt → ecnt
    - Extra character: econt → econnt, speedy → speeedy
    - Swapped characters: speedy → spedey, econt → ecnot
    - Similar character: econt → rcont (e→r adjacent on keyboard)
    
    Examples:
    - spedy (missing 'e' from speedy)
    - econnt (double 'n' in econt)
    - sρeedy (NOT typosquatting, this is homoglyph - Greek ρ)
    
    Returns:
        (has_typosquatting, list_of_detected_typos)
        Each typo is: {'brand': 'speedy', 'typo': 'spedy', 'distance': 1, 'type': 'missing_char'}
    """
    domain_lower = domain.lower()
    detected_typos = []
    
    # Remove www. prefix
    if domain_lower.startswith('www.'):
        domain_lower = domain_lower[4:]
    
    # Extract words from domain (split by dots and hyphens)
    parts = re.split(r'[.\-]', domain_lower)
    
    for brand in brands:
        # Skip very short brands to avoid false positives
        if len(brand) < 4:
            continue
        
        for part in parts:
            # Skip if part is too short or too different in length
            if len(part) < 3:
                continue
            
            # Calculate edit distance
            distance = levenshtein_distance(part, brand)
            
            # Distance of 1-2 = likely typosquatting
            # But only if lengths are similar (within 2 chars)
            length_diff = abs(len(part) - len(brand))
            
            if 0 < distance <= 2 and length_diff <= 2:
                # Make sure it's not an exact match
                if part != brand:
                    # Found potential typosquatting
                    detected_typos.append({
                        'brand': brand,
                        'typo': part,
                        'distance': distance,
                        'type': classify_typo_type(brand, part)
                    })
    
    return (len(detected_typos) > 0, detected_typos)


def classify_typo_type(original: str, typo: str) -> str:
    """Classify the type of typo for better analysis"""
    if len(typo) < len(original):
        return 'missing_char'
    elif len(typo) > len(original):
        return 'extra_char'
    else:
        # Check if it's a swap
        differences = sum(1 for a, b in zip(original, typo) if a != b)
        if differences == 2:
            # Check if it's adjacent swap
            for i in range(len(original) - 1):
                if original[i] == typo[i+1] and original[i+1] == typo[i]:
                    return 'swapped_chars'
        return 'substitution'


# ==================== SCORING SYSTEM ====================

def calculate_score(domain: str) -> Tuple[int, Dict]:
    """
    Calculate phishing suspicion score (0-100, max possible: 195)
    
    ENHANCED: Now includes homoglyph and typosquatting detection
    FOCUSED: Prioritizes Bulgarian (.bg) context
    """
    score = 0
    details = {
        'brand_keywords': [],
        'transaction_keywords': [],
        'geo_indicators': [],
        'suspicious_tld': None,
        'free_hosting': None,
        'multiple_hyphens': False,
        'numeric_suffix': False,
        'subdomain_stacking': False,
        'high_entropy': False,
        'homoglyphs_detected': False,
        'homoglyphs_used': [],
        'typosquatting_detected': False,
        'typosquatting_details': []
    }
    
    domain_lower = domain.lower()
    
    if domain_lower.startswith('www.'):
        domain_lower = domain_lower[4:]
    
    # 1. BRAND KEYWORD DETECTION (+40) - STRICT MATCHING
    has_brand, matched_brands = contains_brand_impersonation(domain)
    if has_brand:
        score += 40
        details['brand_keywords'] = matched_brands
    
    # 2. HOMOGLYPH DETECTION (+30) - Advanced phishing technique
    has_homoglyphs, homoglyphs_list = detect_homoglyphs(domain, BRAND_KEYWORDS)
    if has_homoglyphs:
        score += 30
        details['homoglyphs_detected'] = True
        details['homoglyphs_used'] = homoglyphs_list
    
    # 3. TYPOSQUATTING DETECTION (+25) - Common phishing technique
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
    
    # 6. GEOGRAPHIC INDICATOR (+15) - BULGARIA-FOCUSED
    has_bg_context = False
    for geo in GEO_INDICATORS:
        if geo in domain_lower:
            score += 15
            details['geo_indicators'].append(geo)
            has_bg_context = True
            break
    
    # 7. TRANSACTION KEYWORDS (+10)
    for keyword in TRANSACTION_KEYWORDS:
        if keyword in domain_lower:
            score += 10
            details['transaction_keywords'].append(keyword)
            break
    
    # 8. MULTIPLE HYPHENS (+10)
    hyphen_count = domain_lower.count('-')
    if hyphen_count >= 2:
        score += 10
        details['multiple_hyphens'] = True
    
    # 9. NUMERIC SUFFIX (+10)
    if re.search(r'-\d{3,}\.', domain_lower) or re.search(r'\d{4,}\.', domain_lower):
        score += 10
        details['numeric_suffix'] = True
    
    # 10. SUBDOMAIN STACKING (+10)
    parts = domain_lower.split('.')
    if len(parts) >= 4:
        score += 10
        details['subdomain_stacking'] = True
    
    # 11. HIGH ENTROPY / RANDOMNESS (+10)
    domain_name = domain_lower.split('.')[0]
    if len(domain_name) > 10:
        consonant_clusters = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{3,}', domain_name))
        mixed_alphanum = len(re.findall(r'[a-z]+\d+[a-z]+|\d+[a-z]+\d+', domain_name))
        
        if consonant_clusters >= 2 or mixed_alphanum >= 2:
            score += 10
            details['high_entropy'] = True
    
    # BONUS: .bg-XX.TLD pattern (+10) - BULGARIA-SPECIFIC ABUSE
    if re.search(r'\.bg-[a-z]{2,4}\.(cfd|tk|ml|ga|cf|gq|xyz|online|site|click|icu)', domain_lower):
        score += 10
        details['bg_tld_abuse'] = True
        has_bg_context = True
    
    # SMART BULGARIAN CONTEXT DETECTION
    # Check for 'bg' or 'bulgaria' ANYWHERE in the domain (not just geo indicators)
    if not has_bg_context:
        if 'bg' in domain_lower or 'bulgaria' in domain_lower:
            has_bg_context = True
    
    # BONUS: Direct impersonation of whitelisted domains (+15)
    # Patterns like: econt-bg, econtbg, speedy-bg, speedybg
    direct_impersonation_patterns = [
        r'econt-?bg',
        r'speedy-?bg', 
        r'bgpost-?bg',
        r'olx-?bg',
        r'sameday-?bg',
        r'easypay-?bg',
        r'epay-?bg',
        r'borica-?bg',
        r'bg-?econt',
        r'bg-?speedy',
        r'bg-?post',
        r'bg-?olx',
    ]
    
    for pattern in direct_impersonation_patterns:
        if re.search(pattern, domain_lower):
            score += 15
            details['direct_impersonation'] = True
            has_bg_context = True  # These are clearly Bulgarian-focused
            break
    
    # REFINED PENALTY: Only for weak/generic matches without ANY Bulgarian connection
    # Apply ONLY if:
    # 1. Has brand/homoglyph/typo detection (triggered on brand name)
    # 2. NO Bulgarian context whatsoever (no 'bg', no 'bulgaria', no geo indicators)
    # 3. NOT a direct impersonation pattern
    #
    # This filters out:
    # ✓ gomarketplacecontent.cfd (has 'econt' inside 'content', no 'bg')
    # ✓ yandex.speedyz.top (weak typo, no 'bg')
    # 
    # But keeps:
    # ✓ econt-bg.tk (has brand + 'bg')
    # ✓ econtbg.cfd (has brand + 'bg')
    # ✓ speedy-bulgaria.com (has brand + 'bulgaria')
    
    apply_penalty = False
    if (has_brand or has_homoglyphs or has_typos) and not has_bg_context:
        # Additional check: is this a WEAK match?
        # Only penalize if it's not a direct/strong brand match
        if not details.get('direct_impersonation', False):
            apply_penalty = True
    
    if apply_penalty:
        score -= 20
        details['non_bg_context_penalty'] = True
    
    score = min(max(score, 0), 100)  # Keep between 0-100
    
    return score, details


# ==================== DOMAIN VALIDATION ====================

def is_infrastructure_domain(domain: str) -> bool:
    """Check if domain is infrastructure/internal (should be excluded)"""
    domain_lower = domain.lower()
    return any(pattern in domain_lower for pattern in INFRASTRUCTURE_PATTERNS)


def contains_courier_keyword(domain: str) -> Tuple[bool, List[str]]:
    """Check if domain contains courier/brand keywords using STRICT matching"""
    return contains_brand_impersonation(domain)


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


def add_to_feed(domain: str, score: int, details: Dict, source: str):
    """Add a suspicious domain to the feed (no duplicates)"""
    feed_data = load_existing_feed()
    
    for entry in feed_data:
        if entry['domain'] == domain:
            logging.debug(f"Domain {domain} already in feed")
            return
    
    entry = {
        'domain': domain,
        'score': score,
        'details': details,
        'detected_at': datetime.datetime.now(timezone.utc).isoformat() + 'Z',
        'source': source
    }
    
    feed_data.append(entry)
    save_feed(feed_data)
    logging.info(f"➕ Added to feed: {domain} (score: {score})")


def save_run_stats(domains_processed: int, new_findings: int, elapsed_time: float):
    """Save run statistics"""
    stats = {
        'last_run': datetime.datetime.now(timezone.utc).isoformat() + 'Z',
        'domains_processed': domains_processed,
        'new_findings': new_findings,
        'elapsed_time': round(elapsed_time, 2)
    }
    
    try:
        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2)
        logging.info(f"📊 Stats saved")
    except Exception as e:
        logging.error(f"❌ Error saving stats: {e}")


# ==================== MANUAL DOMAIN CHECKER ====================

def check_manual_domains() -> Set[str]:
    """Check manually specified domains directly"""
    if not MANUAL_CHECK_DOMAINS:
        return set()
    
    logging.info("🔍 Checking manually specified domains...")
    results = set()
    
    for domain in MANUAL_CHECK_DOMAINS:
        domain = domain.strip().lower()
        if domain:
            results.add(domain)
            logging.info(f"   Added manual domain: {domain}")
    
    logging.info(f"   Total manual domains: {len(results)}")
    return results


# ==================== URLSCAN.IO INTEGRATION ====================

def fetch_urlscan_targeted() -> Set[str]:
    """
    Fetch domains from URLScan.io using targeted queries
    
    IMPROVED: Now includes equal coverage for:
    - speedy, econt (already had good coverage)
    - bgpost, olx (NOW ADDED - same pattern coverage)
    """
    if not URLSCAN_API_KEY:
        logging.warning("⚠️ Skipping URLScan.io (no API key)")
        return set()
    
    seen_domains = set()
    
    # OPTIMIZED: Prioritize direct Bulgarian brand impersonation patterns
    # These catch: econt-bg.tk, econt-bg-XX.cfd, econtbg.tk, etc.
    search_queries = [
        # HIGHEST PRIORITY: Direct impersonation patterns
        # econt-bg, econtbg, econt-bg-XX variations
        'page.domain:*econt-bg*',
        'page.domain:*econtbg*',
        'page.domain:*speedy-bg*',
        'page.domain:*speedybg*',
        'page.domain:*bgpost-bg*',
        'page.domain:*olx-bg*',
        'page.domain:*olxbg*',
        
        # PRIORITY 2: .bg-XX.TLD patterns (speedy.bg-pv.cfd style)
        'page.domain:speedy.bg-* AND page.domain:*.cfd*',
        'page.domain:econt.bg-* AND page.domain:*.cfd*',
        'page.domain:econt.bg-* AND page.domain:*.tk*',
        'page.domain:econt.bg-* AND page.domain:*.icu*',
        'page.domain:econt.bg-* AND page.domain:*.click*',
        'page.domain:speedy.bg-* AND page.domain:*.tk*',
        'page.domain:bgpost.bg-* AND page.domain:*.cfd*',
        'page.domain:olx.bg-* AND page.domain:*.cfd*',
        
        # PRIORITY 3: Brand + BG patterns (broad catch)
        'page.domain:*econt* AND page.domain:*bg*',
        'page.domain:*speedy* AND page.domain:*bg*',
        'page.domain:*bgpost* AND page.domain:*bg*',
        'page.domain:*olx* AND page.domain:*bg*',
        'page.domain:*sameday* AND page.domain:*bg*',
        'page.domain:*easypay* AND page.domain:*bg*',
        'page.domain:*epay* AND page.domain:*bg*',
        'page.domain:*borica* AND page.domain:*bg*',
        
        # PRIORITY 4: Brands on high-risk TLDs
        'page.domain:*econt* AND page.domain:*.cfd*',
        'page.domain:*econt* AND page.domain:*.tk*',
        'page.domain:*econt* AND page.domain:*.icu*',
        'page.domain:*speedy* AND page.domain:*.cfd*',
        'page.domain:*speedy* AND page.domain:*.tk*',
        'page.domain:*bgpost* AND page.domain:*.cfd*',
        'page.domain:*olx* AND page.domain:*.cfd*',
        
        # PRIORITY 5: BG + suspicious TLDs (catch-all for Bulgarian context)
        'page.domain:*bg* AND page.domain:*.cfd*',
        'page.domain:*bg* AND page.domain:*.tk*',
        'page.domain:*bg* AND page.domain:*.icu*',
        'page.domain:*bg* AND page.domain:*.click*',
    ]
    
    for query in search_queries[:40]:  # Increased to catch all direct impersonation patterns
        try:
            encoded_query = urllib.parse.quote(query)
            url = f"https://urlscan.io/api/v1/search/?q={encoded_query}&size=100"
            headers = {'API-Key': URLSCAN_API_KEY}
            
            logging.info(f"🔍 URLScan query: {query[:70]}...")
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                new_count = 0
                for result in data.get('results', []):
                    domain = result.get('page', {}).get('domain', '')
                    if domain and domain not in seen_domains:
                        seen_domains.add(domain)
                        new_count += 1
                
                logging.info(f"  → {new_count} new domains (total: {len(seen_domains)})")
                
            elif response.status_code == 429:
                logging.warning(f"⚠️ Rate limit hit, waiting 60s...")
                time.sleep(60)
                continue
            else:
                logging.warning(f"⚠️ URLScan error {response.status_code}")
            
            time.sleep(2)  # Rate limiting
            
        except Exception as e:
            logging.error(f"❌ Query error: {e}")
            continue
    
    logging.info(f"📊 URLScan.io total: {len(seen_domains)} unique domains")
    return seen_domains


def fetch_urlscan_recent() -> Set[str]:
    """Fetch recent domains from URLScan.io (last 24h)"""
    if not URLSCAN_API_KEY:
        return set()
    
    seen_domains = set()
    
    queries = [
        # Recent suspicious TLDs
        'page.domain:*.cfd* AND date:>now-24h',
        'page.domain:*.tk* AND date:>now-24h',
        'page.domain:*.xyz* AND date:>now-24h',
        
        # Recent free hosting
        'page.domain:*pages.dev* AND date:>now-24h',
    ]
    
    for query in queries:
        try:
            encoded_query = urllib.parse.quote(query)
            url = f"https://urlscan.io/api/v1/search/?q={encoded_query}&size=100"
            headers = {'API-Key': URLSCAN_API_KEY}
            
            logging.info(f"🔍 Recent: {query[:50]}...")
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    domain = result.get('page', {}).get('domain', '')
                    if domain:
                        seen_domains.add(domain)
            
            time.sleep(2)
            
        except Exception as e:
            logging.warning(f"⚠️ Recent query error: {e}")
            continue
    
    logging.info(f"📊 Recent submissions: {len(seen_domains)} domains")
    return seen_domains


# ==================== MAIN SCANNING LOGIC ====================

def scan_domains(duration: int = None, sources: List[str] = ['urlscan', 'manual']) -> None:
    """Main scanning function"""
    start_time = datetime.datetime.now(timezone.utc)
    processed_domains = set()
    findings_count = 0
    
    logging.info("=" * 60)
    logging.info("🚨 Bulgarian Phishing Domain Scanner - FIXED")
    logging.info("=" * 60)
    logging.info(f"Sources: {', '.join(sources)}")
    logging.info(f"Score threshold: {SCORE_THRESHOLD}")
    logging.info(f"Whitelisted domains: {len(WHITELISTED_DOMAINS)}")
    logging.info(f"Brand keywords: {len(BRAND_KEYWORDS)}")
    logging.info("=" * 60)
    
    all_domains = set()
    
    # 0. Manual domains
    if 'manual' in sources:
        manual_domains = check_manual_domains()
        all_domains.update(manual_domains)
    
    # 1. URLScan.io
    if 'urlscan' in sources:
        logging.info("🔍 Querying URLScan.io...")
        logging.info("   Coverage: speedy, econt, bgpost, olx (EQUAL)")
        
        targeted_domains = fetch_urlscan_targeted()
        all_domains.update(targeted_domains)
        
        recent_domains = fetch_urlscan_recent()
        all_domains.update(recent_domains)
    
    # Process all domains
    logging.info("=" * 60)
    logging.info(f"📊 Processing {len(all_domains)} total domains...")
    logging.info("=" * 60)
    
    for domain in all_domains:
        if duration:
            elapsed = (datetime.datetime.now(timezone.utc) - start_time).total_seconds()
            if elapsed > duration:
                logging.info(f"⏱️ Duration limit reached. Processed {len(processed_domains)} domains")
                break
        
        domain = domain.strip()
        
        if not domain or domain.startswith('*') or domain in processed_domains:
            continue
        
        processed_domains.add(domain)
        
        # FILTER 1: Skip infrastructure domains
        if is_infrastructure_domain(domain):
            logging.debug(f"[SKIP] Infrastructure: {domain}")
            continue
        
        # FILTER 2: Skip whitelisted legitimate domains
        if is_whitelisted(domain):
            logging.debug(f"[SKIP] Whitelisted: {domain}")
            continue
        
        # FILTER 3: Must be on suspicious platform/TLD (unless manual)
        if domain not in MANUAL_CHECK_DOMAINS:
            matches_suffix = any(domain.endswith(suffix) for suffix in TARGET_SUFFIXES)
            if not matches_suffix:
                logging.debug(f"[SKIP] Not on suspicious platform: {domain}")
                continue
        
        # Check for brand/courier keywords
        has_courier, courier_keywords = contains_courier_keyword(domain)
        
        # SCORE: Calculate suspicion score
        score, details = calculate_score(domain)
        
        # Additional check for non-brand domains
        if not has_courier:
            has_transaction = any(kw in domain.lower() for kw in TRANSACTION_KEYWORDS)
            if not has_transaction and score < 60:
                logging.debug(f"[SKIP] No indicators: {domain} (score: {score})")
                continue
        
        if score >= SCORE_THRESHOLD:
            findings_count += 1
            
            # Determine what triggered the detection
            triggers = []
            if details['brand_keywords']:
                triggers.append(f"Brand: {', '.join(details['brand_keywords'])}")
            if details['free_hosting']:
                triggers.append(f"Hosting: {details['free_hosting']}")
            if details['suspicious_tld']:
                triggers.append(f"TLD: {details['suspicious_tld']}")
            if details['transaction_keywords']:
                triggers.append(f"Keywords: {', '.join(details['transaction_keywords'])}")
            if details.get('bg_tld_abuse'):
                triggers.append("Pattern: .bg-XX.TLD")
            
            # Log detection
            logging.warning(
                f"🚨 PHISHING DETECTED: {domain} | "
                f"Score: {score}/100 | "
                f"{' | '.join(triggers)}"
            )
            
            # Add to feed
            add_to_feed(domain, score, details, 'scanner')
        else:
            logging.info(
                f"[SUSPICIOUS] {domain} (score: {score}) - Below threshold"
            )
    
    # Save statistics
    elapsed = (datetime.datetime.now(timezone.utc) - start_time).total_seconds()
    save_run_stats(len(processed_domains), findings_count, elapsed)
    
    # Final summary
    logging.info("=" * 60)
    logging.info("✅ Scan Complete!")
    logging.info("=" * 60)
    logging.info(f"Domains processed: {len(processed_domains)}")
    logging.info(f"Phishing domains found: {findings_count}")
    logging.info(f"Elapsed time: {elapsed:.1f}s")
    logging.info("=" * 60)


# ==================== MAIN ====================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Bulgarian Phishing Domain Detector - Fixed',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=None,
        help='Maximum runtime in seconds'
    )
    parser.add_argument(
        '--sources',
        nargs='+',
        choices=['urlscan', 'manual'],
        default=['urlscan', 'manual'],
        help='Data sources to use (default: urlscan, manual)'
    )
    parser.add_argument(
        '--check-domain',
        type=str,
        help='Check a specific domain directly'
    )
    
    args = parser.parse_args()
    
    # If specific domain check requested
    if args.check_domain:
        domain = args.check_domain.strip().lower()
        logging.info(f"🔍 Checking specific domain: {domain}")
        
        if is_whitelisted(domain):
            logging.info(f"✅ {domain} is WHITELISTED (legitimate)")
            return
        
        score, details = calculate_score(domain)
        
        logging.info(f"\n{'=' * 60}")
        logging.info(f"Domain: {domain}")
        logging.info(f"Score: {score}/100")
        logging.info(f"Threshold: {SCORE_THRESHOLD}")
        logging.info(f"{'=' * 60}")
        logging.info(f"Brand keywords: {details['brand_keywords']}")
        logging.info(f"Suspicious TLD: {details['suspicious_tld']}")
        logging.info(f"Free hosting: {details['free_hosting']}")
        logging.info(f"Geo indicators: {details['geo_indicators']}")
        logging.info(f"Transaction keywords: {details['transaction_keywords']}")
        logging.info(f"Multiple hyphens: {details['multiple_hyphens']}")
        logging.info(f".bg-XX.TLD pattern: {details.get('bg_tld_abuse', False)}")
        logging.info(f"{'=' * 60}")
        
        if score >= SCORE_THRESHOLD:
            logging.warning(f"🚨 PHISHING DETECTED (score {score} >= {SCORE_THRESHOLD})")
        else:
            logging.info(f"ℹ️ Below threshold (score {score} < {SCORE_THRESHOLD})")
        
        return
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    # Create empty feed if needed
    if not os.path.exists(OUTPUT_FILE):
        save_feed([])
    
    # Run scanner
    scan_domains(duration=args.duration, sources=args.sources)


if __name__ == "__main__":
    main()
