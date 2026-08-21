#!/usr/bin/env python3
"""
Regression tests for the Bulgarian phishing detector.

Run with:  python detection/test_detector.py

No pytest dependency — this has to run inside the GitHub Actions job that
only installs ``requests``.

The two lists below are the contract:

  MUST_FLAG   — real Bulgarian-targeted phishing that must stay in the feed.
                If a change here starts dropping these, precision was bought
                at too high a price.
  MUST_REJECT — false positives that used to reach the feed. Each entry names
                the reason it is out of scope, so a future rule change that
                lets one back in fails loudly instead of silently.
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_PATH = os.path.join(HERE, 'bg-phishing-detector.py')

spec = importlib.util.spec_from_file_location('bg_phishing_detector', SCANNER_PATH)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


# --- Bulgarian-targeted phishing that must be detected ---------------------
MUST_FLAG = [
    # Couriers
    'econt-bg.xyz',
    'econt.bg-pv.cfd',
    'speedy.bg-pv.cfd',
    'speedy-bg-public.cfd',
    'bg-speedy.xyz',
    'bgpost-bg.cfd',
    'new-bgpost.cam',
    'econtbg.secure-safe.xyz',
    'xn--econtbg-6gg.secure-safe.xyz',      # punycode homoglyph wrapper
    # Marketplaces
    'olx-bg.delivery-pay.xyz',
    'olx.olxbg.shop',
    'revolut.dostavka-olx-bg-parite.online',
    # Banks / online banking
    'dskdirect.site',
    'dsk-directlogin1.site',
    'dsk-mobile.xyz',
    'e-postbank-bg.online',
    'e-postbankbg.cfd',
    'uac-procredit-com.l.ink',
    'allianz-bg-vqjpl.icu',
    'ibanking-bg.online',
    'ubb-bg-login.cfd',
    'fibank-bg-secure.top',
    # Government / MVR
    'mvr-bg.top',
    'mvrbg.cyou',
    'mvrgovbg.lol',
    'e-uslugi-mvr.sbs',
    'nap-bg-danaci.top',
    # Toll & vignette — the new coverage
    'bgtoll-bg.top',
    'bg-toll.cfd',
    'tollpass-bg.online',
    'toll-pass-bg.site',
    'vinetki-bg.icu',
    'e-vinetka-bg.xyz',
    'evinetka.pages.dev',
    'digitoll-bg.shop',
    'bgtoll.bg-plati.cfd',
    'vinetka-plashtane-bg.top',
]

# --- Out-of-scope domains that must never reach the feed -------------------
MUST_REJECT = [
    # Legitimate Bulgarian services (whitelist)
    ('tollpass.bg', 'whitelisted'),
    ('www.tollpass.bg', 'whitelisted'),
    ('vinetki.bg', 'whitelisted'),
    ('bgtoll.bg', 'whitelisted'),
    ('web.bgtoll.bg', 'whitelisted'),
    ('digitoll.bg', 'whitelisted'),
    ('econt.bg', 'whitelisted'),
    ('tracking.econt.bg', 'whitelisted'),
    ('ebb.ubb.bg', 'whitelisted'),
    ('my.fibank.bg', 'whitelisted'),
    ('uac.procreditbank.bg', 'whitelisted'),
    ('online.bank.allianz.bg', 'whitelisted'),
    ('e-uslugi.mvr.bg', 'whitelisted'),
    ('abv.bg', 'whitelisted'),
    ('a1.bg', 'whitelisted'),

    # Russian / CIS marketplace chains — the "gibberish" entries
    ('yandex.cdek.youla.blablacar.pochta.kwid9.bg-speedyx.top', 'foreign-market:ru'),
    ('avito.avito.yandex.sberbank.sbermegamarket.kwid9.bg-speedyz.top', 'foreign-market:ru'),
    ('ozon.blablacar.yandex.pochtabank.kwid9.bg-speedyz.top', 'foreign-market:ru'),
    ('nalozhka.yandex.cdek.youla.sbermarket.kwid9.bg-speedyz.top', 'foreign-market:ru'),

    # Not Bulgaria
    ('8guild-izin-trbg-gaes.pages.dev', 'foreign-market:id'),
    ('ww17.nbg-bank-login.fluxio.cfd', 'foreign-market:gr'),
    ('nbg-bank-login.fluxio.cfd', 'foreign-market:gr'),
    ('ibanking-nbg.click', 'foreign-market:gr'),
    ('meine-postbank.online', 'foreign-market:de'),
    ('postbank-ausbildungsnavi-de-59864.pages.dev', 'foreign-market:de'),
    ('olx-ua-safedeal-payment25121.pages.dev', 'foreign-market:ua'),
    ('olx-pay-uah.pages.dev', 'foreign-market:ua'),
    ('dukung-program-mbg-prabowo-gibran.pages.dev', 'foreign-market:id'),
    ('mbg-my-bini-gue.pages.dev', 'foreign-market:id'),
    ('akses-cepat-olx-anti-lag.pages.dev', 'foreign-market:id'),
    ('baji-live-bglsh.click', 'foreign-market:in'),
    ('toto-bg-play.click', 'foreign-market:gambling'),

    # Global brand abuse with no Bulgarian angle
    ('dhl-delivery-system-signin.pages.dev', 'no-bg-context'),
    ('temp-fedex-sameday-portal.pages.dev', 'no-bg-context'),
    ('ibank.688844.xyz', 'no-bg-context'),
    ('olx-safepay.pages.dev', 'no-bg-context'),
    ('olx.plsd2bgflstagf39027.icu', 'no-bg-context'),   # "bg" inside a random string

    # Scanner artefacts / infrastructure
    ('wildcardprobe-1777179948470546854.idgbedcbjxgpx876587654326d6c555d.10iot.xyz', 'infrastructure'),
    ('0-12-account-analyticspage.0.bigobigo1978.xyz', 'infrastructure'),

    # ABV webmail is deliberately not protected — free webmail is not an
    # institution, bank or payment service, and one bulk campaign was 15% of
    # the feed. See WHITELISTED_DOMAINS for the reasoning.
    ('abv-bgz53.top', 'no-brand'),
    ('abv-bgd46.top', 'no-brand'),
    ('abvbg-105306.weeblysite.com', 'no-brand'),
    ('bg-abv-bg.top', 'no-brand'),
    ('upgradewebemail-abv-bg.herokuapp.com', 'no-brand'),
    ('passport-abv-bg-profile-login-gatsby-boilerplate.pages.dev', 'no-brand'),
    ('passport-abu-bg-app-profiles-login-evry-miukrwsdijkmweaszx.pages.dev', 'no-brand'),
    ('abv-bglogin.square.site', 'no-brand'),

    # No protected brand at all
    ('banking-dashboard-march-2026.pages.dev', 'no-brand'),
    ('inntelt-webgl-play.pages.dev', 'no-brand'),        # "bg" inside "webgl"
    ('cost-of-bg-trans-flush-service.pages.dev', 'no-brand'),
    ('gomarketplacecontent.cfd', 'no-brand'),            # "econt" inside "content"
]

# --- Unit-level expectations ----------------------------------------------
TOKEN_CASES = [
    ('inntelt-webgl-play.pages.dev', 'bg', False),   # substring, not a token
    ('olx-bg.moneyget.shop', 'bg', True),
    ('www.speedy.bg-pv.cfd', 'bg', True),
]


def run() -> int:
    failures = []

    for domain in MUST_FLAG:
        result = scanner.evaluate_domain(domain)
        if result['verdict'] != scanner.VERDICT_PHISHING:
            failures.append(
                f'MISSED  {domain}: verdict={result["verdict"]} '
                f'reason={result["reason"]} score={result["score"]}'
            )

    for domain, expected_reason in MUST_REJECT:
        result = scanner.evaluate_domain(domain)
        if result['verdict'] == scanner.VERDICT_PHISHING:
            failures.append(f'FALSE POSITIVE  {domain}: flagged with score {result["score"]}')
        elif result['reason'] != expected_reason:
            failures.append(
                f'WRONG REASON  {domain}: expected {expected_reason}, '
                f'got {result["reason"]}'
            )

    for domain, token, expected in TOKEN_CASES:
        actual = token in scanner.domain_tokens(domain)
        if actual != expected:
            failures.append(f'TOKENS  {domain}: "{token}" in tokens == {actual}, expected {expected}')

    # Typosquatting must no longer report "pay" as a typo of "epay"
    _, typos = scanner.detect_typosquatting('olx-bg.delivery-pay.xyz', scanner.BRAND_KEYWORDS)
    if any(t['typo'] == 'pay' for t in typos):
        failures.append('TYPOSQUAT  "pay" still reported as a typo of a brand')

    # Every whitelisted domain must be recognised as whitelisted
    for domain in scanner.WHITELISTED_DOMAINS:
        if not scanner.is_whitelisted(domain):
            failures.append(f'WHITELIST  {domain} not recognised')

    # A brand may not appear in both brand groups
    overlap = set(scanner.BG_EXCLUSIVE_BRANDS) & set(scanner.AMBIGUOUS_BRANDS)
    if overlap:
        failures.append(f'BRANDS  listed as both BG-exclusive and ambiguous: {sorted(overlap)}')

    total = len(MUST_FLAG) + len(MUST_REJECT) + len(TOKEN_CASES)
    if failures:
        print(f'❌ {len(failures)} failure(s) out of {total} checks:\n')
        for f in failures:
            print(f'   {f}')
        return 1

    print(f'✅ All checks passed '
          f'({len(MUST_FLAG)} must-flag, {len(MUST_REJECT)} must-reject, '
          f'{len(TOKEN_CASES)} token cases)')
    return 0


if __name__ == '__main__':
    sys.exit(run())
