# 📊 Scoring & Filtering Reference

How a hostname gets from "URLScan saw it" to "it is in the feed".

There are two independent questions, and keeping them separate is what makes
the feed precise:

1. **Does this look like brand impersonation?** → the 0-100 **score**.
2. **Is the impersonation aimed at Bulgarian users?** → the **filters**.

A domain needs to pass *both*. A perfect 100/100 German Postbank phish is
still rejected, because this feed exists to protect Bulgarian citizens.

---

## Part 1 — The filter pipeline

`evaluate_domain()` in `detection/bg-phishing-detector.py` is the single
source of truth. Both the live scanner and `detection/prune_feed.py` call it,
so a stored feed entry is always judged by the rules that are in force today.

Filters run in order; the first one that matches wins and its name becomes the
rejection reason.

| # | Filter | Reason code | Rejects |
|---|--------|-------------|---------|
| 1 | Infrastructure & scanner artefacts | `infrastructure` | `wildcardprobe-…10iot.xyz`, `*.rds.amazonaws.com`, `bigobigo1978.xyz` |
| 2 | Whitelist | `whitelisted` | `tollpass.bg`, `tracking.econt.bg`, `ebb.ubb.bg` |
| 3 | Foreign market | `foreign-market:<cc>` | `yandex.cdek.…kwid9.bg-speedyx.top`, `ww17.nbg-bank-login.fluxio.cfd`, `8guild-izin-trbg-gaes.pages.dev` |
| 4 | Gibberish / subdomain chain | `gibberish-chain` | 6+ DNS labels, 60+ chars with 4+ labels, repeated labels |
| 5 | Suspicious platform | `not-suspicious-platform` | ordinary `.com`/`.org` domains (manual watchlist exempt) |
| — | **Manual watchlist short-circuit** | *accepted* | human-verified entries bypass filters 6-8 |
| 6 | Brand impersonation required | `no-brand` | `banking-dashboard-march-2026.pages.dev`, `inntelt-webgl-play.pages.dev` |
| 7 | Bulgarian context required | `no-bg-context` | `dhl-delivery-system-signin.pages.dev`, `olx-safepay.pages.dev` |
| 8 | Score threshold | `below-threshold` | score < 70 |

Every rejection is counted and written to `feed/stats.json` under
`last_run_stats.excluded_by_reason`, and surfaced in the workflow summary — so
if a filter starts eating too much, it shows up immediately.

### Filter 3 — foreign markets

The single largest source of noise. Bulk phishing kits reuse infrastructure
across countries, and a `bg` string in a hostname does not mean Bulgaria.

| Market | Sample tokens | What it was catching |
|--------|---------------|----------------------|
| `ru` | yandex, avito, sberbank, cdek, ozon, blablacar, pochta, youla, nalozhka, kwid9 | Russian marketplace chains on `kwid9.bg-speedyx.top` |
| `ua` | ua, uah, otrymka, novaposhta, privatbank, monobank | Ukrainian OLX "safedeal" pages |
| `id` | mbg, prabowo, gibran, koperasi, diskominfo, akses, cepat, gaes, izin | Indonesian *Makan Bergizi Gratis* pages — the biggest source of accidental `bg` matches |
| `tr` | trbg, turkiye, edevlet, ziraat | Turkish e-Devlet lures |
| `gr` | nbg, ethniki, piraeus | **National Bank of Greece** — not a Bulgarian bank |
| `de` | meine, ausbildungsnavi, auswertungszentrum, pakettracking, sparkasse | German Postbank / DHL campaigns |
| `in` | airtel, paytm, bkash, baji, bglsh | South Asian payment and betting |
| `gambling` | casino, toto, 1xbet, betano, melbet | Casino affiliate spam |

Matching is **token-exact** (DNS labels and hyphen-separated parts). A short
list of long, distinctive tokens is additionally matched as a substring,
because attackers glue them onto other words (`lyjbgozon`).

### Filter 4 — gibberish chains

Rejects hostnames that are infrastructure rather than lures:

- more than **5 DNS labels** — `pochta.yandex.avito.avito.avito.avito.cdek.kwid9.bg-speedyz.top`
- longer than **60 characters** with 4+ labels
- a repeated label — `avito.avito.…`
- a 24+ character label with no vowel in its first 12 characters

### Filter 7 — Bulgarian context

Brands are split into two groups:

**BG-exclusive** — the brand only means something in Bulgaria, so matching it
*is* Bulgarian context: econt, speedy, bgpost, dsk, dskdirect, fibank, ubb,
ccbank, procredit, bulbank, borica, easypay, mypos, mvr, e-uslugi, egov,
**bgtoll, tollpass, vinetki, digitoll**, vivacom, yettel, abv, …

**Ambiguous / global** — the brand is shared with other markets, so it needs an
independent Bulgarian signal: olx, dhl, dpd, fedex, ups, sameday, boxnow,
epay, fastpay, revolut, paypal, skrill, unicredit, postbank, eurobank,
allianz, ibank, ibanking.

A Bulgarian signal is any of:

1. a `bg` / `bulgaria` / Bulgarian-city **token** — token-exact, so `webgl` and
   `plsd2bgflstagf39027` do **not** count;
2. a `.bg` label anywhere in the hostname — `speedy.bg-pv.cfd`;
3. a BG-exclusive brand;
4. a brand glued to `bg` — `econtbg`, `olxbg`, `mvrbg`, `e-postbankbg`;
5. a transliterated Bulgarian lure word — dostavka, pratka, parite, smetka,
   vinetka, plashtane, uslugi, danaci, globi, …;
6. a direct-impersonation pattern match (see below).

### Manual watchlist

Domains in `MANUAL_CHECK_DOMAINS` were verified by a human before being added,
so they are accepted on that authority and skip filters 6-8. Their rule-based
score is still recorded and is often low — those are exactly the mangled
spellings (`mvrx.lat`, `e-uslugivrl.top`) that automated matching is worst at.
Whitelist and infrastructure checks still apply, so a mistaken entry is caught.

---

## Part 2 — The score

| Indicator | Points | Description |
|-----------|--------|-------------|
| Brand keyword | +40 | Protected brand at a token boundary |
| Homoglyphs | +30 | Look-alike Unicode, `0`-for-`o`, or punycode wrapper |
| Typosquatting | +25 | 1-2 edits from a brand name |
| Free hosting | +25 | `.pages.dev`, `.web.app`, `.workers.dev`, … |
| Suspicious TLD | +20 | `.cfd`, `.top`, `.icu`, `.sbs`, `.cyou`, … |
| Direct impersonation | +15 | Known Bulgarian abuse shape (`econt-bg`, `dsk-direct`, `bg-toll`) |
| Bulgarian context | +15 | Any signal from filter 7 |
| Transaction keyword | +10 | login, payment, verify, dostavka, plashtane, … |
| Multiple hyphens | +10 | 2 or more |
| Numeric suffix | +10 | `-123456.` or `1234.` |
| Subdomain stacking | +10 | 4 or more DNS labels |
| High entropy | +10 | Consonant clusters or alternating letters/digits |
| `.bg-XX.TLD` pattern | +10 | `speedy.bg-pv.cfd` |

Raw total is capped at **100**. Threshold is **70**.

There is no longer a negative "non-BG context" penalty — that used to reduce a
score by 20 and let plenty of foreign phishing squeak over the line anyway.
Bulgarian relevance is now a hard gate (filter 7) rather than a discount.

### Brand matching is boundary-anchored

A brand only matches at the start of a label, after a `.` or `-`, or before a
`.` or `-`. This is why:

| Domain | Result |
|--------|--------|
| `gomarketplacecontent.cfd` | no match — "econt" is inside "content" |
| `inntelt-webgl-play.pages.dev` | no match — "bg" is inside "webgl" |
| `speedytest.com` | no match — "speedy" is a prefix of a longer word |
| `bg-speedy.cfd` | match — "speedy" after a hyphen |
| `www.speedy.com` | match — "speedy" between dots |

Each brand is additionally matched in its `brand+bg` and `bg+brand` glued
forms (`econtbg`, `bgecont`), which proves the brand *and* the Bulgarian target
in a single token.

Punycode labels are decoded before matching, so
`xn--econtbg-6gg.secure-safe.xyz` is scored as `econtbg`.

### Typosquatting is deliberately conservative

- brands shorter than **5 characters** are skipped entirely
- 5-6 character brands allow **1** edit; longer brands allow **2**
- ordinary words are never treated as typos (`pay`, `login`, `banking`,
  `dashboard`, `secure`, `direct`, …)

The old rule reported `pay` as a distance-1 typo of `epay` and `banking` as a
typo of `ibanking`, which inflated scores across the whole feed.

### Homoglyph substitutions

| Latin | Look-alikes |
|-------|-------------|
| a | а (Cyrillic), ά, α |
| c | с (Cyrillic), ϲ |
| e | е, ё (Cyrillic), έ, ε |
| i | і (Cyrillic), ı, ι |
| o | о (Cyrillic), ο, **0** |
| p | р (Cyrillic), ρ |
| s | ѕ (Cyrillic) |
| x | х (Cyrillic), χ |
| y | у (Cyrillic) |

---

## Worked examples

```
speedy.bg-pv.cfd                            → 85  FLAGGED
  brand speedy +40 · .cfd +20 · BG token "bg" +15 · high entropy +10

econt-bg.xyz                                → 90  FLAGGED
  brand econt +40 · .xyz +20 · direct impersonation +15 · BG +15

xn--econtbg-6gg.secure-safe.xyz             → 100 FLAGGED
  punycode decoded → econtbg · brand +40 · homoglyph +30 · .xyz +20 · BG +15

bgtoll.bg-plati.cfd                         → 100 FLAGGED
  brand bgtoll +40 · .cfd +20 · direct impersonation +15 · BG +15 · .bg-XX +10

ww17.nbg-bank-login.fluxio.cfd              → REJECTED  foreign-market:gr
yandex.cdek.youla…kwid9.bg-speedyx.top      → REJECTED  foreign-market:ru
8guild-izin-trbg-gaes.pages.dev             → REJECTED  foreign-market:id
dhl-delivery-system-signin.pages.dev        → REJECTED  no-bg-context
inntelt-webgl-play.pages.dev                → REJECTED  no-brand
tollpass.bg                                 → REJECTED  whitelisted
```

---

## Checking a single domain

```bash
python detection/bg-phishing-detector.py --check-domain speedy.bg-pv.cfd
```

Prints the verdict, the rejection reason if any, the score, and every
indicator that fired.

## Changing the rules safely

`detection/test_detector.py` pins the behaviour: a list of Bulgarian phishing
domains that must stay flagged, and a list of false positives that must stay
rejected — each with the reason code it should produce. The hourly workflow
runs it before every scan.

```bash
python detection/test_detector.py
```

After changing rules, re-apply them to the stored feed:

```bash
python detection/prune_feed.py --dry-run
python detection/prune_feed.py --report prune-report.md
```
