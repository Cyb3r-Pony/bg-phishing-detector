# 🚨 Bulgarian Phishing Domain Detector

Automated detection of phishing domains that impersonate **Bulgarian institutions, banks, payment providers, toll & vignette services, couriers and marketplaces** in order to defraud Bulgarian citizens.

Rule-based heuristics find candidates every hour; a free LLM confirms the high-risk ones once a day.

## 🎯 Scope

The feed protects Bulgarian users specifically. That is a deliberate constraint, not an omission:

| In scope | Out of scope |
|----------|--------------|
| `econt-bg.xyz`, `speedy.bg-pv.cfd` | `dhl-delivery-system-signin.pages.dev` (no Bulgarian angle) |
| `dsk-directlogin1.site`, `e-postbankbg.cfd` | `meine-postbank.online` (German Postbank) |
| `mvr-bg.top`, `e-uslugi-mvr.sbs` | `ww17.nbg-bank-login.fluxio.cfd` (National Bank of **Greece**) |
| `olx-bg.delivery-pay.xyz` | `olx-ua-safedeal-payment25121.pages.dev` (Ukraine) |
| `bgtoll.bg-plati.cfd`, `vinetki-bg.icu` | `yandex.cdek.youla.…kwid9.bg-speedyx.top` (Russian marketplaces) |

Protected sectors:

- **Government & e-services** — MVR (Ministry of Interior), e-uslugi, eGov, NRA/NAP, NSSI/NOI, Customs
- **Toll & vignette** — BG TOLL, TollPass, Vinetki, DigiToll and the other officially authorised e-vignette sellers
- **Banks & online banking** — DSK Direct, UBB, Fibank, Postbank/e-Postbank, UniCredit Bulbank, ProCredit, CCB, Investbank, TBI, and more
- **Payment services** — EasyPay, ePay, Borica, myPOS, Revolut, PayPal
- **Couriers & logistics** — Econt, Speedy, Bulgarian Posts, Sameday, BoxNow, Express One, DHL BG
- **Marketplaces & consumer services** — OLX.bg, Bazar.bg, eMAG, ABV mail, A1, Yettel, Vivacom

## 🔬 How it works

**Stage 1 — Hourly scanner** (`detection/bg-phishing-detector.py`)

- Queries URLScan.io with ~70 targeted patterns, plus a manual watchlist
- Runs every candidate through an ordered filter pipeline, then scores it 0-100
- Flags domains scoring ≥70 into `feed/phishing_feed.json`
- Runs every hour at :00

**Stage 2 — Daily LLM analysis** (`detection/llm_analyzer.py`)

- Takes flagged domains scoring ≥75 from the last 24 hours
- Asks a free OpenRouter model for threat level, the impersonated brand, and a BLOCK/INVESTIGATE decision
- Merges results into `feed/llm-analysis.json`
- Runs daily at 00:10 UTC

Certificate Transparency log polling was removed — it returned no findings that URLScan did not already cover.

## 🧠 Detection logic

Two independent questions, both of which must be answered yes:

**1. Does this look like brand impersonation?** — the score.

| Indicator | Points |
|-----------|--------|
| Brand keyword (boundary-anchored) | +40 |
| Homoglyphs (Cyrillic/Greek look-alikes, `0`-for-`o`, punycode) | +30 |
| Typosquatting (1-2 edits) | +25 |
| Free hosting platform | +25 |
| Suspicious TLD | +20 |
| Direct impersonation shape | +15 |
| Bulgarian context | +15 |
| Transaction keyword | +10 |
| Multiple hyphens / numeric suffix / subdomain stacking / high entropy | +10 each |
| `.bg-XX.TLD` pattern | +10 |

Capped at 100. **Threshold: 70.**

**2. Is it aimed at Bulgaria?** — the filters.

| Filter | Rejects |
|--------|---------|
| `infrastructure` | Cloud infrastructure and other people's scanner artefacts |
| `whitelisted` | Legitimate Bulgarian services and their subdomains |
| `foreign-market:<cc>` | RU / UA / ID / TR / GR / DE / IN markets and gambling spam |
| `gibberish-chain` | 6+ label subdomain stacks, 60+ character hostnames, repeated labels |
| `not-suspicious-platform` | Ordinary domains on ordinary TLDs |
| `no-brand` | Nothing impersonated — a transaction keyword alone is not enough |
| `no-bg-context` | A global brand abused with nothing tying it to Bulgaria |

Rejection counts are recorded per run in `feed/stats.json` and shown in the workflow summary.

**Why token matching matters.** Brand and geography are matched against DNS labels and hyphen-separated tokens, never as raw substrings. `econt` is not found inside `content`, and `bg` is not found inside `webgl` or `plsd2bgflstagf39027`.

See [docs/SCORING.md](docs/SCORING.md) for the full reference.

## 🛡️ Protected brands & whitelist

Legitimate domains — and all their subdomains — are never scored.

Brands are split into two groups. **BG-exclusive** brands only mean something in Bulgaria, so matching one is itself proof of Bulgarian targeting. **Ambiguous** brands are shared with other markets and only count when the hostname carries an independent Bulgarian signal.

### Government & public services

| Domain | Service | Group |
|--------|---------|-------|
| mvr.bg, e-uslugi.mvr.bg | Ministry of Interior | BG-exclusive |
| egov.bg, gov.bg, government.bg | e-Government portal | BG-exclusive |
| nra.bg, nap.bg | National Revenue Agency (НАП) | BG-exclusive |
| nssi.bg, noi.bg | National Social Security Institute (НОИ) | BG-exclusive |
| customs.bg | Agency "Customs" | BG-exclusive |
| registryagency.bg | Registry Agency | BG-exclusive |

### Toll & vignette services

| Domain | Service | Group |
|--------|---------|-------|
| bgtoll.bg | National Toll Administration (official e-vignette portal) | BG-exclusive |
| **tollpass.bg** | Authorised e-vignette / toll reseller | BG-exclusive |
| **vinetki.bg** | Authorised e-vignette reseller | BG-exclusive |
| digitoll.bg | Authorised e-vignette reseller | BG-exclusive |
| api.bg | Road Infrastructure Agency (АПИ) | BG-exclusive |
| boleron.bg, spotins.bg, grabo.bg, amarantbg.com | Authorised e-vignette resellers | BG-exclusive |

Vignette fraud is an active problem in Bulgaria — unlicensed sites resell e-vignettes at inflated euro-only prices with hidden fees, and drivers can end up without a valid vignette. The brand keywords cover `bgtoll`, `bg-toll`, `tollpass`, `toll-pass`, `vinetki`, `vinetka`, `e-vinetka`, `evinetki` and `digitoll`.

### Banks

| Domain | Bank | Online banking |
|--------|------|----------------|
| ubb.bg | United Bulgarian Bank | ebb.ubb.bg |
| dskbank.bg | DSK Bank | dskdirect.bg, dskmobile.bg |
| unicreditbulbank.bg | UniCredit Bulbank | bulbankonline.bg |
| fibank.bg | First Investment Bank | my.fibank.bg |
| postbank.bg | Postbank (Eurobank Bulgaria) | e-postbank.bg |
| ccbank.bg | Central Cooperative Bank | online.ccbank.bg |
| ibank.bg | Investbank | ibanking.ibank.bg |
| procreditbank.bg | ProCredit Bank | uac.procreditbank.bg |
| tbibank.bg | TBI Bank | online.tbibank.bg |
| iabank.bg | International Asset Bank | assetonline.iabank.bg |
| bacb.bg | Bulgarian-American Credit Bank | online.bacb.bg |
| municipalbank.bg | Municipal Bank | sca.municipalbank.bg |
| teximbank.bg | Texim Bank | web.teximbank.bg |
| tokudabank.bg | Tokuda Bank | rbank.tokudabank.bg |
| allianz.bg | Allianz Bank Bulgaria | online.bank.allianz.bg |
| bbr.bg | Bulgarian Development Bank | bdbank.bg |

Online-banking subdomains of an already whitelisted apex are covered automatically; only those on their own apex domain are listed separately in the code.

### Payment services

| Domain | Service | Group |
|--------|---------|-------|
| easypay.bg | EasyPay | BG-exclusive |
| borica.bg | Borica | BG-exclusive |
| mypos.com | myPOS | BG-exclusive |
| paysera.bg | Paysera | BG-exclusive |
| epay.bg | ePay | Ambiguous |
| fastpay.bg | FastPay | Ambiguous |
| revolut.com, paypal.com, skrill.com | International wallets | Ambiguous |

### Couriers, marketplaces & consumer services

| Domain | Service | Group |
|--------|---------|-------|
| econt.bg, econt.com | Econt Express | BG-exclusive |
| speedy.bg | Speedy | BG-exclusive |
| bgpost.bg, bulgariapost.bg | Bulgarian Posts | BG-exclusive |
| evropat.bg, cityexpress.bg, expressone.bg, interlogistica.bg | Bulgarian couriers | BG-exclusive |
| bazar.bg, emag.bg | Marketplaces | BG-exclusive |
| abv.bg | ABV mail | BG-exclusive |
| a1.bg, yettel.bg, vivacom.bg | Telecoms | BG-exclusive |
| olx.bg | OLX Bulgaria | Ambiguous |
| dhl.bg, dpd.bg, sameday.bg, boxnow.bg, intime.bg | International couriers | Ambiguous |

## 🔧 Setup

See [docs/SETUP.md](docs/SETUP.md) for the detailed guide.

### Quick start

```bash
git clone https://github.com/Cyb3r-Pony/bg-phishing-detector.git
cd bg-phishing-detector
pip install -r requirements.txt
```

Add two repository secrets under **Settings → Secrets and variables → Actions**:

- `URLSCAN_API_KEY` — your URLScan.io API key
- `OPENROUTER_API_KEY` — your OpenRouter API key

Then enable workflows under **Actions**. To test immediately: **Actions → Hourly Phishing Scanner → Run workflow**.

## 📁 Project structure

```
bg-phishing-detector/
├── detection/
│   ├── bg-phishing-detector.py  # Scanner: filters, scoring, URLScan queries
│   ├── llm_analyzer.py          # Stage 2 LLM confirmation
│   ├── prune_feed.py            # Re-apply current rules to the stored feed
│   └── test_detector.py         # Regression tests (must-flag / must-reject)
├── .github/workflows/
│   ├── scan.yml                 # Hourly scanner
│   └── llm-analysis.yml         # Daily LLM analysis
├── docs/
│   ├── SETUP.md
│   └── SCORING.md               # Full scoring & filtering reference
├── feed/
│   ├── phishing_feed.json       # Threat feed
│   ├── llm-analysis.json        # LLM verdicts
│   └── stats.json               # Run and cumulative statistics
├── requirements.txt
└── README.md
```

## 🚀 Usage

### Automated

- **Scanner:** hourly at :00 → commits `feed/phishing_feed.json` and `feed/stats.json`
- **LLM analysis:** daily at 00:10 UTC → commits `feed/llm-analysis.json`

### Local

```bash
export URLSCAN_API_KEY="your_key_here"
export OPENROUTER_API_KEY="your_key_here"

# Full scan
python detection/bg-phishing-detector.py --sources urlscan manual

# Manual watchlist only (no API key needed)
python detection/bg-phishing-detector.py --sources manual

# Explain one domain
python detection/bg-phishing-detector.py --check-domain speedy.bg-pv.cfd

# LLM analysis
python detection/llm_analyzer.py --min-score 75 --max-analyze 50
```

### Command-line options

**Scanner**

```
--sources {urlscan,manual} [...]   Data sources (default: urlscan manual)
--duration SECONDS                 Stop after N seconds
--check-domain HOSTNAME            Explain one verdict and exit
```

**LLM analyser**

```
--feed-file PATH        Feed JSON (default: feed/phishing_feed.json)
--output-file PATH      Output JSON (default: feed/llm-analysis.json)
--min-score INT         Minimum score to analyse (default: 70; workflow uses 75)
--lookback-hours INT    Only analyse domains detected in the last N hours (default: 24)
--max-analyze INT       Maximum domains per run (default: 100; workflow uses 50)
--model NAME            OpenRouter model (default: arcee-ai/trinity-large-preview:free)
```

**Feed pruner**

```
--dry-run          Report what would change without writing
--report PATH      Write a markdown prune report
```

## 🧪 Testing & maintenance

`detection/test_detector.py` pins the behaviour that matters: Bulgarian phishing that must stay flagged, and false positives that must stay rejected — each with the reason code it should produce. It runs in the hourly workflow before every scan, so a rule change that breaks either side fails loudly.

```bash
python detection/test_detector.py
```

When you add brands, whitelist entries or exclusions, re-apply the rules to what is already stored:

```bash
python detection/prune_feed.py --dry-run
python detection/prune_feed.py --report prune-report.md
```

The pruner imports the scanner's own `evaluate_domain`, so the feed can never drift from the live rules. It also collapses `www.` / `wwNN.` mirrors onto a single entry and rebuilds `feed/stats.json` to mirror the feed.

## 📋 Feed format

### phishing_feed.json

```json
[
  {
    "domain": "econt-bg.xyz",
    "score": 90,
    "details": {
      "brand_keywords": ["econt"],
      "bg_exclusive_brands": ["econt"],
      "ambiguous_brands": [],
      "bg_context_signals": ["geo:bg", "brand:econt", "direct-impersonation"],
      "geo_indicators": ["bg"],
      "transaction_keywords": [],
      "suspicious_tld": ".xyz",
      "free_hosting": null,
      "direct_impersonation": true,
      "homoglyphs_detected": false,
      "homoglyphs_used": [],
      "typosquatting_detected": false,
      "typosquatting_details": [],
      "multiple_hyphens": false,
      "numeric_suffix": false,
      "subdomain_stacking": false,
      "high_entropy": false
    },
    "detected_at": "2026-02-02T08:31:54Z",
    "source": "scanner"
  }
]
```

`source` is `scanner` for URLScan findings and `manual` for human-verified watchlist entries. Manual entries also carry `"manual_watchlist": true` in `details`.

### stats.json

```json
{
  "last_run": "2026-02-08T10:17:07Z",
  "last_run_stats": {
    "domains_processed": 1792,
    "phishing_detected": 257,
    "new_unique_phishing": 3,
    "elapsed_time": 233.48,
    "excluded_by_reason": {
      "not-suspicious-platform": 1104,
      "no-bg-context": 214,
      "foreign-market:ru": 46
    }
  },
  "cumulative_stats": {
    "total_domains_scanned": 4910865,
    "total_unique_phishing_found": 264,
    "total_runs": 3003,
    "phishing_detection_rate": 0.01
  },
  "all_phishing_domains": ["..."]
}
```

`total_domains_scanned` is the sum of per-run processed counts and is **not** deduplicated across runs — the same domain reappearing in URLScan results counts again. `all_phishing_domains` mirrors the feed exactly.

### llm-analysis.json

```json
{
  "analyzed_at": "2026-02-08T00:15:32Z",
  "total_analyzed": 49,
  "newly_analyzed": 3,
  "domains": [
    {
      "domain": "econt-bg.xyz",
      "detected_at": "2026-02-02T08:31:54Z",
      "phishing_score": 90,
      "detection_details": { "...": "..." },
      "llm_analysis": {
        "threat_level": "HIGH",
        "confidence": 95,
        "phishing_score": 90,
        "mimicked_domain": "econt.bg",
        "decision": "BLOCK",
        "reasoning": "Direct Econt brand impersonation with Bulgarian geo marker.",
        "model": "arcee-ai/trinity-large-preview:free",
        "analyzed_at": "2026-02-08T00:15:32Z"
      }
    }
  ]
}
```

## 🛠️ Customisation

All configuration lives at the top of `detection/bg-phishing-detector.py`.

**Add a protected brand** — put it in `BG_EXCLUSIVE_BRANDS` if it only exists in Bulgaria, `AMBIGUOUS_BRANDS` if it is global. Add the legitimate domain to `WHITELISTED_DOMAINS`, and consider a URLScan query in `URLSCAN_QUERIES`.

```python
BG_EXCLUSIVE_BRANDS = [..., 'tollpass', 'vinetki']
AMBIGUOUS_BRANDS    = [..., 'revolut']
WHITELISTED_DOMAINS = [..., 'tollpass.bg', 'vinetki.bg']
```

**Exclude a foreign market** — add tokens to `FOREIGN_MARKET_TOKENS`. Keep them token-exact; only long, distinctive tokens belong in `FOREIGN_SUBSTRING_TOKENS`.

**Add a known-bad domain by hand** — append it to `MANUAL_CHECK_DOMAINS`. It is accepted on your authority and skips the heuristic gates.

**Tune sensitivity**

```python
SCORE_THRESHOLD = 70      # lower = more findings, more noise
MAX_DNS_LABELS = 5        # subdomain-chain cutoff
MAX_HOSTNAME_LENGTH = 60  # gibberish cutoff
```

After any change: run the tests, then run the pruner.

## ⚠️ Rate limits

- **URLScan.io** — free tier ~100 searches/day; the scanner sleeps 2s between queries and backs off 60s on HTTP 429
- **OpenRouter free models** — 3s between requests, capped at 200 requests per analyser run

## 🐛 Troubleshooting

**Scanner finds nothing** — check `URLSCAN_API_KEY` in Secrets, and look at `excluded_by_reason` in the workflow summary to see which filter is consuming candidates.

**A legitimate domain got flagged** — add it to `WHITELISTED_DOMAINS`, add a test case to `MUST_REJECT` in `detection/test_detector.py`, then run `python detection/prune_feed.py`.

**Real phishing is being missed** — run `--check-domain` on it. The output names the exact filter that rejected it.

**Push failures in Actions** — the commit step retries three times with `git pull --rebase --autostash`.

## 🔐 Security

- API keys live in GitHub Secrets, never in code
- The whitelist prevents flagging legitimate Bulgarian services
- Concurrency groups prevent overlapping workflow runs

## 📄 License

MIT License — free to use and modify.

## 🙏 Acknowledgments

- [URLScan.io](https://urlscan.io) for the domain scanning API
- [OpenRouter](https://openrouter.ai) for free LLM access
- [Агенция „Пътна инфраструктура"](https://www.api.bg) / [BG TOLL](https://www.bgtoll.bg) for the list of authorised e-vignette sellers

---

**⚡ Built to protect Bulgarian users from phishing attacks**
