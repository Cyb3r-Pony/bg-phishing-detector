# 🚨 Bulgarian Phishing Domain Detector

Automated phishing detection system targeting Bulgarian courier services, logistics companies, payment platforms, and banks using rule-based heuristics and AI analysis.

## 🎯 Overview

This system detects phishing domains impersonating Bulgarian services including:
- **Courier & Logistics:** Econt, Speedy, BulgariaPost, OLX, Sameday, etc.
- **Payment Services:** EasyPay, ePay, Borica, FastPay
- **Banks:** UBB, DSK Bank, UniCredit Bulbank, Fibank, Postbank, and 11 more Bulgarian banks

Detection is performed through a two-stage pipeline:

1. **Stage 1 - Hourly Scanner** (Fast, Rule-based)
   - Polls URLScan.io, Google CT, Cloudflare CT logs
   - Applies deterministic heuristics (0-100 score)
   - Flags domains scoring ≥70
   - Runs every hour at :00 (e.g., 7:00, 8:00, 9:00)

2. **Stage 2 - Daily LLM Analysis** (Slow, AI-powered)
   - Analyzes high-risk domains (score ≥75) from feed
   - Uses Llama 3.3 70B via OpenRouter (free tier)
   - Provides threat level, confidence, and decision
   - Outputs to separate `feed/llm-analysis.json`
   - Runs once daily at 00:10 UTC

## 📊 Scoring System

Domains are scored 0-100 based on 13 heuristic indicators:

| Indicator | Points | Description |
|-----------|--------|-------------|
| Brand keyword | +40 | Contains protected brand name |
| Homoglyphs | +30 | Uses look-alike Unicode characters |
| Typosquatting | +25 | Common misspellings of brands |
| Free hosting | +25 | Uses free hosting platform |
| Suspicious TLD | +20 | Commonly abused TLD |
| Direct impersonation | +15 | Exact brand name with suffix |
| Geographic indicator | +15 | Contains .bg, bulgaria, -bg |
| Transaction keywords | +10 | Payment/delivery terms |
| .bg-XX.TLD pattern | +10 | Pattern like speedy.bg-pv.cfd |
| Multiple hyphens | +10 | 2+ hyphens in domain |
| Numeric suffix | +10 | Random numbers appended |
| Subdomain stacking | +10 | 3+ subdomain levels |
| High entropy | +10 | Random/gibberish characters |
| Non-BG context | -20 | Penalty for non-Bulgarian context |

**Threshold:** Domains scoring ≥70 are flagged and added to the feed.

See [docs/SCORING.md](docs/SCORING.md) for detailed scoring documentation.

## 🛡️ Protected Brands (Whitelisted)

Legitimate domains and their subdomains are excluded from detection:

### Courier & Logistics Services
| Domain | Service |
|--------|---------|
| econt.com, econt.bg | Econt Express |
| speedy.bg | Speedy |
| bgpost.bg, bulgariapost.bg | Bulgarian Posts |
| olx.bg | OLX Bulgaria |
| intime.bg | InTime |
| interlogistica.bg | Interlogistica |
| samedaybg.com, sameday.bg | Sameday |
| boxnow.bg | BoxNow |
| cityexpress.bg | City Express |
| expressone.bg | Express One |
| evropat.bg | Evropat |
| dhl.bg | DHL Bulgaria |

### Payment Services
| Domain | Service |
|--------|---------|
| easypay.bg | EasyPay |
| epay.bg | ePay |
| borica.bg | Borica |
| fastpay.bg | FastPay |

### Bulgarian Banks
| Domain | Bank |
|--------|------|
| ubb.bg | United Bulgarian Bank |
| dskbank.bg | DSK Bank |
| unicreditbulbank.bg | UniCredit Bulbank |
| fibank.bg | First Investment Bank |
| postbank.bg | Postbank (Eurobank Bulgaria) |
| ccbank.bg | Central Cooperative Bank |
| investbank.bg | Investbank |
| procreditbank.bg | ProCredit Bank |
| tbibank.bg | TBI Bank |
| iabank.bg | International Asset Bank |
| bacb.bg | Bulgarian-American Credit Bank |
| municipalbank.bg | Municipal Bank |
| teximbank.bg | Texim Bank |
| tokudabank.bg | Tokuda Bank |
| allianz.bg | Allianz Bank Bulgaria |
| bbr.bg | Bulgarian Development Bank |

## 🔧 Setup

See [docs/SETUP.md](docs/SETUP.md) for detailed setup instructions.

### Quick Start

1. **Fork or clone this repository**

```bash
git clone https://github.com/YOUR_USERNAME/bg-phishing-detector.git
cd bg-phishing-detector
```

2. **Add GitHub Secrets**

Go to your repository → Settings → Secrets and variables → Actions → New repository secret

Add these two secrets:

- **Name:** `URLSCAN_API_KEY`
  - **Value:** Your URLScan.io API key

- **Name:** `OPENROUTER_API_KEY`
  - **Value:** Your OpenRouter API key

3. **Enable GitHub Actions**

Go to your repository → Actions → Enable workflows

4. **Manual test run (optional)**

Go to Actions → "Hourly Phishing Scanner" → Run workflow

## 📁 Project Structure

```
bg-phishing-detector/
├── detection/
│   ├── bg-phishing-detector.py  # Main scanner script
│   └── llm_analyzer.py          # LLM analysis script
├── .github/
│   └── workflows/
│       ├── scan.yml             # Hourly scanner workflow
│       └── llm-analysis.yml     # Daily LLM analysis workflow
├── docs/
│   ├── SETUP.md                 # Detailed setup guide
│   └── SCORING.md               # Scoring system reference
├── feed/
│   ├── phishing_feed.json       # Threat feed (auto-generated)
│   ├── llm-analysis.json        # LLM analysis results (auto-generated)
│   └── .gitkeep                 # Keeps directory in git
├── .gitignore
├── requirements.txt
└── README.md
```

## 🚀 Usage

### Automated Mode (Recommended)

Once setup, the system runs automatically:

- **Scanner:** Every hour at :00
- **LLM Analysis:** Daily at 00:10 UTC

Results are committed to:
- `feed/phishing_feed.json` - All detected domains
- `feed/llm-analysis.json` - LLM analysis results

### Manual Mode (Local Testing)

```bash
# Install dependencies
pip install -r requirements.txt

# Set API keys
export URLSCAN_API_KEY="your_key_here"
export OPENROUTER_API_KEY="your_key_here"

# Run scanner
python detection/bg-phishing-detector.py --sources urlscan google cloudflare

# Run LLM analysis (on high-risk domains)
python detection/llm_analyzer.py \
  --feed-file feed/phishing_feed.json \
  --output-file feed/llm-analysis.json \
  --min-score 75 \
  --max-analyze 50
```

### Command-line Options

**Scanner:**
```bash
python detection/bg-phishing-detector.py [OPTIONS]

Options:
  --sources [urlscan|google|cloudflare] ...
      Data sources to use (default: all)
  --duration SECONDS
      Maximum runtime in seconds
```

**LLM Analyzer:**
```bash
python detection/llm_analyzer.py [OPTIONS]

Options:
  --feed-file PATH
      Path to feed JSON (default: feed/phishing_feed.json)
  --output-file PATH
      Path to output JSON (default: feed/llm-analysis.json)
  --min-score INT
      Minimum score to analyze (default: 75)
  --max-analyze INT
      Maximum domains to analyze (default: 50)
```

## 📋 Feed Format

### phishing_feed.json

Contains detected domains from the scanner:

```json
[
  {
    "domain": "econt-bg.pages.dev",
    "score": 90,
    "details": {
      "brand_keywords": ["econt"],
      "suspicious_tld": null,
      "free_hosting": ".pages.dev",
      "geo_indicators": ["bg"],
      "transaction_keywords": [],
      "multiple_hyphens": true,
      "numeric_suffix": false,
      "subdomain_stacking": false,
      "high_entropy": false
    },
    "detected_at": "2026-01-30T14:23:45Z",
    "source": "urlscan.io"
  }
]
```

### llm-analysis.json

Contains LLM analysis results (separate file):

```json
{
  "last_updated": "2026-01-31T00:15:32Z",
  "analyzed_domains": [
    {
      "domain": "econt-bg.pages.dev",
      "threat_level": "HIGH",
      "confidence": 95,
      "phishing_score": 90,
      "mimicked_domain": "econt.bg",
      "decision": "BLOCK",
      "reasoning": "Clear Econt brand abuse on Cloudflare Pages with geographic targeting.",
      "analyzed_at": "2026-01-31T00:15:32Z"
    }
  ]
}
```

## 🔍 Detection Examples

**Flagged - Courier Phishing (High Score):**

- ✅ `speedy.bg-pv.cfd` (85/100) - .bg-XX.TLD pattern
- ✅ `econt-bg-delivery.pages.dev` (90/100) - Brand + free hosting
- ✅ `speedy.bg-track.cfd` (85/100) - .bg-XX.TLD pattern
- ✅ `olx-payment-bg.herokuapp.com` (88/100) - Multiple indicators

**Flagged - Bank Phishing (High Score):**

- ✅ `ubb-pay-login.cfd` (85/100) - Bank brand + suspicious TLD
- ✅ `dskbank-secure.icu` (80/100) - Bank brand + suspicious TLD
- ✅ `unicreditbulbank.verify-login.xyz` (90/100) - Bank brand impersonation
- ✅ `postbank-bg-authentication.top` (85/100) - Bank + geo indicator + suspicious TLD
- ✅ `fibank-ebanking.pages.dev` (88/100) - Bank brand + free hosting

**Whitelisted (Legitimate):**

- ❌ `tracking.econt.bg` (legitimate subdomain)
- ❌ `my.speedy.bg` (legitimate subdomain)
- ❌ `ebanking.ubb.bg` (legitimate bank subdomain)
- ❌ `online.dskbank.bg` (legitimate bank subdomain)

**Filtered Out (Low Score):**

- ❌ `example-delivery.com` (no brand keyword)
- ❌ `random-site.pages.dev` (no courier reference)

## 🛠️ Customization

### Adding More Brands

Edit `detection/bg-phishing-detector.py`:

```python
BRAND_KEYWORDS = [
    'econt',
    'speedy',
    'your_brand_here'  # Add your brand
]

WHITELISTED_DOMAINS = [
    'econt.bg',
    'speedy.bg',
    'your-legitimate-domain.com'  # Add legitimate domains
]
```

### Adjusting Score Threshold

Edit `detection/bg-phishing-detector.py`:

```python
SCORE_THRESHOLD = 70  # Change threshold (0-100)
```

### Adding More TLDs or Hosting Platforms

Edit `detection/bg-phishing-detector.py`:

```python
SUSPICIOUS_TLDS = (
    '.cfd',
    '.xyz',
    '.your-tld-here'  # Add suspicious TLD
)

FREE_HOSTING_SUFFIXES = (
    '.pages.dev',
    '.herokuapp.com',
    '.your-hosting.com'  # Add hosting platform
)
```

## 📊 Monitoring

### GitHub Actions Dashboard

View scan results: Repository → Actions

### Feed Statistics

Check `feed/stats.json` for last run metrics:

```json
{
  "last_run": "2026-01-30T15:00:00Z",
  "domains_processed": 1247,
  "new_findings": 3,
  "elapsed_time": 45.2
}
```

### Workflow Summaries

Each workflow run creates a summary with:

- Domains processed
- New findings
- LLM analysis results
- Recent high-threat domains

## ⚠️ Rate Limits

**URLScan.io:**

- Free tier: ~100 requests/day
- 1 request per second in scanner

**OpenRouter (Llama 3.3 70B):**

- Free tier: generous but limited
- 3 seconds between requests
- Max 50 domains/day analyzed

**Certificate Transparency:**

- No strict limits
- 500 entries per log queried

## 🐛 Troubleshooting

**Scanner not finding domains:**

- Check API key in GitHub Secrets
- Verify keywords match target brands
- Lower score threshold temporarily for testing

**LLM analysis not running:**

- Verify OPENROUTER_API_KEY is set
- Check if domains scored ≥75 in feed
- Review OpenRouter free tier limits

**Workflow conflicts:**

- Only one scanner/analysis runs at a time (concurrency control)
- Failed runs retry up to 3 times

**Push failures:**

- Automatic retry with rebase (up to 3 attempts)
- Check repository permissions

## 🔐 Security

- **API keys:** Stored as GitHub Secrets (never in code)
- **Whitelisting:** Prevents false positives on legitimate domains
- **Rate limiting:** Built-in delays to respect API limits
- **Concurrency control:** Prevents workflow collisions

## 📈 Performance

- **Scanner runtime:** ~30-60 seconds (depending on sources)
- **LLM analysis:** ~3-5 minutes (for 50 domains)
- **Memory usage:** <500MB
- **Storage:** ~1-2MB per 1000 domains

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test locally
5. Submit a pull request

## 📄 License

MIT License - feel free to use and modify for your needs.

## 🙏 Acknowledgments

- URLScan.io for domain scanning API
- OpenRouter for free LLM access
- Google/Cloudflare for Certificate Transparency logs

## 📞 Support

- **Issues:** Open a GitHub issue
- **Questions:** Check existing issues or start a discussion

---

**⚡ Built with ❤️ to protect Bulgarian users from phishing attacks**
