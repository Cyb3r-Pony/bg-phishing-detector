# 📊 Phishing Domain Scoring Reference

Complete documentation of the 13 detection methods used to score phishing domains.

## Scoring System Overview

Domains are scored from **0 to 100** based on multiple indicators.

- **Threshold:** Domains scoring **≥70** are flagged as suspicious
- **Maximum raw score:** 230 points (capped at 100)
- **Penalty:** Non-BG context reduces score by 20 points

## The 13 Detection Methods

### 1. Brand Keywords (+40 points)

**Description:** Domain contains a protected Bulgarian brand name.

**Examples:**
- `econt-delivery.com` → matches "econt" → +40
- `speedy-bg.pages.dev` → matches "speedy" → +40
- `olx-payment.tk` → matches "olx" → +40

**Protected Brands:**
- econt, speedy, bulgariapost, bgpost, bg-post
- samedaybg, boxnow, boxnowbg
- cityexpress, cityexpressbg, expressone, expressonebg
- intime, interlogistica, olx, dhl

---

### 2. Homoglyphs (+30 points)

**Description:** Uses look-alike Unicode characters to impersonate brands.

**Examples:**
- `еcont.bg` → Cyrillic 'е' instead of Latin 'e' → +30
- `spееdy.bg` → Cyrillic 'е' instead of Latin 'e' → +30
- `оlx.bg` → Cyrillic 'о' instead of Latin 'o' → +30

**Common Substitutions:**
| Latin | Cyrillic | Unicode |
|-------|----------|---------|
| a | а | U+0430 |
| e | е | U+0435 |
| o | о | U+043E |
| c | с | U+0441 |
| p | р | U+0440 |

---

### 3. Typosquatting (+25 points)

**Description:** Uses common misspellings or keyboard-adjacent errors.

**Examples:**
- `econt.bg` → `ecomt.bg` (m/n adjacent) → +25
- `speedy.bg` → `speey.bg` (missing d) → +25
- `speedy.bg` → `speddy.bg` (double d) → +25

**Detection Patterns:**
- Missing letters: `econt` → `ecot`
- Double letters: `speedy` → `speeedy`
- Adjacent key swaps: `econt` → `econt` (r/t)
- Transpositions: `econt` → `ecotn`

---

### 4. Free Hosting (+25 points)

**Description:** Domain uses a free hosting platform commonly abused for phishing.

**Examples:**
- `econt-bg.pages.dev` → Cloudflare Pages → +25
- `speedy-delivery.herokuapp.com` → Heroku → +25
- `olx-payment.netlify.app` → Netlify → +25

**Free Hosting Platforms:**
- `.pages.dev` (Cloudflare)
- `.herokuapp.com` (Heroku)
- `.netlify.app` (Netlify)
- `.vercel.app` (Vercel)
- `.web.app`, `.firebaseapp.com` (Firebase)
- `.onrender.com`, `.render.com` (Render)
- `.fly.dev` (Fly.io)
- `.surge.sh`, `.gitlab.io`, `.github.io`
- `.repl.co`, `.replit.dev`, `.replit.app` (Replit)
- `.glitch.me`, `.cyclic.app`, `.railway.app`
- `.deta.dev`, `.azurestaticapps.net`, `.amplifyapp.com`

---

### 5. Suspicious TLD (+20 points)

**Description:** Uses a top-level domain commonly abused for phishing.

**Examples:**
- `econt-bg.cfd` → +20
- `speedy-delivery.xyz` → +20
- `olx-payment.tk` → +20

**Suspicious TLDs:**
- Free TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`
- Cheap TLDs: `.cfd`, `.top`, `.xyz`, `.club`, `.online`
- Suspicious: `.site`, `.space`, `.click`, `.link`, `.live`
- Other: `.icu`, `.buzz`, `.cam`, `.rest`, `.store`, `.tech`, `.website`, `.world`, `.pw`, `.cc`

---

### 6. Direct Impersonation (+15 points)

**Description:** Uses exact brand name followed by suspicious suffix.

**Examples:**
- `econt-official.com` → exact "econt" + "official" → +15
- `speedy-secure.net` → exact "speedy" + "secure" → +15
- `olx-verify.org` → exact "olx" + "verify" → +15

**Suspicious Suffixes:**
- `-official`, `-secure`, `-verify`, `-login`
- `-payment`, `-update`, `-confirm`, `-account`
- `-support`, `-help`, `-service`

---

### 7. Geographic Indicators (+15 points)

**Description:** Domain contains Bulgarian geographic references.

**Examples:**
- `econt-bg.com` → contains "-bg" → +15
- `speedy.bulgaria.pages.dev` → contains "bulgaria" → +15
- `olx-sofia.tk` → contains "sofia" → +15

**Geographic Patterns:**
- Country code: `.bg`, `-bg`, `bg-`, `_bg`
- Country name: `bulgaria`, `bulgarian`
- Cities: `sofia`, `plovdiv`, `varna`, `burgas`

---

### 8. Transaction Keywords (+10 points)

**Description:** Domain contains payment or delivery-related terms.

**Examples:**
- `econt-payment.com` → contains "payment" → +10
- `speedy-tracking.pages.dev` → contains "tracking" → +10
- `olx-delivery.tk` → contains "delivery" → +10

**Transaction Keywords (English):**
- tracking, delivery, shipment, parcel
- payment, pay-now, secure-pay, invoice
- confirm, verify, account, login, update
- suspended, tax, fee, customer-center

**Transaction Keywords (Bulgarian):**
- klient (клиент - client)
- pratka (пратка - parcel)
- dostavka (доставка - delivery)
- usluga (услуга - service)
- plashtane (плащане - payment)

---

### 9. .bg-XX.TLD Pattern (+10 points)

**Description:** Special pattern where `.bg` appears as subdomain before suspicious TLD.

**Examples:**
- `speedy.bg-pv.cfd` → ".bg-" + suspicious TLD → +10
- `econt.bg-track.xyz` → ".bg-" + suspicious TLD → +10
- `olx.bg-delivery.tk` → ".bg-" + suspicious TLD → +10

**Why This Matters:**
This pattern tricks users into thinking the domain is `.bg` (Bulgarian) when it's actually a suspicious TLD. The `.bg` becomes part of a subdomain, not the actual TLD.

---

### 10. Multiple Hyphens (+10 points)

**Description:** Domain contains 2 or more hyphens.

**Examples:**
- `econt-bg-delivery.com` → 2 hyphens → +10
- `speedy-track-parcel.pages.dev` → 2 hyphens → +10
- `olx-payment-secure-login.tk` → 3 hyphens → +10

**Why This Matters:**
Legitimate brands rarely use multiple hyphens. Phishing domains often chain keywords with hyphens to appear legitimate.

---

### 11. Numeric Suffix (+10 points)

**Description:** Domain ends with random numbers.

**Examples:**
- `econt-12345.com` → numeric suffix → +10
- `speedy-delivery-2024.pages.dev` → numeric suffix → +10
- `olx-payment-001.tk` → numeric suffix → +10

**Why This Matters:**
Attackers add numbers to create unique domains when the original is taken. Legitimate brands don't use random number suffixes.

---

### 12. Subdomain Stacking (+10 points)

**Description:** Domain has 3 or more subdomain levels.

**Examples:**
- `login.secure.econt.phishing.com` → 4 levels → +10
- `track.delivery.speedy.fake.pages.dev` → 4 levels → +10
- `a.b.c.olx.tk` → 3+ levels → +10

**Why This Matters:**
Excessive subdomains are used to hide the actual domain or make URLs look more legitimate.

---

### 13. High Entropy (+10 points)

**Description:** Domain name contains random or gibberish characters.

**Examples:**
- `xk7m9p-econt.com` → high entropy prefix → +10
- `speedy-a8b2c4d6.pages.dev` → random characters → +10
- `olx-qwerty123xyz.tk` → gibberish → +10

**How It's Calculated:**
Shannon entropy measures randomness. High entropy (>3.5) suggests auto-generated or random strings rather than meaningful words.

---

### 14. Non-BG Context Penalty (-20 points)

**Description:** Domain appears to target non-Bulgarian context, reducing suspicion.

**Examples:**
- `econt-usa.com` → USA context → -20
- `speedy-uk-delivery.pages.dev` → UK context → -20
- `olx-france.tk` → France context → -20

**Non-BG Indicators:**
- Country codes: `-us`, `-uk`, `-de`, `-fr`, etc.
- Country names: `america`, `germany`, `france`, etc.
- Languages: English-only content without BG indicators

**Why This Matters:**
If a domain clearly targets another country, it's less likely to be a Bulgarian phishing attempt (though still flagged for other indicators).

---

## Scoring Examples

### Example 1: High-Risk Domain

**Domain:** `speedy.bg-pv.cfd`

| Indicator | Points |
|-----------|--------|
| Brand keyword (speedy) | +40 |
| Suspicious TLD (.cfd) | +20 |
| Geographic indicator (bg) | +15 |
| .bg-XX.TLD pattern | +10 |
| **Total** | **85** ✅ FLAGGED |

---

### Example 2: Very High-Risk Domain

**Domain:** `econt-bg-payment.pages.dev`

| Indicator | Points |
|-----------|--------|
| Brand keyword (econt) | +40 |
| Free hosting (.pages.dev) | +25 |
| Geographic indicator (bg) | +15 |
| Transaction keyword (payment) | +10 |
| Multiple hyphens (2) | +10 |
| **Total** | **100** ✅ FLAGGED (capped) |

---

### Example 3: Maximum Indicators

**Domain:** `еcont-bg-secure-payment-12345.pages.dev` (with Cyrillic е)

| Indicator | Points |
|-----------|--------|
| Brand keyword | +40 |
| Homoglyph (Cyrillic е) | +30 |
| Free hosting | +25 |
| Direct impersonation (secure) | +15 |
| Geographic indicator (bg) | +15 |
| Transaction keyword (payment) | +10 |
| Multiple hyphens (4) | +10 |
| Numeric suffix (12345) | +10 |
| **Raw Total** | **155** |
| **Capped Total** | **100** ✅ FLAGGED |

---

### Example 4: Below Threshold

**Domain:** `econt-tracking.com`

| Indicator | Points |
|-----------|--------|
| Brand keyword (econt) | +40 |
| Transaction keyword (tracking) | +10 |
| **Total** | **50** ❌ Not flagged |

*Missing free hosting, suspicious TLD, or geographic indicators*

---

### Example 5: Whitelisted Domain

**Domain:** `tracking.econt.bg`

```
✅ WHITELISTED
Subdomain of legitimate econt.bg
Not scored - Excluded from detection
```

---

## LLM Analysis

Domains scoring **≥75** are analyzed by Llama 3.3 70B for validation.

### Output Format

```json
{
  "domain": "econt-bg.pages.dev",
  "threat_level": "HIGH",
  "confidence": 95,
  "phishing_score": 90,
  "mimicked_domain": "econt.bg",
  "decision": "BLOCK",
  "reasoning": "Clear Econt brand abuse on Cloudflare Pages with geographic targeting."
}
```

### Threat Levels

| Level | Description |
|-------|-------------|
| HIGH | Confirmed phishing, immediate block recommended |
| MEDIUM | Likely phishing, investigation recommended |
| LOW | Possibly legitimate, monitor |

### Decisions

| Decision | Action |
|----------|--------|
| BLOCK | Add to blocklist immediately |
| INVESTIGATE | Manual review required |
| FALSE_POSITIVE | Remove from feed |

---

## Adjusting Detection

### Change Score Threshold

Edit `detection/bg-phishing-detector.py`:

```python
SCORE_THRESHOLD = 70  # Default: 70
```

**Recommendations:**
- **60:** More sensitive, catches more but increases false positives
- **70:** Balanced (default)
- **80:** Selective, fewer false positives but may miss threats

### Change LLM Analysis Threshold

Edit workflow or command line:

```bash
python detection/llm_analyzer.py --min-score 75  # Default: 75
```

---

## Score Distribution Guidelines

| Score Range | Classification | Expected % |
|-------------|----------------|------------|
| 0-39 | Not suspicious | 70% |
| 40-69 | Low concern | 22% |
| 70-79 | Medium risk | 5% |
| 80-89 | High risk | 2% |
| 90-100 | Critical | 1% |

---

**📝 Note:** Rule-based scoring is fast and deterministic. LLM analysis provides additional AI-powered validation for high-risk detections.
