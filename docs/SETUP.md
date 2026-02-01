# 🚀 Setup Guide

Complete setup instructions for the Bulgarian Phishing Domain Detector.

## Step 1: Get API Keys

### URLScan.io API Key

URLScan.io provides domain scanning and intelligence data.

1. Go to [https://urlscan.io/](https://urlscan.io/)
2. Click **Sign Up** (top right)
3. Create a free account with your email
4. Verify your email address
5. Log in to your account
6. Click your username (top right) → **Settings**
7. Scroll to **API Keys** section
8. Click **Create new API key**
9. Give it a name (e.g., "bg-phishing-detector")
10. Copy the API key and save it securely

**Note:** Free tier allows ~100 requests/day, which is sufficient for hourly scans.

### OpenRouter API Key

OpenRouter provides access to Llama 3.3 70B for AI analysis.

1. Go to [https://openrouter.ai/](https://openrouter.ai/)
2. Click **Sign Up**
3. Create an account (Google/GitHub sign-in available)
4. Navigate to **Keys** (left sidebar)
5. Click **Create Key**
6. Name it (e.g., "bg-phishing-detector")
7. Copy the API key and save it securely

**Note:** Free tier includes generous usage of Llama 3.3 70B Instruct.

## Step 2: Set Up Repository

### Option A: Fork Repository (Recommended)

1. Go to the original repository on GitHub
2. Click the **Fork** button (top right)
3. Select your account as the destination
4. Wait for the fork to complete
5. You now have your own copy

### Option B: Clone and Push

```bash
# Clone the repository
git clone https://github.com/ORIGINAL_OWNER/bg-phishing-detector.git
cd bg-phishing-detector

# Create your own repository on GitHub first, then:
git remote set-url origin https://github.com/YOUR_USERNAME/bg-phishing-detector.git
git push -u origin main
```

## Step 3: Add GitHub Secrets

GitHub Secrets store your API keys securely. They are encrypted and never exposed in logs.

### Step-by-Step Guide

1. **Open your repository** on GitHub

2. **Go to Settings**
   - Click the **Settings** tab (gear icon, top menu bar)
   - If you don't see Settings, you may not have admin access

3. **Navigate to Secrets**
   - In the left sidebar, find **Security** section
   - Click **Secrets and variables**
   - Click **Actions**

4. **Add URLSCAN_API_KEY**
   - Click the green **New repository secret** button
   - In the **Name** field, enter: `URLSCAN_API_KEY`
   - In the **Secret** field, paste your URLScan.io API key
   - Click **Add secret**

5. **Add OPENROUTER_API_KEY**
   - Click **New repository secret** again
   - In the **Name** field, enter: `OPENROUTER_API_KEY`
   - In the **Secret** field, paste your OpenRouter API key
   - Click **Add secret**

### Visual Guide

```
GitHub Repository
    │
    └── Settings (tab)
            │
            └── Secrets and variables (left sidebar)
                    │
                    └── Actions
                            │
                            ├── [New repository secret]
                            │       Name: URLSCAN_API_KEY
                            │       Secret: sk-xxx...
                            │       [Add secret]
                            │
                            └── [New repository secret]
                                    Name: OPENROUTER_API_KEY
                                    Secret: sk-or-xxx...
                                    [Add secret]
```

### Verify Secrets

After adding, you should see:

```
Repository secrets (2)
├── URLSCAN_API_KEY     Updated just now
└── OPENROUTER_API_KEY  Updated just now
```

**Important:** You cannot view secret values after saving. If you need to change them, you must update with a new value.

## Step 4: Enable GitHub Actions

GitHub Actions runs the automated workflows.

1. Go to your repository
2. Click the **Actions** tab
3. If you see a warning about workflows:
   - Click **I understand my workflows, go ahead and enable them**
4. Workflows are now enabled

### Enable Workflow Permissions

Ensure workflows can commit changes:

1. Go to **Settings** → **Actions** → **General**
2. Scroll to **Workflow permissions**
3. Select **Read and write permissions**
4. Check **Allow GitHub Actions to create and approve pull requests** (optional)
5. Click **Save**

## Step 5: Test the Setup

### Run the Scanner Manually

1. Go to **Actions** tab
2. Click **Hourly Phishing Scanner** (left sidebar)
3. Click **Run workflow** dropdown (right side)
4. Select branch: `main`
5. Click the green **Run workflow** button
6. Wait 1-2 minutes for completion
7. Check for green checkmark (success)

### View Scanner Results

1. Click on the completed workflow run
2. View the **Summary** tab for statistics
3. Check `feed/phishing_feed.json` in repository for results

### Run LLM Analysis Manually

1. Go to **Actions** tab
2. Click **Daily LLM Analysis** (left sidebar)
3. Click **Run workflow**
4. Wait 3-5 minutes for completion
5. Check `feed/llm-analysis.json` for results

## Step 6: Verify Everything Works

### Checklist

- [ ] URLScan.io API key added as secret
- [ ] OpenRouter API key added as secret
- [ ] GitHub Actions enabled
- [ ] Workflow permissions set to read/write
- [ ] Scanner workflow runs successfully
- [ ] LLM analysis workflow runs successfully
- [ ] `feed/phishing_feed.json` is created/updated
- [ ] `feed/llm-analysis.json` is created/updated

### Common Issues

**Workflow fails at "Run phishing scanner":**
- Check URLSCAN_API_KEY is set correctly
- Verify API key is active on URLScan.io

**Workflow fails at "Run LLM analysis":**
- Check OPENROUTER_API_KEY is set correctly
- Verify API key is active on OpenRouter

**Push fails after scan:**
- Ensure workflow permissions are set to "Read and write"
- Check repository is not protected

## Local Testing Instructions

Test the detector locally before relying on GitHub Actions.

### Prerequisites

- Python 3.10+
- pip package manager

### Setup

```bash
# Clone your repository
git clone https://github.com/YOUR_USERNAME/bg-phishing-detector.git
cd bg-phishing-detector

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export URLSCAN_API_KEY="your_urlscan_api_key"
export OPENROUTER_API_KEY="your_openrouter_api_key"
```

### Run Scanner

```bash
# Full scan (all sources)
python detection/bg-phishing-detector.py --sources urlscan google cloudflare

# Quick test (URLScan only)
python detection/bg-phishing-detector.py --sources urlscan
```

### Run LLM Analysis

```bash
# Analyze high-risk domains
python detection/llm_analyzer.py \
  --feed-file feed/phishing_feed.json \
  --output-file feed/llm-analysis.json \
  --min-score 75 \
  --max-analyze 10
```

### View Results

```bash
# Check phishing feed
cat feed/phishing_feed.json | python -m json.tool | head -50

# Check LLM analysis
cat feed/llm-analysis.json | python -m json.tool
```

## Automated Schedule

Once setup is complete, workflows run automatically:

| Workflow | Schedule | Purpose |
|----------|----------|---------|
| Hourly Phishing Scanner | Every hour at :00 | Detect new phishing domains |
| Daily LLM Analysis | Daily at 00:10 UTC | AI validation of high-risk domains |

## Security Best Practices

- ✅ API keys stored in GitHub Secrets (encrypted)
- ✅ Keys never appear in code or logs
- ✅ `.gitignore` prevents accidental key commits
- ✅ Workflows use `secrets.` syntax to access keys
- ✅ Repository can be public (keys remain safe)

## Updating API Keys

If you need to rotate or update API keys:

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click on the secret name (e.g., URLSCAN_API_KEY)
3. Click **Update secret**
4. Paste the new key
5. Click **Update secret**

## Getting Help

- **GitHub Issues:** Report bugs or request features
- **Actions Tab:** View detailed workflow logs
- **Workflow Summary:** Each run creates a summary with stats

---

**🎉 Setup complete! Your phishing detector is now running automatically.**
