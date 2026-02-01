#!/usr/bin/env python3
"""
LLM-based phishing domain analyzer
Analyzes high-risk domains (score ≥80) using OpenRouter API
Runs daily to enrich detection feed with AI analysis
"""

import json
import os
import sys
import time
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional


class OpenRouterAnalyzer:
    """Analyzer using free models via OpenRouter"""
    
    def __init__(self, api_key: str, model: str = "arcee-ai/trinity-large-preview:free"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.requests_made = 0
        self.max_requests = 200  # Conservative daily limit
        
        # Model display names
        self.model_names = {
            "arcee-ai/trinity-large-preview:free": "Arcee Trinity Large",
            "nvidia/nemotron-nano-9b-v2:free": "Nvidia Nemotron Nano 9B V2",
            "nvidia/nemotron-3-nano-30b-a3b:free": "Nvidia Nemotron 3 Nano 30B",
            "meta-llama/llama-3.3-70b-instruct:free": "Meta Llama 3.3 70B",
            "upstage/solar-pro-3:free": "Upstage Solar Pro 3",
            "qwen/qwen3-coder:free": "Qwen 3 Coder"
        }
        
    def analyze_domain(self, domain: str, score: int, details: Dict) -> Optional[Dict]:
        """
        Analyze a domain using LLM
        
        Args:
            domain: Domain name
            score: Rule-based score (0-100)
            details: Detection details from scanner
        
        Returns:
            Analysis dict or None if failed
        """
        if self.requests_made >= self.max_requests:
            print(f"⚠️  Daily limit reached ({self.max_requests} requests)")
            return None
        
        # Build analysis prompt
        prompt = self._build_prompt(domain, score, details)
        
        try:
            response = requests.post(
                self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "HTTP-Referer": "https://github.com/bg-phishing-detector",
                    "X-Title": "BG Phishing Detector"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a cybersecurity expert specializing in phishing detection. Analyze domains targeting Bulgarian courier services. Be concise and decisive."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.2,  # Low temperature for consistent analysis
                    "max_tokens": 400
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis_text = result['choices'][0]['message']['content']
                self.requests_made += 1
                
                # Parse analysis
                parsed = self._parse_analysis(analysis_text)
                
                # Add metadata
                parsed['raw_analysis'] = analysis_text
                parsed['model'] = self.model
                parsed['analyzed_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                
                # Rate limiting: 3 seconds between requests (respects 20/minute limit)
                time.sleep(3)
                
                return parsed
                
            elif response.status_code == 429:
                print(f"⚠️  Rate limit hit, waiting 60s...")
                time.sleep(60)
                return None
            else:
                print(f"❌ API error {response.status_code}: {response.text[:200]}")
                return None
                
        except Exception as e:
            print(f"❌ Error analyzing {domain}: {e}")
            return None
    
    def _build_prompt(self, domain: str, score: int, details: Dict) -> str:
        """Build analysis prompt for LLM"""
        
        # Extract key details
        brands = ', '.join(details.get('brand_keywords', []))
        trans_kw = ', '.join(details.get('transaction_keywords', [])[:3])  # Limit to 3
        tld = details.get('suspicious_tld', 'N/A')
        hosting = details.get('free_hosting', 'N/A')
        
        # Identify mimicked domain
        whitelisted = [
            'econt.bg', 'econt.com', 'speedy.bg', 'bgpost.bg', 'bulgariapost.bg',
            'olx.bg', 'dhl.bg', 'sameday.bg', 'evropat.bg', 'easypay.bg',
            'epay.bg', 'borica.bg', 'fastpay.bg', 'intime.bg', 'boxnow.bg'
        ]
        
        prompt = f"""Analyze this suspected phishing domain targeting Bulgarian services:

**Domain:** {domain}
**Phishing Score:** {score}/100 (rule-based)
**Detected Brands:** {brands if brands else 'None'}
**Transaction Keywords:** {trans_kw if trans_kw else 'None'}
**TLD:** {tld}

**Whitelisted Legitimate Domains:**
{', '.join(whitelisted[:10])}

**Task:** Provide EXACTLY this format (no extra text):

THREAT_LEVEL: [HIGH/MEDIUM/LOW]
CONFIDENCE: [0-100]
PHISHING_SCORE: {score}
MIMICKED_DOMAIN: [Which legitimate domain is being impersonated, e.g., econt.bg, speedy.bg, or NONE if no clear target]
DECISION: [BLOCK/INVESTIGATE]
REASONING: [One concise sentence explaining the primary threat indicator]

Rules:
- THREAT_LEVEL: HIGH if obvious brand impersonation, MEDIUM if suspicious patterns, LOW if unclear
- CONFIDENCE: 0-100 numeric value only (no % symbol)
- MIMICKED_DOMAIN: Must be from the whitelisted list above, or NONE
- DECISION: BLOCK for clear phishing, INVESTIGATE for suspicious but unclear
- REASONING: Single sentence, max 100 characters, focus on PRIMARY indicator

Be precise and concise."""
        
        return prompt
    
    def _parse_analysis(self, analysis_text: str) -> Dict:
        """Parse LLM response into structured format"""
        
        result = {
            'threat_level': 'UNKNOWN',
            'confidence': 0,
            'phishing_score': 0,
            'mimicked_domain': 'NONE',
            'decision': 'INVESTIGATE',
            'reasoning': ''
        }
        
        lines = analysis_text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('THREAT_LEVEL:'):
                level = line.split(':', 1)[1].strip().upper()
                if level in ['HIGH', 'MEDIUM', 'LOW']:
                    result['threat_level'] = level
            
            elif line.startswith('CONFIDENCE:'):
                try:
                    conf_str = line.split(':', 1)[1].strip().replace('%', '')
                    result['confidence'] = int(conf_str)
                except:
                    pass
            
            elif line.startswith('PHISHING_SCORE:'):
                try:
                    score_str = line.split(':', 1)[1].strip()
                    result['phishing_score'] = int(score_str)
                except:
                    pass
            
            elif line.startswith('MIMICKED_DOMAIN:'):
                mimicked = line.split(':', 1)[1].strip()
                # Clean up and validate
                mimicked = mimicked.lower().replace('www.', '')
                if mimicked and mimicked != 'none':
                    result['mimicked_domain'] = mimicked
                else:
                    result['mimicked_domain'] = 'NONE'
            
            elif line.startswith('DECISION:'):
                decision = line.split(':', 1)[1].strip().upper()
                if decision in ['BLOCK', 'INVESTIGATE']:
                    result['decision'] = decision
            
            elif line.startswith('REASONING:'):
                result['reasoning'] = line.split(':', 1)[1].strip()
        
        return result


def load_feed(feed_path: str) -> List[Dict]:
    """Load phishing feed from JSON"""
    if not os.path.exists(feed_path):
        print(f"❌ Feed file not found: {feed_path}")
        sys.exit(1)
    
    with open(feed_path, 'r') as f:
        return json.load(f)


def save_llm_analysis(output_path: str, analyzed_domains: List[Dict]):
    """Save LLM analysis to separate JSON file"""
    # Create analysis output with metadata
    output = {
        'analyzed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'total_analyzed': len(analyzed_domains),
        'domains': analyzed_domains
    }
    
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)


def load_existing_analysis(output_path: str) -> List[str]:
    """Load list of already analyzed domain names"""
    if not os.path.exists(output_path):
        return []
    
    try:
        with open(output_path, 'r') as f:
            data = json.load(f)
            return [d['domain'] for d in data.get('domains', [])]
    except:
        return []


def filter_domains_for_analysis(
    feed: List[Dict],
    min_score: int,
    lookback_hours: int,
    already_analyzed: List[str]
) -> List[Dict]:
    """
    Filter domains that need LLM analysis
    
    Args:
        feed: Full feed data
        min_score: Minimum score threshold
        lookback_hours: Only analyze domains from last N hours
        already_analyzed: List of domain names already analyzed
    
    Returns:
        List of domains to analyze
    """
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    to_analyze = []
    
    for entry in feed:
        domain = entry.get('domain', '')
        
        # Skip if already analyzed
        if domain in already_analyzed:
            continue
        
        # Check score threshold
        if entry.get('score', 0) < min_score:
            continue
        
        # Check time window
        detected_at = entry.get('detected_at')
        if detected_at:
            try:
                detected_time = datetime.fromisoformat(detected_at.replace('Z', '+00:00'))
                if detected_time < cutoff_time:
                    continue
            except:
                pass
        
        to_analyze.append(entry)
    
    return to_analyze


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='LLM Analysis for High-Risk Phishing Domains'
    )
    parser.add_argument(
        '--feed-file',
        default='feed/phishing_feed.json',
        help='Path to phishing feed JSON'
    )
    parser.add_argument(
        '--min-score',
        type=int,
        default=70,
        help='Minimum score to analyze (default: 70)'
    )
    parser.add_argument(
        '--lookback-hours',
        type=int,
        default=24,
        help='Analyze domains from last N hours (default: 24)'
    )
    parser.add_argument(
        '--max-analyze',
        type=int,
        default=100,
        help='Maximum domains to analyze (default: 100)'
    )
    parser.add_argument(
        '--model',
        type=str,
        default='arcee-ai/trinity-large-preview:free',
        choices=[
            'arcee-ai/trinity-large-preview:free',
            'nvidia/nemotron-nano-9b-v2:free',
            'nvidia/nemotron-3-nano-30b-a3b:free',
            'upstage/solar-pro-3:free',
            'qwen/qwen3-coder:free'
        ],
        help='LLM model to use (default: arcee-ai/trinity-large-preview:free)'
    )
    parser.add_argument(
        '--output-file',
        default='feed/llm-analysis.json',
        help='Output file for LLM analysis (default: feed/llm-analysis.json)'
    )
    
    args = parser.parse_args()
    
    # Get API key
    api_key = os.environ.get('OPENROUTER_API_KEY')
    if not api_key:
        print("❌ Error: OPENROUTER_API_KEY environment variable not set")
        sys.exit(1)
    
    # Load feed
    print(f"📂 Loading feed from {args.feed_file}...")
    feed = load_feed(args.feed_file)
    print(f"   Total entries in feed: {len(feed)}")
    
    # Load existing analysis to avoid re-analyzing
    already_analyzed = load_existing_analysis(args.output_file)
    if already_analyzed:
        print(f"   Already analyzed: {len(already_analyzed)} domains")
    
    # Filter domains for analysis
    to_analyze = filter_domains_for_analysis(
        feed,
        min_score=args.min_score,
        lookback_hours=args.lookback_hours,
        already_analyzed=already_analyzed
    )
    
    # Sort by score (highest first) and limit
    to_analyze = sorted(
        to_analyze,
        key=lambda x: x.get('score', 0),
        reverse=True
    )[:args.max_analyze]
    
    if not to_analyze:
        print("✅ No domains need analysis")
        return
    
    # Initialize analyzer with selected model
    analyzer = OpenRouterAnalyzer(api_key, model=args.model)
    model_display = analyzer.model_names.get(args.model, args.model)
    
    print(f"\n🔍 Analyzing {len(to_analyze)} high-risk domains...")
    print(f"   Model: {model_display}")
    print(f"   Score threshold: ≥{args.min_score}")
    print(f"   Lookback window: {args.lookback_hours} hours")
    print(f"=" * 60)
    
    # Track statistics
    stats = {
        'analyzed': 0,
        'high_threat': 0,
        'medium_threat': 0,
        'low_threat': 0,
        'block_recommended': 0,
        'false_positives': 0,
        'errors': 0
    }
    
    # Track analyzed domains
    analyzed_domains = []
    
    # Analyze each domain
    for i, entry in enumerate(to_analyze, 1):
        domain = entry.get('domain', 'unknown')
        score = entry.get('score', 0)
        details = entry.get('details', {})
        
        print(f"\n[{i}/{len(to_analyze)}] Analyzing: {domain}")
        print(f"   Phishing Score: {score}/100")
        
        # Perform LLM analysis
        analysis = analyzer.analyze_domain(domain, score, details)
        
        if analysis:
            # Create analyzed entry with all info
            analyzed_entry = {
                'domain': domain,
                'detected_at': entry.get('detected_at'),
                'phishing_score': score,
                'detection_details': details,
                'llm_analysis': analysis
            }
            analyzed_domains.append(analyzed_entry)
            stats['analyzed'] += 1
            
            # Display standardized output
            threat = analysis['threat_level']
            confidence = analysis['confidence']
            mimicked = analysis['mimicked_domain']
            decision = analysis['decision']
            reasoning = analysis['reasoning']
            
            # Threat level with confidence
            if threat == 'HIGH':
                stats['high_threat'] += 1
                print(f"   🚨 Threat Level: HIGH")
            elif threat == 'MEDIUM':
                stats['medium_threat'] += 1
                print(f"   ⚠️  Threat Level: MEDIUM")
            elif threat == 'LOW':
                stats['low_threat'] += 1
                print(f"   ℹ️  Threat Level: LOW")
            
            print(f"   📊 Confidence: {confidence}%")
            print(f"   🎯 Mimicked Domain: {mimicked}")
            
            # Decision
            if decision == 'BLOCK':
                stats['block_recommended'] += 1
                print(f"   🛑 Decision: BLOCK")
            else:
                print(f"   🔍 Decision: INVESTIGATE")
            
            print(f"   💡 {reasoning}")
            
        else:
            stats['errors'] += 1
            print(f"   ❌ Analysis failed")
    
    # Save LLM analysis to separate file
    if analyzed_domains:
        print(f"\n💾 Saving analysis to {args.output_file}...")
        save_llm_analysis(args.output_file, analyzed_domains)
        print(f"   ✅ Saved {len(analyzed_domains)} analyzed domains")
    else:
        print(f"\n   No new domains analyzed")
    
    # Print summary
    print(f"\n{'=' * 60}")
    print(f"✅ LLM Analysis Complete")
    print(f"{'=' * 60}")
    print(f"  Domains analyzed: {stats['analyzed']}")
    print(f"  High threat: {stats['high_threat']} 🚨")
    print(f"  Medium threat: {stats['medium_threat']} ⚠️")
    print(f"  Low threat: {stats['low_threat']} ℹ️")
    print(f"  Block recommended: {stats['block_recommended']}")
    print(f"  False positives: {stats['false_positives']}")
    print(f"  Errors: {stats['errors']}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
