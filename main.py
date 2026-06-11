import json, logging, os, re, time, threading
import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Token Rotation
# ---------------------------------------------------------------------------

class TokenRotator:
    """
    Rotate through multiple GitHub tokens.
    Tokens are read from:
      - GITHUB_TOKEN          (single token, legacy)
      - GITHUB_TOKEN_1 .. N   (multiple tokens)
      - GITHUB_TOKENS         (comma-separated list)
    """
    def __init__(self):
        self._tokens = []
        self._reset_at = {}   # token -> unix timestamp when it becomes usable again
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        seen = set()
        tokens = []
        # Comma-separated list
        bulk = os.environ.get('GITHUB_TOKENS', '')
        for t in bulk.split(','):
            t = t.strip()
            if t and t not in seen:
                seen.add(t)
                tokens.append(t)
        # Numbered tokens
        for i in range(1, 20):
            t = os.environ.get(f'GITHUB_TOKEN_{i}', '').strip()
            if t and t not in seen:
                seen.add(t)
                tokens.append(t)
        # Legacy single token
        t = os.environ.get('GITHUB_TOKEN', '').strip()
        if t and t not in seen:
            tokens.append(t)
        self._tokens = tokens
        self._index = 0

    def reload(self):
        with self._lock:
            self._load()

    def count(self):
        return len(self._tokens)

    def current(self):
        with self._lock:
            return self._next_available()

    def _next_available(self):
        """Return first token not currently rate-limited (or None)."""
        now = time.time()
        for offset in range(len(self._tokens)):
            idx = (self._index + offset) % len(self._tokens)
            t = self._tokens[idx]
            reset = self._reset_at.get(t, 0)
            if now >= reset:
                self._index = idx
                return t
        return None

    def mark_rate_limited(self, token, reset_ts):
        """Mark a token as rate-limited until reset_ts (unix timestamp)."""
        with self._lock:
            self._reset_at[token] = reset_ts
            logger.warning(f'Token ...{token[-6:]} rate-limited until {time.strftime("%H:%M:%S", time.localtime(reset_ts))}')
            # Advance to next
            self._index = (self._index + 1) % len(self._tokens)

    def headers(self, token=None):
        if token is None:
            token = self.current()
        h = {
            'Accept': 'application/vnd.github.cloak-preview+json',
            'User-Agent': 'crypto-commit-dorker/2.0'
        }
        if token:
            h['Authorization'] = f'Bearer {token}'
        return h

    def status(self):
        now = time.time()
        result = []
        for t in self._tokens:
            reset = self._reset_at.get(t, 0)
            result.append({
                'token': f'...{t[-6:]}',
                'available': now >= reset,
                'reset_at': reset if reset > now else None
            })
        return result


# Global rotator instance
rotator = TokenRotator()


# ---------------------------------------------------------------------------
# Crypto patterns
# ---------------------------------------------------------------------------

CRYPTO_DORK_TEMPLATES = [
    'private key', 'BEGIN PRIVATE KEY', 'BEGIN EC PRIVATE KEY',
    'mnemonic phrase', 'seed phrase', 'recovery phrase',
    'wallet private key', 'ethereum private key', 'bitcoin private key',
    '0x[a-fA-F0-9]{64}',
    '5[J-K][a-zA-Z0-9]{49}',
    'L[a-zA-Z0-9]{51}', 'K[a-zA-Z0-9]{51}',
    'infura project id', 'infura_secret',
    'alchemy api key', 'alchemy_url',
    'moralis api key', 'quicknode api key',
    'web3 provider', 'web3_endpoint',
    'etherscan api key', 'bscscan api key',
    'binance api key', 'binance_secret',
    'coinbase api key', 'coinbase_secret',
    'kucoin api key', 'kraken api key',
    'deployer private key', 'owner private key',
    'admin wallet', 'treasury wallet',
    'multisig address', 'cold wallet',
    '.env', '.secret', 'config.json', 'hardhat.config.js',
    'truffle-config.js', 'foundry.toml', 'Brownie config',
    'wss://', 'https://mainnet.infura.io', 'https://rpc.ankr.com',
    '.eth', '.crypto',
    'web3.eth.accounts', 'ethers.Wallet', 'new ethers.Wallet',
    'web3.eth.accounts.wallet.add', 'privateKey:',
]

CRYPTO_PATTERNS = {
    'eth_private_key': r'0x[a-fA-F0-9]{64}',
    'btc_wif': r'5[HJK][1-9A-Za-z][^OIl]{49}',
    'btc_wif_compressed': r'[KL][1-9A-Za-z][^OIl]{51}',
    'mnemonic_12': r'\b(?:[a-z]+ ){11}[a-z]+\b',
    'mnemonic_24': r'\b(?:[a-z]+ ){23}[a-z]+\b',
    'pem_key': r'-----BEGIN (?:EC|RSA|DSA) PRIVATE KEY-----',
}

STATIC_JUNK_EXT = {'.css','.png','.jpg','.jpeg','.gif','.svg','.ico',
                   '.woff','.woff2','.ttf','.eot','.webp','.bmp','.map',
                   '.mp4', '.mp3', '.wav', '.pdf', '.doc', '.docx'}
URL_PAT = re.compile(r'https?://[^\s"\'<>]+')
COMMIT_API = 'https://api.github.com/search/commits'


# ---------------------------------------------------------------------------
# API queries with rotation
# ---------------------------------------------------------------------------

def query_commits(dork, page=1):
    """Query GitHub Commit API with token rotation."""
    per_page = 30

    token = rotator.current()
    headers = rotator.headers(token)

    try:
        params = {
            'q': dork,
            'per_page': per_page,
            'page': page,
            'sort': 'committer-date',
            'order': 'desc'
        }

        r = requests.get(COMMIT_API, headers=headers, params=params, timeout=20)

        if r.status_code in (403, 429):
            reset_ts = int(r.headers.get('X-RateLimit-Reset', time.time() + 60))
            if token:
                rotator.mark_rate_limited(token, reset_ts + 2)
            # Try with next token immediately
            next_token = rotator.current()
            if next_token and next_token != token:
                return query_commits(dork, page)
            # All tokens exhausted — wait
            wait = max(reset_ts - int(time.time()), 10) + 2
            logger.warning(f'All tokens rate-limited. Waiting {wait}s...')
            time.sleep(wait)
            return query_commits(dork, page)

        if r.status_code == 422:
            logger.debug(f'Unprocessable query: {dork}')
            return {}

        r.raise_for_status()
        data = r.json()
        items = data.get('items', [])

        if len(items) == per_page and page < 3:
            time.sleep(1)
            next_page = query_commits(dork, page + 1)
            if next_page.get('items'):
                items.extend(next_page['items'])

        return {'items': items, 'total_count': data.get('total_count', 0)}

    except Exception as e:
        logger.error(f'Query error: {e}')
        return {}


def extract_crypto_from_commit(commit_data, keyword=None):
    findings = []
    urls = set()

    for item in commit_data.get('items', []):
        repo_name = item.get('repository', {}).get('full_name', 'unknown')
        commit = item.get('commit', {})
        commit_sha = item.get('sha', '')
        commit_html = item.get('html_url', '')
        message = commit.get('message', '')
        author = commit.get('author', {}).get('name', 'unknown')
        date = commit.get('author', {}).get('date', '')

        for url in URL_PAT.findall(message):
            urls.add(url.rstrip('.,;:)!?"\''))

        crypto_matches = []
        for crypto_type, pattern in CRYPTO_PATTERNS.items():
            m = re.search(pattern, message, re.IGNORECASE)
            if m:
                crypto_matches.append({'type': crypto_type, 'match': m.group()})

        message_lower = message.lower()
        for kw in ['private key', 'mnemonic', 'seed', 'wallet', 'password',
                   'secret', 'api key', 'token', '0x', 'deploy']:
            if kw in message_lower:
                if not any(m['type'] == kw for m in crypto_matches):
                    crypto_matches.append({'type': f'keyword_{kw.replace(" ", "_")}', 'match': kw})

        if keyword and keyword.lower() in message_lower:
            crypto_matches.append({'type': f'target_keyword_{keyword}', 'match': keyword})

        if crypto_matches or (keyword and keyword.lower() in message_lower):
            findings.append({
                'repo': repo_name,
                'commit_sha': commit_sha,
                'commit_url': commit_html,
                'author': author,
                'date': date,
                'message': message[:500],
                'crypto_matches': crypto_matches,
                'urls_found': list(urls)
            })

    return findings, urls


def generate_crypto_dorks(keyword=None):
    dorks = list(CRYPTO_DORK_TEMPLATES)
    if keyword:
        dorks.extend([
            f'"{keyword}" private key',
            f'"{keyword}" mnemonic',
            f'"{keyword}" wallet',
            f'"{keyword}" .env',
            f'"{keyword}" secret',
            f'"{keyword}" api key',
            f'"{keyword}" deployer',
        ])
    return dorks


# ---------------------------------------------------------------------------
# Main search runner (supports a progress_callback for web streaming)
# ---------------------------------------------------------------------------

def run_crypto_search(keyword=None, output_dir='./crypto_output',
                      rate_limit=5.0, progress_callback=None):
    os.makedirs(output_dir, exist_ok=True)

    def log(msg, level='info'):
        if level == 'info':
            logger.info(msg)
        elif level == 'warning':
            logger.warning(msg)
        elif level == 'error':
            logger.error(msg)
        if progress_callback:
            progress_callback({'level': level, 'message': msg})

    rotator.reload()
    log("=" * 60)
    log("CRYPTO COMMIT SEARCH TOOL")
    log(f"Target keyword: {keyword if keyword else 'all crypto patterns'}")
    log(f"Active tokens: {rotator.count()}")
    log("=" * 60)

    if rotator.count() == 0:
        log("WARNING: No GITHUB_TOKEN found! Rate limit will be very low (60 req/hr)", 'warning')

    dorks = generate_crypto_dorks(keyword)
    log(f"Generated {len(dorks)} search queries")

    all_urls = set()
    all_findings = []
    processed_dorks = set()

    for i, dork in enumerate(dorks, 1):
        if dork in processed_dorks:
            continue
        processed_dorks.add(dork)

        log(f'[{i}/{len(dorks)}] Searching: "{dork[:60]}"')

        commit_data = query_commits(dork)
        if commit_data.get('total_count', 0) == 0:
            log(f'  No results found')
            time.sleep(rate_limit)
            continue

        findings, urls = extract_crypto_from_commit(commit_data, keyword)
        new_findings = [f for f in findings if f not in all_findings]
        new_urls = urls - all_urls
        all_findings.extend(new_findings)
        all_urls.update(urls)

        log(f'  Commits: {commit_data["total_count"]} | New findings: {len(new_findings)} | '
            f'New URLs: {len(new_urls)} | Total: {len(all_findings)}')

        for finding in new_findings[:2]:
            log(f'    [!] {finding["repo"]} - {finding["commit_sha"][:8]}')
            if finding['crypto_matches']:
                matches_str = ', '.join([m['type'] for m in finding['crypto_matches'][:3]])
                log(f'        Patterns: {matches_str}')

        time.sleep(rate_limit)

    # Save outputs
    urls_file = f'{output_dir}/crypto_commit_urls.txt'
    findings_file = f'{output_dir}/crypto_commit_findings.json'
    report_file = f'{output_dir}/crypto_report.txt'

    with open(urls_file, 'w') as f:
        f.write('\n'.join(sorted(all_urls)))

    with open(findings_file, 'w') as f:
        json.dump(all_findings, f, indent=2)

    with open(report_file, 'w') as f:
        f.write("CRYPTO COMMIT SEARCH REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Search keyword: {keyword if keyword else 'all crypto patterns'}\n")
        f.write(f"Total findings: {len(all_findings)}\n")
        f.write(f"Total unique URLs: {len(all_urls)}\n\n")
        f.write("HIGH RISK FINDINGS:\n")
        f.write("-" * 50 + "\n")
        for finding in all_findings:
            has_high_risk = any(m['type'] in ['eth_private_key', 'btc_wif', 'btc_wif_compressed',
                                              'mnemonic_12', 'mnemonic_24', 'pem_key']
                               for m in finding['crypto_matches'])
            if has_high_risk:
                f.write(f"\n[{finding['repo']}] - {finding['commit_url']}\n")
                f.write(f"Author: {finding['author']} | Date: {finding['date']}\n")
                f.write(f"Message: {finding['message'][:200]}\n")
                for match in finding['crypto_matches']:
                    if match['type'] in ['eth_private_key', 'btc_wif', 'mnemonic_12', 'mnemonic_24']:
                        f.write(f"CRITICAL: {match['type']} detected\n")

        f.write("\n\nALL FINDINGS:\n")
        f.write("-" * 50 + "\n")
        for finding in all_findings:
            f.write(f"\n- {finding['repo']}\n")
            f.write(f"  Commit: {finding['commit_url']}\n")
            f.write(f"  Patterns: {', '.join([m['type'] for m in finding['crypto_matches']])}\n")

    log("=" * 60)
    log(f"DONE — {len(all_findings)} findings saved to {output_dir}")
    log("=" * 60)

    if progress_callback:
        progress_callback({'level': 'done', 'message': 'Search complete',
                           'findings_count': len(all_findings),
                           'urls_count': len(all_urls)})

    return all_urls, all_findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%H:%M:%S')

    print("\n" + "=" * 60)
    print("CRYPTO COMMIT SEARCH TOOL")
    print("=" * 60 + "\n")

    keyword = sys.argv[1] if len(sys.argv) > 1 else None
    if not keyword:
        keyword = input("Keyword/project/domain (Enter = all patterns): ").strip() or None

    output_dir = sys.argv[2] if len(sys.argv) > 2 else './crypto_output'
    run_crypto_search(keyword=keyword, output_dir=output_dir, rate_limit=5.0)
