import json, logging, math, os, re, time, threading
import requests
from secrets_db import db as secrets_db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# BIP-39 wordlist loader
# ---------------------------------------------------------------------------

def _load_bip39():
    path = os.path.join(os.path.dirname(__file__), 'bip39_words.txt')
    try:
        with open(path) as f:
            return set(w.strip().lower() for w in f if w.strip())
    except Exception:
        return set()

BIP39_WORDS = _load_bip39()

def is_valid_bip39(phrase):
    """Return True if ALL words in the phrase are BIP-39 words."""
    if not BIP39_WORDS:
        return False
    words = phrase.lower().split()
    return len(words) >= 12 and all(w in BIP39_WORDS for w in words)

def shannon_entropy(s):
    """Shannon entropy (bits/char). Real keys are typically > 3.5."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())


# ---------------------------------------------------------------------------
# Token Rotation
# ---------------------------------------------------------------------------

class TokenRotator:
    """
    Rotate through multiple GitHub tokens.
    Reads from: GITHUB_TOKEN, GITHUB_TOKEN_1..N, GITHUB_TOKENS (comma-sep).
    """
    def __init__(self):
        self._tokens = []
        self._reset_at = {}
        self._invalid = set()
        self._lock = threading.Lock()
        self._index = 0
        self._load()

    def _load(self):
        seen, tokens = set(), []
        for t in os.environ.get('GITHUB_TOKENS', '').split(','):
            t = t.strip()
            if t and t not in seen:
                seen.add(t); tokens.append(t)
        for i in range(1, 20):
            t = os.environ.get(f'GITHUB_TOKEN_{i}', '').strip()
            if t and t not in seen:
                seen.add(t); tokens.append(t)
        t = os.environ.get('GITHUB_TOKEN', '').strip()
        if t and t not in seen:
            tokens.append(t)
        self._tokens = tokens
        self._invalid = set()
        self._index = 0

    def reload(self):
        with self._lock:
            self._load()

    def add_token(self, token: str) -> bool:
        """Add a token at runtime. Returns True if it was new, False if duplicate."""
        token = token.strip()
        if not token:
            return False
        with self._lock:
            existing = {t for t in self._tokens}
            if token in existing:
                return False
            self._tokens.append(token)
            return True

    def remove_token(self, token_suffix: str) -> bool:
        """Remove a token by its last-6-char suffix. Only removes if marked INVALID."""
        with self._lock:
            for t in self._tokens:
                if t.endswith(token_suffix):
                    if t not in self._invalid:
                        return False  # aktif atau rate-limited — tolak penghapusan
                    self._tokens.remove(t)
                    self._invalid.discard(t)
                    self._reset_at.pop(t, None)
                    if self._index >= len(self._tokens) and self._tokens:
                        self._index = 0
                    return True
        return False

    def count(self):
        return len(self._tokens)

    def current(self):
        with self._lock:
            return self._next_available()

    def _next_available(self):
        now = time.time()
        for offset in range(len(self._tokens)):
            idx = (self._index + offset) % len(self._tokens)
            t = self._tokens[idx]
            if t in self._invalid:
                continue
            if now >= self._reset_at.get(t, 0):
                self._index = idx
                return t
        return None

    def mark_rate_limited(self, token, reset_ts):
        with self._lock:
            self._reset_at[token] = reset_ts
            logger.warning(f'Token ...{token[-6:]} rate-limited until '
                           f'{time.strftime("%H:%M:%S", time.localtime(reset_ts))}')
            self._index = (self._index + 1) % max(len(self._tokens), 1)

    def mark_invalid(self, token):
        with self._lock:
            self._invalid.add(token)
            logger.warning(f'Token ...{token[-6:]} marked invalid (401 Unauthorized)')
            self._index = (self._index + 1) % max(len(self._tokens), 1)

    def headers(self, token=None):
        if token is None:
            token = self.current()
        h = {'Accept': 'application/vnd.github.cloak-preview+json',
             'User-Agent': 'crypto-commit-dorker/2.0'}
        if token:
            h['Authorization'] = f'Bearer {token}'
        return h

    def status(self):
        now = time.time()
        return [{'token': f'...{t[-6:]}',
                 'invalid':   t in self._invalid,
                 'available': t not in self._invalid and now >= self._reset_at.get(t, 0),
                 'reset_at':  self._reset_at.get(t, 0) if now < self._reset_at.get(t, 0) else None}
                for t in self._tokens]


rotator = TokenRotator()


# ---------------------------------------------------------------------------
# Dork catalogue  — tiered by confidence
# ---------------------------------------------------------------------------
# CRITICAL: almost guaranteed to be a real secret
# HIGH    : very likely a real secret
# MEDIUM  : possible, needs scoring to confirm
# LOW     : generic, too noisy — skipped by default

DORK_TIERS = {
    'CRITICAL': [
        'BEGIN EC PRIVATE KEY',
        'BEGIN RSA PRIVATE KEY',
        'BEGIN DSA PRIVATE KEY',
        'BEGIN OPENSSH PRIVATE KEY',
        'mnemonic phrase',
        'seed phrase',
        'recovery phrase',
        'wallet mnemonic',
        'ethereum private key',
        'bitcoin private key',
        'deployer private key',
        'owner private key',
        'privateKey: 0x',
        'PRIVATE_KEY=0x',
        'MNEMONIC=',
    ],
    'HIGH': [
        'hardhat.config private key',
        'foundry.toml private_key',
        'web3.eth.accounts.wallet.add',
        'new ethers.Wallet',
        'Wallet.fromMnemonic',
        'ethers.Wallet.fromMnemonic',
        'infura_secret',
        'alchemy api key',
        'INFURA_PROJECT_SECRET',
        'binance_secret',
        'coinbase_secret',
        'kucoin api key',
        'kraken api key',
        'ETHERSCAN_API_KEY',
        'BSCSCAN_API_KEY',
        'ALCHEMY_API_KEY',
        'QUICKNODE_API_KEY',
    ],
    'MEDIUM': [
        'private key',
        'wallet private key',
        'admin wallet',
        'treasury wallet',
        'cold wallet',
        'infura project id',
        'web3 provider',
        'moralis api key',
        'hardhat.config.js',
        'truffle-config.js',
    ],
    'LOW': [   # Not searched by default
        '.env', '.secret', 'config.json',
        'wss://', '.eth', '.crypto', 'web3_endpoint',
        'multisig address', 'web3.eth.accounts',
    ],
}

# Flatten ordered list for iteration (CRITICAL first)
def get_ordered_dorks(keyword=None, include_low=False):
    dorks = []
    seen = set()
    for tier in (['CRITICAL', 'HIGH', 'MEDIUM'] + (['LOW'] if include_low else [])):
        for d in DORK_TIERS[tier]:
            if d not in seen:
                seen.add(d)
                dorks.append((tier, d))
    if keyword:
        kw_dorks = [
            (f'"{keyword}" mnemonic phrase', 'CRITICAL'),
            (f'"{keyword}" BEGIN PRIVATE KEY', 'CRITICAL'),
            (f'"{keyword}" ethereum private key', 'CRITICAL'),
            (f'"{keyword}" PRIVATE_KEY', 'HIGH'),
            (f'"{keyword}" deployer', 'HIGH'),
            (f'"{keyword}" wallet secret', 'HIGH'),
            (f'"{keyword}" api key', 'MEDIUM'),
        ]
        for d, t in kw_dorks:
            if d not in seen:
                seen.add(d)
                dorks.append((t, d))
    return dorks


# ---------------------------------------------------------------------------
# Regex patterns for direct secret detection
# ---------------------------------------------------------------------------

CRYPTO_PATTERNS = {
    'eth_private_key':    (r'(?<![0-9a-fA-F])0x[a-fA-F0-9]{64}(?![0-9a-fA-F])', 'CRITICAL'),
    'btc_wif':            (r'\b5[HJK][1-9A-Za-z][^OIl0]{48}\b',                  'CRITICAL'),
    'btc_wif_compressed': (r'\b[KL][1-9A-Za-z][^OIl0]{50}\b',                    'CRITICAL'),
    'mnemonic_12':        (r'\b([a-z]{3,10} ){11}[a-z]{3,10}\b',                  'HIGH'),
    'mnemonic_24':        (r'\b([a-z]{3,10} ){23}[a-z]{3,10}\b',                  'CRITICAL'),
    'pem_private_key':    (r'-----BEGIN (?:EC|RSA|DSA|OPENSSH) PRIVATE KEY-----', 'CRITICAL'),
    'raw_hex_key':        (r'(?i)(?:private[_\s]?key|pk|secret)["\s:=]+([0-9a-fA-F]{64})', 'CRITICAL'),
    'env_mnemonic':       (r'(?i)MNEMONIC\s*=\s*["\']?([a-z]+ ){11,23}[a-z]+',   'CRITICAL'),
    'env_private_key':    (r'(?i)PRIVATE_KEY\s*=\s*0x[a-fA-F0-9]{64}',           'CRITICAL'),
    'infura_secret':      (r'(?i)infura[_\s]?(secret|api[_\s]?secret)\s*[=:]\s*[0-9a-f]{32}', 'HIGH'),
    'alchemy_key':        (r'(?i)alchemy[_\s]?(api[_\s]?key|key)\s*[=:]\s*[A-Za-z0-9_-]{32,}', 'HIGH'),
}

# Patterns that suggest this commit is test/doc/noise → lower score
NOISE_PATTERNS = [
    r'(?i)(test|mock|dummy|example|sample|placeholder|tutorial|demo)',
    r'(?i)(readme|documentation|docs/|\.md)',
    r'(?i)(TODO|FIXME|xxx{3,})',
    r'0{10,}|f{10,}|1{10,}',                      # all-same repeated chars
    r'(?:1234){3,}|(?:abcd){3,}|(?:0123){3,}',    # obviously sequential placeholders
    r'(?i)node_modules',
    r'0x[0-9a-fA-F]{0,4}(?:0{10,}|f{10,})',  # All-zero or all-F keys
]

# Context keywords that boost confidence
BOOST_KEYWORDS = [
    r'(?i)(\.env|dotenv)',
    r'(?i)(hardhat|foundry|truffle|brownie)',
    r'(?i)(deploy|deployer)',
    r'(?i)(mainnet|ropsten|rinkeby|goerli|polygon|arbitrum|bsc)',
    r'(?i)(infura|alchemy|quicknode|moralis)',
    r'(?i)(wallet|account|signer)',
]

# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def score_finding(message, crypto_matches, dork_tier='MEDIUM'):
    """
    Returns an integer confidence score 0-100 and a label.
    Aim: findings with score >= 65 are reported.
    """
    score = 0

    # Base score from dork tier
    tier_base = {'CRITICAL': 40, 'HIGH': 25, 'MEDIUM': 15, 'LOW': 5}
    score += tier_base.get(dork_tier, 15)

    # Score from matched patterns
    # mnemonic_12 promoted to critical: a 12-word BIP-39 phrase is a real key
    critical_types = {'eth_private_key', 'btc_wif', 'btc_wif_compressed',
                      'mnemonic_12', 'mnemonic_24', 'pem_private_key',
                      'raw_hex_key', 'env_mnemonic', 'env_private_key'}
    high_types     = {'infura_secret', 'alchemy_key'}

    for m in crypto_matches:
        t = m['type']
        if t in critical_types:
            score += 35
            # BIP-39 validation for any mnemonic type
            if 'mnemonic' in t and m.get('match'):
                if is_valid_bip39(m['match']):
                    score += 20  # valid BIP-39 wordlist — confirmed real mnemonic
                else:
                    score -= 15  # penalise random-word sequences
            # Entropy check for hex keys
            if 'key' in t or 'hex' in t:
                raw = re.sub(r'0x', '', m.get('match', ''), flags=re.I)
                ent = shannon_entropy(raw)
                if ent < 2.5:     # too uniform → placeholder/fake
                    score -= 25
                elif ent > 3.8:
                    score += 10
        elif t in high_types:
            score += 20
            # Bonus: match actually contains a credential value (hex/base64 string)
            match_val = m.get('match', '')
            if re.search(r'[0-9a-zA-Z_-]{20,}', match_val):
                score += 15  # real credential present, not just the label
        else:
            score += 8   # keyword_* matches

    # Boost: context suggests real deployment / secrets
    for pat in BOOST_KEYWORDS:
        if re.search(pat, message):
            score += 8
            break  # only count once

    # Noise penalty
    for pat in NOISE_PATTERNS:
        if re.search(pat, message):
            score -= 20
            break

    score = max(0, min(100, score))

    if score >= 85:   label = 'CRITICAL'
    elif score >= 65: label = 'HIGH'
    elif score >= 45: label = 'MEDIUM'
    else:             label = 'LOW'

    return score, label


# ---------------------------------------------------------------------------
# GitHub API  (Commits  +  Code/file search)
# ---------------------------------------------------------------------------

COMMIT_API = 'https://api.github.com/search/commits'
CODE_API   = 'https://api.github.com/search/code'

# ── Code-search dorks: target file contents where real secrets live ─────────
# Format: (query, tier, description)
CODE_DORKS = [
    # .env files — the most common place secrets leak
    ('PRIVATE_KEY=0x filename:.env',                  'CRITICAL'),
    ('MNEMONIC= filename:.env',                       'CRITICAL'),
    ('PRIVATE_KEY=0x extension:env',                  'CRITICAL'),
    ('MNEMONIC= extension:env',                       'CRITICAL'),
    # Hardhat / Foundry / Truffle config files
    ('privateKey: 0x filename:hardhat.config.js',     'CRITICAL'),
    ('privateKey: 0x filename:hardhat.config.ts',     'CRITICAL'),
    ('PRIVATE_KEY filename:hardhat.config.js',        'HIGH'),
    ('mnemonic filename:hardhat.config.js',           'HIGH'),
    ('private_key filename:foundry.toml',             'CRITICAL'),
    ('accounts filename:truffle-config.js',           'HIGH'),
    # PEM keys in any file
    ('BEGIN EC PRIVATE KEY',                          'CRITICAL'),
    ('BEGIN RSA PRIVATE KEY',                         'CRITICAL'),
    ('BEGIN OPENSSH PRIVATE KEY',                     'CRITICAL'),
    # Raw env-style assignments in any file
    ('DEPLOYER_PRIVATE_KEY=0x',                       'CRITICAL'),
    ('DEPLOYER_MNEMONIC=',                            'CRITICAL'),
    ('WALLET_PRIVATE_KEY=0x',                         'CRITICAL'),
    ('INFURA_PROJECT_SECRET= extension:env',          'HIGH'),
    ('ALCHEMY_API_KEY= extension:env',                'HIGH'),
    # ethers.js / web3.js code with embedded keys
    ('new ethers.Wallet("0x',                         'CRITICAL'),
    ('Wallet.fromMnemonic(',                          'HIGH'),
    ('web3.eth.accounts.wallet.add("0x',              'CRITICAL'),
    # secrets.js / secrets.json / config.json
    ('privateKey filename:secrets.json',              'CRITICAL'),
    ('mnemonic filename:secrets.json',                'CRITICAL'),
    ('privateKey filename:secrets.js',                'CRITICAL'),
    ('"private_key": "0x',                            'CRITICAL'),
    # .secret files
    ('extension:secret PRIVATE_KEY',                  'CRITICAL'),
    ('extension:secret MNEMONIC',                     'CRITICAL'),
]


def _github_request(url, params, extra_accept=None, _depth=0):
    """Shared rate-limit-aware GitHub GET helper."""
    if _depth > 4:
        return None
    token = rotator.current()
    headers = rotator.headers(token)
    if extra_accept:
        headers['Accept'] = extra_accept
    try:
        r = requests.get(url, headers=headers, timeout=20, params=params)
        if r.status_code == 401:
            if token:
                rotator.mark_invalid(token)
            next_tok = rotator.current()
            if next_tok and next_tok != token:
                return _github_request(url, params, extra_accept, _depth + 1)
            return None
        if r.status_code in (403, 429):
            reset_ts = int(r.headers.get('X-RateLimit-Reset', time.time() + 61))
            if token:
                rotator.mark_rate_limited(token, reset_ts + 2)
            next_tok = rotator.current()
            if next_tok and next_tok != token:
                return _github_request(url, params, extra_accept, _depth + 1)
            wait = max(reset_ts - int(time.time()), 10) + 2
            logger.warning(f'Rate-limited — waiting {wait}s…')
            time.sleep(wait)
            return _github_request(url, params, extra_accept, _depth + 1)
        if r.status_code == 422:
            return None
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error(f'GitHub request error: {e}')
        return None


def query_commits(dork, page=1, _depth=0):
    data = _github_request(COMMIT_API, {
        'q': dork, 'per_page': 30, 'page': page,
        'sort': 'committer-date', 'order': 'desc'
    }, _depth=_depth)
    if not data:
        return {}
    items = data.get('items', [])
    if len(items) == 30 and page < 3:
        time.sleep(1)
        nxt = query_commits(dork, page + 1, _depth)
        items += nxt.get('items', [])
    return {'items': items, 'total_count': data.get('total_count', 0)}


def query_code(dork, page=1):
    """Search GitHub file contents. Returns list of code items."""
    # text-match accept header gives us the matched fragment in the file
    accept = 'application/vnd.github.v3.text-match+json'
    data = _github_request(CODE_API, {
        'q': dork, 'per_page': 30, 'page': page
    }, extra_accept=accept)
    if not data:
        return []
    items = data.get('items', [])
    # Fetch page 2 if full result set
    if len(items) == 30 and page < 2:
        time.sleep(1.5)
        items += query_code(dork, page + 1)
    return items


# ---------------------------------------------------------------------------
# Extraction + scoring
# ---------------------------------------------------------------------------

URL_PAT = re.compile(r'https?://[^\s"\'<>]+')

def extract_findings(commit_data, keyword=None, dork_tier='MEDIUM', min_score=65):
    findings, urls = [], set()

    for item in commit_data.get('items', []):
        repo   = item.get('repository', {}).get('full_name', 'unknown')
        commit = item.get('commit', {})
        sha    = item.get('sha', '')
        url    = item.get('html_url', '')
        msg    = commit.get('message', '')
        author = commit.get('author', {}).get('name', 'unknown')
        date   = commit.get('author', {}).get('date', '')

        for u in URL_PAT.findall(msg):
            urls.add(u.rstrip('.,;:)!?"\''))

        crypto_matches = []

        # Regex-based detection
        for pat_name, (pattern, pat_tier) in CRYPTO_PATTERNS.items():
            m = re.search(pattern, msg, re.IGNORECASE)
            if m:
                crypto_matches.append({
                    'type': pat_name,
                    'tier': pat_tier,
                    'match': m.group()[:120],
                })

        # Keyword fallback (only if no regex matched)
        if not crypto_matches:
            kws = ['private key', 'mnemonic', 'seed phrase', 'wallet', 'deployer',
                   'BEGIN PRIVATE KEY', 'MNEMONIC=', 'PRIVATE_KEY=']
            for kw in kws:
                if kw.lower() in msg.lower():
                    crypto_matches.append({'type': f'keyword_{kw.replace(" ","_")}',
                                           'tier': 'MEDIUM', 'match': kw})

        if keyword and keyword.lower() in msg.lower():
            crypto_matches.append({'type': f'target_{keyword}',
                                   'tier': 'HIGH', 'match': keyword})

        if not crypto_matches:
            continue

        score, risk_label = score_finding(msg, crypto_matches, dork_tier)

        if score < min_score:
            continue

        findings.append({
            'repo':          repo,
            'commit_sha':    sha,
            'commit_url':    url,
            'author':        author,
            'date':          date,
            'message':       msg[:500],
            'crypto_matches': crypto_matches,
            'urls_found':    list(urls),
            'confidence':    score,
            'risk_label':    risk_label,
        })

    return findings, urls


def extract_code_findings(code_items, dork_tier='CRITICAL', min_score=65):
    """
    Parse results from /search/code.

    Each item has:
      item['repository']['full_name']
      item['path']              — file path e.g. ".env", "hardhat.config.js"
      item['html_url']          — link to the file on GitHub
      item['text_matches']      — list of {fragment, matches} (needs text-match Accept header)

    We reassemble the fragment as the "message" body and run the same scoring pipeline.
    """
    findings = []
    seen_urls = set()

    for item in code_items:
        repo     = item.get('repository', {}).get('full_name', 'unknown')
        path     = item.get('path', '')
        url      = item.get('html_url', '')
        sha      = item.get('sha', '')

        if url in seen_urls:
            continue
        seen_urls.add(url)

        # Collect all text fragments exposed by the text-match header
        fragments = []
        for tm in item.get('text_matches', []):
            frag = tm.get('fragment', '')
            if frag:
                fragments.append(frag)

        # Fallback: build a pseudo-message from filename + dork tier
        if not fragments:
            fragments = [f'{path}']

        content = '\n'.join(fragments)[:1000]

        crypto_matches = []
        for pat_name, (pattern, pat_tier) in CRYPTO_PATTERNS.items():
            m = re.search(pattern, content, re.IGNORECASE)
            if m:
                crypto_matches.append({
                    'type':  pat_name,
                    'tier':  pat_tier,
                    'match': m.group()[:200],
                })

        # If no regex hit, still record the dork as a keyword match
        if not crypto_matches:
            crypto_matches.append({
                'type':  f'file_{path.replace("/","_").replace(".","_")}',
                'tier':  dork_tier,
                'match': content[:120],
            })

        # Boost score for sensitive file names
        sensitive_files = {'.env', 'secrets.json', 'secrets.js',
                           'hardhat.config.js', 'hardhat.config.ts',
                           'truffle-config.js', 'foundry.toml', '.secret'}
        fname = path.split('/')[-1]
        if fname in sensitive_files or path.endswith('.env'):
            dork_tier = 'CRITICAL'

        score, risk_label = score_finding(content, crypto_matches, dork_tier)

        if score < min_score:
            continue

        findings.append({
            'repo':           repo,
            'commit_sha':     sha,
            'commit_url':     url,
            'author':         '',
            'date':           '',
            'message':        f'[FILE: {path}]\n{content[:400]}',
            'crypto_matches': crypto_matches,
            'urls_found':     [],
            'confidence':     score,
            'risk_label':     risk_label,
            'source':         'code',
            'file_path':      path,
        })

    return findings


# ---------------------------------------------------------------------------
# Main search runner
# ---------------------------------------------------------------------------

def _save_to_vault(finding, total_new_db, total_dup_db, log, progress_callback):
    """Helper: persist one finding to the dedup vault and emit events."""
    n, d = secrets_db.add_finding(finding)
    total_new_db += n
    total_dup_db += d
    if n:
        log(f'    💾 Saved {n} new secret(s) to vault')
    if d:
        log(f'    ⏭  Skipped {d} duplicate(s) already in vault')
    if progress_callback and (n or d):
        progress_callback({
            'level':      'vault',
            'message':    f'Vault: {secrets_db.stats()["total"]} unique secrets',
            'vault_total': secrets_db.stats()['total'],
        })
    return total_new_db, total_dup_db


def run_crypto_search(keyword=None, output_dir='./crypto_output',
                      rate_limit=5.0, min_score=65,
                      include_low_dorks=False, progress_callback=None):
    os.makedirs(output_dir, exist_ok=True)

    def log(msg, level='info', **extra):
        getattr(logger, level, logger.info)(msg)
        if progress_callback:
            progress_callback({'level': level, 'message': msg, **extra})

    rotator.reload()
    log("=" * 60)
    log("CRYPTO SECRET SCANNER  v3.0")
    log(f"Keyword   : {keyword or '(all crypto patterns)'}")
    log(f"Min score : {min_score}/100")
    log(f"Tokens    : {rotator.count()}")
    log("=" * 60)

    if rotator.count() == 0:
        log("WARNING: No GITHUB_TOKEN — rate limited to 60 req/hr", 'warning')

    all_findings, all_urls = [], set()
    seen_keys     = set()   # commit_sha OR file_url — dedup within this scan
    total_new_db  = 0
    total_dup_db  = 0

    # ── PHASE 1: Code search (file contents) — finds real secrets directly ──
    code_dorks = list(CODE_DORKS)
    if keyword:
        code_dorks = [
            (f'"{keyword}" PRIVATE_KEY=0x',        'CRITICAL'),
            (f'"{keyword}" MNEMONIC=',              'CRITICAL'),
            (f'"{keyword}" BEGIN PRIVATE KEY',      'CRITICAL'),
            (f'"{keyword}" privateKey filename:hardhat.config.js', 'CRITICAL'),
            (f'"{keyword}" filename:.env',          'HIGH'),
        ] + code_dorks

    log(f"[PHASE 1] Code search — {len(code_dorks)} queries targeting file contents")
    for i, (dork, tier) in enumerate(code_dorks, 1):
        log(f'  [{i}/{len(code_dorks)}] [{tier}] {dork[:70]}')
        items = query_code(dork)
        if not items:
            log(f'    → 0 files found')
            time.sleep(rate_limit * 0.4)
            continue

        findings = extract_code_findings(items, dork_tier=tier, min_score=min_score)
        new = [f for f in findings if f['commit_url'] not in seen_keys]
        for f in new:
            seen_keys.add(f['commit_url'])
            total_new_db, total_dup_db = _save_to_vault(
                f, total_new_db, total_dup_db, log, progress_callback)

        all_findings.extend(new)
        log(f'    → {len(items)} files | {len(new)} passed filter | '
            f'total: {len(all_findings)}')

        for f in new[:3]:
            log(f'    [{f["risk_label"]}][{f["confidence"]}] {f["repo"]} '
                f'— {f.get("file_path","?")} '
                f'— {", ".join(m["type"] for m in f["crypto_matches"][:2])}')

        time.sleep(rate_limit)

    # ── PHASE 2: Commit message search ──────────────────────────────────────
    dorks = get_ordered_dorks(keyword, include_low=include_low_dorks)
    log(f"[PHASE 2] Commit search — {len(dorks)} queries on commit messages")

    for i, (tier, dork) in enumerate(dorks, 1):
        log(f'  [{i}/{len(dorks)}] [{tier}] "{dork[:60]}"')

        data = query_commits(dork)
        total = data.get('total_count', 0)

        if total == 0:
            log(f'    → No commits found')
            time.sleep(rate_limit * 0.5)
            continue

        findings, urls = extract_findings(data, keyword,
                                          dork_tier=tier, min_score=min_score)
        all_urls.update(urls)

        new = [f for f in findings if f['commit_sha'] not in seen_keys]
        for f in new:
            seen_keys.add(f['commit_sha'])
            total_new_db, total_dup_db = _save_to_vault(
                f, total_new_db, total_dup_db, log, progress_callback)

        all_findings.extend(new)
        passed_pct = f'{(len(new)/max(total,1)*100):.0f}%' if total else '0%'
        log(f'    → {total} commits | {len(new)} passed ({passed_pct}) | '
            f'total: {len(all_findings)}')

        for f in new[:2]:
            log(f'    [{f["risk_label"]}][{f["confidence"]}] {f["repo"]} '
                f'— {", ".join(m["type"] for m in f["crypto_matches"][:3])}')

        time.sleep(rate_limit)

    # Sort by confidence descending
    all_findings.sort(key=lambda x: -x['confidence'])

    # ── Stats
    total_f = len(all_findings)
    high_quality = [f for f in all_findings
                    if f['risk_label'] in ('CRITICAL', 'HIGH')]
    pct = (len(high_quality) / total_f * 100) if total_f else 0
    db_stats = secrets_db.stats()

    log("=" * 60)
    log(f"SCAN COMPLETE")
    log(f"  Total findings     : {total_f}")
    log(f"  CRITICAL+HIGH      : {len(high_quality)} ({pct:.0f}%)")
    log(f"  New secrets saved  : {total_new_db}")
    log(f"  Duplicates skipped : {total_dup_db}")
    log(f"  Vault total        : {db_stats['total']} unique secrets")
    log(f"  Total URLs         : {len(all_urls)}")
    log("=" * 60)

    # ── Write outputs
    with open(f'{output_dir}/crypto_commit_urls.txt', 'w') as f:
        f.write('\n'.join(sorted(all_urls)))

    with open(f'{output_dir}/crypto_commit_findings.json', 'w') as f:
        json.dump(all_findings, f, indent=2)

    with open(f'{output_dir}/crypto_report.txt', 'w') as f:
        f.write("CRYPTO COMMIT SCANNER — REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Keyword : {keyword or 'all patterns'}\n")
        f.write(f"Findings: {total_f} (CRITICAL+HIGH: {len(high_quality)}, {pct:.0f}%)\n")
        f.write(f"URLs    : {len(all_urls)}\n\n")

        for risk in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            group = [x for x in all_findings if x['risk_label'] == risk]
            if not group:
                continue
            f.write(f"\n{'─'*50}\n[{risk}] — {len(group)} findings\n{'─'*50}\n")
            for finding in group:
                f.write(f"\n  Repo   : {finding['repo']}\n")
                f.write(f"  URL    : {finding['commit_url']}\n")
                f.write(f"  Author : {finding['author']}  |  {finding['date']}\n")
                f.write(f"  Score  : {finding['confidence']}/100\n")
                f.write(f"  Patterns: {', '.join(m['type'] for m in finding['crypto_matches'])}\n")
                f.write(f"  Message: {finding['message'][:200]}\n")

    if progress_callback:
        progress_callback({
            'level':              'done',
            'message':            'Search complete',
            'findings_count':     total_f,
            'urls_count':         len(all_urls),
            'high_quality_count': len(high_quality),
            'quality_pct':        round(pct),
            'new_secrets':        total_new_db,
            'dup_secrets':        total_dup_db,
            'vault_total':        db_stats['total'],
        })

    return all_urls, all_findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%H:%M:%S')
    keyword = sys.argv[1] if len(sys.argv) > 1 else None
    if not keyword:
        keyword = input("Keyword (Enter = all patterns): ").strip() or None
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './crypto_output'
    run_crypto_search(keyword=keyword, output_dir=output_dir)
