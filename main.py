import json, logging, os, re, time
import requests

logger = logging.getLogger(__name__)

# Crypto-specific patterns untuk mencari di commit messages dan diffs
CRYPTO_DORK_TEMPLATES = [
    # Private keys & seeds
    'private key', 'BEGIN PRIVATE KEY', 'BEGIN EC PRIVATE KEY',
    'mnemonic phrase', 'seed phrase', 'recovery phrase',
    'wallet private key', 'ethereum private key', 'bitcoin private key',
    
    # Specific crypto wallets & formats
    '0x[a-fA-F0-9]{64}',  # Ethereum private key pattern (64 hex chars)
    '5[J-K][a-zA-Z0-9]{49}',  # Bitcoin WIF private key pattern
    'L[a-zA-Z0-9]{51}', 'K[a-zA-Z0-9]{51}',  # Bitcoin WIF compressed
    
    # API keys for crypto services
    'infura project id', 'infura_secret',
    'alchemy api key', 'alchemy_url',
    'moralis api key', 'quicknode api key',
    'web3 provider', 'web3_endpoint',
    'etherscan api key', 'bscscan api key',
    
    # Exchange API keys
    'binance api key', 'binance_secret',
    'coinbase api key', 'coinbase_secret',
    'kucoin api key', 'kraken api key',
    
    # Smart contract & blockchain
    'deployer private key', 'owner private key',
    'admin wallet', 'treasury wallet',
    'multisig address', 'cold wallet',
    
    # Configuration files
    '.env', '.secret', 'config.json', 'hardhat.config.js',
    'truffle-config.js', 'foundry.toml', ' Brownie config',
    
    # RPC endpoints
    'wss://', 'https://mainnet.infura.io', 'https://rpc.ankr.com',
    '.discover', '.eth', '.crypto',
    
    # Web3 specific
    'web3.eth.accounts', 'ethers.Wallet', 'new ethers.Wallet',
    'web3.eth.accounts.wallet.add', 'privateKey:',
]

# Tambahan pola regex untuk deteksi otomatis
CRYPTO_PATTERNS = {
    'eth_private_key': r'0x[a-fA-F0-9]{64}',
    'btc_wif': r'5[HJK][1-9A-Za-z][^OIl]{49}',
    'btc_wif_compressed': r'[KL][1-9A-Za-z][^OIl]{51}',
    'mnemonic_12': r'\b(?:[a-z]+ ){11}[a-z]+\b',  # 12 word phrase
    'mnemonic_24': r'\b(?:[a-z]+ ){23}[a-z]+\b',  # 24 word phrase
    'pem_key': r'-----BEGIN (?:EC|RSA|DSA) PRIVATE KEY-----',
}

STATIC_JUNK_EXT = {'.css','.png','.jpg','.jpeg','.gif','.svg','.ico',
                   '.woff','.woff2','.ttf','.eot','.webp','.bmp','.map',
                   '.mp4', '.mp3', '.wav', '.pdf', '.doc', '.docx'}
URL_PAT = re.compile(r'https?://[^\s"\'<>]+')
# GitHub API untuk pencarian COMMIT (bukan code)
COMMIT_API = 'https://api.github.com/search/commits'

def _headers():
    token = os.environ.get('GITHUB_TOKEN','').strip()
    h = {'Accept': 'application/vnd.github.cloak-preview+json',  # Preview untuk commit search
         'User-Agent': 'crypto-commit-dorker/1.0'}
    if token: 
        h['Authorization'] = f'Bearer {token}'
    return h

def generate_crypto_dorks(keyword=None):
    """Generate dorks untuk mencari crypto-related commits"""
    dorks = []
    
    # Base crypto dorks
    for template in CRYPTO_DORK_TEMPLATES:
        dorks.append(template)
    
    # Jika ada keyword spesifik (seperti domain atau project)
    if keyword:
        keyword_dorks = [
            f'"{keyword}" private key',
            f'"{keyword}" mnemonic',
            f'"{keyword}" wallet',
            f'"{keyword}" .env',
            f'"{keyword}" secret',
            f'"{keyword}" api key',
            f'"{keyword}" deployer',
        ]
        dorks.extend(keyword_dorks)
    
    return dorks

def query_commits(dork, headers, page=1):
    """Query GitHub Commit API dengan pagination"""
    all_results = []
    per_page = 30
    
    try:
        params = {
            'q': dork,
            'per_page': per_page,
            'page': page,
            'sort': 'committer-date',
            'order': 'desc'
        }
        
        r = requests.get(COMMIT_API, headers=headers, params=params, timeout=20)
        
        # Handle rate limiting
        if r.status_code in (403,429):
            reset_time = int(r.headers.get('X-RateLimit-Reset', time.time()+60))
            wait = max(reset_time - int(time.time()), 10) + 2
            logger.warning(f'Rate limited. Waiting {wait} seconds...')
            time.sleep(wait)
            return query_commits(dork, headers, page)  # Retry
        
        if r.status_code == 422:
            logger.debug(f'Unprocessable query: {dork}')
            return {}
            
        r.raise_for_status()
        data = r.json()
        
        # Ambil commits
        items = data.get('items', [])
        all_results.extend(items)
        
        # Cek pagination (max 3 pages untuk menghindari rate limit)
        if len(all_results) < data.get('total_count', 0) and page < 3:
            time.sleep(1)
            next_page = query_commits(dork, headers, page+1)
            if next_page.get('items'):
                all_results.extend(next_page['items'])
            return {'items': all_results, 'total_count': data.get('total_count', 0)}
        
        return {'items': all_results, 'total_count': data.get('total_count', 0)}
        
    except Exception as e:
        logger.error(f'Query error: {e}')
        return {}

def extract_crypto_from_commit(commit_data, keyword=None):
    """Extract crypto-related findings dari commit"""
    findings = []
    urls = set()
    
    for item in commit_data.get('items', []):
        repo_name = item.get('repository', {}).get('full_name', 'unknown')
        commit = item.get('commit', {})
        commit_sha = item.get('sha', '')
        commit_html = item.get('html_url', '')
        
        # Data dari commit
        message = commit.get('message', '')
        author = commit.get('author', {}).get('name', 'unknown')
        date = commit.get('author', {}).get('date', '')
        
        # URL dalam commit message
        for url in URL_PAT.findall(message):
            url = url.rstrip('.,;:)!?"\'')
            urls.add(url)
        
        # Deteksi pola crypto dalam commit message
        crypto_matches = []
        
        # Cek pola regex
        for crypto_type, pattern in CRYPTO_PATTERNS.items():
            if re.search(pattern, message, re.IGNORECASE):
                crypto_matches.append({
                    'type': crypto_type,
                    'match': re.search(pattern, message, re.IGNORECASE).group()
                })
        
        # Cek keyword sederhana
        message_lower = message.lower()
        for keyword_check in ['private key', 'mnemonic', 'seed', 'wallet', 'password', 
                              'secret', 'api key', 'token', '0x', 'deploy']:
            if keyword_check in message_lower:
                if not any(m['type'] == keyword_check for m in crypto_matches):
                    crypto_matches.append({
                        'type': f'keyword_{keyword_check.replace(" ", "_")}',
                        'match': keyword_check
                    })
        
        # Cek jika keyword spesifik ada
        if keyword and keyword.lower() in message_lower:
            crypto_matches.append({
                'type': f'target_keyword_{keyword}',
                'match': keyword
            })
        
        # Jika ada temuan atau keyword spesifik
        if crypto_matches or (keyword and keyword.lower() in message_lower):
            findings.append({
                'repo': repo_name,
                'commit_sha': commit_sha,
                'commit_url': commit_html,
                'author': author,
                'date': date,
                'message': message[:500],  # Batasi panjang
                'crypto_matches': crypto_matches,
                'urls_found': list(urls)
            })
    
    return findings, urls

def run_crypto_search(keyword=None, output_dir='./crypto_output', rate_limit=5.0):
    """
    Jalankan pencarian crypto di GitHub commits
    
    Args:
        keyword: Domain, project name, atau keyword spesifik untuk difilter
        output_dir: Direktori output
        rate_limit: Delay antar request (detik)
    """
    os.makedirs(output_dir, exist_ok=True)
    logging.basicConfig(level=logging.INFO, 
                       format='%(asctime)s %(levelname)s %(message)s', 
                       datefmt='%H:%M:%S')
    
    logger.info("="*60)
    logger.info("CRYPTO COMMIT SEARCH TOOL")
    logger.info(f"Target keyword: {keyword if keyword else 'all crypto patterns'}")
    logger.info("="*60)
    
    headers = _headers()
    if not headers.get('Authorization'):
        logger.warning("No GITHUB_TOKEN found! Rate limit will be very low (60 requests/hour)")
    
    # Generate dorks
    dorks = generate_crypto_dorks(keyword)
    logger.info(f"Generated {len(dorks)} search queries")
    
    all_urls = set()
    all_findings = []
    processed_dorks = set()
    
    for i, dork in enumerate(dorks, 1):
        # Skip duplicate atau terlalu umum
        if dork in processed_dorks:
            continue
        processed_dorks.add(dork)
        
        logger.info(f'[{i}/{len(dorks)}] Searching: "{dork[:60]}"')
        
        # Search commits
        commit_data = query_commits(dork, headers)
        
        if commit_data.get('total_count', 0) == 0:
            logger.info(f'  No results found')
            time.sleep(rate_limit)
            continue
        
        findings, urls = extract_crypto_from_commit(commit_data, keyword)
        
        # Filter temuan baru
        new_findings = [f for f in findings if f not in all_findings]
        new_urls = urls - all_urls
        
        all_findings.extend(new_findings)
        all_urls.update(urls)
        
        logger.info(f'  Total commits: {commit_data["total_count"]} | '
                   f'New findings: {len(new_findings)} | '
                   f'New URLs: {len(new_urls)} | '
                   f'Total unique findings: {len(all_findings)}')
        
        # Tampilkan sample findings
        if new_findings:
            for finding in new_findings[:2]:  # Show max 2 samples
                logger.info(f'    [!] {finding["repo"]} - {finding["commit_sha"][:8]}')
                if finding['crypto_matches']:
                    matches_str = ', '.join([m['type'] for m in finding['crypto_matches'][:3]])
                    logger.info(f'        Crypto patterns: {matches_str}')
        
        time.sleep(rate_limit)
    
    # Save results
    urls_file = f'{output_dir}/crypto_commit_urls.txt'
    findings_file = f'{output_dir}/crypto_commit_findings.json'
    report_file = f'{output_dir}/crypto_report.txt'
    
    with open(urls_file, 'w') as f:
        f.write('\n'.join(sorted(all_urls)))
    
    with open(findings_file, 'w') as f:
        json.dump(all_findings, f, indent=2)
    
    # Generate readable report
    with open(report_file, 'w') as f:
        f.write("CRYPTO COMMIT SEARCH REPORT\n")
        f.write("="*60 + "\n\n")
        f.write(f"Search keyword: {keyword if keyword else 'all crypto patterns'}\n")
        f.write(f"Total findings: {len(all_findings)}\n")
        f.write(f"Total unique URLs: {len(all_urls)}\n\n")
        
        f.write("HIGH RISK FINDINGS (Potential private keys/mnemonics):\n")
        f.write("-"*50 + "\n")
        
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
                        f.write(f"⚠️  CRITICAL: {match['type']} detected\n")
        
        f.write("\n\nALL FINDINGS SUMMARY:\n")
        f.write("-"*50 + "\n")
        for finding in all_findings:
            f.write(f"\n- {finding['repo']}\n")
            f.write(f"  Commit: {finding['commit_url']}\n")
            f.write(f"  Patterns: {', '.join([m['type'] for m in finding['crypto_matches']])}\n")
    
    logger.info("="*60)
    logger.info(f"RESULTS SAVED TO: {output_dir}")
    logger.info(f"  - {findings_file} (JSON details)")
    logger.info(f"  - {report_file} (Readable report)")
    logger.info(f"  - {urls_file} (URLs found)")
    logger.info(f"Total: {len(all_findings)} crypto-related commits found")
    logger.info("="*60)
    
    return all_urls, all_findings

if __name__ == '__main__':
    import sys
    
    print("\n" + "="*60)
    print("CRYPTO COMMIT SEARCH TOOL")
    print("Mencari exposed crypto keys, mnemonics, dan secrets di GitHub commits")
    print("="*60 + "\n")
    
    keyword = None
    if len(sys.argv) > 1:
        keyword = sys.argv[1]
        print(f"Target: {keyword}\n")
    else:
        keyword = input("Enter keyword/project/domain (or press Enter for all crypto patterns): ").strip()
        if not keyword:
            keyword = None
            print("Searching all crypto patterns (may take longer)...\n")
    
    # Optional: custom output directory
    output_dir = './crypto_output'
    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    
    # Jalankan pencarian
    run_crypto_search(keyword=keyword, output_dir=output_dir, rate_limit=5.0)
