"""
Persistent deduplication database for discovered crypto secrets.

Every unique secret (keyed by SHA-256 of its normalised core value) is stored
in  crypto_output/secrets_db.json  and persisted to disk on every write.
Subsequent scans that find the same secret only bump its `scan_count` —
they never create duplicate entries.
"""

import hashlib, json, logging, os, re, threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DB_PATH = os.path.join('crypto_output', 'secrets_db.json')
_VERSION = 6   # bumped: mnemonic_12 subset-of-mnemonic_24 deduplication pass

# Types that carry an actual extractable secret value
_TYPES_WITH_VALUE = {
    'eth_private_key', 'btc_wif', 'btc_wif_compressed',
    'mnemonic_12', 'mnemonic_24', 'pem_private_key',
    'raw_hex_key', 'env_mnemonic', 'env_private_key',
    'infura_secret', 'alchemy_key',
}

# Patterns to extract the core secret from a full regex match
_HEX64     = re.compile(r'[0-9a-fA-F]{64}')
_WORDS12   = re.compile(r'(?:[a-z]{3,10}\s+){11}[a-z]{3,10}', re.I)
_WORDS24   = re.compile(r'(?:[a-z]{3,10}\s+){23}[a-z]{3,10}', re.I)
_HEX32     = re.compile(r'[0-9a-zA-Z_\-]{32,}')


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _normalise_core(match_type: str, raw_val: str) -> str:
    """
    Extract just the core secret from a regex match string and normalise it.
    Same underlying secret must always produce the same string regardless of
    which pattern captured it or what surrounding context was included.
    """
    v = raw_val.strip()

    # Hex private keys (eth, raw_hex, env) → bare 64-char hex, lowercase, no 0x
    if any(k in match_type for k in ('eth_private_key', 'raw_hex_key', 'env_private_key')):
        m = _HEX64.search(v)
        if m:
            return m.group().lower()

    # BIP-39 mnemonics → normalised word sequence
    # Always try 24-word first so the same seed isn't stored as two fingerprints
    # (mnemonic_12 dork can capture a 24-word mnemonic's first 12 words, and
    #  env_mnemonic with 12 words used to fall through to the raw string)
    if any(k in match_type for k in ('mnemonic_12', 'mnemonic_24', 'env_mnemonic')):
        m24 = _WORDS24.search(v)
        if m24:
            return ' '.join(m24.group().lower().split())
        m12 = _WORDS12.search(v)
        if m12:
            return ' '.join(m12.group().lower().split())

    # API keys (infura, alchemy) → extract the credential token part
    if any(k in match_type for k in ('infura_secret', 'alchemy_key')):
        m = _HEX32.search(v)
        if m:
            return m.group().lower()

    # BTC WIF, PEM → keep as-is (already distinct strings)
    return v.lower()


def _fingerprint(core_value: str) -> str:
    """SHA-256 of the normalised core secret value → dedup key."""
    return hashlib.sha256(core_value.encode()).hexdigest()


def _extract_secret_value(crypto_match: dict) -> str | None:
    """
    Pull the normalised core secret out of a crypto_match dict.
    Returns None for keyword-only matches that carry no real value.
    """
    t   = crypto_match.get('type', '')
    val = crypto_match.get('match', '').strip()

    if not val:
        return None

    for known in _TYPES_WITH_VALUE:
        if known in t:
            return _normalise_core(t, val)

    return None


class SecretsDB:
    """Thread-safe persistent store of unique crypto secrets."""

    def __init__(self, path: str = DB_PATH):
        self._path  = path
        self._lock  = threading.Lock()
        self._data  = self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> dict:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        if os.path.exists(self._path):
            try:
                with open(self._path, encoding='utf-8') as f:
                    d = json.load(f)
                if d.get('version') == _VERSION:
                    return d
                # Older versions → migrate by re-fingerprinting entries
                if d.get('version') in (2, 3, 4, 5) and 'entries' in d:
                    return self._migrate(d)
            except Exception as e:
                logger.warning(f'secrets_db: could not load {self._path}: {e}')
        return {'version': _VERSION, 'total': 0,
                'last_updated': _now_iso(), 'entries': {}}

    @staticmethod
    def _merge_entry(existing: dict, incoming: dict) -> None:
        """Merge incoming into existing (in-place): sum counts, keep best confidence."""
        existing['scan_count'] = existing.get('scan_count', 1) + incoming.get('scan_count', 1)
        if incoming.get('confidence', 0) > existing.get('confidence', 0):
            existing['confidence'] = incoming['confidence']
            existing['risk_label'] = incoming.get('risk_label', existing.get('risk_label'))
        # Accumulate repos list
        repos = existing.setdefault('repos', [])
        seen_urls = {r.get('commit_url') for r in repos}
        for r in incoming.get('repos', []):
            if r.get('commit_url') not in seen_urls and len(repos) < 20:
                repos.append(r)
                seen_urls.add(r.get('commit_url'))

    def _migrate(self, old: dict) -> dict:
        """Re-fingerprint all entries with the new normalisation logic and dedup."""
        new_entries: dict = {}
        dupes = 0
        for old_fp, e in old.get('entries', {}).items():
            secret_val = e.get('secret', '')
            match_type = e.get('type', '')
            core = _normalise_core(match_type, secret_val)
            new_fp = _fingerprint(core)
            if new_fp in new_entries:
                self._merge_entry(new_entries[new_fp], e)
                dupes += 1
            else:
                e = dict(e)   # shallow copy so we don't mutate the old dict
                e['fingerprint'] = new_fp
                e['id'] = new_fp[:16]
                e['secret'] = core   # store normalised value
                new_entries[new_fp] = e

        # ── Extra pass: merge mnemonic_12 entries that are a word-prefix of a
        #    mnemonic_24 entry (same seed, different dork captured different length)
        dupes += self._dedup_mnemonic_subsets(new_entries)

        logger.info(f'secrets_db: migrated {len(old.get("entries",{}))} entries → '
                    f'{len(new_entries)} unique ({dupes} duplicates merged)')
        result = {'version': _VERSION, 'total': len(new_entries),
                  'last_updated': _now_iso(), 'entries': new_entries}
        # Persist the migrated data immediately
        tmp = self._path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            os.replace(tmp, self._path)
        except Exception as e:
            logger.warning(f'secrets_db: migration save failed: {e}')
        return result

    @staticmethod
    def _dedup_mnemonic_subsets(entries: dict) -> int:
        """
        Merge mnemonic_12 entries whose words are a prefix of a mnemonic_24 entry.
        Returns number of entries removed.
        """
        # Build word-prefix index for mnemonic_24 entries
        # key = tuple of words → fingerprint
        prefix_index: dict[tuple, str] = {}
        for fp, e in entries.items():
            if 'mnemonic_24' in e.get('type', ''):
                words = tuple(e['secret'].split())
                # Store every prefix ≥ 12 words so any shorter match can find it
                for length in range(12, len(words)):
                    prefix_index[words[:length]] = fp

        to_remove: list[str] = []
        for fp, e in entries.items():
            if fp in to_remove:
                continue
            if 'mnemonic_12' not in e.get('type', '') and 'env_mnemonic' not in e.get('type', ''):
                continue
            words = tuple(e['secret'].split())
            parent_fp = prefix_index.get(words)
            if parent_fp and parent_fp != fp and parent_fp not in to_remove:
                # Merge this 12-word entry into the 24-word parent
                SecretsDB._merge_entry(entries[parent_fp], e)
                to_remove.append(fp)

        for fp in to_remove:
            del entries[fp]

        return len(to_remove)

    def _save(self):
        """Must be called with self._lock held."""
        self._data['last_updated'] = _now_iso()
        tmp = self._path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
        except Exception as e:
            logger.error(f'secrets_db: _save failed, database NOT overwritten: {e}')
            try:
                os.remove(tmp)
            except OSError:
                pass

    # ── Public API ────────────────────────────────────────────────────────────

    def is_known(self, secret_value: str) -> bool:
        """Return True if this exact secret was already seen."""
        fp = _fingerprint(secret_value)
        with self._lock:
            return fp in self._data['entries']

    def is_all_known(self, finding: dict) -> bool:
        """Return True if every extractable secret in this finding is already in vault."""
        secrets = [_extract_secret_value(m) for m in finding.get('crypto_matches', [])]
        secrets = [s for s in secrets if s]
        if not secrets:
            return False
        with self._lock:
            return all(_fingerprint(s) in self._data['entries'] for s in secrets)

    def add_finding(self, finding: dict) -> tuple[int, int]:
        """
        Process one finding dict (as returned by extract_findings).

        Returns (new_count, dup_count) for this call:
          new_count  — secrets that were NOT in the DB and got added
          dup_count  — secrets that were already known (skipped)
        """
        new_count = dup_count = 0
        repo       = finding.get('repo', '')
        commit_url = finding.get('commit_url', '')

        with self._lock:
            for m in finding.get('crypto_matches', []):
                secret_val = _extract_secret_value(m)
                if not secret_val:
                    continue

                fp = _fingerprint(secret_val)

                if fp in self._data['entries']:
                    entry = self._data['entries'][fp]
                    entry['scan_count'] += 1
                    # Accumulate source repos (max 20, no duplicates)
                    repos = entry.setdefault('repos', [])
                    existing_urls = {r.get('commit_url') for r in repos}
                    if commit_url and commit_url not in existing_urls and len(repos) < 20:
                        repos.append({'repo': repo, 'commit_url': commit_url})
                    dup_count += 1
                    continue

                entry = {
                    'id':          fp[:16],
                    'fingerprint': fp,
                    'type':        m.get('type', 'unknown'),
                    'secret':      secret_val,
                    'risk_label':  finding.get('risk_label', 'MEDIUM'),
                    'confidence':  finding.get('confidence', 0),
                    'repo':        repo,
                    'commit_url':  commit_url,
                    'commit_sha':  finding.get('commit_sha', ''),
                    'author':      finding.get('author', ''),
                    'date':        finding.get('date', ''),
                    'first_seen':  _now_iso(),
                    'scan_count':  1,
                    'message':     finding.get('message', '')[:300],
                    'repos':       [{'repo': repo, 'commit_url': commit_url}] if repo else [],
                }
                self._data['entries'][fp] = entry
                self._data['total'] = len(self._data['entries'])
                new_count += 1

            if new_count or dup_count:
                self._save()

        return new_count, dup_count

    def all_entries(self) -> list[dict]:
        """Return all entries sorted by confidence desc, then first_seen desc."""
        with self._lock:
            entries = list(self._data['entries'].values())
        entries.sort(key=lambda e: (e.get('confidence', 0), e.get('first_seen', '')), reverse=True)
        return entries

    def stats(self) -> dict:
        with self._lock:
            entries = self._data['entries']
            total   = len(entries)
            by_risk = {}
            for e in entries.values():
                rl = e.get('risk_label', 'UNKNOWN')
                by_risk[rl] = by_risk.get(rl, 0) + 1
        return {
            'total':        total,
            'by_risk':      by_risk,
            'last_updated': self._data.get('last_updated', ''),
        }

    def clear(self):
        with self._lock:
            self._data = {'version': _VERSION, 'total': 0,
                          'last_updated': _now_iso(), 'entries': {}}
            self._save()


# Module-level singleton — shared across app.py and main.py
db = SecretsDB()
