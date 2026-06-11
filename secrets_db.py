"""
Persistent deduplication database for discovered crypto secrets.

Every unique secret (keyed by SHA-256 of its normalised value) is stored
in  crypto_output/secrets_db.json  and persisted to disk on every write.
Subsequent scans that find the same secret only bump its `scan_count` —
they never create duplicate entries.
"""

import hashlib, json, logging, os, threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DB_PATH = os.path.join('crypto_output', 'secrets_db.json')
_VERSION = 3

# Types that carry an actual extractable secret value
_TYPES_WITH_VALUE = {
    'eth_private_key', 'btc_wif', 'btc_wif_compressed',
    'mnemonic_12', 'mnemonic_24', 'pem_private_key',
    'raw_hex_key', 'env_mnemonic', 'env_private_key',
    'infura_secret', 'alchemy_key',
}


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _fingerprint(secret_value: str) -> str:
    """SHA-256 of the normalised secret value → dedup key."""
    norm = secret_value.strip().lower()
    return hashlib.sha256(norm.encode()).hexdigest()


def _extract_secret_value(crypto_match: dict) -> str | None:
    """
    Pull the actual secret string out of a crypto_match dict.
    Returns None for keyword-only matches that carry no real value.
    """
    t   = crypto_match.get('type', '')
    val = crypto_match.get('match', '').strip()

    if not val:
        return None

    # Only track matches that contain a real credential value
    for known in _TYPES_WITH_VALUE:
        if known in t:
            return val

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
            except Exception as e:
                logger.warning(f'secrets_db: could not load {self._path}: {e}')
        return {'version': _VERSION, 'total': 0,
                'last_updated': _now_iso(), 'entries': {}}

    def _save(self):
        """Must be called with self._lock held."""
        self._data['last_updated'] = _now_iso()
        tmp = self._path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self._path)

    # ── Public API ────────────────────────────────────────────────────────────

    def is_known(self, secret_value: str) -> bool:
        """Return True if this exact secret was already seen."""
        fp = _fingerprint(secret_value)
        with self._lock:
            return fp in self._data['entries']

    def add_finding(self, finding: dict) -> tuple[int, int]:
        """
        Process one finding dict (as returned by extract_findings).

        Returns (new_count, dup_count) for this call:
          new_count  — secrets that were NOT in the DB and got added
          dup_count  — secrets that were already known (skipped)
        """
        new_count = dup_count = 0

        with self._lock:
            for m in finding.get('crypto_matches', []):
                secret_val = _extract_secret_value(m)
                if not secret_val:
                    continue

                fp = _fingerprint(secret_val)

                if fp in self._data['entries']:
                    # Already known — just increment scan count
                    self._data['entries'][fp]['scan_count'] += 1
                    dup_count += 1
                    continue

                # New secret — store it
                entry = {
                    'id':          fp[:16],   # short display ID
                    'fingerprint': fp,
                    'type':        m.get('type', 'unknown'),
                    'secret':      secret_val,
                    'risk_label':  finding.get('risk_label', 'MEDIUM'),
                    'confidence':  finding.get('confidence', 0),
                    'repo':        finding.get('repo', ''),
                    'commit_url':  finding.get('commit_url', ''),
                    'commit_sha':  finding.get('commit_sha', ''),
                    'author':      finding.get('author', ''),
                    'date':        finding.get('date', ''),
                    'first_seen':  _now_iso(),
                    'scan_count':  1,
                    'message':     finding.get('message', '')[:300],
                }
                self._data['entries'][fp] = entry
                self._data['total'] = len(self._data['entries'])
                new_count += 1

            if new_count:
                self._save()

        return new_count, dup_count

    def all_entries(self) -> list[dict]:
        """Return all entries sorted by confidence desc, then first_seen desc."""
        with self._lock:
            entries = list(self._data['entries'].values())
        entries.sort(key=lambda e: (-e.get('confidence', 0), e.get('first_seen', '')), reverse=False)
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
            'total':       total,
            'by_risk':     by_risk,
            'last_updated': self._data.get('last_updated', ''),
        }

    def clear(self):
        with self._lock:
            self._data = {'version': _VERSION, 'total': 0,
                          'last_updated': _now_iso(), 'entries': {}}
            self._save()


# Module-level singleton — shared across app.py and main.py
db = SecretsDB()
