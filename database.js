const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

const db = new DatabaseSync(path.join(__dirname, "veri.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS checks (
    url_hash TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    verdict TEXT NOT NULL,
    threat_types TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  ) STRICT;
`);

const findCachedCheck = db.prepare(`
  SELECT url_hash, domain, verdict, threat_types, checked_at, expires_at
  FROM checks
  WHERE url_hash = ? AND expires_at > ?
`);

function getCachedCheck(urlHash) {
  const row = findCachedCheck.get(urlHash, new Date().toISOString());

  if (!row) {
    return null;
  }

  return {
    ...row,
    threatTypes: JSON.parse(row.threat_types)
  };
}

const saveCheckQuery = db.prepare(`
  INSERT INTO checks (
    url_hash, domain, verdict, threat_types, checked_at, expires_at
  )
  VALUES (?, ?, ?, ?, ?, ?)
  ON CONFLICT(url_hash) DO UPDATE SET
    domain = excluded.domain,
    verdict = excluded.verdict,
    threat_types = excluded.threat_types,
    checked_at = excluded.checked_at,
    expires_at = excluded.expires_at
`);

function saveCheck(check) {
  saveCheckQuery.run(
    check.urlHash,
    check.domain,
    check.verdict,
    JSON.stringify(check.threatTypes),
    check.checkedAt,
    check.expiresAt
  );
}

module.exports = { getCachedCheck, saveCheck };