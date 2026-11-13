-- Seed rule packs and the default policy. (Agents embed their own default rules; server-side rules are additive.)
INSERT OR IGNORE INTO rule_packs(id, name, source, version, r2_key, updated_at) VALUES
  ('default', 'Aegis defaults', 'custom', 'builtin', NULL, '1970-01-01T00:00:00.000Z'),
  ('sigmahq', 'SigmaHQ (linux)', 'sigmahq', 'none', NULL, '1970-01-01T00:00:00.000Z'),
  ('custom', 'Custom rules', 'custom', '1', NULL, '1970-01-01T00:00:00.000Z'),
  ('ai', 'AI-proposed rules', 'ai', '1', NULL, '1970-01-01T00:00:00.000Z');

INSERT OR IGNORE INTO policies(host_id, version, body_json, created_by, reason, created_at) VALUES
  ('default', 1,
   '{"log_level":"info","thresholds":{"native:ssh_bruteforce.count":10,"native:ssh_bruteforce.window_s":60,"baseline.zscore":4},"watches":[],"suppressions":[]}',
   'system', 'initial default policy', '1970-01-01T00:00:00.000Z');
