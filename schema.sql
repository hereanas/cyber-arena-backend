-- CyberArena CTF Database Schema
-- Run: psql $DATABASE_URL -f schema.sql

BEGIN;

CREATE TABLE IF NOT EXISTS users (
  id          SERIAL PRIMARY KEY,
  username    VARCHAR(50)  NOT NULL UNIQUE,
  password    VARCHAR(255) NOT NULL,
  avatar      VARCHAR(10)  DEFAULT '🥷',
  score       INTEGER      NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS challenges (
  id          SERIAL PRIMARY KEY,
  title       VARCHAR(200) NOT NULL,
  description TEXT         NOT NULL,
  category    VARCHAR(50)  NOT NULL DEFAULT 'misc',
  difficulty  VARCHAR(20)  NOT NULL DEFAULT 'easy',
  points      INTEGER      NOT NULL,
  flag        VARCHAR(255) NOT NULL,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS submissions (
  id            SERIAL PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  challenge_id  INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
  submitted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, challenge_id)
);

CREATE INDEX IF NOT EXISTS idx_users_score ON users(score DESC);
CREATE INDEX IF NOT EXISTS idx_submissions_user ON submissions(user_id);
CREATE INDEX IF NOT EXISTS idx_submissions_challenge ON submissions(challenge_id);

-- Seed challenges
INSERT INTO challenges (title, description, category, difficulty, points, flag) VALUES
  ('The Hidden Message',   'Decode this Base64 string to find the flag: Q1RGe0FuYXNfSXNfSGVyZX0=',                          'crypto',  'easy',   100, 'CTF{Anas_Is_Here}'),
  ('SQL Injection 101',    'A classic login bypass. The admin panel uses: SELECT * FROM users WHERE user=''__'' AND pass=''__''. Find the flag hidden behind the login.', 'web',     'easy',   200, 'CTF{SQL_Master}'),
  ('Cookie Monster',       'The admin left a debug cookie on the server. Inspect the HTTP headers to find the flag.',         'web',     'medium', 300, 'CTF{Cookie_Thief}'),
  ('Reverse Me',           'This binary prints the flag backwards: }3sr3v3R_4_t0G{FTC. Can you read it?',                     'reverse', 'easy',   150, 'CTF{Got_4_R3v3rs3}'),
  ('Hash Cracker',         'Crack this MD5 hash to reveal the flag: 5d41402abc4b2a76b9719d911017c592 (hint: it''s a common word)', 'crypto',  'medium', 250, 'CTF{hello_hashed}'),
  ('Packet Sniffer',       'Analyze the network capture. The flag was sent in plaintext over HTTP on port 8080.',             'forensics','hard',   400, 'CTF{Sniff_Sniff_Got_It}'),
  ('The Invisible Ink',    'The flag is hidden in this image using steganography. Look beyond what the eye can see.',          'stego',   'hard',   500, 'CTF{St3g0_N1nj4}')
ON CONFLICT DO NOTHING;

COMMIT;
