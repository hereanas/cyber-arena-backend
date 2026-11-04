const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

// ---------------------------------------------------------------------------
// Environment validation
// ---------------------------------------------------------------------------
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = parseInt(process.env.PORT, 10) || 3000;
const CORS_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(s => s.trim())
  : [`http://localhost:${PORT}`];

if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL environment variable is required.');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is required. Generate one with:');
  console.error('  node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
});

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: CORS_ORIGINS }));
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ status: 'error', message: 'Authentication required.' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);
    req.user = { id: decoded.id, username: decoded.username };
    next();
  } catch {
    return res.status(401).json({ status: 'error', message: 'Invalid or expired token.' });
  }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch {
    res.status(503).json({ status: 'error', message: 'Database unreachable.' });
  }
});

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password, avatar } = req.body;

  if (!username || typeof username !== 'string' || username.trim().length < 2 || username.trim().length > 50) {
    return res.status(400).json({ status: 'error', message: 'Username must be 2-50 characters.' });
  }
  if (!password || typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ status: 'error', message: 'Password must be at least 6 characters.' });
  }

  const allowedAvatars = ['🥷', '🕵️‍♂️', '🤖', '👽'];
  const safeAvatar = allowedAvatars.includes(avatar) ? avatar : '🥷';

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password, avatar, score) VALUES ($1, $2, $3, 0) RETURNING id, username, avatar, score',
      [username.trim(), hashedPassword, safeAvatar]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ status: 'success', message: 'Account created.', token, user: { id: user.id, username: user.username, avatar: user.avatar, score: user.score } });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ status: 'error', message: 'Username already taken.' });
    }
    console.error('Register error:', err.message);
    res.status(500).json({ status: 'error', message: 'Internal server error.' });
  }
});

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------
app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ status: 'error', message: 'Username and password are required.' });
  }

  try {
    const result = await pool.query('SELECT id, username, password, avatar, score FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ status: 'error', message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ status: 'success', message: 'Welcome back.', token, user: { id: user.id, username: user.username, avatar: user.avatar, score: user.score } });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ status: 'error', message: 'Internal server error.' });
  }
});

// ---------------------------------------------------------------------------
// Current user profile
// ---------------------------------------------------------------------------
app.get('/api/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, avatar, score FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ status: 'error', message: 'User not found.' });
    }

    const solvedResult = await pool.query(
      'SELECT challenge_id FROM submissions WHERE user_id = $1',
      [req.user.id]
    );

    const user = result.rows[0];
    user.solved = solvedResult.rows.map(r => r.challenge_id);

    res.json(user);
  } catch (err) {
    console.error('Profile error:', err.message);
    res.status(500).json({ status: 'error', message: 'Internal server error.' });
  }
});

// ---------------------------------------------------------------------------
// Challenges (public list — never expose flags)
// ---------------------------------------------------------------------------
app.get('/api/challenges', async (_req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, title, description, category, difficulty, points FROM challenges ORDER BY points ASC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Challenges error:', err.message);
    res.status(500).json({ status: 'error', message: 'Internal server error.' });
  }
});

// ---------------------------------------------------------------------------
// Leaderboard (public — only username, avatar, score)
// ---------------------------------------------------------------------------
app.get('/api/leaderboard', async (_req, res) => {
  try {
    const result = await pool.query(
      'SELECT username, avatar, score FROM users ORDER BY score DESC, username ASC LIMIT 50'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Leaderboard error:', err.message);
    res.status(500).json({ status: 'error', message: 'Internal server error.' });
  }
});

// ---------------------------------------------------------------------------
// Flag submission (authenticated, race-safe)
// ---------------------------------------------------------------------------
app.post('/api/submit', authenticate, async (req, res) => {
  const { challenge_id, flag } = req.body;

  if (!challenge_id || !flag || typeof flag !== 'string') {
    return res.status(400).json({ status: 'error', message: 'challenge_id and flag are required.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const challengeResult = await client.query(
      'SELECT id, title, points, flag FROM challenges WHERE id = $1',
      [challenge_id]
    );
    if (challengeResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ status: 'error', message: 'Challenge not found.' });
    }

    const challenge = challengeResult.rows[0];

    if (flag.trim() !== challenge.flag) {
      await client.query('ROLLBACK');
      return res.status(400).json({ status: 'error', message: 'Incorrect flag. Try again.' });
    }

    // INSERT with ON CONFLICT to atomically prevent duplicates
    const insertResult = await client.query(
      'INSERT INTO submissions (user_id, challenge_id) VALUES ($1, $2) ON CONFLICT (user_id, challenge_id) DO NOTHING RETURNING id',
      [req.user.id, challenge.id]
    );

    if (insertResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ status: 'warning', message: 'You already solved this challenge.' });
    }

    const scoreResult = await client.query(
      'UPDATE users SET score = score + $1 WHERE id = $2 RETURNING score',
      [challenge.points, req.user.id]
    );

    await client.query('COMMIT');

    res.json({
      status: 'success',
      message: `Correct! You solved "${challenge.title}".`,
      points: challenge.points,
      newScore: scoreResult.rows[0].score,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Submit error:', err.message);
    res.status(500).json({ status: 'error', message: 'Internal server error.' });
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// SPA fallback
// ---------------------------------------------------------------------------
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`CyberArena API listening on http://localhost:${PORT}`);
});
