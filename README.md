# CyberArena CTF

A Capture The Flag platform built with Express, PostgreSQL, and a single-page frontend.

## Setup

### 1. Prerequisites

- Node.js 18+
- PostgreSQL 14+

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment

Copy `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
```

Generate a JWT secret:

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

Paste the output as `JWT_SECRET` in `.env`.

Set `DATABASE_URL` to your PostgreSQL connection string.

### 4. Create the database schema

```bash
npm run db:setup
```

Or manually: `psql $DATABASE_URL -f schema.sql`

### 5. Run

```bash
npm start
```

The app serves at `http://localhost:3000` (or the `PORT` you configured).

## API Endpoints

| Method | Path               | Auth     | Description                      |
|--------|--------------------|----------|----------------------------------|
| GET    | `/api/health`      | No       | Health check                     |
| POST   | `/api/register`    | No       | Create account                   |
| POST   | `/api/login`       | No       | Login                            |
| GET    | `/api/me`          | Bearer   | Current user profile + solved    |
| GET    | `/api/challenges`  | No       | List challenges (no flags)       |
| GET    | `/api/leaderboard` | No       | Top 50 users                     |
| POST   | `/api/submit`      | Bearer   | Submit a flag                    |
