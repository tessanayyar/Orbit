# Orbit — social super-app starter

Orbit is a local full-stack starter based on the pastel social UI in `public/index.html`. It adds a persistent SQLite database and an Express API for accounts, posts, likes, replies, saved posts, 24-hour stories, events, user lookup, and direct messages.

## Requirements
- Node.js 20 or newer
- npm

## Run locally
```bash
npm install
```

Create a `.env` file if desired (the server currently reads environment variables directly):
```bash
# macOS/Linux
export SESSION_SECRET="$(openssl rand -hex 32)"
export NODE_ENV=development
npm start
```

Then open http://localhost:3000

On Windows PowerShell:
```powershell
$env:SESSION_SECRET = "replace-this-with-a-long-random-secret"
$env:NODE_ENV = "development"
npm start
```

The SQLite database and session database are created under `data/` automatically.

## First API smoke test
```bash
# Register a user and keep the session cookie
curl -i -c cookies.txt -H "Content-Type: application/json" \
  -d '{"username":"tes_demo","displayName":"Tes","password":"a-long-demo-password"}' \
  http://localhost:3000/api/auth/register

# Create a post using that cookie
curl -i -b cookies.txt -H "Content-Type: application/json" \
  -d '{"body":"Hello from Orbit ✨","moodCard":"currently in my own little universe"}' \
  http://localhost:3000/api/posts

# Read the feed
curl -b cookies.txt http://localhost:3000/api/posts
```

## API overview
- `GET /api/health`
- `POST /api/auth/register` — `{ username, displayName, password }`
- `POST /api/auth/login` — `{ username, password }`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/posts?limit=30&before=123`
- `POST /api/posts` — `{ body, moodCard? }` (auth required)
- `DELETE /api/posts/:id` (owner only)
- `POST /api/posts/:id/like` (auth required; toggles like)
- `GET /api/posts/:id/comments`
- `POST /api/posts/:id/comments` — `{ body }` (auth required)
- `GET /api/saved` (auth required)
- `POST /api/posts/:id/save` (auth required; toggles saved status)
- `GET /api/stories`
- `POST /api/stories` — `{ body }` (auth required; expires after 24 hours)
- `GET /api/events`
- `POST /api/events` — `{ title, date: "YYYY-MM-DD", time?: "HH:MM" }` (auth required)
- `GET /api/users` (auth required)
- `GET /api/messages/:userId` (auth required)
- `POST /api/messages/:userId` — `{ body }` (auth required)

## Important notes
- The current UI is included as `public/index.html`. Its sample posts and controls remain a front-end demo; the API is ready for integration, but the existing page does **not yet call every endpoint**. To make this a true connected social app, wire the UI's feed, auth forms, post actions, stories, events and chat screens to these endpoints.
- This is a development starter, not production-hardened. Before deploying publicly: set a strong `SESSION_SECRET`, use HTTPS, add CSRF protection for cookie-authenticated mutations, configure rate limits and backups, add email verification/password reset/account deletion, validate moderation/report flows, privacy controls, and automated tests. For a public multi-instance deployment, use a managed database and shared session store.
- No external accounts or cloud services are connected. All users must register in this local instance.
