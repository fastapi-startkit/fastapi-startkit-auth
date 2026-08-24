# Session-based login example (Inertia.js + Vue 3)

A self-contained example of cookie/session authentication with
`fastapi-startkit-auth`, using an [Inertia.js](https://inertiajs.com) + Vue 3
frontend wired into FastAPI per the
[Inertia integration guide](https://fastapi-startkit.github.io/docs/frontend/inertia).

What it demonstrates:

- **Login** — `POST /login` validates credentials via `Auth.attempt()`
  (`SessionGuard`), creates a server-side session in an
  `InMemorySessionStore`, and sets the HttpOnly `startkit_session` cookie.
- **Protected page** — `GET /dashboard` requires a live session; unauthenticated
  visits are redirected to `/login`.
- **Logout** — `POST /logout` destroys the server-side session and clears the
  cookie (`Max-Age=0`).
- **Validation errors** — invalid credentials re-render the login page with a
  generic error (no user enumeration) surfaced through Inertia's standard
  `errors` prop.

## Layout

```
example/sessions/
├── app.py                        # Startkit application: providers + routes
├── package.json                  # Frontend dependencies and scripts
├── vite.config.ts                # Vite build (manifest for asset versioning)
├── tsconfig.json
└── resources/
    ├── templates/index.html      # Inertia root template
    ├── css/app.css
    └── js/
        ├── app.ts                # Inertia + Vue 3 entry point
        └── Pages/
            ├── Login.vue         # Username/password form
            └── Dashboard.vue     # Protected page + logout
```

## Setup

Requires [uv](https://docs.astral.sh/uv/) (Python 3.12+) and Node 20+.

```sh
cd example/sessions

# 1. Backend dependencies (this package + the startkit framework extras)
uv venv
uv pip install -e ../.. "fastapi-startkit[inertia,vite]>=0.51" uvicorn

# 2. Frontend dependencies + production asset build
npm install
npm run build
```

`npm run build` emits hashed assets and a manifest to `public/build/`; the
manifest hash doubles as the Inertia asset version, so stale clients are
hard-reloaded automatically after a rebuild.

## Run

```sh
npm run dev
```

This starts backend and frontend together (via `npx concurrently`):
`uv run uvicorn app:app --reload` plus the Vite dev server for hot reload.
Each is also available on its own as `npm run dev:backend` /
`npm run dev:frontend` — for a production-style run, `npm run build` once and
start only the backend.

If port 8000 is taken, pick another one — everything else adapts:

```sh
BACKEND_PORT=8001 npm run dev
# or standalone: uv run uvicorn app:app --factory --reload --port 8001
```

(HMR is unaffected: `public/hot` carries the Vite dev-server origin, not the
backend's, and Vite's dev CORS allows any localhost port.)

Open http://127.0.0.1:8000/login (or your chosen port) and sign in with the
seeded demo user:

| Email              | Password   |
| ------------------ | ---------- |
| `demo@example.com` | `password` |

Type-check the frontend with:

```sh
npm run types:check
```

## How it works

| Route            | Behaviour                                                                                                                              |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /login`     | Renders the `Login` page. Already authenticated → `303` redirect to `/dashboard`.                                                       |
| `POST /login`    | Body `{email, password}`. Success → session created, cookie set, `303` to `/dashboard`. Failure → direct Inertia render of `Login` with `errors.email` (a failed login has no session to flash errors into). |
| `GET /dashboard` | Renders `Dashboard` with `{user: {id, email}}`. No valid session → `303` to `/login`.                                                   |
| `POST /logout`   | Destroys the session server-side, expires the cookie, `303` to `/login`.                                                                |

Notes:

- The session cookie is HttpOnly + SameSite=Lax; the example runs over plain
  HTTP so `secure` is disabled in the session config. **Expect a `UserWarning`
  about `secure` at startup — it is intentional here.** Keep `secure` on in
  production.
- POST responses redirect with `303 See Other` so Inertia follows up with a
  `GET`, per the Inertia protocol.
- CSRF protection is on via the package's SPA mode (`CsrfMiddleware`).
  Enforcement is session-bound: the guest `POST /login` is exempt (no session
  yet), while `POST /logout` requires the `X-XSRF-TOKEN` header — which axios
  (Inertia's transport) echoes automatically from the `XSRF-TOKEN` cookie, so
  no extra frontend code is needed.
- Sessions live in memory: restarting the server signs everyone out. Swap in
  `SqlSessionStore` for persistence.
- Troubleshooting: if pages hang loading assets, check for a stale
  `public/hot` file (left behind if a dev server crashed) and delete it — while
  it exists the backend emits dev-server asset URLs instead of built ones.
