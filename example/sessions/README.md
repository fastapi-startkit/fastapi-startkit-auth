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
├── app.py                        # FastAPI app: auth config + routes
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

Requires Python 3.10+ and Node 20+.

```sh
cd example/sessions

# 1. Backend dependencies
uv venv && uv pip install fastapi-startkit fastapi-startkit-auth uvicorn
# (or: pip install fastapi-startkit fastapi-startkit-auth uvicorn)

# 2. Frontend dependencies + production asset build
npm install
npm run build
```

`npm run build` emits hashed assets and a manifest to `public/build/`; the
manifest hash doubles as the Inertia asset version, so stale clients are
hard-reloaded automatically after a rebuild.

## Run

```sh
uvicorn app:app --reload
```

Open http://127.0.0.1:8000/login and sign in with the seeded demo user:

| Email              | Password   |
| ------------------ | ---------- |
| `demo@example.com` | `password` |

For frontend development with hot reload, run `npm run dev` alongside uvicorn.

Type-check the frontend with:

```sh
npm run types:check
```

## How it works

| Route            | Behaviour                                                                                                                              |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /login`     | Renders the `Login` page. Already authenticated → `303` redirect to `/dashboard`.                                                       |
| `POST /login`    | Body `{email, password}`. Success → session created, cookie set, `303` to `/dashboard`. Failure → back to `/login` with `errors.email`. |
| `GET /dashboard` | Renders `Dashboard` with `{user: {id, email}}`. No valid session → `303` to `/login`.                                                   |
| `POST /logout`   | Destroys the session server-side, expires the cookie, `303` to `/login`.                                                                |

Notes:

- The session cookie is HttpOnly + SameSite=Lax; the example runs over plain
  HTTP so `secure` is disabled in the session config (a `UserWarning` reminds
  you — keep `secure` on in production).
- POST responses redirect with `303 See Other` so Inertia follows up with a
  `GET`, per the Inertia protocol.
- If the CSRF middleware is enabled, its defaults (`XSRF-TOKEN` cookie,
  `X-XSRF-TOKEN` header) match axios's built-in echo behaviour, so Inertia
  requests pass CSRF checks with no extra frontend code.
- Sessions live in memory: restarting the server signs everyone out. Swap in
  `SqlSessionStore` for persistence.
