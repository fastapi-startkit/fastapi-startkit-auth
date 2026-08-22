# Framework `package:publish` contract — investigation note

**Task:** #1500 — confirm the manifest/contract the framework expects for publishable
package assets, so Phase 2 (SPA auth) can ship the `auth:cors` stub.

**Status:** investigation only. No feature code. Findings below are drawn from the
`fastapi-startkit-framework` repo (framework version `0.51.0`).

## TL;DR

- The command the roadmap calls `package:publish` **does not exist under that name**.
  The real framework command is **`provider:publish`** (`fastapi_startkit/console/publish_command.py`).
- There is **no manifest file format**. Publishing is entirely **provider-driven**: a
  framework `Provider` subclass calls `self.publishes({source: "dest"})` and the files
  accumulate into `application.published_resources`.
- Selection is **by provider**, via `provider:publish -p <ProviderName>` — **not** by a
  per-asset tag like `auth:cors`. The `tag` argument to `publishes()` exists in the
  signature but is **currently ignored** (not stored, not filterable).
- To publish anything, the package must ship a **registered framework `Provider`**
  (extends `fastapi_startkit.support.Provider`). The auth package's current
  `AuthProvider` is a plain FastAPI wrapper and is **not** framework-native, so it is
  not publishable as-is.

The roadmap's assumed contract (a `publishable/` directory + a `manifest` file +
`package:publish auth:cors`) is **not** how the framework works today. Phase 2 needs
either a small framework change (tag support / a `package:publish` alias) or must adapt
to the provider-driven mechanism described below.

## How publishing actually works

### 1. The command — `provider:publish`

`fastapi_startkit/src/fastapi_startkit/console/publish_command.py`:

```python
class PublishCommand(Command):
    name = "provider:publish"
    description = "Publish provider config files into the project."
    options = [option("provider", "p", description="Provider name to publish ...", flag=False)]
```

Behaviour:

- With no `--provider`, it publishes **every** registered provider's resources.
- With `-p/--provider <name>`, it filters providers whose **slugified key/class name**
  equals the slugified argument (`LogProvider`, `log_provider`, `log-provider` all match).
- For each `{source: destination}` pair it resolves `destination` against the project
  base path, prompts to overwrite if the file exists (default **no**), creates parent
  dirs, and `shutil.copy2`s the source in.

Registered by `AppProvider` (a default provider), so it is always available:
`self.commands([PublishCommand])` in `foundation/app_provider.py`.

### 2. The registration hook — `Provider.publishes()`

`fastapi_startkit/src/fastapi_startkit/support/providers/provider.py`:

```python
class Provider:
    provider_key: str = None            # defaults to slugified class name minus "Provider"

    def register(self) -> None: ...      # runs at app construction
    def boot(self) -> None: ...          # runs after all providers registered

    def publishes(self, resources: dict, tag: str = None) -> None:
        self.app.published_resources.setdefault(self.provider_key, {}).update(resources)

    def merge_config_from(self, source, provider_key) -> None: ...
    def commands(self, commands: list) -> None: ...
```

Key points:

- `resources` is a plain `dict[str_source_abs_path, str_dest_project_relative_path]`.
- **`tag` is accepted but discarded** — there is no per-tag storage or filtering today.
  So `auth:cors` cannot be targeted as a tag; it can only be a *provider* selector.
- Resources are keyed by `provider_key`, so a provider can register many files and they
  publish together.

### 3. Where `publishes()` is called

Providers call it in `register()` or `boot()`. Real examples:

```python
# vite/providers/provider.py (boot)
self.publishes({source: "config/vite.py"})
self.publishes({
    os.path.join(stubs_path, "vite.config.ts"): "vite.config.ts",
    os.path.join(stubs_path, "package.json"): "package.json",
    ...
})

# logging/providers/log_provider.py (register)
self.publishes({<pkg>/config/logging.py: "config/logging.py"})
```

Convention: sources live inside the package (under `config/` or `stubs/`); use an
absolute path built from `__file__`. Destinations are **project-relative** and choose
their own directory (`config/…`, `resources/…`, or a bare filename).

## File layout the framework expects

There is **no enforced layout and no manifest**. The only real requirements:

| Concern            | Requirement                                                                 |
| ------------------ | --------------------------------------------------------------------------- |
| Source files       | anywhere in the package; reference by absolute path (convention: `config/`, `stubs/`) |
| Destination paths  | project-relative strings you pass to `publishes()`                          |
| Discovery          | via a **registered `Provider`** whose `register()`/`boot()` calls `publishes()` |
| Selection          | by provider name (`-p`), slug-matched                                       |
| Manifest           | none — the "manifest" is the in-code `publishes({...})` dict                |

## Config merge (for the CORS config stub)

Package defaults are merged so a published file only *overrides*:

- `merge_config_from(config, provider_key)` → `config.merge_with(key, external)`
  (`configuration/Configuration.py`). Project config wins over package defaults:
  `merged = {**package_defaults, **project_config}`.
- **Reserved keys** (e.g. `application`) cannot be used as a merge key —
  raises `InvalidConfigurationSetup`. Use a package-specific key such as `auth` / `cors`.

## Versioning constraints

- No manifest → **no manifest schema version**. The only version surface is the
  framework package version (`fastapi-startkit == 0.51.0`) and the `Provider` API shape.
- **Hard dependency implication:** to be publishable, the auth package must import
  `fastapi_startkit.support.Provider`, i.e. take a dependency on `fastapi-startkit`.
  Today `fastapi-startkit-auth` depends only on `fastapi` — it has **no** framework
  dependency. Recommend adding the framework as an **optional extra**
  (e.g. `fastapi-startkit-auth[framework]`) so standalone FastAPI use keeps working.
- The publish API (`publishes`, `provider_key`, `provider:publish`) is stable in 0.51.0
  but the `tag` parameter is effectively unimplemented — do not design against it.

## Gap analysis for `auth:cors` (Phase 2 enabler)

To ship a publishable `auth:cors` stub the way the roadmap imagines, one of these is
needed — **flag this decision to the PM before Phase 2 starts**:

1. **Adapt to the framework as-is (lowest friction).** Add a framework-native
   `Provider` in the auth package (e.g. `provider_key = "auth"`) that calls
   `self.publishes({<pkg>/publishable/cors.py: "config/cors.py"})`. Users publish with
   `provider:publish -p auth`. No `auth:cors` tag — the whole auth provider's assets
   publish together. Requires adding `fastapi-startkit` as an optional dependency.

2. **Add tag support upstream (framework change).** Implement the `tag` parameter in
   `Provider.publishes()` + a positional/tag filter on `provider:publish` (and possibly
   a `package:publish` alias) so `provider:publish auth:cors` selects just the CORS
   stub. This is a framework-repo task, not an auth-package task, and would gate Phase 2.

3. **Dedicated tiny provider per asset.** Ship a `CorsProvider`
   (`provider_key = "auth_cors"`) whose only job is `publishes({...: "config/cors.py"})`,
   selected via `provider:publish -p auth_cors`. Gets close to `auth:cors` ergonomics
   without a framework change, at the cost of an extra provider class.

**Recommendation:** Option 1 or 3 (no framework change, keeps Phase 2 self-contained).
Option 1 is simplest; Option 3 gives cleaner per-asset selection. Confirm with PM which
publish ergonomics are acceptable and whether the framework dependency should be an
optional extra.

## Sources reviewed

- `fastapi_startkit/src/fastapi_startkit/console/publish_command.py` — the command
- `fastapi_startkit/src/fastapi_startkit/support/providers/provider.py` — `publishes()`
- `fastapi_startkit/src/fastapi_startkit/application.py` — `published_resources`, provider registration
- `fastapi_startkit/src/fastapi_startkit/foundation/app_provider.py` — command registration
- `fastapi_startkit/src/fastapi_startkit/vite/providers/provider.py`, `logging/providers/log_provider.py` — real `publishes()` usage
- `fastapi_startkit/src/fastapi_startkit/configuration/Configuration.py` — `merge_with`
- `docs/roadmap-auth.md` — the Phase 2 assumptions being validated
