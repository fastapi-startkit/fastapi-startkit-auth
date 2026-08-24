# Vite integration config, published from the framework's ViteProvider
# (uv run artisan provider:publish -p vite). Values are read by the config
# loader as plain module attributes — keep this file import-free.
#
# Paths are resolved relative to the working directory, so run the app from
# the example root (example/sessions).

public_path = "public"
build_directory = "build"
hot_file = "hot"
manifest_filename = "manifest.json"
asset_url = ""
static_url = "/build"
mount_static = True
template = True
templates_directory = "resources/templates"
