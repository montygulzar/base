"""Third-party module discovery via Python entry points.

Install a plugin package with a `base_osint.modules` entry point
pointing at a module whose import registers via `base.modules.register()`.
The registry entry adds itself; this file just drives the loading.

Example `pyproject.toml` in a plugin:

    [project.entry-points."base_osint.modules"]
    my_module = "my_pkg.my_module"
"""
from __future__ import annotations
import logging
import importlib

log = logging.getLogger("base.plugins")

try:
    from importlib.metadata import entry_points
    try:
        eps = entry_points(group="base_osint.modules")
    except TypeError:
        eps = entry_points().get("base_osint.modules", [])
    for ep in eps:
        try:
            importlib.import_module(ep.value if hasattr(ep, "value") else ep.module)
            log.info("loaded plugin module: %s", ep.name)
        except Exception as e:
            log.warning("plugin load failed: %s (%s)", ep.name, e)
except Exception as e:
    log.debug("entry-point discovery unavailable: %s", e)
