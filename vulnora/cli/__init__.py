"""
Vulnora AI Command Line Interface (CLI).
"""

def __getattr__(name):
    if name == "app":
        from .main import app
        return app
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

__all__ = ["app"]

