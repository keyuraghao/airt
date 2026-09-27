"""Entry point of the PyInstaller bundle.

Applies the per-user application directory defaults (data, logs, SQLite file, generated secret key
and admin token in aisrf.env) and then hands over to the regular typer CLI, so ``aisrf serve``,
``aisrf desktop``, ``aisrf init-db`` and every other command behave like the pip install, except
that state lives under the app directory instead of the current working directory.
"""

from __future__ import annotations

import multiprocessing
import sys


def main() -> None:
    multiprocessing.freeze_support()
    from aisrf.desktop import configure_environment

    configure_environment()
    from aisrf.cli import app

    app()


if __name__ == "__main__":
    sys.exit(main())
