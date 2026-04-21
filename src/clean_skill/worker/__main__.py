"""Allow ``python -m clean_skill.worker`` to launch the worker."""

from __future__ import annotations

from .entrypoint import main

if __name__ == "__main__":
    main()
