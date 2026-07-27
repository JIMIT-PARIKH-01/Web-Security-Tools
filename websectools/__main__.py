"""Entry point:  python -m websectools <headers|csp|clickjack|disclosure|audit> ..."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
