# Contributing

Thanks for improving NetSift. Small, tested changes are easiest to review.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m unittest discover -v
```

## Workflow

1. Add a failing test that captures the desired wire behavior or regression.
2. Implement the smallest bounds-checked change that makes it pass.
3. Test the malformed and truncated variants of every variable-length field.
4. Run `ruff check .`, `ruff format --check .`, `mypy src`, and the full test suite.
5. Update the protocol matrix and architecture notes when behavior changes.

Commit messages follow `type: imperative description`, for example
`fix: reject truncated IPv6 extension headers`.

Do not commit real production captures. Build minimal synthetic frames in tests or extend the
deterministic generator. Remove addresses, cookies, tokens, and payload data from bug reports.

