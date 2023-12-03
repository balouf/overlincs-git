# History

## 0.1.0 (2023-12-03): First release

- CLI renamed from slatex to olincs.
- Fix compatibility with overleaf v4:
  - Docs pull update: change ref tag from "_id" (now unavailable) to "fullname".
  - Docs pull update: add offset to time to adjust nsync discrepancies.
  - Push: update upload POST command.
- Remove the "no untracked file" requirements as most users don't gitignore the latex produced files.
- Set `community` (v4) as the default authentication method.
- First release on PyPI.
