<a id="contribuer-à-noisefence"></a>
# Contribute to NoiseFence

NoiseFence is developed under GPL-3.0-only. Contributions to the project are proposed under this same license, keeping the records of third-party components.

Create a branch from `main` and propose a pull request describing the problem, the behaviour obtained and the checks performed. For a SMTP, persistence or authorization change, add a targeted regression test. Never include real messages, private addresses, SQLite databases, corpus, production keys or server configurations in a contribution.

```sh
python3 scripts/version.py --check
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo clippy --locked --all-targets --features semantic -- -D warnings
cargo test --locked --features semantic
python3 -m unittest discover -s tests_python -v
cd web
npm ci
npm test
npx tsc --noEmit
npm run lint
npm run build
```

Tests use reserved addresses and loopback sockets. `tests/fixtures/public-test-key.txt` is a public test key. Download the Apache corpus separately; training data and private exports are not part of the repository. See [versioning](docs/releasing.md) for releases.

CI installs `research/requirements.txt` for Python training tests and executes concurrent systemd, OCR and SMTP tests on Linux. Documentation contributions do not need to add artificial tests.
