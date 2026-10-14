# MedChain local research prototype

This research rebuild is based on [anasAlsalol/MedChainPure](https://github.com/anasAlsalol/MedChainPure), baseline `95911f7563ac6f07cbefc08f6ad9cd6055c9ed68`. The upstream [Apache-2.0 LICENSE](LICENSE) is retained. The supported implementation is `src/`; legacy starter Add code is omitted from the clean export.

**Release candidate: final cloud experiment and scoped logging-fix review pending.** No performance results are asserted by this candidate. See [research status](docs/research-results.md) and [source provenance](docs/release-provenance.json).

Use Node **24.19.0**, o1js **exactly 2.2.0**, and the retained dependency lock:

```sh
npm ci
npm run build
npm run test:functional -- --runInBand
node build/src/benchmark.js --seed 20261014 --output work/benchmark-full
```

Functional tests use proofs disabled for contract logic and direct membership constraint evaluation. They are not cryptographic proof-generation evidence. Jest's experimental VM Modules warning is expected. The full benchmark always enables actual proofs and one o1js worker; run only one proving process at a time. It measures datasets of 100, 500 and 1,000 synthetic records with height-11 Merkle trees (verified capacity 1,024). `--smoke` is a separate nonreportable diagnostic protocol. `npm run test:real` and `npm run demo` are available but are not redundant steps in the final experiment.

The manual GitHub Actions workflow uses one standard Ubuntu 24.04 x64 job, a 90-minute timeout and a fixed non-cancelling concurrency group. It installs the lock, builds, runs functional tests, then executes the full benchmark. Actual Linux CPU/RAM/runtime/cache metadata and source/lock hashes are recorded by the runner. No repository secrets are required. A failed or interrupted run retains available public observations and is never presented as completed evidence. Uploads contain only explicitly allowlisted public JSON/CSV/proofs/verification keys and filtered log derivatives; private diagnostics and ciphertext are excluded. Action pins were verified against the official GitHub API on 2026-10-14; version tags are recorded in the workflow comments.

The supported flow validates synthetic medicine records, encrypts each record and an independently random 128-bit salt using AES-256-GCM (random 32-byte keys, fresh 12-byte nonces and 16-byte tags), checks SHA-256-addressed local storage, publishes replacement Merkle roots and proves encoded record membership against an independently read ledger root and caller ID. Local content hashes are not IPFS CIDs. Mina LocalBlockchain runs on the host, including a cloud runner; this is not Devnet.

The host validates schema, UTF-8, numeric and time semantics. The circuit proves membership of encoded values, not the truth of submitted medicine or identity claims. Public ID hashes may reveal guessable IDs. A trusted administrator controls root publication. The workflow serializes one registrar session; it is not a distributed multi-writer protocol or a proof of append-only history. Retrieval verifies content digest, authenticated decryption, record identity, commitment and current-root membership.

Keys and administrator credentials are fresh and held in memory only. Complete round trips before exit: stored ciphertext is not a recoverable vault. Rotation commits after ten successful checked encrypted writes; failed storage does not consume a version/count. Publication failure after checked storage can consume a write and leave an encrypted orphan while registered state stays unchanged. Old key versions remain within the process; rotation does not re-encrypt old files or revoke shared keys.

Never commit real `.env` files, credentials, keys, salts, witnesses or private diagnostics. Any future `PINATA_JWT` must be an environment secret only; this prototype does not implement or measure Pinata/IPFS. Protokit, Auro, ARCOS, public Mina integration, production custody/access control, and real patient data remain outside the measured scope. No paid service or public-chain transaction is needed.
