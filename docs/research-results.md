# Research results and evidence status

Stage 1 is a source/CI candidate. The final full cloud experiment has not run for this release, so final timing tables, cloud clean-install evidence, public run IDs, result archive and final source ZIP are pending. Previous local pilots and interrupted runs are excluded from this clean export. No local Windows timing is relabeled as Linux evidence.

The benchmark protocol is `reportable-v1`, seed 20261014, datasets 100/500/1000, one proving process and one o1js worker. Host phases use one warmup/five measured trials; AES/storage use five warmups/thirty measured trials; membership proving uses one warmup/five measured trials, with ten verifications per measured proof. Registry update proving is one feasibility observation per dataset, not a distribution. Compilation reuses an SDK filesystem cache and is explicitly cache affected; no cold-start claim is made. See clock boundaries in run metadata for preparation and storage exclusions.

The cloud workflow records raw observations/events, recomputed success-only summaries, failure/skip counts, runtime/hardware/cache metadata, exact source manifests and dependency lock hash, plus public proofs/verification keys. A failed proof or verification stops remaining heavy work without identical retries. Partial evidence is retained and labeled by its actual status. Functional tests are a distinct fast validation mode, not proof or timing evidence.

| Claim | Evidence required | Current release status |
| --- | --- | --- |
| Clean Linux dependency install/build | cloud stage exits and sanitized logs | Pending |
| Functional behavior on Linux | complete functional test exit/counts | Pending |
| Real proof feasibility | successful actual proofs, verifier outcomes, public artifacts | Pending full cloud run |
| Phase timings and counts | observations JSONL, metadata, summaries | Pending full cloud run |
| Source equivalence | per-file source/config/lock hash manifest | Prepared for review |
| Publication eligibility | broad source/workflow/export review and scoped fix verification | Broad review complete; I1 fix scoped review pending |

`scripts/collect-cloud-evidence.mjs` copies only known public benchmark filenames from UUID run directories and creates filtered readable log derivatives. It never copies raw logs, scratch, ciphertext, caches, environment files or private errors. The cloud artifact manifest links derivative hashes to original log hashes and records rejected files. Unfiltered raw logs remain runner-local and disappear with the job. A hard runner termination may prevent final collection/upload; available artifact absence is not success.

The optional real-proof pilot uses the same sanitized error categories as the benchmark and throws a new fixed-message error for Jest. Its new logs are under ignored `work/pilot-public`; historical evidence remains unchanged. A bounded injected-error regression checks JSONL, stdout, rethrown error properties and Jest formatting without generating a proof.

Stage 2 must audit the completed cloud evidence, compare executable source/lock manifests, link the actual public code SHA and run ID, then prepare final source/results/report packages. Documentation-only later SHAs must remain distinct from the measured SHA. This candidate is not Task 6 completion.
