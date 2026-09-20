# Security policy

## Supported versions

Only the latest commit on `main` is supported. This is a portfolio project, not a product with
release branches.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability
reporting ("Report a vulnerability" under the repository's Security tab). Include:

- the affected commit and component;
- steps to reproduce, ideally as a failing test or a plan that reaches a sink it should not;
- the impact you expect.

You can expect an acknowledgement within 7 days and a fix or a written assessment within 30 days.
Credit is given in the fix commit unless you ask otherwise.

## What this system guarantees

These are the properties the design is meant to provide, each with the evidence that checks it.
Numbers come from `uv run python tasks.py bench` on the machine named in the README.

1. **The privileged planner never reads untrusted content.** The prompt builder accepts
   `TrustedText` only — the user's request, developer-written tool signatures and a fixed system
   prompt — and rejects a `str`, a `Labeled` value or anything else at runtime as well as under
   mypy. Canary tests run all 40 tasks through every carrier and mutation with unique markers
   planted in every untrusted field and assert that no planner request contains one
   (`tests/integration/test_planner_isolation.py`).
2. **A plan cannot leave the interpreter.** Plans are parsed against an allowlist of `ast` node
   *types*, so unknown syntax is refused rather than overlooked. There is no attribute access, no
   `eval`, no `exec` and no import. Depth, size, statement count, step count, loop iterations,
   collection size, value size and wall-clock time are all bounded.
3. **Every value carries its provenance, and every sink call is checked against it.** Labels join
   on every operation, including through branches and loops (implicit flows). A sink with no policy
   entry is denied. A denial records the provenance path of the argument it refused.
4. **A compromised quarantined reader cannot reach a protected sink without a human approving
   that exact call.** Measured over 200 attacked runs with a reader that obeys every injection and
   a careful reviewer: 0 successes; the same number for a single-LLM ReAct baseline is 73 of the 73
   runs that exposed it. The qualifier is load-bearing and is measured, not assumed: the same 200
   runs with a reviewer that rubber-stamps every declassification request give **6 successes**
   (three attacker payments, three attacker contacts). The architecture turns "attacker controls an
   action" into "attacker must obtain one specific human approval, with the provenance path shown";
   it does not remove the human.
5. **Every label-propagation rule is load-bearing.** Switching any one of the fifteen off lets a
   probe or attack case through under the pc-blind policy; CI fails if that stops being true.
6. **Declassification is a human decision bound to one call.** The approval covers the canonical
   hash of the exact call, is single use, and cannot be granted by the principal that requested it.
   The approver is shown the provenance subgraph — label summaries and structure, never values.
7. **Reports, errors, logs and metrics carry labels and structure, not data.** A denial names the
   sink, the argument and the rule; it does not echo the account number it refused.
8. **Actions are attributable.** Plans, per-statement label derivations, policy decisions and
   declassifications are appended to a hash-chained audit log that detects edits, deletions,
   reordering and (against an anchored head) truncation.

## What this system does *not* guarantee

Stated plainly, because a security claim without its limits is marketing.

1. **It does not defend against a malicious planner or a malicious user request.** The plan is the
   user's authority. If the privileged model is adversarial, or the request itself is, whatever it
   writes is authorised by definition. Limiting *authority* is a different mechanism from limiting
   *data influence*.
2. **Manipulation inside permitted free text is not prevented.** The policy deliberately lets an
   e-mail body carry untrusted content once the recipient is trusted. An attacker who gets text
   into a body a human will read is not stopped by an information-flow label.
3. **A plausible wrong value in an unprotected argument is undetectable.** With a compromised
   reader and a careful reviewer, 9 of 200 attacked runs completed with content the attacker chose
   but that every policy rule permitted — a different amount, a different summary. Labels say where
   a value came from, not whether it is true.
4. **The gate is only as good as the reviewer.** The rules that protect the highest-stakes
   arguments fail to `declassify`, not to `deny`, so the last step is a human decision. A reviewer
   who approves every request gives an attacker 6 successes in 200 attacked runs; a reviewer who
   denies every request gives zero and costs 55 points of benign utility. Both ends are measured
   and both are in the README table.
5. **Confidentiality is enforced at the gate, not by refusal.** `send_email.subject`/`.body`
   require the recipient to be in the data's reader set and fail to `declassify` when it is not, so
   a private record leaving its reader set always reaches a human first — but a human who approves
   it releases it. Across 240 runs, 19 verbatim leaks occurred with an approving reviewer and 0
   with a refusing one. The leak count is a lower bound: it matches verbatim fragments only, so a
   summarised or reformatted value is not counted even though its label says it is derived.
6. **Side channels are out of scope.** Timing, which error was raised, resource use, and the
   observable fact that a run was denied all leak something about untrusted data. The pc label
   covers implicit flows *inside* the interpreter, not what an outside observer learns.
7. **Availability under attack is traded away.** An injection planted in a tool's error text stops
   37 of 200 runs with `status=error`. The agent refuses to act rather than acting on injected
   content; that is the intended behaviour and it is a denial of service.
8. **Implicit-flow tracking is conservative and incomplete.** Raising the pc over a whole branch
   denies runs a perfect analysis would allow. Conversely, the mutation study shows each rule is
   *necessary*, not that the rule set is *sufficient*.
9. **List ordering is not labelled.** Selecting `emails[0]` picks whichever element the tool put
   first; influence over ordering does not show up as a label on the selected element
   (see `docs/adr/0004-fine-grained-per-element-labels.md`).
10. **Offline results measure the architecture, not planner quality.** The benchmark's scripted
   planner always writes the reference plan. Benign utility of 100% says nothing about how well a
   real model plans.
11. **Nothing here has been deployed against a real mail server, payment rail or file system.**
   Every tool is an in-memory simulation.

## How this repository is hardened

- Threats, controls and the tests that prove them: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- Every security claim is linked to evidence in [CLAIMS.md](CLAIMS.md).
- Design trade-offs are recorded in [docs/adr/](docs/adr/).
- CI runs ruff, mypy --strict, pytest with a coverage floor, bandit, semgrep (registry packs plus
  `.semgrep/rules.yml`, which bans `eval`/`exec` and unsafe YAML loading repo-wide), pip-audit,
  gitleaks, a trivy image scan, a syft CycloneDX SBOM, the 1440-run attack benchmark (uploaded as
  SARIF) and the propagation-rule mutation study.
- Secrets come only from the environment; only `.env.example` is committed. The tests, the demo
  and every benchmark run without an API key and without network access.
- The sink policy is data, loaded with `yaml.safe_load` and validated before the service reports
  ready. `policies/default.yaml` is pinned byte-for-byte to the copy embedded in the package.
