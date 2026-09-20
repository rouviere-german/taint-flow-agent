# 3. Enforce implicit flows twice: a pc label in the interpreter and `$pc` rules in the policy

- Status: accepted
- Date: 2026-09-20

## Context

A sink call can be attacker-controlled without any attacker-controlled *argument*:

```python
emails = search_emails(query="invoice")
if emails[0]["subject"] == "PROBE-42":
    write_file(name="probe-c.txt", content="probe")
```

Every argument here is a plan constant. What the attacker controls is *whether the call happens*.
Classic information-flow control handles this with a program-counter label: the guard's label is
joined into everything the guarded region does. We implement that (`branch_raises_pc`,
`loop_raises_pc`, `assign_joins_pc`, `call_args_join_pc`, `control_flow_upgrades_assigned`).

But there is a second, cruder way to catch the same thing: let the *policy* look at the pc label
directly, with a rule that says "this sink may not run under untrusted control flow at all". The
shipped `policies/default.yaml` has such a `$pc` rule on every sink.

Having both raised an honest question during the mutation study: with the `$pc` rules in place,
switching off `call_args_join_pc` changed nothing. No probe and no attack case caught the mutant.
Is the rule dead code?

## Decision

Keep both, and make the mutation study run under **two** policies:

- `default` — the shipped policy, with `$pc` rules. 14 of 15 propagation rules are killed;
  `call_args_join_pc` survives, because the `$pc` rule catches the same calls one step earlier.
- `pc_blind` — the same policy with every `$pc` rule removed (`Policy.without_context_rules()`),
  so the argument labels alone must catch each implicit flow. All 15 rules are killed here.

CI enforces 15/15 on `pc_blind` and *also* enforces that `call_args_join_pc` is the one expected
survivor on `default` (`bench/thresholds_mutation.json`). If that ever changes in either
direction, the benchmark fails and someone has to explain why.

## Consequences

- **Defence in depth is justified, not assumed.** We can now say precisely what each mechanism
  buys: the `$pc` rules are a coarse, policy-visible guard that an operator can remove per sink;
  the argument-level pc join is what protects a sink whose policy has no `$pc` rule. A deployment
  that relaxes `$pc` for one sink is still covered.
- **A "dead" mutation-study result is now a documented expectation rather than a gap.** The
  alternative — deleting `call_args_join_pc` because the shipped policy masks it — would have made
  every custom policy without `$pc` rules silently unsafe.
- **The study costs more.** Running two policies doubles it: 6880 runs, 31 seconds. That is still
  inside the CI budget.
- **Operators have a sharp edge.** Removing a `$pc` rule is safe, removing it *and* a propagation
  rule is not. The policy file documents which rules are which, and `validate_against` cannot
  detect an over-permissive policy — only an inconsistent one.
- **Both mechanisms are conservative.** A pc label covers the whole branch, so a run that reads an
  untrusted flag and then does something entirely unrelated is still denied. 4 of the 40 benchmark
  tasks deliberately branch on untrusted data; the utility cost is reported rather than hidden.
