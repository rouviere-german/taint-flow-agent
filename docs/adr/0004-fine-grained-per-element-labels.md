# 4. Label containers per element, and accept that the order of a list can leak

- Status: accepted
- Date: 2026-09-20

## Context

`read_inbox()` returns a list of e-mails. Each one has a different sender, so each one should have
a different label: one from a contact, one from a stranger, one from the attacker. Two designs were
possible.

**Coarse (one label per value).** The whole list carries the join of everything in it. Simple, and
trivially sound: nothing can be selected out of it that is less restrictive than the whole.
But it is useless in practice — a single attacker e-mail in the inbox makes *every* subsequent
operation untrusted, so a plan that reads the inbox can never reach a protected sink again. Every
realistic task would be denied.

**Fine-grained (a label per element, plus one for the container).** `Labeled[T]` where `T` may be a
tuple or mapping of further `Labeled` values. Selecting `emails[0]` yields that element's label
joined with the container's own label and the key's. `effective_label` joins everything inside when
a whole value is handed to a tool or to the reader. This is the CaMeL approach and what makes the
benchmark's 100% benign utility possible.

The awkward consequence is that "the derived label dominates the join of its inputs" — the property
one wants to state about an IFC system — is *false* for selection, and saying otherwise would be
dishonest. `[s1, s2][0]` does not carry `s2`'s label, and it should not.

## Decision

Fine-grained labels, with the invariant stated in two parts instead of one:

1. For every expression where all named inputs flow into the single result — arithmetic, string
   concatenation, f-strings, comparisons, builtins — the result's label dominates the join of all
   of them. Tested with hypothesis over 17 expression shapes and random labels.
2. For selection (`xs[i]`, `d["k"]`, `sorted(xs)[i]`) the result carries the selected element's
   label joined with the container's own label and the key's, and the *container's* effective label
   still dominates every element. Tested separately, including a concrete case asserting that a
   sibling's label does **not** leak in.

The container's own label is the structural information — how many elements there are, and what
the tool call that produced it was. That is why `index_joins_container` exists as a separate
propagation rule, and the mutation study kills it with a probe that selects a constant from a dict
using an untrusted key.

## Consequences

- **Utility is possible at all.** Benign utility is 100% across all 40 tasks. Under the coarse
  design it would be near zero for any task that touches the inbox.
- **The property tests are harder to write and honest about what they check.** A single sweeping
  "monotonicity" assertion would have been wrong; two narrower ones are right.
- **Selection by an untrusted index still taints.** The key's label is joined, so
  `table[untrusted_key]` yields an untrusted value even though every value in `table` is a plan
  constant. This is what `P-index` in the mutation study exercises.
- **Element *ordering* is a side channel we do not close.** A list's structure (length, order) is
  covered only by the container's label. A plan that picks `emails[0]` gets whichever e-mail the
  tool put first, and an attacker who can influence ordering influences which element is chosen
  without that showing up as a label difference on the element itself. In this workspace, ordering
  is deterministic and attacker-influenceable only by sending an e-mail, which is already modelled.
  Closing it properly would mean labelling indices, which collapses back toward the coarse design.
- **`effective_label` is recursive and therefore not free.** It walks the value on every operation
  that needs the whole-value label. Measured at ~3 us per join and ~11 ms for a complete task run,
  it is not the bottleneck (the `fsync`-per-entry audit log is).
