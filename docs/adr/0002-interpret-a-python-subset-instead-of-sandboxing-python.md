# 2. Interpret a Python subset instead of sandboxing Python

- Status: accepted
- Date: 2026-09-20

## Context

The planner has to emit *something* the runtime can execute while tracking labels through it.
Three options were on the table.

1. **A tool-call list.** The planner emits a flat sequence of `(tool, arguments)` pairs. Simple to
   label, but it cannot express "for each unpaid invoice, look up the payee", which a large share
   of realistic assistant tasks need. Every such task would have to round-trip through the planner
   after each tool result — and the results are untrusted, so that round trip is exactly the thing
   this architecture exists to avoid.
2. **Real Python in a sandbox.** Run the plan with `exec` under an audit hook, a restricted
   `__builtins__`, or a subprocess with seccomp. This is a well-known losing position: CPython's
   object graph gives dozens of routes from any object back to `__class__`, `__globals__`,
   `__subclasses__` and the import machinery, and the attack surface grows with every CPython
   release. It also gives no place to hang labels: `a + b` on two `str` objects has no hook.
3. **Parse a subset and interpret it ourselves.** Write the plan in Python syntax (so an LLM writes
   it fluently and a human reads it), parse it with `ast`, refuse anything outside an allowlist,
   and evaluate the tree with our own evaluator over `Labeled[T]` values.

## Decision

Option 3. `parse_plan` walks every node of the tree and rejects any node *type* that is not on
`ALLOWED_NODE_TYPES`, rather than blocking a list of dangerous constructs. Depth, node count,
statement count, string length, call arity and source size are bounded at parse time; steps, loop
iterations, collection size, value size and wall-clock time at run time. The interpreter never
calls `eval`, `exec` or `getattr`; it pattern-matches on node types it knows and raises on anything
else. `# type:` comments are parsed rather than discarded so they cannot carry metadata the checker
never sees, and tool names may appear only as the callee of a call — never as a value.

The language is deliberately small: assignments to plain names, registered tool calls, `if`/`else`,
`for` over bounded collections, string/number/bool/None constants, lists, string-keyed dicts,
indexing, single comparisons, `and`/`or`/`not`, unary minus, `+`/`-`/`*`, f-strings without
conversions or format specs, and 22 pure builtins. There is no attribute access at all.

## Consequences

- **Deny by default survives Python upgrades.** When CPython adds syntax, `ast.parse` produces a
  node type that is not on the allowlist, and the plan is refused until someone adds it on purpose.
  A blocklist would silently admit it.
- **Every operation has a place to join labels.** Because we evaluate the tree, `a + b`,
  `x["k"]`, `f"{v}"` and a loop body are all our code, and each one joins the labels it should.
  This is what makes fine-grained, per-element labelling possible at all.
- **Plans cannot do arithmetic the language lacks.** No division, no exponentiation, no bitwise
  operators, no regular expressions, no sorting by key. Tasks needing them must push the work into
  a tool, which is where a policy can see it. That is a real expressiveness cost.
- **We own the evaluator's bugs.** A wrong comparison or a missing overflow check is ours, not
  CPython's. The mitigation is that the evaluator is ~900 lines with 97% branch coverage, property
  tests over its label behaviour, and a fuzzer over the parser.
- **The planner must be taught the subset.** The system prompt enumerates the grammar and the
  builtins. A plan that strays is rejected with a structural reason, which is a recoverable error,
  not a security failure.
