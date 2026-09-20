"""Sink policies as code, declassification and the guarded tool table.

A *sink* is a tool with a side effect (send, write, pay ...). Every sink must have a policy entry
(deny by default); the entry names, per argument, a predicate over the argument's label and
plain value, and what to do when it fails: deny, or escalate to a human who sees the provenance
graph and decides once for that exact call.
"""
