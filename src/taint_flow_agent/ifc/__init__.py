"""Information-flow control primitives: the label lattice, labeled values and trusted text.

The lattice is the product of three lattices (integrity, confidentiality readers, provenance
sources). ``join`` is the least upper bound: the result is at least as restrictive as every input.
This is the construction described by Debenedetti et al., "Defeating Prompt Injections by Design"
(CaMeL, 2025), which itself builds on classic information-flow labels (Denning, 1976; Myers and
Liskov's decentralized label model, 1997). The code here is an original implementation.
"""
