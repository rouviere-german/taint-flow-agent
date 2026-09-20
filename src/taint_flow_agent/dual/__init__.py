"""Dual-LLM wiring: the privileged planner, the quarantined reader and the agent around them.

The planner sees only :class:`~taint_flow_agent.ifc.trusted.TrustedText` and writes a plan; the
reader sees untrusted data but has no tools and can only return schema-validated JSON; the
interpreter and the sink policy sit between them and every side effect.
"""
