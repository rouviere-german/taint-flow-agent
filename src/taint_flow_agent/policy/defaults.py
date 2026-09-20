"""The default sink policy, embedded so benchmarks and tests do not depend on the working directory.

``policies/default.yaml`` at the repository root is the deployable copy operators edit; a test
checks that it is byte-identical to :data:`DEFAULT_POLICY_YAML`.
"""

from __future__ import annotations

from typing import Final

from taint_flow_agent.policy.rules import Policy, load_policy_text

__all__ = ["DEFAULT_POLICY_YAML", "default_policy"]

DEFAULT_POLICY_YAML: Final = """\
# Sink policy for the workspace tools. Loaded with yaml.safe_load and validated at startup;
# /readyz fails if any sink lacks an entry or a rule names an unknown argument.
#
# Semantics (see src/taint_flow_agent/policy/rules.py):
#   integrity: user            the value was written by the planner from the user's request
#   member_of: contacts        the value is in a trusted collection of the workspace
#   argument_integrity         another argument of the same call has that integrity
#   readers_include: to        the data may be read by every principal named in `to`
#   $pc / pc_integrity         the call is not guarded by a branch on less trusted data
#   on_fail: deny              stop the run, record the provenance path
#   on_fail: declassify        hold the call for a human who sees the provenance graph
version: 1
default: deny
sinks:
  send_email:
    to:
      require:
        any_of:
          - integrity: user
          - member_of: contacts
      on_fail: deny
    subject:
      require:
        any_of:
          - argument_integrity: {argument: to, level: user}
          - readers_include: to
      on_fail: declassify
    body:
      require:
        any_of:
          - argument_integrity: {argument: to, level: user}
          - readers_include: to
      on_fail: declassify
    $pc:
      require: {pc_integrity: trusted_tool}
      on_fail: declassify

  pay_invoice:
    recipient:
      require:
        any_of:
          - integrity: user
          - all_of:
              - member_of: payees
              - integrity: trusted_tool
      on_fail: declassify
    amount:
      require: {integrity: user}
      on_fail: declassify
    reference:
      require: {max_length: 200}
      on_fail: deny
    $pc:
      require: {pc_integrity: trusted_tool}
      on_fail: declassify

  create_event:
    attendees:
      require:
        any_of:
          - integrity: user
          - member_of: contacts
      on_fail: deny
    date:
      require: {matches: "^\\\\d{4}-\\\\d{2}-\\\\d{2}$"}
      on_fail: deny
    $pc:
      require: {pc_integrity: trusted_tool}
      on_fail: declassify

  add_contact:
    email:
      require: {integrity: user}
      on_fail: declassify
    $pc:
      require: {pc_integrity: trusted_tool}
      on_fail: declassify

  write_file:
    name:
      require:
        all_of:
          - integrity: user
          - matches: "^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$"
      on_fail: deny
    $pc:
      require: {pc_integrity: trusted_tool}
      on_fail: declassify
"""


def default_policy() -> Policy:
    """The embedded default policy, freshly compiled."""
    return load_policy_text(DEFAULT_POLICY_YAML, source="default.yaml")
