from __future__ import annotations

import pytest

from taint_flow_agent.ifc.trusted import PromptBuilder, TrustedText
from taint_flow_agent.ifc.values import Labeled

pytestmark = pytest.mark.unit


def test_prompt_builder_accepts_trusted_text_only() -> None:
    builder = PromptBuilder()
    builder.add(TrustedText.system("rules")).add(TrustedText.from_signature("- tool()"))
    builder.add(TrustedText.from_user("do it"))
    with pytest.raises(TypeError, match="TrustedText only"):
        builder.add("an e-mail body")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="TrustedText only"):
        builder.add(Labeled("data"))  # type: ignore[arg-type]
    assert [part.origin for part in builder.parts] == ["system", "tool_signature", "user_request"]
    assert builder.render("user_request") == "do it"
    assert builder.render() == "rules\n\n- tool()\n\ndo it"


def test_trusted_text_validation() -> None:
    with pytest.raises(TypeError):
        TrustedText(b"bytes", "user_request")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="origin"):
        TrustedText("x", "tool_result")  # type: ignore[arg-type]
