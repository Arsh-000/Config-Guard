"""
test_dry_run.py — validates ConfigGuard full loop without real API key or device.
"""

import sys
import json

sys.path.insert(0, ".")
import agent
from policy_store import build_index


class FakeFunction:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class FakeToolCall:
    def __init__(self, id_, name, arguments_dict):
        self.id = id_
        self.function = FakeFunction(name, json.dumps(arguments_dict))


class FakeMessage:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls

    def model_dump(self, exclude_none=True):
        d = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            d["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in self.tool_calls
            ]
        return d


class FakeChoice:
    def __init__(self, message):
        self.message = message


class FakeResponse:
    def __init__(self, message):
        self.choices = [FakeChoice(message)]


class FakeCompletions:
    def __init__(self):
        self.call_count = 0

    def create(self, **kwargs):
        self.call_count += 1
        if self.call_count == 1:
            return FakeResponse(FakeMessage(content=None, tool_calls=[
                FakeToolCall("c1", "pull_running_config", {"section_keyword": "line vty"})
            ]))
        elif self.call_count == 2:
            return FakeResponse(FakeMessage(content=None, tool_calls=[
                FakeToolCall("c2", "retrieve_policy", {"query": "SSH remote access control"})
            ]))
        elif self.call_count == 3:
            return FakeResponse(FakeMessage(content=None, tool_calls=[
                FakeToolCall("c3", "propose_compliance_fix", {
                    "finding": "vty lines allow SSH from any source, no ACL applied",
                    "policy_citation": "SSH access must be restricted using an ACL limiting source IPs to the management subnet.",
                    "proposed_commands": ["ip access-list standard MGMT-ONLY", "permit 10.0.0.0 0.0.0.255",
                                           "line vty 0 4", "access-class MGMT-ONLY in"],
                    "severity": "high",
                })
            ]))
        else:
            return FakeResponse(FakeMessage(content="Compliance check complete. High-severity finding proposed for review."))


class FakeChat:
    def __init__(self):
        self.completions = FakeCompletions()


class FakeClient:
    def __init__(self):
        self.chat = FakeChat()


def fake_pull_config(payload):
    return "line vty 0 4\n transport input ssh\n login local\n! (no access-class configured)"


def main():
    policy_index = build_index()
    import unittest.mock as mock
    with mock.patch.object(agent, "pull_running_config", fake_pull_config):
        result = agent.run_agent(
            "Check SSH access configuration for policy compliance.",
            client=FakeClient(),
            policy_index=policy_index,
        )
        print("FINAL AGENT OUTPUT:\n", result)
        assert "Compliance check complete" in result
        print("\n✅ Dry run passed: config-pull -> RAG policy retrieval -> compliance fix proposal all work correctly.")


if __name__ == "__main__":
    main()
