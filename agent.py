"""
agent.py — ConfigGuard's ReAct loop using Groq API.
Combines live config retrieval (Netmiko) with RAG policy lookup.
"""

import json
import os
from openai import OpenAI
from schemas import PullConfigInput, RetrievePolicyInput, ProposeComplianceFixInput
from tools import pull_running_config, retrieve_policy_tool, propose_compliance_fix
from policy_store import build_index

MAX_ITERATIONS = 8
MODEL = "llama-3.3-70b-versatile"

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "pull_running_config",
            "description": "Pull the live running-config from the network device, optionally filtered by section keyword.",
            "parameters": PullConfigInput.model_json_schema(),
        },
    },
    {
        "type": "function",
        "function": {
            "name": "retrieve_policy",
            "description": "Retrieve relevant company network security policy clauses for a given topic.",
            "parameters": RetrievePolicyInput.model_json_schema(),
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_compliance_fix",
            "description": "Record a policy-cited compliance finding and proposed fix for human review. Does NOT change the device.",
            "parameters": ProposeComplianceFixInput.model_json_schema(),
        },
    },
]

SYSTEM_PROMPT = """You are ConfigGuard, a network configuration compliance agent.
Pull the device's running configuration, retrieve the relevant company security
policy for the area you're checking, compare the live config against that policy,
and if you find a violation, call propose_compliance_fix with the exact policy
clause you're citing. Never claim to have applied a fix yourself."""


def _make_client():
    return OpenAI(
        api_key=os.environ.get("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )


def run_agent(user_goal: str, client=None, policy_index=None):
    client = client or _make_client()
    policy_index = policy_index or build_index()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_goal},
    ]

    tool_impl = {
        "pull_running_config": (pull_running_config, PullConfigInput),
        "retrieve_policy": (lambda p: retrieve_policy_tool(p, policy_index), RetrievePolicyInput),
        "propose_compliance_fix": (propose_compliance_fix, ProposeComplianceFixInput),
    }

    for _ in range(MAX_ITERATIONS):
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOL_SPECS,
        )
        message = response.choices[0].message
        messages.append(message.model_dump(exclude_none=True) if hasattr(message, "model_dump") else message)

        if not getattr(message, "tool_calls", None):
            return message.content

        for call in message.tool_calls:
            fn, schema_cls = tool_impl[call.function.name]
            try:
                args = json.loads(call.function.arguments)
                validated = schema_cls(**args)
                result = fn(validated)
            except Exception as e:
                result = f"TOOL ERROR: {e}"
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": str(result),
            })

    return "Max iterations reached without a final compliance verdict."


if __name__ == "__main__":
    goal = "Check this device's SSH access configuration for policy compliance and flag any violations."
    print(run_agent(goal))
