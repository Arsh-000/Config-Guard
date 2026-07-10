"""
tools.py — ConfigGuard's tools. Device credentials read from environment
variables. propose_compliance_fix NEVER touches the device.
"""

import os
from netmiko import ConnectHandler
from schemas import PullConfigInput, RetrievePolicyInput, ProposeComplianceFixInput
from policy_store import retrieve_policy
from audit_log import log_event


def _connect():
    return ConnectHandler(
        device_type=os.environ.get("NET_DEVICE_TYPE", "cisco_xe"),
        host=os.environ.get("NET_DEVICE_HOST", "devnetsandboxiosxec8k.cisco.com"),
        username=os.environ.get("NET_DEVICE_USER", "jokearns"),
        password=os.environ.get("NET_DEVICE_PASS", ""),
        port=int(os.environ.get("NET_DEVICE_PORT", "22")),
    )


def pull_running_config(payload: PullConfigInput) -> str:
    conn = _connect()
    try:
        cmd = "show running-config"
        if payload.section_keyword:
            cmd += f" | section {payload.section_keyword}"
        output = conn.send_command(cmd)
        log_event("pull_running_config", {"section_keyword": payload.section_keyword}, output[:300])
        return output or "No config returned for that section."
    finally:
        conn.disconnect()


def retrieve_policy_tool(payload: RetrievePolicyInput, index) -> str:
    results = retrieve_policy(payload.query, index, k=3)
    log_event("retrieve_policy", {"query": payload.query}, str(results)[:300])
    if not results:
        return "No relevant policy found for that query."
    return "\n".join(f"- {r}" for r in results)


def propose_compliance_fix(payload: ProposeComplianceFixInput) -> str:
    record = payload.model_dump()
    log_event("propose_compliance_fix", record, "AWAITING_HUMAN_APPROVAL")
    lines = [
        "=== COMPLIANCE FINDING (not applied — requires human approval) ===",
        f"Finding: {payload.finding}",
        f"Policy citation: {payload.policy_citation}",
        f"Severity: {payload.severity}",
        "Proposed commands:",
    ] + [f"  {c}" for c in payload.proposed_commands]
    return "\n".join(lines)
