"""Response actions: strict validation, human approval, dry-run by default."""
import ipaddress
import json
import re
import urllib.request

ALLOWED_ACTIONS = {
    "block_ip", "disable_account", "isolate_host",
    "open_ticket", "notify_oncall", "sinkhole_domain",
}
HIGH_IMPACT_ACTIONS = {"isolate_host", "disable_account"}
NOTIFY_ACTIONS = {"open_ticket", "notify_oncall"}

HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
FREE_TEXT_PATTERN = re.compile(r"^[^\r\n\x00-\x1f]{1,200}$")


def is_safe_ip(text):
    """True for a unicast IP address; special-purpose and non-routable ranges are refused."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
    )


def validate_action(action, protected_targets=()):
    """Return (True, cleaned_action) or (False, reason). Never trust model output."""
    if not isinstance(action, dict):
        return False, "action is not an object"
    action_type = action.get("type")
    target = action.get("target")
    reason_text = action.get("reason", "")
    if action_type not in ALLOWED_ACTIONS:
        return False, f"action type not allowed: {str(action_type)[:40]}"
    if not isinstance(target, str) or not target.strip():
        return False, "target missing"
    target = target.strip()
    if target in protected_targets:
        return False, "target is protected"

    if action_type == "block_ip" and not is_safe_ip(target):
        return False, "block_ip target is not a valid public or private unicast IP"
    if action_type == "isolate_host" and not (is_safe_ip(target) or HOSTNAME_PATTERN.match(target)):
        return False, "isolate_host target is not a valid IP or hostname"
    if action_type == "sinkhole_domain" and not (HOSTNAME_PATTERN.match(target) and "." in target):
        return False, "sinkhole_domain target is not a valid domain"
    if action_type == "disable_account" and not USERNAME_PATTERN.match(target):
        return False, "disable_account target is not a valid username"
    if action_type in NOTIFY_ACTIONS and not FREE_TEXT_PATTERN.match(target):
        return False, "target contains invalid characters or is too long"

    cleaned = {
        "type": action_type,
        "target": target,
        "reason": str(reason_text)[:300],
        "high_impact": action_type in HIGH_IMPACT_ACTIONS,
    }
    return True, cleaned


def execute_action(action, dry_run=True, slack_webhook_url=None, protected_targets=()):
    """Run an already human-approved action. Only Slack notifications are really implemented."""
    is_valid, cleaned = validate_action(action, protected_targets)
    if not is_valid:
        return {"status": "rejected", "message": cleaned}
    summary = f"{cleaned['type']} {cleaned['target']} - {cleaned['reason']}"
    if dry_run:
        return {"status": "dry_run", "message": "Would execute: " + summary}
    if cleaned["type"] in NOTIFY_ACTIONS and slack_webhook_url:
        if not slack_webhook_url.startswith("https://"):
            return {"status": "error", "message": "webhook must use https"}
        body = json.dumps({"text": "NetSentinel approved action: " + summary}).encode("utf-8")
        request = urllib.request.Request(
            slack_webhook_url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return {"status": "sent", "message": f"Slack responded {response.status}"}
    return {"status": "not_implemented", "message": "No integration for this action type (no firewall or IAM connector)."}
