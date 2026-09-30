"""Input hygiene for untrusted log text. Logs are attacker-controlled data, never instructions."""
import re

MAX_LOG_CHARS = 8000

# Heuristic patterns. These only raise a flag for the analyst; they are not the main defense.
# The main defenses are: delimiting logs as data, validating model output, and the action allowlist.
INJECTION_PATTERNS = {
    "ignore_instructions": re.compile(r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)", re.I),
    "disregard": re.compile(r"disregard\s+(the\s+|all\s+|any\s+)?(playbook|instructions|rules|system|previous)", re.I),
    "role_override": re.compile(r"you\s+are\s+now\b|act\s+as\s+(an?\s+)?(admin|root|system)|admin\s+mode", re.I),
    "addressing_ai": re.compile(r"(note|message|instruction)s?\s+(to|for)\s+(the\s+)?(ai|assistant|model|llm|analyst\s+bot)", re.I),
    "fake_role_tag": re.compile(r"</?\s*(system|assistant|logs|playbook_context)\s*>|^\s*(system|assistant)\s*:", re.I | re.M),
    "force_output": re.compile(r"respond\s+only\s+with|output\s+only|classify\s+(this\s+)?as\s+(low|benign|safe)", re.I),
}

CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def detect_injection(text):
    """Return the names of injection patterns found in text (empty list if none)."""
    return [name for name, pattern in INJECTION_PATTERNS.items() if pattern.search(text)]


def sanitize_logs(text, max_chars=MAX_LOG_CHARS):
    """Remove control characters, neutralize our own delimiter tags, and cap the length."""
    cleaned = CONTROL_CHARACTERS.sub("", text)
    cleaned = re.sub(r"</?\s*(logs|playbook_context)\s*>", "[tag removed]", cleaned, flags=re.I)
    return cleaned[:max_chars]
