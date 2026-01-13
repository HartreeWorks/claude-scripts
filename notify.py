#!/usr/bin/env python3
import json
import os
import sys
import subprocess
from typing import Any, List, Dict


def expand_path(path: str) -> str:
    """Expand leading ~ in paths if present."""
    if not path:
        return ""
    if path.startswith("~"):
        return os.path.expanduser(path)
    return path

def flatten_content(content: Any) -> str:
    """
    Flatten Claude-style message content into a string.

    * If it's a string, return as-is.
    * If it's a list, join:
      * objects: .text or .content
      * strings: as-is
    * Otherwise, return empty string.
    """
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, dict):
                v = item.get("text") or item.get("content") or ""
                if isinstance(v, str):
                    parts.append(v)
            elif isinstance(item, str):
                parts.append(item)
        return " ".join(parts)

    return ""


def load_transcript(path: str) -> List[Dict[str, Any]]:
    """
    Load the transcript file.

    Tries:
    * JSON array
    * JSON Lines (one JSON object per line)
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError:
        return []

    # Try as a single JSON value
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        # If it's a single object, wrap in a list
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Fallback: JSON Lines
    messages: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            messages.append(obj)
    return messages


def get_last_turn_text(messages: List[Dict[str, Any]]) -> str:
    """
    Last conversation turn (user or assistant), following the jq logic.
    """
    filtered: List[Any] = []
    for m in messages:
        if m.get("type") in ("user", "assistant"):
            filtered.append(m.get("message", ""))

    if not filtered:
        return ""

    msg = filtered[-1]
    if not isinstance(msg, dict):
        return ""

    role = msg.get("role")
    if role == "user":
        content = msg.get("content") or ""
    else:
        # assistant: content defaults to [] in the jq script
        content = msg.get("content") or []

    return flatten_content(content)


def get_last_user_text(messages: List[Dict[str, Any]]) -> str:
    """
    Last *user* message, following the jq logic.
    """
    filtered: List[Any] = []
    for m in messages:
        if m.get("type") == "user":
            filtered.append(m.get("message", ""))

    if not filtered:
        return ""

    msg = filtered[-1]
    if not isinstance(msg, dict):
        return ""

    content = msg.get("content") or ""
    return flatten_content(content)


def get_pending_question(messages: List[Dict[str, Any]]) -> str:
    """
    Look for an AskUserQuestion tool call in the last assistant message
    and extract the question text.
    """
    # Find the last assistant message
    for m in reversed(messages):
        if m.get("type") != "assistant":
            continue

        msg = m.get("message", {})
        if not isinstance(msg, dict):
            continue

        content = msg.get("content", [])
        if not isinstance(content, list):
            continue

        # Look for AskUserQuestion tool use
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "tool_use":
                continue
            if item.get("name") != "AskUserQuestion":
                continue

            # Found it - extract the question
            tool_input = item.get("input", {})
            questions = tool_input.get("questions", [])
            if questions and isinstance(questions, list):
                first_q = questions[0]
                if isinstance(first_q, dict):
                    return first_q.get("question", "")

        # Only check the last assistant message
        break

    return ""


def main() -> None:
    # First argument = hook event type ("Notification", "Stop", etc.)
    event_type = sys.argv[1] if len(sys.argv) > 1 else "Notification"

    # Read hook JSON input from stdin
    try:
        input_json_str = sys.stdin.read()
        hook = json.loads(input_json_str) if input_json_str.strip() else {}
    except json.JSONDecodeError:
        hook = {}

    # Extract cwd, transcript_path, notification_type, and message from hook input
    cwd = hook.get("cwd", "") or ""
    transcript_path_raw = hook.get("transcript_path", "") or ""
    notification_type = hook.get("notification_type", "") or ""
    hook_message = hook.get("message", "") or ""

    # Do nothing if notification type is "idle_prompt"
    #
    # This fires 60 seconds after the previous notification—it's annoying
    # to get a "follow-up" notification
    if notification_type == "idle_prompt":
        sys.exit(0)

    transcript_path = expand_path(transcript_path_raw)

    # Direct parent directory name from cwd
    if cwd:
        dir_name = os.path.basename(cwd)
        if not dir_name:
            dir_name = "(no-cwd)"
    else:
        dir_name = "(no-cwd)"

    # Determine title and content based on notification type
    if notification_type == "permission_prompt":
        # For permission prompts, try to extract the actual question from transcript
        question_text = ""
        if transcript_path and os.path.isfile(transcript_path):
            messages = load_transcript(transcript_path)
            question_text = get_pending_question(messages)

        if question_text:
            # We found an AskUserQuestion - show the question
            title = f"Claude is asking ({dir_name})"
            subtitle = question_text
            preview = ""
        else:
            # Generic permission prompt (not a question)
            title = f"Claude needs permission ({dir_name})"
            subtitle = hook_message if hook_message else "Permission requested"
            preview = ""
    elif hook_message:
        # Use the hook message directly (e.g., for questions, prompts)
        title = f"Claude ({dir_name})"
        subtitle = hook_message
        preview = ""
    else:
        # Fallback to transcript-based content
        title = f"Claude ({dir_name})"
        preview = "(no transcript entries yet)"
        subtitle = "(no recent user message)"

        if transcript_path and os.path.isfile(transcript_path):
            messages = load_transcript(transcript_path)

            last_turn_text = get_last_turn_text(messages)
            last_user_text = get_last_user_text(messages)

            if last_turn_text:
                preview = "Code: " + last_turn_text

            if last_user_text:
                subtitle = f"You: {last_user_text}"

    # Build terminal-notifier command
    cmd = [
        "terminal-notifier",
        "-title",
        title,
        "-subtitle",
        subtitle,
        "-sound",
        "Glass",
    ]

    # Only add -message if we have content to show
    if preview:
        cmd.extend(["-message", preview])

    subprocess.run(cmd, check=False)


if __name__ == "__main__":
    main()
