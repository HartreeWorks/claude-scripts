# Claude Scripts

A collection of utility scripts for [Claude Code](https://claude.com/claude-code).

These scripts are used with Claude Code hooks to add safety checks, notifications, and other automation.

## Scripts

### bash-safety-hook.py

A PreToolUse hook that detects dangerous bash command patterns and asks for user confirmation before allowing execution.

**What it catches:**
- Remote code execution (piping curl/wget to bash)
- Catastrophic deletions (rm -rf /, rm -rf ~)
- Data exfiltration (sending sensitive files over network)
- Persistence mechanisms (crontab, launchd, shell profile modifications)
- Privilege escalation (chmod +s, setuid)
- System file modifications (writes to /etc/)

**Installation:**

1. Copy the script:
   ```bash
   curl -o ~/.claude/scripts/bash-safety-hook.py \
     https://raw.githubusercontent.com/HartreeWorks/claude-scripts/main/bash-safety-hook.py
   ```

2. Add to your `~/.claude/settings.json`:
   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/scripts/bash-safety-hook.py"
             }
           ]
         }
       ]
     }
   }
   ```

---

### notify.py

A notification hook that shows desktop notifications when Claude Code needs your attention (permission prompts, questions, task completion).

**Features:**
- Shows the project directory name in the notification title
- Extracts the actual question text from AskUserQuestion prompts
- Displays context from the conversation transcript
- Ignores idle_prompt notifications to reduce noise

**Prerequisites:**
- macOS with [terminal-notifier](https://github.com/julienXX/terminal-notifier) installed:
  ```bash
  brew install terminal-notifier
  ```

**Installation:**

1. Copy the script:
   ```bash
   curl -o ~/.claude/scripts/notify.py \
     https://raw.githubusercontent.com/HartreeWorks/claude-scripts/main/notify.py
   ```

2. Add to your `~/.claude/settings.json`:
   ```json
   {
     "hooks": {
       "Notification": [
         {
           "matcher": "",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/scripts/notify.py Notification"
             }
           ]
         }
       ],
       "Stop": [
         {
           "matcher": "",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/scripts/notify.py Stop"
             }
           ]
         }
       ]
     }
   }
   ```

---

## About

Created by [Peter Hartree](https://x.com/peterhartree). For updates, follow [AI Wow](https://wow.pjh.is), my AI uplift newsletter.

Find more Claude Code resources at [HartreeWorks](https://github.com/HartreeWorks).
