# Claude Scripts

A collection of utility scripts for [Claude Code](https://claude.com/claude-code).

These scripts are used with Claude Code hooks, commands, and other automation workflows.

## Installation

Copy any script to your `~/.claude/scripts/` directory and ensure it's executable:

```bash
chmod +x ~/.claude/scripts/script-name.py
```

## Available scripts

| Script | Description |
|--------|-------------|
| [bash-safety-hook.py](./bash-safety-hook.py) | PreToolUse hook that detects dangerous bash patterns (RCE, catastrophic deletions, exfiltration, persistence) and asks for user confirmation |

## About

Created by [Peter Hartree](https://x.com/peterhartree). For updates, follow [AI Wow](https://wow.pjh.is), my AI uplift newsletter.

Find more Claude Code resources at [HartreeWorks](https://github.com/HartreeWorks).
