# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

## What Goes Here

Things like:

- Camera names and locations
- SSH hosts and aliases
- Preferred voices for TTS
- Speaker/room names
- Device nicknames
- Anything environment-specific

## Examples

```markdown
### Cameras

- living-room -> Main area, 180 deg wide angle
- front-door -> Entrance, motion-triggered

### SSH

- home-server -> 192.168.1.100, user: admin

### TTS

- Preferred voice: "Nova" (warm, slightly British)
- Default speaker: Kitchen HomePod
```

## OpenClaw

Use this section for machine-specific OpenClaw runtime details. Keep shared setup in
`README.md`; keep local gateway, auth, and model choices here.

- Repo default: simulation-only unless a task explicitly needs OpenClaw
- Python extra install: `pip install -e ".[openclaw]"`
- CLI check: `openclaw --help`
- Gateway URL:
- Auth mode:
- Token source:
- Gateway startup command:
- Planner agent: `watchdog-planner`
- Executor agent: `watchdog-executor`
- Sensor agent: `watchdog-sensor`
- Debate agent: `watchdog-debate`
- Planner model:
- Executor model:
- Sensor model:
- Debate model:
- Notes:

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.

---

Add whatever helps you do your job. This is your cheat sheet.
