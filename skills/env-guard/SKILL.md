---
name: env-guard
description: Validate .env files, detect secret leaks, and analyze environment drift
tags: [env, security, validation, secrets]
---

# Environment Guard

Tools for managing environment configuration safely.

## When to Use

- Before committing code: scan for leaked secrets
- Onboarding new developers: validate their .env setup
- CI/CD pipelines: ensure environment consistency
- Debugging config issues: check for drift between .env and .env.example

## Tools

### env_validate
Validates `.env` against `.env.example`. Reports missing required variables, placeholder values, and extra variables.

### env_leak_detect
Scans project source files for hardcoded secrets, API keys, passwords, tokens, private keys, and database URLs. Skips `node_modules`, `.git`, and binary files.

### env_drift
Compares `.env` and `.env.example` to find variables that were added, removed, or have type mismatches.

## Command

`/env-check` — Runs all three checks and displays a consolidated report.
