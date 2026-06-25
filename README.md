# pi-env-guard

> Validate .env files, detect secret leaks, and check for environment drift in your Pi projects.

## Installation

```bash
pi install npm:pi-env-guard
```

## What It Does

Every developer uses `.env` files, but they're easy to mess up — missing variables, accidentally committed secrets, and `.env.example` files that drift out of sync. `pi-env-guard` adds three tools to Pi that catch these issues before they become problems.

## Tools

### `env_validate`
Validates your `.env` file against `.env.example` to find missing, extra, or misconfigured variables.

**Parameters:**
- `env_path` (string, optional) — Path to .env file (default: `.env`)
- `example_path` (string, optional) — Path to .env.example (default: `.env.example`)

**Example:**
```
Use the env_validate tool to check my environment configuration
```

### `env_leak_detect`
Scans files for accidentally committed secrets like API keys, tokens, and passwords.

**Parameters:**
- `path` (string, optional) — Directory or file to scan (default: current directory)
- `patterns` (string[], optional) — Additional regex patterns to detect

**Example:**
```
Use the env_leak_detect tool to scan for secrets in my project
```

### `env_drift`
Compares environment variables across `.env`, `.env.example`, and code references to detect drift.

**Parameters:**
- `root_dir` (string, optional) — Project root directory (default: current directory)

**Example:**
```
Use the env_drift tool to check if my .env.example is up to date
```

## Commands

### `/env-check`
Runs all three validations in one shot — validate, leak detection, and drift check. Gives you a complete environment health report.

## Resources

- [npm](https://www.npmjs.com/package/pi-env-guard)
- [GitHub](https://github.com/ZachDreamZ/pi-env-guard)
- [pi.dev](https://pi.dev/packages/pi-env-guard)

## License

MIT
