# pi-env-guard

Environment variable validation, secret leak detection, and drift analysis for pi.dev projects.

## Features

- **env_validate** — Validate `.env` against `.env.example` for missing/extra/placeholder values
- **env_leak_detect** — Scan project files for accidentally committed secrets, API keys, and tokens
- **env_drift** — Detect drift between `.env` and `.env.example` (added/removed/modified variables)

## Usage

### Tools

```typescript
// Validate your .env file
await pi.tools.env_validate({});

// Scan for secret leaks
await pi.tools.env_leak_detect({ directory: "./src" });

// Check for environment drift
await pi.tools.env_drift({});
```

### Commands

```
/env-check    # Run all checks and display a report
```

## Installation

```bash
npm install pi-env-guard
```

## License

MIT
