import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

// --- Types ---

interface ValidationResult {
	valid: boolean;
	errors: string[];
	warnings: string[];
	checked_vars: number;
	missing_required: string[];
	extra_vars: string[];
}

interface LeakResult {
	leaks_found: boolean;
	total_files_scanned: number;
	total_secrets_found: number;
	findings: LeakFinding[];
	summary: string;
}

interface LeakFinding {
	file: string;
	line: number;
	type: string;
	severity: "critical" | "high" | "medium" | "low";
	snippet: string;
	recommendation: string;
}

interface DriftResult {
	drift_detected: boolean;
	added: string[];
	removed: string[];
	modified: DriftModification[];
	summary: string;
}

interface DriftModification {
	variable: string;
	type: "value_changed" | "type_changed" | "comment_changed";
	detail: string;
}

// --- Secret patterns for leak detection ---

const SECRET_PATTERNS: Array<{
	pattern: RegExp;
	type: string;
	severity: "critical" | "high" | "medium" | "low";
	recommendation: string;
}> = [
	{
		pattern:
			/(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi,
		type: "API Key",
		severity: "critical",
		recommendation: "Move to .env and add to .gitignore",
	},
	{
		pattern:
			/(?:secret[_-]?key|secret)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi,
		type: "Secret Key",
		severity: "critical",
		recommendation: "Use environment variables instead of hardcoded values",
	},
	{
		pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,})['"]?/gi,
		type: "Password",
		severity: "critical",
		recommendation: "Never commit passwords; use secret manager",
	},
	{
		pattern: /(?:token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.]{20,})['"]?/gi,
		type: "Token",
		severity: "high",
		recommendation: "Rotate token and store in environment variables",
	},
	{
		pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
		type: "Private Key",
		severity: "critical",
		recommendation: "Remove private key from code immediately",
	},
	{
		pattern:
			/(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['"]?([a-zA-Z0-9]{20})['"]?/gi,
		type: "AWS Access Key",
		severity: "critical",
		recommendation: "Rotate AWS key and use IAM roles",
	},
	{
		pattern:
			/(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?/gi,
		type: "AWS Secret Key",
		severity: "critical",
		recommendation: "Rotate AWS secret and use IAM roles",
	},
	{
		pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi,
		type: "Database URL",
		severity: "high",
		recommendation: "Use environment variables for connection strings",
	},
	{
		pattern: /(?:Bearer|Authorization)\s+[a-zA-Z0-9_\-\.]+/gi,
		type: "Auth Header",
		severity: "high",
		recommendation: "Remove hardcoded auth headers",
	},
];

// --- Helper functions ---

function parseEnvFile(content: string): Map<string, string> {
	const vars = new Map<string, string>();
	const lines = content.split("\n");

	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;

		const eqIndex = trimmed.indexOf("=");
		if (eqIndex === -1) continue;

		const key = trimmed.slice(0, eqIndex).trim();
		let value = trimmed.slice(eqIndex + 1).trim();

		// Remove surrounding quotes
		if (
			(value.startsWith('"') && value.endsWith('"')) ||
			(value.startsWith("'") && value.endsWith("'"))
		) {
			value = value.slice(1, -1);
		}

		vars.set(key, value);
	}

	return vars;
}

function parseExampleFile(
	content: string,
): Map<string, { required: boolean; defaultValue?: string }> {
	const vars = new Map<string, { required: boolean; defaultValue?: string }>();
	const lines = content.split("\n");

	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;

		const eqIndex = trimmed.indexOf("=");
		if (eqIndex === -1) {
			vars.set(trimmed, { required: true });
			continue;
		}

		const key = trimmed.slice(0, eqIndex).trim();
		const value = trimmed.slice(eqIndex + 1).trim();

		vars.set(key, {
			required: !value || value === "your_value_here" || value === "changeme",
			defaultValue: value || undefined,
		});
	}

	return vars;
}

function resolveEnvPath(envPath?: string, cwd?: string): string {
	const base = cwd || process.cwd();
	return path.resolve(base, envPath || ".env");
}

function resolveExamplePath(examplePath?: string, cwd?: string): string {
	const base = cwd || process.cwd();
	return path.resolve(base, examplePath || ".env.example");
}

// --- Tool implementations ---

export function validateEnv(
	envPath?: string,
	examplePath?: string,
	cwd?: string,
): ValidationResult {
	const resolvedEnvPath = resolveEnvPath(envPath, cwd);
	const resolvedExamplePath = resolveExamplePath(examplePath, cwd);

	const errors: string[] = [];
	const warnings: string[] = [];
	const missingRequired: string[] = [];
	const extraVars: string[] = [];

	// Check if .env exists
	if (!fs.existsSync(resolvedEnvPath)) {
		return {
			valid: false,
			errors: [`.env file not found at ${resolvedEnvPath}`],
			warnings: [],
			checked_vars: 0,
			missing_required: [],
			extra_vars: [],
		};
	}

	const envContent = fs.readFileSync(resolvedEnvPath, "utf-8");
	const envVars = parseEnvFile(envContent);

	// Check for empty .env
	if (envVars.size === 0) {
		return {
			valid: true,
			errors: [],
			warnings: [".env file is empty"],
			checked_vars: 0,
			missing_required: [],
			extra_vars: [],
		};
	}

	// If example file exists, validate against it
	if (fs.existsSync(resolvedExamplePath)) {
		const exampleContent = fs.readFileSync(resolvedExamplePath, "utf-8");
		const exampleVars = parseExampleFile(exampleContent);

		for (const [key, config] of exampleVars) {
			if (config.required && !envVars.has(key)) {
				missingRequired.push(key);
				errors.push(`Missing required variable: ${key}`);
			}
		}

		for (const key of envVars.keys()) {
			if (!exampleVars.has(key)) {
				extraVars.push(key);
				warnings.push(`Extra variable not in .env.example: ${key}`);
			}
		}
	}

	// Check for placeholder values
	for (const [key, value] of envVars) {
		if (
			!value ||
			value === "changeme" ||
			value === "your_value_here" ||
			value === "TODO"
		) {
			warnings.push(`Variable ${key} has placeholder value`);
		}
	}

	return {
		valid: errors.length === 0,
		errors,
		warnings,
		checked_vars: envVars.size,
		missing_required: missingRequired,
		extra_vars: extraVars,
	};
}

export function detectLeaks(
	directory?: string,
	fileGlobs?: string[],
	cwd?: string,
): LeakResult {
	const baseDir = cwd || process.cwd();
	const resolvedDir = path.resolve(baseDir, directory || ".");

	const findings: LeakFinding[] = [];
	let totalFiles = 0;

	const ignoreDirs = new Set([
		"node_modules",
		".git",
		"dist",
		"build",
		".next",
		"__pycache__",
	]);
	const defaultExts = new Set([
		".ts",
		".js",
		".tsx",
		".jsx",
		".py",
		".rb",
		".go",
		".rs",
		".java",
		".php",
		".env",
		".yaml",
		".yml",
		".json",
		".toml",
		".cfg",
		".conf",
		".ini",
	]);

	function shouldScan(filePath: string): boolean {
		const ext = path.extname(filePath).toLowerCase();
		const basename = path.basename(filePath).toLowerCase();
		// Always scan env files
		if (basename.startsWith(".env")) return true;
		// Skip binary-like files
		if (
			[
				".png",
				".jpg",
				".jpeg",
				".gif",
				".ico",
				".woff",
				".woff2",
				".ttf",
				".eot",
				".pdf",
				".zip",
				".tar",
				".gz",
			].includes(ext)
		)
			return false;
		return (
			defaultExts.has(ext) ||
			fileGlobs?.some((g) => filePath.includes(g.replace("*", ""))) ||
			false
		);
	}

	function scanDir(dir: string): void {
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}

		for (const entry of entries) {
			const fullPath = path.join(dir, entry.name);

			if (entry.isDirectory()) {
				if (!ignoreDirs.has(entry.name)) {
					scanDir(fullPath);
				}
				continue;
			}

			if (!entry.isFile() || !shouldScan(fullPath)) continue;

			totalFiles++;

			let content: string;
			try {
				content = fs.readFileSync(fullPath, "utf-8");
			} catch {
				continue;
			}

			const lines = content.split("\n");
			for (let i = 0; i < lines.length; i++) {
				for (const {
					pattern,
					type,
					severity,
					recommendation,
				} of SECRET_PATTERNS) {
					pattern.lastIndex = 0;
					if (pattern.test(lines[i])) {
						findings.push({
							file: path.relative(baseDir, fullPath),
							line: i + 1,
							type,
							severity,
							snippet: lines[i].trim().slice(0, 100),
							recommendation,
						});
					}
				}
			}
		}
	}

	scanDir(resolvedDir);

	return {
		leaks_found: findings.length > 0,
		total_files_scanned: totalFiles,
		total_secrets_found: findings.length,
		findings,
		summary:
			findings.length > 0
				? `Found ${findings.length} potential secret(s) in ${totalFiles} files`
				: `No secrets found in ${totalFiles} files scanned`,
	};
}

export function detectDrift(
	envPath?: string,
	examplePath?: string,
	cwd?: string,
): DriftResult {
	const resolvedEnvPath = resolveEnvPath(envPath, cwd);
	const resolvedExamplePath = resolveExamplePath(examplePath, cwd);

	const added: string[] = [];
	const removed: string[] = [];
	const modified: DriftModification[] = [];

	// Both files must exist
	if (!fs.existsSync(resolvedEnvPath)) {
		return {
			drift_detected: true,
			added: [],
			removed: [],
			modified: [],
			summary: `.env file not found at ${resolvedEnvPath}`,
		};
	}

	if (!fs.existsSync(resolvedExamplePath)) {
		return {
			drift_detected: true,
			added: [],
			removed: [],
			modified: [],
			summary: `.env.example file not found at ${resolvedExamplePath}`,
		};
	}

	const envContent = fs.readFileSync(resolvedEnvPath, "utf-8");
	const exampleContent = fs.readFileSync(resolvedExamplePath, "utf-8");

	const envVars = parseEnvFile(envContent);
	const exampleVars = parseExampleFile(exampleContent);

	// Find added (in .env but not in .env.example)
	for (const key of envVars.keys()) {
		if (!exampleVars.has(key)) {
			added.push(key);
		}
	}

	// Find removed (in .env.example but not in .env)
	for (const key of exampleVars.keys()) {
		if (!envVars.has(key)) {
			removed.push(key);
		}
	}

	// Check for value patterns that suggest type changes
	for (const [key, envValue] of envVars) {
		const exampleConfig = exampleVars.get(key);
		if (!exampleConfig?.defaultValue) continue;

		const exVal = exampleConfig.defaultValue;

		// Detect potential type mismatches
		const envIsNum = /^\d+$/.test(envValue);
		const exIsNum = /^\d+$/.test(exVal);
		const envIsBool = /^(true|false)$/i.test(envValue);
		const exIsBool = /^(true|false)$/i.test(exVal);

		if (envIsNum && !exIsNum && !exIsNum) {
			modified.push({
				variable: key,
				type: "type_changed",
				detail: "Expected non-numeric, got numeric",
			});
		} else if (envIsBool && !exIsBool) {
			modified.push({
				variable: key,
				type: "type_changed",
				detail: "Expected non-boolean, got boolean",
			});
		}
	}

	const driftDetected =
		added.length > 0 || removed.length > 0 || modified.length > 0;

	return {
		drift_detected: driftDetected,
		added,
		removed,
		modified,
		summary: driftDetected
			? `Drift detected: ${added.length} added, ${removed.length} removed, ${modified.length} modified`
			: "No drift detected between .env and .env.example",
	};
}

// --- Extension registration ---

export default function (pi: ExtensionAPI) {
	// Tool 1: env_validate
	pi.registerTool({
		name: "env_validate",
		label: "Validate Environment",
		description:
			"Validate .env file against .env.example. Checks for missing required variables, placeholder values, and extra variables.",
		parameters: Type.Object({
			env_path: Type.Optional(
				Type.String({ description: "Path to .env file (default: .env)" }),
			),
			example_path: Type.Optional(
				Type.String({
					description: "Path to .env.example file (default: .env.example)",
				}),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const result = validateEnv(params.env_path, params.example_path);
			return {
				content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
				details: result,
			};
		},
	});

	// Tool 2: env_leak_detect
	pi.registerTool({
		name: "env_leak_detect",
		label: "Detect Secret Leaks",
		description:
			"Scan project files for accidentally committed secrets, API keys, passwords, and tokens.",
		parameters: Type.Object({
			directory: Type.Optional(
				Type.String({
					description: "Directory to scan (default: current directory)",
				}),
			),
			file_globs: Type.Optional(
				Type.Array(Type.String(), {
					description: "Additional file patterns to scan",
				}),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const result = detectLeaks(params.directory, params.file_globs);
			return {
				content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
				details: result,
			};
		},
	});

	// Tool 3: env_drift
	pi.registerTool({
		name: "env_drift",
		label: "Detect Environment Drift",
		description:
			"Compare .env against .env.example to find added, removed, or modified variables.",
		parameters: Type.Object({
			env_path: Type.Optional(
				Type.String({ description: "Path to .env file (default: .env)" }),
			),
			example_path: Type.Optional(
				Type.String({
					description: "Path to .env.example file (default: .env.example)",
				}),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const result = detectDrift(params.env_path, params.example_path);
			return {
				content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
				details: result,
			};
		},
	});

	// Command: /env-check
	pi.registerCommand("env-check", {
		description:
			"Run all environment checks (validate, leak detect, drift) and display results",
		handler: async (_args, ctx) => {
			const cwd = ctx.cwd;

			ctx.ui.notify("Running environment checks...", "info");

			const validation = validateEnv(undefined, undefined, cwd);
			const leaks = detectLeaks(undefined, undefined, cwd);
			const drift = detectDrift(undefined, undefined, cwd);

			const report = [
				"=== Environment Guard Report ===",
				"",
				`Validation: ${validation.valid ? "PASS" : "FAIL"} (${validation.checked_vars} vars checked)`,
				...validation.errors.map((e) => `  ERROR: ${e}`),
				...validation.warnings.map((w) => `  WARN: ${w}`),
				"",
				`Leak Scan: ${leaks.leaks_found ? "ISSUES FOUND" : "CLEAN"} (${leaks.total_files_scanned} files, ${leaks.total_secrets_found} findings)`,
				...leaks.findings.map(
					(f) =>
						`  ${f.severity.toUpperCase()}: ${f.file}:${f.line} - ${f.type}`,
				),
				"",
				`Drift Check: ${drift.drift_detected ? "DRIFT DETECTED" : "OK"}`,
				...drift.added.map((a) => `  ADDED: ${a}`),
				...drift.removed.map((r) => `  REMOVED: ${r}`),
				...drift.modified.map((m) => `  MODIFIED: ${m.variable} - ${m.detail}`),
			].join("\n");

			ctx.ui.notify(`Environment Guard Report:\n${report}`, "info");
			ctx.ui.notify("Environment checks complete", "info");
		},
	});
}
