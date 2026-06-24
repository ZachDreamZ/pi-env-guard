import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { detectDrift, detectLeaks, validateEnv } from "./index.js";

// Helper to create temp dirs with test files
function createTmpDir(): string {
	return fs.mkdtempSync(path.join(os.tmpdir(), "env-guard-test-"));
}

function writeFile(dir: string, name: string, content: string): string {
	const filePath = path.join(dir, name);
	fs.writeFileSync(filePath, content, "utf-8");
	return filePath;
}

// =========================================
// env_validate tests
// =========================================
describe("env_validate", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = createTmpDir();
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("should report error when .env is missing", () => {
		const result = validateEnv(undefined, undefined, tmpDir);
		expect(result.valid).toBe(false);
		expect(result.errors.length).toBeGreaterThan(0);
		expect(result.errors[0]).toContain(".env file not found");
	});

	it("should handle empty .env file", () => {
		writeFile(tmpDir, ".env", "");
		const result = validateEnv(undefined, undefined, tmpDir);
		expect(result.valid).toBe(true);
		expect(result.checked_vars).toBe(0);
		expect(result.warnings).toContain(".env file is empty");
	});

	it("should validate .env against .env.example and find missing vars", () => {
		writeFile(tmpDir, ".env", "FOO=bar");
		writeFile(tmpDir, ".env.example", "FOO=\nBAZ=");
		const result = validateEnv(undefined, undefined, tmpDir);
		expect(result.valid).toBe(false);
		expect(result.missing_required).toContain("BAZ");
	});

	it("should detect extra variables not in .env.example", () => {
		writeFile(tmpDir, ".env", "FOO=bar\nEXTRA=value");
		writeFile(tmpDir, ".env.example", "FOO=");
		const result = validateEnv(undefined, undefined, tmpDir);
		expect(result.extra_vars).toContain("EXTRA");
		expect(result.warnings.some((w) => w.includes("EXTRA"))).toBe(true);
	});

	it("should detect placeholder values", () => {
		writeFile(
			tmpDir,
			".env",
			"API_KEY=changeme\nSECRET=your_value_here\nREAL=value123",
		);
		const result = validateEnv(undefined, undefined, tmpDir);
		expect(result.warnings.length).toBeGreaterThanOrEqual(2);
		expect(result.valid).toBe(true); // placeholders are warnings, not errors
	});

	it("should pass when all required vars are present", () => {
		writeFile(tmpDir, ".env", "FOO=bar\nBAZ=real_value");
		writeFile(tmpDir, ".env.example", "FOO=\nBAZ=required");
		const result = validateEnv(undefined, undefined, tmpDir);
		expect(result.valid).toBe(true);
		expect(result.errors.length).toBe(0);
		expect(result.checked_vars).toBe(2);
	});
});

// =========================================
// env_leak_detect tests
// =========================================
describe("env_leak_detect", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = createTmpDir();
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("should find no leaks in clean directory", () => {
		writeFile(tmpDir, "index.ts", 'const x = "hello world";');
		const result = detectLeaks(undefined, undefined, tmpDir);
		expect(result.leaks_found).toBe(false);
		expect(result.total_secrets_found).toBe(0);
		expect(result.total_files_scanned).toBeGreaterThan(0);
	});

	it("should detect hardcoded API keys", () => {
		writeFile(
			tmpDir,
			"config.ts",
			'const apiKey = "sk-abc123def456ghi789jkl012mno345";',
		);
		const result = detectLeaks(undefined, undefined, tmpDir);
		expect(result.leaks_found).toBe(true);
		expect(result.total_secrets_found).toBeGreaterThan(0);
		expect(result.findings[0].type).toBe("API Key");
	});

	it("should detect hardcoded passwords", () => {
		writeFile(tmpDir, "db.ts", 'password = "supersecretpassword123"');
		const result = detectLeaks(undefined, undefined, tmpDir);
		expect(result.leaks_found).toBe(true);
		expect(result.findings.some((f) => f.type === "Password")).toBe(true);
	});

	it("should detect private keys", () => {
		writeFile(
			tmpDir,
			"config.ts",
			"const key = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAK...';",
		);
		const result = detectLeaks(undefined, undefined, tmpDir);
		expect(result.leaks_found).toBe(true);
		expect(result.findings.some((f) => f.type === "Private Key")).toBe(true);
		expect(result.findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("should detect database URLs", () => {
		writeFile(
			tmpDir,
			"config.ts",
			'const dbUrl = "mongodb://admin:pass@localhost:27017/mydb";',
		);
		const result = detectLeaks(undefined, undefined, tmpDir);
		expect(result.leaks_found).toBe(true);
		expect(result.findings.some((f) => f.type === "Database URL")).toBe(true);
	});

	it("should skip node_modules directory", () => {
		const nodeModulesDir = path.join(tmpDir, "node_modules", "pkg");
		fs.mkdirSync(nodeModulesDir, { recursive: true });
		writeFile(
			nodeModulesDir,
			"index.ts",
			'apiKey = "sk-abc123def456ghi789jkl012mno345"',
		);
		writeFile(tmpDir, "app.ts", 'const x = "clean";');
		const result = detectLeaks(undefined, undefined, tmpDir);
		// Should not scan node_modules
		expect(result.findings.every((f) => !f.file.includes("node_modules"))).toBe(
			true,
		);
	});
});

// =========================================
// env_drift tests
// =========================================
describe("env_drift", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = createTmpDir();
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("should report error when .env is missing", () => {
		writeFile(tmpDir, ".env.example", "FOO=");
		const result = detectDrift(undefined, undefined, tmpDir);
		expect(result.drift_detected).toBe(true);
		expect(result.summary).toContain(".env file not found");
	});

	it("should report error when .env.example is missing", () => {
		writeFile(tmpDir, ".env", "FOO=bar");
		const result = detectDrift(undefined, undefined, tmpDir);
		expect(result.drift_detected).toBe(true);
		expect(result.summary).toContain(".env.example file not found");
	});

	it("should detect no drift when files match", () => {
		writeFile(tmpDir, ".env", "FOO=bar\nBAZ=qux");
		writeFile(tmpDir, ".env.example", "FOO=\nBAZ=");
		const result = detectDrift(undefined, undefined, tmpDir);
		expect(result.drift_detected).toBe(false);
		expect(result.added.length).toBe(0);
		expect(result.removed.length).toBe(0);
	});

	it("should detect added variables", () => {
		writeFile(tmpDir, ".env", "FOO=bar\nEXTRA=new_value");
		writeFile(tmpDir, ".env.example", "FOO=");
		const result = detectDrift(undefined, undefined, tmpDir);
		expect(result.drift_detected).toBe(true);
		expect(result.added).toContain("EXTRA");
	});

	it("should detect removed variables", () => {
		writeFile(tmpDir, ".env", "FOO=bar");
		writeFile(tmpDir, ".env.example", "FOO=\nMISSING_VAR=");
		const result = detectDrift(undefined, undefined, tmpDir);
		expect(result.drift_detected).toBe(true);
		expect(result.removed).toContain("MISSING_VAR");
	});

	it("should handle comments and blank lines gracefully", () => {
		writeFile(
			tmpDir,
			".env",
			"# comment\nFOO=bar\n\n# another comment\nBAZ=qux",
		);
		writeFile(tmpDir, ".env.example", "# config\nFOO=\nBAZ=");
		const result = detectDrift(undefined, undefined, tmpDir);
		expect(result.drift_detected).toBe(false);
	});
});

// =========================================
// Extension registration tests
// =========================================
describe("extension registration", () => {
	it("should export a default function", async () => {
		const mod = await import("./index.js");
		expect(typeof mod.default).toBe("function");
	});

	it("should export tool functions directly", async () => {
		const mod = await import("./index.js");
		expect(typeof mod.validateEnv).toBe("function");
		expect(typeof mod.detectLeaks).toBe("function");
		expect(typeof mod.detectDrift).toBe("function");
	});
});
