/**
 * safe-mode / checks.ts
 *
 * 执行前分析引擎：
 *   - 路径归一化（Windows：大小写不敏感、`..`、`~`、`\\?\`、UNC、软链接别名）
 *   - shell 命令分段 / wrapper 识别 / 不透明命令标记
 *   - 规则裁决，返回 ALLOW / CONFIRM / DENY
 *
 * 设计约束：
 *   - 只做 允许 / 拦截，**绝不改写工具参数**（避免"净化"逻辑本身成为绕过面）
 *   - 所有裁决都带 safe.txt 章节出处，便于 /safe rules 审计
 */

import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { win32 as pathWin32 } from "node:path";
import {
	type Action,
	type Level,
	type LevelActions,
	actionFor,
	BOUNDARY_PATH_RULES,
	CMD_RULES,
	CREDENTIAL_PATH_RULES,
	ENV_FILE_ACTIONS,
	ENV_FILE_RE,
	EXFIL_CMD_RE,
	lv,
	MALICIOUS_CMD_RULES,
	PATH_RULES,
	SOFT_SECRET_ACTIONS,
	SOFT_SECRET_PATH_RULES,
	SUPPLY_CHAIN_CMD_RULES,
	THRESHOLDS,
	WORKSPACE_DELETE_ACTIONS,
	worst,
} from "./policy.ts";

export interface Verdict {
	action: Action;
	ruleId: string;
	source: string;
	reason: string;
	risk: string;
	target: string;
	/** 属于"永远生效集"（含 OFF） */
	invariant: boolean;
	/** UNKNOWN / UNPARSED / OPAQUE COMMAND */
	opaque: boolean;
	/** CONFIRM 时可确认继续；DENY 时不可 */
	resumable: boolean;
}

export interface EvalInput {
	toolName: string;
	input: Record<string, unknown>;
	cwd: string;
	level: Level;
	trustedRoots: string[];
}

const OUTSIDE_WRITE_ACTIONS: LevelActions = lv("ALLOW", "CONFIRM", "CONFIRM", "CONFIRM");
const OPAQUE_NORMAL_ACTIONS: LevelActions = lv("ALLOW", "ALLOW", "CONFIRM", "CONFIRM");

// ---------------------------------------------------------------------------
// 路径归一化
// ---------------------------------------------------------------------------

function toPosix(value: string): string {
	return value.replace(/\\/g, "/");
}

function stripQuotes(value: string): string {
	if (value.length >= 2) {
		const first = value[0];
		const last = value[value.length - 1];
		if ((first === '"' && last === '"') || (first === "'" && last === "'")) return value.slice(1, -1);
	}
	return value;
}

/** 从 `file=@.env`、`@.env`、`.env` 这类 token 里取出候选文件名 */
function pathCandidatesInToken(token: string): string[] {
	const out = [token];
	const at = token.lastIndexOf("@");
	if (at >= 0 && at + 1 < token.length) out.push(token.slice(at + 1));
	const eq = token.lastIndexOf("=");
	if (eq >= 0 && eq + 1 < token.length) out.push(token.slice(eq + 1));
	return out;
}

/** 归一化为小写、正斜杠、绝对路径；不做 IO */
export function normalizePath(raw: string, cwd: string): string {
	let value = stripQuotes(String(raw ?? "").trim());
	if (!value) return "";
	value = value.replace(/^\\\\\?\\/, "");
	if (value === "~" || value.startsWith("~/") || value.startsWith("~\\")) {
		value = `${toPosix(homedir())}${value.slice(1)}`;
	}
	let abs: string;
	if (/^\/[a-zA-Z](\/|$)/.test(value)) {
		// MSYS / Git-Bash 风格 /d/foo（必须在 win32.isAbsolute 之前判定）
		abs = pathWin32.normalize(`${value[1]}:${value.slice(2)}`);
	} else if (pathWin32.isAbsolute(value)) {
		abs = pathWin32.normalize(value);
	} else {
		abs = pathWin32.resolve(cwd, value);
	}
	return toPosix(abs).toLowerCase();
}

function isUnder(target: string, root: string): boolean {
	if (!root) return false;
	const r = root.endsWith("/") ? root.slice(0, -1) : root;
	return target === r || target.startsWith(`${r}/`);
}

/** 软链接别名：真实路径也参与判定（safe.txt §8 的 symlink 别名要求） */
function realVariants(normalized: string): string[] {
	const out = [normalized];
	try {
		const real = toPosix(realpathSync.native(normalized)).toLowerCase();
		if (real !== normalized) out.push(real);
	} catch {
		/* 目标不存在 —— 忽略 */
	}
	return out;
}

export type PathKind = "read" | "write";

interface PathHit {
	action: Action;
	ruleId: string;
	source: string;
	reason: string;
	risk: string;
	invariant: boolean;
	target: string;
}

function evaluateOnePath(
	normalized: string,
	kind: PathKind,
	level: Level,
	cwdNorm: string,
	trustedRoots: string[],
): PathHit | undefined {
	if (!normalized) return undefined;
	const variants = realVariants(normalized);
	const test = (re: RegExp) => variants.some((v) => re.test(v));

	// 1) 凭据类：读 / 写 一律 DENY（IRON CORE）
	for (const rule of CREDENTIAL_PATH_RULES) {
		if (test(rule.re)) {
			return {
				action: "DENY",
				ruleId: "iron.credential-path",
				source: "safe.txt §8 SENSITIVE PATHS, §15 CREDENTIALS AND SECRETS",
				reason: rule.reason,
				risk: rule.risk,
				invariant: true,
				target: normalized,
			};
		}
	}

	// 2) 安全边界：写入 / 删除 一律 CONFIRM（IRON CORE，含 OFF）
	if (kind === "write") {
		for (const rule of BOUNDARY_PATH_RULES) {
			if (test(rule.re)) {
				return {
					action: "CONFIRM",
					ruleId: "iron.boundary-write",
					source: "safe.txt §8 SENSITIVE PATHS, §20 DO NOT MODIFY YOUR OWN SECURITY BOUNDARY",
					reason: rule.reason,
					risk: rule.risk,
					invariant: true,
					target: normalized,
				};
			}
		}
	}

	// 3a) .env 类文件（最终方案.txt 第 4 条；.env.example 等模板不算）
	if (kind === "read" && test(ENV_FILE_RE)) {
		return {
			action: actionFor(ENV_FILE_ACTIONS, level),
			ruleId: "secret.env-read",
			source: "safe.txt §15 CREDENTIALS AND SECRETS",
			reason: "path is a .env file that may contain secrets",
			risk: "secret exposure (safe.txt §15)",
			invariant: false,
			target: normalized,
		};
	}

	// 3) 软密钥文件（项目内可能是正常工程）：按等级，只对读取生效
	if (kind === "read") {
		for (const rule of SOFT_SECRET_PATH_RULES) {
			if (test(rule.re)) {
				return {
					action: actionFor(SOFT_SECRET_ACTIONS, level),
					ruleId: "secret.soft-key-file",
					source: "safe.txt §15 CREDENTIALS AND SECRETS",
					reason: rule.reason,
					risk: rule.risk,
					invariant: false,
					target: normalized,
				};
			}
		}
	}

	// 4) 受保护位置（写入 / 删除）
	if (kind === "write") {
		for (const rule of PATH_RULES) {
			if (test(rule.re)) {
				return {
					action: actionFor(rule.actions, level),
					ruleId: rule.id,
					source: rule.source,
					reason: rule.reason,
					risk: rule.risk,
					invariant: false,
					target: normalized,
				};
			}
		}
	}

	// 5) 作用域
	const inside = isUnder(normalized, cwdNorm) || trustedRoots.some((r) => isUnder(normalized, r));
	if (inside) return undefined;

	if (kind === "write") {
		return {
			action: actionFor(OUTSIDE_WRITE_ACTIONS, level),
			ruleId: "path.outside-workspace",
			source: "safe.txt §6 WORKSPACE BOUNDARY, §5 LEVEL 2",
			reason: "write outside the workspace and outside the trusted roots",
			risk: "modifying files outside the project (safe.txt §6)",
			invariant: false,
			target: normalized,
		};
	}

	// 读取：外部仅在 STRICT 下复核（safe.txt §27）
	if (level === "strict") {
		return {
			action: "CONFIRM",
			ruleId: "path.outside-workspace-read",
			source: "safe.txt §6 WORKSPACE BOUNDARY, §27 PRIVACY",
			reason: "read outside the workspace (STRICT review)",
			risk: "accessing unrelated personal data (safe.txt §27)",
			invariant: false,
			target: normalized,
		};
	}
	return undefined;
}

// ---------------------------------------------------------------------------
// shell 命令分析
// ---------------------------------------------------------------------------

const WRITE_VERB_RE =
	/(^|[\s|&;(])(rm|rmdir|del|erase|unlink|mv|move|cp|copy|robocopy|xcopy|mkdir|md|touch|tee|truncate|chmod|chown|attrib|icacls|takeown|sed|set-content|add-content|out-file|new-item|remove-item|rename-item|move-item|copy-item|clear-content|git\s+(clone|checkout|reset|clean|restore|apply|init|switch))\b/i;

const PATH_TOKEN_RE = /^(?:[a-zA-Z]:[\\/]|\\\\|\/|~[\\/]?|\.{1,2}[\\/])/;
const FILE_TOKEN_RE = /^[\w.$@~+-]+[\\/][^\s]*$|^[\w.$@+-]+\.[a-z0-9]{1,8}$/i;
const SCRIPT_EXT_RE = /\.(ps1|bat|cmd|vbs|js|mjs|cjs|sh|bash|zsh|py|pl|rb|exe|msi|jar|dll)$/i;
const LAUNCHER_RE = /(^|[\s|&;(])(\.\/|\.\\|bash|sh|zsh|pwsh|powershell|cmd|node|python|python3|py|perl|ruby|java|start|invoke-item|&)\s/i;

const OPAQUE_HIGH_RE =
	/(-encodedcommand|\s-enc\s|\bfrombase64string\b|\|\s*(sh|bash|zsh|pwsh|powershell|iex|invoke-expression)\b|\biex\s*\(|\binvoke-expression\b|\beval\s*\()/i;

const OPAQUE_NORMAL_RE =
	/(\b(python|python3|py|perl|ruby|node|php)\s+(-c|-e|--eval|-p)\b|\b(bash|sh|zsh|pwsh|powershell|cmd)\b.{0,12}[\\/]?(-c|\/c|-command)\b|\$\(|`)/;

export function splitSegments(command: string): string[] {
	const out: string[] = [];
	let cur = "";
	let quote: string | null = null;
	for (let i = 0; i < command.length; i++) {
		const ch = command[i];
		if (quote) {
			if (ch === "\\" && quote === '"' && i + 1 < command.length) {
				cur += ch + command[i + 1];
				i++;
				continue;
			}
			if (ch === quote) quote = null;
			cur += ch;
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			cur += ch;
			continue;
		}
		if (ch === "\n" || ch === ";") {
			out.push(cur);
			cur = "";
			continue;
		}
		if ((ch === "&" || ch === "|") && command[i + 1] === ch) {
			out.push(cur);
			cur = "";
			i++;
			continue;
		}
		if (ch === "|" || ch === "&") {
			out.push(cur);
			cur = "";
			continue;
		}
		cur += ch;
	}
	out.push(cur);
	return out.map((s) => s.trim()).filter(Boolean);
}

function tokensOf(segment: string): string[] {
	return (segment.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map(stripQuotes);
}

/** 命令是否引用了 .env 类文件（排除 .env.example / .env.sample / .env.template） */
function mentionsEnvFile(command: string): boolean {
	for (const segment of splitSegments(command)) {
		for (const token of tokensOf(segment)) {
			for (const candidate of pathCandidatesInToken(token)) {
				const cleaned = candidate.replace(/^[=@]+/, "");
				if (ENV_FILE_RE.test(cleaned)) return true;
			}
		}
	}
	return false;
}

/** 当前活跃 conda 环境是否是项目专用 env（而非 base） */
function activeCondaIsProjectEnv(): boolean {
	const prefix = process.env.CONDA_PREFIX;
	if (!prefix) return false;
	const norm = prefix.replace(/\\/g, "/").toLowerCase();
	if (/\/envs\/[^/]+$/.test(norm)) return true;
	return false;
}

/** 空设备：`2>nul` / `> /dev/null` 这类重定向不是写入目标 */
const NULL_DEVICE_RE = /^(nul|\/dev\/(null|stdout|stderr|zero)|con)$/i;

function redirectTargets(segment: string): string[] {
	const out: string[] = [];
	const re = />>?\s*("[^"]*"|'[^']*'|[^\s|&;>]+)/g;
	let m = re.exec(segment);
	while (m) {
		const target = stripQuotes(m[1]);
		if (!NULL_DEVICE_RE.test(target)) out.push(target);
		m = re.exec(segment);
	}
	return out;
}

export interface PathCandidate {
	token: string;
	kind: PathKind;
}

/**
 * 从一个命令段里提取候选路径。
 * 写入语义来自：写动词 或 shell 重定向。
 */
export function candidatesOfSegment(segment: string): PathCandidate[] {
	const out: PathCandidate[] = [];
	const writeish = WRITE_VERB_RE.test(segment);
	for (const token of tokensOf(segment)) {
		if (token.startsWith("-") || token.startsWith("/") && /^\/[a-z]{1,3}$/i.test(token)) continue;
		const looksLikePath =
			PATH_TOKEN_RE.test(token) || token.includes("/") || token.includes("\\") || FILE_TOKEN_RE.test(token);
		if (!looksLikePath) continue;
		if (NULL_DEVICE_RE.test(token)) continue;
		if (token.toLowerCase() === "nul") continue;
		if (!writeish && !SCRIPT_EXT_RE.test(token) && !PATH_TOKEN_RE.test(token) && !token.includes("/") && !token.includes("\\")) {
			continue;
		}
		out.push({ token, kind: writeish ? "write" : "read" });
	}
	for (const target of redirectTargets(segment)) {
		out.push({ token: target, kind: "write" });
	}
	return out;
}

function scriptTargetsOf(segment: string): string[] {
	const out: string[] = [];
	if (!LAUNCHER_RE.test(segment) && !/^(\.\/|\.\\)/.test(segment.trim())) return out;
	for (const token of tokensOf(segment)) {
		if (SCRIPT_EXT_RE.test(token)) out.push(token);
	}
	return out;
}

/** 含变量/通配符的路径无法静态解析 —— 不能据此放宽删除规则（fail-closed） */
function isStaticallyResolvable(token: string): boolean {
	return !/[$%`*?\[\]{}]/.test(token);
}

/**
 * 删除命令的上下文判定（safe.txt §4 / §5 LEVEL 3 / §7 / §37）：
 * 只有当**每一个**可静态解析的删除目标都落在 workspace 或可信根内，
 * 且目标数不超阈值时，才算“项目内普通删除”，按 WORKSPACE_DELETE_ACTIONS 处理。
 * 任何无法解析或越界的情况都维持 fail-closed（按原 rules.actions）。
 */
function workspaceDeleteIsBenign(
	candidates: PathCandidate[],
	cwdNorm: string,
	trustedRoots: string[],
): boolean {
	const writes = candidates.filter((c) => c.kind === "write");
	if (writes.length === 0) return false;
	if (writes.length > THRESHOLDS.deleteFiles) return false;
	for (const candidate of writes) {
		if (!isStaticallyResolvable(candidate.token)) return false;
		const norm = normalizePath(candidate.token, cwdNorm);
		if (!norm) return false;
		const inside = isUnder(norm, cwdNorm) || trustedRoots.some((r) => isUnder(norm, r));
		if (!inside) return false;
	}
	return true;
}

const ACTION_RANK: Record<Action, number> = { ALLOW: 0, CONFIRM: 1, DENY: 2 };

function worse(a: Verdict | undefined, b: Verdict | undefined): Verdict | undefined {
	if (!a) return b;
	if (!b) return a;
	if (ACTION_RANK[b.action] > ACTION_RANK[a.action]) return b;
	if (ACTION_RANK[b.action] < ACTION_RANK[a.action]) return a;
	if (b.invariant && !a.invariant) return b;
	return a;
}

function makeVerdict(
	action: Action,
	ruleId: string,
	source: string,
	reason: string,
	risk: string,
	target: string,
	invariant: boolean,
	opaque = false,
): Verdict {
	return { action, ruleId, source, reason, risk, target, invariant, opaque, resumable: action === "CONFIRM" };
}

function fromPathHit(hit: PathHit): Verdict {
	return {
		action: hit.action,
		ruleId: hit.ruleId,
		source: hit.source,
		reason: hit.reason,
		risk: hit.risk,
		target: hit.target,
		invariant: hit.invariant,
		opaque: false,
		resumable: hit.action === "CONFIRM",
	};
}

export interface CommandVerdict {
	verdict?: Verdict;
	opaque: boolean;
	opaqueLabel?: string;
}

/** 纯命令裁决（bash / powershell / user_bash 共用） */
export function evaluateCommand(command: string, cwd: string, level: Level, trustedRoots: string[]): CommandVerdict {
	const raw = String(command ?? "");
	const cwdNorm = normalizePath(cwd, cwd);
	const segments = splitSegments(raw);
	const allCandidates: PathCandidate[] = [];
	for (const segment of segments) {
		for (const candidate of candidatesOfSegment(segment)) allCandidates.push(candidate);
	}
	let best: Verdict | undefined;

	// --- IRON CORE: 明确恶意（一律 DENY） ---
	for (const rule of MALICIOUS_CMD_RULES) {
		if (rule.re.test(raw)) {
			best = worse(
				best,
				makeVerdict(
					"DENY",
					"iron.malicious",
					"safe.txt §4 LEVEL 4 PROHIBITED, §20, §28",
					rule.reason,
					rule.risk,
					raw.slice(0, 300),
					true,
				),
			);
		}
	}

	// --- IRON CORE: 供应链 / 安全边界（一律 CONFIRM，含 OFF） ---
	for (const rule of SUPPLY_CHAIN_CMD_RULES) {
		if (!rule.re.test(raw)) continue;
		if (rule.unless && rule.unless.test(raw)) continue;
		best = worse(
			best,
			makeVerdict(
				"CONFIRM",
				"iron.supply-chain",
				"safe.txt §19 EXTENSIONS, PACKAGES, SKILLS, AND MCP TOOLS, §20",
				rule.reason,
				rule.risk,
				raw.slice(0, 300),
				true,
			),
		);
	}

	// --- IRON CORE: 敏感文件外传（DENY） ---
	if (EXFIL_CMD_RE.test(raw)) {
		const sensitiveRef =
			mentionsEnvFile(raw) ||
			/(id_rsa|id_ed25519|id_ecdsa|\.ssh|\.aws|auth\.json|\.npmrc|\.git-credentials|\.netrc|login\s*data|cookies)/i.test(
				raw,
			);
		if (sensitiveRef) {
			best = worse(
				best,
				makeVerdict(
					"DENY",
					"iron.secret-exfil",
					"safe.txt §15 CREDENTIALS AND SECRETS, §14 NETWORK OPERATIONS",
					"command appears to upload a credential / sensitive file",
					"credential exfiltration (safe.txt §4 LEVEL 4)",
					raw.slice(0, 300),
					true,
				),
			);
		}
	}

	// --- .env 读取（等级相关；最终方案第 4 条） ---
	if (mentionsEnvFile(raw) && (level === "balanced" || level === "strict")) {
		best = worse(
			best,
			makeVerdict(
				"CONFIRM",
				"secret.env-read",
				"safe.txt §15 CREDENTIALS AND SECRETS",
				"command may read a .env file containing secrets",
				"secret exposure (safe.txt §15)",
				".env",
				false,
			),
		);
	}

	// --- 等级相关命令规则 ---
	for (const rule of CMD_RULES) {
		if (!rule.re.test(raw)) continue;
		if (rule.unless && rule.unless.test(raw)) continue;
		if (rule.allowWhenActiveCondaEnv && activeCondaIsProjectEnv()) continue;
		let action = actionFor(rule.actions, level);
		// 删除类：仅当所有删除目标都在 workspace/可信根内、且可静态解析、且未超阈值
		// 才降为 WORKSPACE_DELETE_ACTIONS（safe.txt §4 低风险自动执行 / §37 阈值）
		if (rule.workspaceDeleteContext && workspaceDeleteIsBenign(allCandidates, cwdNorm, trustedRoots)) {
			action = actionFor(WORKSPACE_DELETE_ACTIONS, level);
		}
		if (action === "ALLOW") continue;
		best = worse(
			best,
			makeVerdict(action, rule.id, rule.source, rule.reason, rule.risk, raw.slice(0, 300), rule.invariant === true),
		);
	}

	// --- 路径作用域 / 受保护路径 ---
	for (const candidate of allCandidates) {
		const hit = evaluateOnePath(normalizePath(candidate.token, cwd), candidate.kind, level, cwdNorm, trustedRoots);
		if (hit) best = worse(best, fromPathHit(hit));
	}

	// --- 脚本执行：工作区内 = 正常开发（§4/§12）；外部 = 确认 ---
	for (const segment of segments) {
		for (const token of scriptTargetsOf(segment)) {
			const norm = normalizePath(token, cwd);
			const inside = isUnder(norm, cwdNorm) || trustedRoots.some((r) => isUnder(norm, r));
			if (inside) continue;
			const action = actionFor(OUTSIDE_WRITE_ACTIONS, level);
			if (action === "ALLOW") continue;
			best = worse(
				best,
				makeVerdict(
					action,
					"exec.script-outside-workspace",
					"safe.txt §14 NETWORK OPERATIONS, §25 FAILURE HANDLING",
					"executing a script from outside the workspace / trusted roots",
					"unknown third-party code execution (safe.txt §25)",
					norm,
					false,
				),
			);
		}
	}

	// --- 不透明命令标记 ---
	let opaque = false;
	let opaqueLabel: string | undefined;
	if (OPAQUE_HIGH_RE.test(raw)) {
		opaque = true;
		opaqueLabel = "UNKNOWN / UNPARSED / OPAQUE COMMAND (encoded or piped-to-interpreter)";
		best = worse(
			best,
			makeVerdict(
				"CONFIRM",
				"shell.opaque-high",
				"safe.txt §9 DANGEROUS COMMANDS, §30 FINAL DECISION ALGORITHM",
				"command cannot be reviewed statically (encoded / piped to an interpreter)",
				"unreviewable execution (safe.txt §30)",
				raw.slice(0, 300),
				false,
				true,
			),
		);
	} else if (OPAQUE_NORMAL_RE.test(raw)) {
		opaque = true;
		opaqueLabel = "UNKNOWN / UNPARSED / OPAQUE COMMAND (inline interpreter code)";
		const action = actionFor(OPAQUE_NORMAL_ACTIONS, level);
		if (action !== "ALLOW") {
			best = worse(
				best,
				makeVerdict(
					action,
					"shell.opaque-normal",
					"safe.txt §9 DANGEROUS COMMANDS, §30 FINAL DECISION ALGORITHM",
					"command contains inline interpreter code that cannot be reviewed statically",
					"unreviewable execution (safe.txt §30)",
					raw.slice(0, 300),
					false,
					true,
				),
			);
		}
	}

	return { verdict: best && best.action !== "ALLOW" ? best : undefined, opaque, opaqueLabel };
}

// ---------------------------------------------------------------------------
// 工具调用裁决
// ---------------------------------------------------------------------------

const READ_TOOLS = new Set(["read", "grep", "find", "ls"]);
const WRITE_TOOLS = new Set(["write", "edit"]);
const PATH_ARG_KEYS = [
	"path",
	"file_path",
	"filepath",
	"paths",
	"target",
	"dest",
	"destination",
	"file",
	"files",
	"dir",
	"directory",
	"cwd",
];

function collectPathArgs(input: Record<string, unknown>): string[] {
	const out: string[] = [];
	for (const key of PATH_ARG_KEYS) {
		const value = input?.[key];
		if (typeof value === "string") out.push(value);
		else if (Array.isArray(value)) {
			for (const item of value) if (typeof item === "string") out.push(item);
		}
	}
	return out;
}

export function evaluateToolCall({ toolName, input, cwd, level, trustedRoots }: EvalInput): Verdict | undefined {
	const cwdNorm = normalizePath(cwd, cwd);
	let best: Verdict | undefined;

	if (toolName === "bash" || toolName === "powershell") {
		const command = typeof input?.command === "string" ? input.command : "";
		return evaluateCommand(command, cwd, level, trustedRoots).verdict;
	}

	if (READ_TOOLS.has(toolName) || WRITE_TOOLS.has(toolName)) {
		const kind: PathKind = WRITE_TOOLS.has(toolName) ? "write" : "read";
		for (const raw of collectPathArgs(input)) {
			const hit = evaluateOnePath(normalizePath(raw, cwd), kind, level, cwdNorm, trustedRoots);
			if (hit) best = worse(best, fromPathHit(hit));
		}
		return best;
	}

	// 扩展 / MCP 工具：路径类参数 + 恶意标记扫描
	const inferredWrite = /(write|edit|create|update|delete|remove|move|copy|save|put|upload|apply|patch)/i.test(toolName);
	for (const raw of collectPathArgs(input)) {
		const hit = evaluateOnePath(
			normalizePath(raw, cwd),
			inferredWrite ? "write" : "read",
			level,
			cwdNorm,
			trustedRoots,
		);
		if (hit) best = worse(best, fromPathHit(hit));
	}

	for (const value of Object.values(input ?? {})) {
		if (typeof value !== "string" || value.length === 0 || value.length > 8192) continue;
		for (const rule of MALICIOUS_CMD_RULES) {
			if (rule.re.test(value)) {
				best = worse(
					best,
					makeVerdict(
						"DENY",
						"iron.malicious",
						"safe.txt §4 LEVEL 4 PROHIBITED",
						rule.reason,
						rule.risk,
						value.slice(0, 300),
						true,
					),
				);
			}
		}
	}

	return best;
}
