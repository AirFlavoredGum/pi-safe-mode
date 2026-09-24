/**
 * safe-mode / loader.ts
 *
 * 读取并校验策略源（safe.txt，路径由 paths.ts 解析），计算 hash，提供快路径签名。
 *
 * 遵守 方案.txt 第五节：safe.txt 不存在 / 不可读 / 格式有问题时，
 * **绝不假装 Safe Mode 正常工作** —— 返回结构化失败并附带原因。
 */

import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { isLevel, type Level, REQUIRED_SECTIONS } from "./policy.ts";

/**
 * 目录布局（全部 Safe Mode 文件都在 Safe Mode 家目录下，默认 <PI_ROOT>\safe-mode\）：
 *
 *   <safe-mode home>\                 <- Safe Mode 的家（Pi 更新碰不到）
 *     safe.txt                            <- 策略源（唯一权威）
 *     safe.txt.bak                        <- 人工回滚备份（不参与自动流程）
 *     safe-manifest.json                  <- 完整性基线（只存哈希）
 *     safe-state.json                     <- 可变状态：新开 pi 时的默认等级
 *     safe-integrity.log                  <- L1 校验日志
 *     safe-bootstrap.ps1 / safe-launch.cmd / safe-regen.ps1
 *     README.md
 *     pi-extension\                       <- 规范实现（**唯一镜像源**）
 *   <agent dir>\extensions\safe-mode\ <- Pi 自动发现并加载的镜像
 *
 * 所有的具体路径都在 paths.ts 里解析（SAFE_MODE_ROOT / SAFE_MODE_HOME / PI_CODING_AGENT_DIR
 * 可显式覆盖），loader 只 re-export，保证策略、清单、镜像三者对同一套路径达成一致。
 *
 * 关键：可变/自引用文件（manifest / state / log / 备份）**不能**放在 pi-extension\ 里，
 *      因为那目录会被递归哈希并镜像到 Pi 扩展目录：
 *        - manifest 会变成自哈希
 *        - state / log 每次变动 → 哈希永远不过 → 永久 DEGRADED
 *        - 策略源会出现两份副本 → 不再是「唯一权威源」
 */

/**
 * 路径全部来自 paths.ts（**唯一**路径解析处）：这里只做 re-export，保持既有导入方不受影响。
 * 解析顺序（SAFE_MODE_ROOT → PI_CODING_AGENT_DIR 的父目录 → 镜像自身位置 → 历史默认值）见 paths.ts。
 */
export * from "./paths.ts";
import {
	PLATFORM_SUPPORTED,
	SAFE_AUDIT_PATH,
	SAFE_AUDIT_ROTATED_PATH,
	SAFE_MANIFEST_PATH,
	SAFE_PI_PACKAGE_PATH,
	SAFE_POLICY_PATH,
	SAFE_STATE_PATH,
} from "./paths.ts";

/** 审计日志轮转阈值 */
export const AUDIT_MAX_BYTES = 2_000_000;

/** 本版本的路径语义是否经校验的平台（非 Windows 时 verifyIntegrity 会主动降级） */
export const SUPPORTED_PLATFORM = PLATFORM_SUPPORTED;

export interface PolicySection {
	num: number;
	title: string;
	/** 1-based 行号 */
	line: number;
}

export interface LoadedPolicy {
	ok: true;
	/** 原文（CRLF 归一化为 LF） */
	text: string;
	hash: string;
	bytes: number;
	mtimeMs: number;
	title: string;
	sections: PolicySection[];
	/** 摘要行：给状态卡显示 */
	summary: string;
}

export interface PolicyFailure {
	ok: false;
	error: string;
	detail: string;
}

export type PolicyLoadResult = LoadedPolicy | PolicyFailure;

export function sha256Text(text: string): string {
	return createHash("sha256").update(text, "utf8").digest("hex");
}

export function sha256File(path: string): string | undefined {
	try {
		if (!existsSync(path)) return undefined;
		return createHash("sha256").update(readFileSync(path)).digest("hex");
	} catch {
		return undefined;
	}
}

export function shortHash(hash: string | undefined): string {
	return hash ? hash.slice(0, 12) : "--------";
}

/**
 * 快路径签名：只有 mtime 或 size 变化时才需要重新 hash。
 */
export function policySignature(): string {
	try {
		const st = statSync(SAFE_POLICY_PATH);
		return `${st.mtimeMs}:${st.size}`;
	} catch {
		return "missing";
	}
}

const SECTION_RE = /^#\s+(\d+)\.\s+(.+?)\s*$/;

function parseSections(text: string): PolicySection[] {
	const out: PolicySection[] = [];
	const lines = text.split("\n");
	for (let i = 0; i < lines.length; i++) {
		const m = SECTION_RE.exec(lines[i]);
		if (m) {
			out.push({ num: Number.parseInt(m[1], 10), title: m[2], line: i + 1 });
		}
	}
	return out;
}

/**
 * 状态文件（`safe-state.json`）——**不是**策略源，只存两类用户偏好：
 *   · defaultLevel            启动默认等级
 *   · acknowledgedPiVersion   「版本漂移提醒」已被用户确认过的 Pi 版本
 * 读失败一律降级：策略裁决绝不依赖它。
 */
type SafeState = Record<string, unknown>;

function readStateFile(): { data: SafeState; error?: string } {
	if (!existsSync(SAFE_STATE_PATH)) return { data: {} };
	try {
		const parsed: unknown = JSON.parse(readFileSync(SAFE_STATE_PATH, "utf8").replace(/^\uFEFF/, ""));
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
			return { data: {}, error: "state file is not a JSON object" };
		}
		return { data: parsed as SafeState };
	} catch (error) {
		return { data: {}, error: `state file unreadable: ${error instanceof Error ? error.message : String(error)}` };
	}
}

/** 合并写回状态文件：只覆盖传入字段，其余原样保留 */
function writeStateFile(patch: SafeState): { ok: boolean; error?: string } {
	try {
		const { data } = readStateFile();
		const payload = { ...data, version: 2, ...patch, updatedAt: new Date().toISOString() };
		writeFileSync(SAFE_STATE_PATH, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
		return { ok: true };
	} catch (error) {
		return { ok: false, error: error instanceof Error ? error.message : String(error) };
	}
}

/**
 * 读取状态文件：启动默认等级 + 已确认过的 Pi 版本。
 * 兼容旧字段 `level`。
 */
export function loadState(): { level?: Level; acknowledgedPiVersion?: string; error?: string } {
	const { data, error } = readStateFile();
	const out: { level?: Level; acknowledgedPiVersion?: string; error?: string } = {};
	if (typeof data.acknowledgedPiVersion === "string" && data.acknowledgedPiVersion) {
		out.acknowledgedPiVersion = data.acknowledgedPiVersion;
	}
	const raw = data.defaultLevel ?? data.level;
	const value = typeof raw === "string" ? raw.toLowerCase() : undefined;
	if (value && isLevel(value)) {
		out.level = value;
	} else if (raw !== undefined) {
		out.error = `state file has an invalid default level: ${JSON.stringify(raw)}`;
	} else if (error) {
		out.error = error;
	}
	return out;
}

/** 写入**启动默认等级**（仅在用户显式执行 `/safe default <level>` 或 `/safe reset` 时触发） */
export function saveStateDefault(level: Level): { ok: boolean; error?: string } {
	return writeStateFile({ defaultLevel: level });
}

/**
 * 记录「这个 Pi 版本的漂移提醒已经被用户确认过」。
 * 只在用户显式做完完整性校验**且校验通过**时调用 —— 让提示里那句「请重跑 /safe verify」
 * 真的能生效（manifest 里的 piVersion 只有 safe-regen.ps1 会改写，否则提醒会每次开 pi 都重复）。
 */
export function saveAcknowledgedPiVersion(version: string): { ok: boolean; error?: string } {
	return writeStateFile({ acknowledgedPiVersion: version });
}

/**
 * 加载 safe.txt。
 * 校验项：
 *   1. 文件存在
 *   2. 可读且非空
 *   3. 含政策标题头
 *   4. REQUIRED_SECTIONS 至少 90% 存在（防止被替换成空壳或无关文件）
 */
export function loadPolicy(): PolicyLoadResult {
	if (!existsSync(SAFE_POLICY_PATH)) {
		return {
			ok: false,
			error: "Safe Mode cannot be reliably enabled because safe.txt could not be loaded.",
			detail: `policy file does not exist: ${SAFE_POLICY_PATH}`,		};
	}

	let raw: string;
	let rawBytes: Buffer;
	try {
		// 完整性基线必须是**原始字节**：PowerShell 侧 (Get-FileHash) 也是按字节算的，
		// 两边必须一致，否则会永久 DEGRADED。
		rawBytes = readFileSync(SAFE_POLICY_PATH);
		raw = rawBytes.toString("utf8");
	} catch (error) {
		return {
			ok: false,
			error: "Safe Mode cannot be reliably enabled because safe.txt could not be loaded.",
			detail: `read failed: ${error instanceof Error ? error.message : String(error)}`,
		};
	}

	const text = raw.replace(/\r\n/g, "\n").replace(/^\uFEFF/, "");
	if (text.trim().length === 0) {
		return {
			ok: false,
			error: "Safe Mode cannot be reliably enabled because safe.txt is empty.",
			detail: `policy file has zero content: ${SAFE_POLICY_PATH}`,
		};
	}

	const titleMatch = /^#\s+(PI SAFETY POLICY[^\n]*)$/m.exec(text) || /^#\s+(.+)$/m.exec(text);
	if (!titleMatch) {
		return {
			ok: false,
			error: "Safe Mode cannot be reliably enabled because safe.txt has an unusable format.",
			detail: "no top-level '# ' title line found",
		};
	}

	const sections = parseSections(text);
	const found = new Set(sections.map((s) => s.num));
	const missing = REQUIRED_SECTIONS.filter((s) => !found.has(s.num));
	const requiredRatio = (REQUIRED_SECTIONS.length - missing.length) / REQUIRED_SECTIONS.length;
	if (requiredRatio < 0.9) {
		return {
			ok: false,
			error: "Safe Mode cannot be reliably enabled because safe.txt has an unusable format.",
			detail:
				`missing ${missing.length}/${REQUIRED_SECTIONS.length} required sections: ` +
				missing.map((s) => `§${s.num} ${s.title}`).join(", "),
		};
	}

	let st: { mtimeMs: number; size: number };
	try {
		const s = statSync(SAFE_POLICY_PATH);
		st = { mtimeMs: s.mtimeMs, size: s.size };
	} catch {
		st = { mtimeMs: 0, size: Buffer.byteLength(text, "utf8") };
	}

	return {
		ok: true,
		text,
		hash: createHash("sha256").update(rawBytes).digest("hex"),
		bytes: Buffer.byteLength(text, "utf8"),
		mtimeMs: st.mtimeMs,
		title: titleMatch[1].trim(),
		sections,
		summary: `${titleMatch[1].trim()} · ${sections.length} sections · ${Buffer.byteLength(text, "utf8")} B`,
	};
}

/** 读取 manifest（可能不存在） */
export interface ManifestFile {
	path: string;
	sha256: string;
	bytes: number;
}

export interface Manifest {
	version: number;
	generatedAt: string;
	piVersion?: string;
	policyPath: string;
	policySha256: string;
	files: ManifestFile[];
}

/** manifest 里记录的 pi 版本（regen 时写入；老 manifest 没有这个字段） */
export interface ManifestMeta {
	version: number | undefined;
	generatedAt: string | undefined;
	piVersion: string | undefined;
}

/** 读取 manifest 元信息用于状态显示（不参与裁决） */
export function readManifestMeta(): ManifestMeta {
	const result = loadManifest();
	if (!result.ok) return { version: undefined, generatedAt: undefined, piVersion: undefined };
	const raw = result.manifest as Manifest & { piVersion?: unknown };
	return {
		version: typeof raw.version === "number" ? raw.version : undefined,
		generatedAt: typeof raw.generatedAt === "string" ? raw.generatedAt : undefined,
		piVersion: typeof raw.piVersion === "string" ? raw.piVersion : undefined,
	};
}

/** 当前 Pi 版本（读安装目录的 package.json；读不到返回 undefined，绝不猜） */
export function readPiVersion(): string | undefined {
	try {
		const parsed = JSON.parse(readFileSync(SAFE_PI_PACKAGE_PATH, "utf8").replace(/^\uFEFF/, "")) as { version?: unknown };
		return typeof parsed?.version === "string" ? parsed.version : undefined;
	} catch {
		return undefined;
	}
}

/**
 * 追加一条审计记录。
 * 绝不影响拦截：任何失败都被吞掉。调用方必须已经做过秘密脱敏。
 */
export function appendAudit(entry: Record<string, unknown>): void {
	try {
		try {
			if (statSync(SAFE_AUDIT_PATH).size > AUDIT_MAX_BYTES) renameSync(SAFE_AUDIT_PATH, SAFE_AUDIT_ROTATED_PATH);
		} catch {
			/* 文件不存在 → 直接写 */
		}
		appendFileSync(SAFE_AUDIT_PATH, `${JSON.stringify(entry)}\n`, "utf8");
	} catch {
		/* 审计写失败绝不能改变裁决结果 */
	}
}

/** 读取审计日志尾部（给人看，最多 maxLines 行） */
export function readAuditTail(maxLines = 20): string[] {
	try {
		const text = readFileSync(SAFE_AUDIT_PATH, "utf8");
		const lines = text.split("\n").filter((line) => line.trim().length > 0);
		return lines.slice(-maxLines);
	} catch {
		return [];
	}
}

/** 审计日志当前大小（字节），不存在返回 0 */
export function auditSize(): number {
	try {
		return statSync(SAFE_AUDIT_PATH).size;
	} catch {
		return 0;
	}
}

export function loadManifest(): { ok: true; manifest: Manifest } | { ok: false; error: string } {	if (!existsSync(SAFE_MANIFEST_PATH)) {
		return { ok: false, error: `manifest missing: ${SAFE_MANIFEST_PATH}` };
	}
	try {
		const parsed = JSON.parse(readFileSync(SAFE_MANIFEST_PATH, "utf8").replace(/^\uFEFF/, "")) as Manifest;
		if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.files)) {
			return { ok: false, error: "manifest root is not a valid object with a files[] array" };
		}
		return { ok: true, manifest: parsed };
	} catch (error) {
		return {
			ok: false,
			error: `manifest unreadable: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
}
