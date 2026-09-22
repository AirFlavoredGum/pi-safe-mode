/**
 * safe-mode / paths.ts
 *
 * 全部 Safe Mode 路径的**唯一来源**。
 * policy.ts 与 loader.ts 都从这里取路径 —— 本模块不 import 它们，避免循环引用。
 *
 * 解析顺序（前一项优先；每一项都可以用环境变量显式覆盖）：
 *   1. `SAFE_MODE_ROOT`              显式根目录（最高优先）
 *   2. `SAFE_MODE_HOME` 的父目录      你只设了 home 时的反推
 *   3. `PI_CODING_AGENT_DIR` 的父目录  pi 自己导出的变量（推荐：零配置）
 *   4. 本模块自身的镜像位置            `<root>/agent/extensions/safe-mode/…` 反推
 *   5. 历史默认值                     `D:\pi-agent`（仅当该目录真实存在）
 *   6. 最后兜底                       `<homedir>/.pi-agent`
 *
 * 只解析路径，不猜策略、不猜哈希。解析结果通过 `SAFE_ROOT_SOURCE` 暴露给 `/safe doctor`，
 * 这样「为什么判到了别的目录」是可自查的，而不是黑箱。
 *
 * 平台支持见 `PLATFORM_SUPPORTED`：本版本的路径语义按 Windows 校验，非 Windows 会主动进入
 * DEGRADED（fail-closed），而不是假装路径保护仍然有效。
 */

import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** 本版本的路径语义按 Windows 校验（NTFS 大小写不敏感 + `D:\` 驱动器语义） */
export const IS_WINDOWS = process.platform === "win32";
export const PLATFORM_SUPPORTED = IS_WINDOWS;

/** 兼容旧布局的默认根目录（只在它真的存在时才会被采用） */
const LEGACY_ROOT = "D:\\pi-agent";

/**
 * 归一化成「比较用」的形式：统一 posix 分隔符、去掉尾部斜杠。
 * Windows 下额外小写化（NTFS 大小写不敏感）—— 必须与 checks.ts 的 normalizePath 保持一致，
 * 否则策略表里的路径正则匹配不上。
 */
export function toCanonicalPath(value: string): string {
	const posix = String(value ?? "")
		.trim()
		.replace(/^\\\\\?\\/, "")
		.replace(/\\/g, "/")
		.replace(/\/+$/, "");
	return IS_WINDOWS ? posix.toLowerCase() : posix;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * 由绝对路径构造边界正则：
 *   - 默认匹配「该路径本身 + 其下所有子孙」（`^/abs/path(/|$)`）
 *   - `exact: true` 时只匹配该路径本身
 *
 * 规则表统一走这个函数，避免在 policy.ts 里散落硬编码的机器相关路径。
 */
export function boundaryPathRe(absPath: string, opts: { exact?: boolean } = {}): RegExp {
	const base = escapeRegExp(toCanonicalPath(absPath));
	return opts.exact ? new RegExp(`^${base}$`) : new RegExp(`^${base}(/|$)`);
}

/**
 * 由「目录 + 子项片段正则」构造边界正则。片段按正则解释（例如 `safe-(bootstrap|launch|regen)`）。
 * 用于「同一个目录下只保护某一类文件」的情形。
 */
export function boundaryChildRe(dir: string, childPattern: string, opts: { exact?: boolean } = {}): RegExp {
	const tail = `${escapeRegExp(toCanonicalPath(dir))}/${childPattern}`;
	return opts.exact ? new RegExp(`^${tail}$`) : new RegExp(`^${tail}(/|$)`);
}

interface Guess {
	root: string;
	/** 给人看的来源说明（/safe doctor 会显示） */
	source: string;
}

/** 从本模块自身位置反推根目录：`<root>/agent/extensions/safe-mode/paths.ts` */
function rootFromOwnLocation(): Guess | undefined {
	try {
		const here = fileURLToPath(import.meta.url);
		const parts = here.split(/[\\/]/);
		const name = parts[parts.length - 1];
		if (!name || parts.length < 3) return undefined;
		const isMirrorLayout = parts[parts.length - 3] === "safe-mode" && parts[parts.length - 4] === "extensions";
		if (!isMirrorLayout) return undefined;
		return { root: dirname(dirname(dirname(here))), source: "own mirror location (<root>/agent/extensions/safe-mode)" };
	} catch {
		return undefined;
	}
}

function guessRoot(): Guess {
	const explicit = process.env.SAFE_MODE_ROOT;
	if (explicit && explicit.trim()) return { root: explicit.trim(), source: "env SAFE_MODE_ROOT" };

	const home = process.env.SAFE_MODE_HOME;
	if (home && home.trim()) return { root: dirname(home.trim()), source: "parent of env SAFE_MODE_HOME" };

	const agentDir = process.env.PI_CODING_AGENT_DIR;
	if (agentDir && agentDir.trim()) return { root: dirname(agentDir.trim()), source: "parent of env PI_CODING_AGENT_DIR" };

	const fromSelf = rootFromOwnLocation();
	if (fromSelf) return fromSelf;

	if (existsSync(LEGACY_ROOT)) return { root: LEGACY_ROOT, source: "legacy default (D:\\pi-agent exists)" };

	return { root: join(homedir(), ".pi-agent"), source: "fallback (<homedir>/.pi-agent)" };
}

const rootGuess = guessRoot();

/** 外部根：Safe Mode 的全部文件都在 Pi 安装目录（Pi Home）之外 */
export const SAFE_ROOT = rootGuess.root;
/** 根目录是怎么被判定的 —— 只在诊断里显示，不参与裁决 */
export const SAFE_ROOT_SOURCE = rootGuess.source;

/** Safe Mode 的家（策略源 / 清单 / 脚本 / 规范实现） */
export const SAFE_HOME = process.env.SAFE_MODE_HOME || join(SAFE_ROOT, "safe-mode");

/** Pi 的 agent 目录（配置 / 扩展 / 会话） */
export const AGENT_DIR = process.env.PI_CODING_AGENT_DIR || join(SAFE_ROOT, "agent");

/** 规范实现目录 —— 唯一会被镜像到 Pi 扩展目录的地方 */
export const SAFE_IMPL_DIR = join(SAFE_HOME, "pi-extension");
export const SAFE_POLICY_PATH = join(SAFE_HOME, "safe.txt");
export const SAFE_BACKUP_PATH = join(SAFE_HOME, "safe.txt.bak");
export const SAFE_MANIFEST_PATH = join(SAFE_HOME, "safe-manifest.json");
export const SAFE_LOG_PATH = join(SAFE_HOME, "safe-integrity.log");
export const SAFE_BOOTSTRAP_PATH = join(SAFE_HOME, "safe-bootstrap.ps1");
export const SAFE_LAUNCH_PATH = join(SAFE_HOME, "safe-launch.cmd");
export const SAFE_REGEN_PATH = join(SAFE_HOME, "safe-regen.ps1");
export const SAFE_README_PATH = join(SAFE_HOME, "README.md");

/** Pi 自动发现并加载的镜像（内容必须 = SAFE_IMPL_DIR） */
export const SAFE_MIRROR_DIR = process.env.SAFE_MODE_MIRROR || join(AGENT_DIR, "extensions", "safe-mode");

/** 等级状态文件（新开 pi 时的默认等级），**不**纳入 manifest */
export const SAFE_STATE_PATH = process.env.SAFE_MODE_STATE || join(SAFE_HOME, "safe-state.json");

/**
 * 决策审计日志。**不**纳入 manifest，也**不**放 pi-extension\。
 * 上限 2 MB，超过后轮转为 `safe-audit.jsonl.1`。
 */
export const SAFE_AUDIT_PATH = process.env.SAFE_MODE_AUDIT || join(SAFE_HOME, "safe-audit.jsonl");
export const SAFE_AUDIT_ROTATED_PATH = `${SAFE_AUDIT_PATH}.1`;

const PI_PACKAGE_REL = ["node_modules", "@earendil-works", "pi-coding-agent", "package.json"];
/** 历史布局下 Pi 安装目录里的 package.json 位置 */
const LEGACY_PI_PACKAGE = join(SAFE_ROOT, "current", ...PI_PACKAGE_REL);

/** 当前进程里能否解析到 pi 的 package.json（全局安装 / 其它布局时用） */
function piPackageFromResolver(): string | undefined {
	try {
		const require = createRequire(import.meta.url);
		return require.resolve("@earendil-works/pi-coding-agent/package.json");
	} catch {
		return undefined;
	}
}

/**
 * Pi 的 package.json —— 用来读取当前 Pi 版本（与 bootstrap 的 $PiPkg 一致）。
 * 依次尝试：环境变量 → 历史布局 → 模块解析。都失败时返回历史路径（不存在就当作「读不到版本」，
 * readPiVersion() 会返回 undefined，绝不猜版本号）。
 */
export const SAFE_PI_PACKAGE_PATH =
	process.env.SAFE_MODE_PI_PACKAGE || (existsSync(LEGACY_PI_PACKAGE) ? LEGACY_PI_PACKAGE : piPackageFromResolver() || LEGACY_PI_PACKAGE);

/**
 * Pi 运行时安装目录（`<install>/node_modules/@earendil-works/pi-coding-agent/package.json` 的第 3 层父目录）。
 * 认不出 `node_modules/@earendil-works/<pkg>` 结构时退回 `<root>/current`（历史布局）。
 */
function piInstallDir(): string {
	const resolved = SAFE_PI_PACKAGE_PATH.replace(/\\/g, "/");
	const parts = resolved.split("/");
	const idx = parts.lastIndexOf("node_modules");
	const looksLikeInstall = idx > 0 && parts[idx + 1]?.startsWith("@");
	if (looksLikeInstall) {
		const head = parts.slice(0, idx).join("/");
		if (head) return head;
	}
	return join(SAFE_ROOT, "current");
}

export const PI_INSTALL_DIR = piInstallDir();
