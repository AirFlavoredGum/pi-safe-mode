/**
 * safe-mode / tests / harness.mjs
 *
 * 测试公共引导：自动发现「Pi 装在哪、jiti 在哪、实现目录在哪」，让测试不再绑定某台机器的路径。
 *
 * 与运行时同一套路径规则（见 ../paths.ts）：
 *   SAFE_MODE_ROOT → SAFE_MODE_HOME 的父目录 → PI_CODING_AGENT_DIR 的父目录 → 默认 D:\pi-agent
 *
 * 额外的测试专用覆盖：
 *   SAFE_TEST_IMPL_DIR   规范实现目录（默认：paths.ts 推导出的 SAFE_IMPL_DIR）
 *   SAFE_TEST_LOAD_DIR   e2e 要加载的那份实现（默认：镜像目录，即 pi 真正加载的那份）
 *   SAFE_TEST_JITI       jiti 的 lib/jiti.mjs 路径
 *   SAFE_TEST_PI_ROOT    @earendil-works/pi-coding-agent 包目录
 */
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const require = createRequire(import.meta.url);

export function fail(message, hint) {
	console.error(`\n[harness] ${message}`);
	if (hint) console.error(`          ${hint}`);
	process.exit(2);
}

const toPosix = (value) => String(value).replace(/\\/g, "/").replace(/\/+$/, "");
const isWindows = process.platform === "win32";

/** 与 paths.ts 的归一化规则一致：Windows 下小写（NTFS 大小写不敏感） */
export function canonical(value) {
	const posix = toPosix(value);
	return isWindows ? posix.toLowerCase() : posix;
}

// ---- 1) 找到 jiti（pi 自带一份；也支持本仓库 npm i 的那份）----
const agentDirGuess =
	process.env.PI_CODING_AGENT_DIR ||
	join(process.env.SAFE_MODE_ROOT || (existsSync("D:\\pi-agent") ? "D:\\pi-agent" : process.env.HOME || process.cwd()), "agent");

let jitiPath = process.env.SAFE_TEST_JITI;
if (!jitiPath) {
	const candidates = [
		join(agentDirGuess, "npm", "node_modules", "jiti", "lib", "jiti.mjs"),
		join(agentDirGuess, "node_modules", "jiti", "lib", "jiti.mjs"),
	];
	jitiPath = candidates.find((candidate) => existsSync(candidate));
}
if (!jitiPath) {
	try {
		jitiPath = require.resolve("jiti");
	} catch {
		jitiPath = undefined;
	}
}
if (!jitiPath || !existsSync(jitiPath)) {
	fail(
		`cannot find the jiti loader (looked under ${agentDirGuess}).`,
		"set SAFE_TEST_JITI=/path/to/jiti/lib/jiti.mjs, or run `npm i jiti` in this folder.",
	);
}

const { createJiti } = await import(pathToFileURL(jitiPath).href);

// ---- 2) 用 jiti 载入 paths.ts，拿到与运行时完全一致的路径推导 ----
const bootstrapJiti = createJiti(import.meta.url, { moduleCache: false });
const implDirDefault = join(dirname(fileURLToPath(import.meta.url)), "..");
const paths = await bootstrapJiti.import(pathToFileURL(join(implDirDefault, "paths.ts")).href);

if (!paths?.SAFE_POLICY_PATH) fail("could not load ../paths.ts through jiti", "check that pi-extension/paths.ts exists.");

export const implDir = toPosix(process.env.SAFE_TEST_IMPL_DIR || paths.SAFE_IMPL_DIR);
export const loadDir = toPosix(process.env.SAFE_TEST_LOAD_DIR || paths.SAFE_MIRROR_DIR);
export const mirrorDir = toPosix(paths.SAFE_MIRROR_DIR);
export const safeHome = toPosix(paths.SAFE_HOME);
export const safeRoot = toPosix(paths.SAFE_ROOT);
export const agentDir = toPosix(paths.AGENT_DIR);
export const policyPath = toPosix(paths.SAFE_POLICY_PATH);
export const manifestPath = toPosix(paths.SAFE_MANIFEST_PATH);
export const auditPath = toPosix(paths.SAFE_AUDIT_PATH);
export const statePath = toPosix(paths.SAFE_STATE_PATH);

/** 当前 Pi 的包目录（`dist/index.js` 所在目录的上一层是包根） */
export const piPackage = toPosix(paths.SAFE_PI_PACKAGE_PATH);
export const piRoot = process.env.SAFE_TEST_PI_ROOT
	? toPosix(process.env.SAFE_TEST_PI_ROOT)
	: dirname(toPosix(paths.SAFE_PI_PACKAGE_PATH));
if (!existsSync(piRoot)) {
	fail(
		`cannot find the pi package at ${piRoot}.`,
		"set SAFE_TEST_PI_ROOT=/path/to/node_modules/@earendil-works/pi-coding-agent, or set SAFE_MODE_ROOT.",
	);
}

/** 规范化后的根路径（与 checks.normalizePath 的输出同形式），供断言使用 */
export const ROOT = canonical(safeRoot);
/** 把 SAFE_ROOT 下的相对路径拼成规范化绝对路径：P("safe-mode/safe.txt") */
export const P = (relative) => canonical(`${safeRoot}/${relative}`);
/** 原始（未规范化）绝对路径，用于构造命令行样本 */
export const RAW = (relative) => `${safeRoot}/${relative}`;
export const isWin = isWindows;

// ---- 3) 创建加载主实现的 jiti 实例 ----
export const jiti = createJiti(import.meta.url, {
	moduleCache: false,
	alias: {
		"@earendil-works/pi-coding-agent": `${piRoot}/dist/index.js`,
		"@earendil-works/pi-agent-core": `${piRoot}/node_modules/@earendil-works/pi-agent-core/dist/index.js`,
		"@earendil-works/pi-tui": `${piRoot}/node_modules/@earendil-works/pi-tui/dist/index.js`,
	},
});

export function info() {
	console.log(`[harness] platform=${process.platform} root=${safeRoot} impl=${implDir} load=${loadDir}`);
}
