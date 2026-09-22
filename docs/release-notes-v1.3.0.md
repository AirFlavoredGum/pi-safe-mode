# v1.3.0 — HARD-OFF 进入设置面板

> HARD-OFF becomes a first-class item in the `/safe` panel — still behind the same two-step
> human confirmation. Release tag: `v1.3.0`.

---

## 一句话

完全关闭以前只有「知道命令才能用」；现在它就在 `/safe` 面板里，**和四个等级并排**，
但打开它仍然要你本人过两道确认 —— 更好找，没有更好骗。

---

## 面板现在长这样

```
🛡 Safe Mode 设置 · v1.3.0

当前等级：🔵 平衡（本窗口一直有效）
新开 pi 时：🔵 平衡

选一个等级就切换。带 ✅ 的是当前生效的。
↑↓ 选择 · 回车确认 · Esc 关闭

　 ⭕ 关闭（OFF）—— 只留最基本保护（凭据、窃取、恶意行为仍然拦）
　 🟢 低（LOW）—— 开发最顺畅，几乎不弹窗
✅ 🔵 平衡（BALANCED）—— 日常推荐：普通开发自动执行，危险操作问一下
　 🟠 严格（STRICT）—— 陌生项目、第三方代码、复杂命令时用
　 ⛔ 完全关闭（HARD-OFF）—— 不拦截 / 不注入 / 不审计 / 不脱敏（需两步确认）
────────────────────────────────
　⭐ 让新开的 pi 也用「平衡」
　ℹ️ 查看简版状态
　🔧 查看详细状态（技术信息）
```

处于 HARD-OFF 时，面板会变成：

- 标题显示 `当前状态：⛔ 完全关闭（HARD-OFF）—— 本窗口不拦截、不注入、不审计、不脱敏`
- ✅ 落在 ⛔ 那一行，四个等级都不再标 ✅（因为此刻**没有任何等级在生效**）
- 此时选任一等级 = **恢复保护**（会自动重读 safe.txt + 重新做完整性校验 + 重装子代理上限）

---

## 安全性质没有放松

| 保证 | 是否仍然成立 |
| --- | --- |
| 只有真人能开启（模型无法调用 `/safe`） | ✅ |
| 面板里选 ⛔ 也要**确认框 + 键入「完全关闭」**两步 | ✅ |
| 不能通过 `/safe <level>` 设置 HARD-OFF，也不能成为新开 pi 的默认值 | ✅ |
| 永不持久化（重启即回到配置等级） | ✅ |
| 状态栏徽标始终可见（`🛡 SAFE: HARD-OFF — no protection`） | ✅ |
| 模型不得开启 / 建议开启 / 拿它绕过被拒绝的操作（§38） | ✅ |

面板只是让开关**更容易被找到**，不是让它更容易被触发 —— 这是刻意的：一个藏起来的逃生口
会诱使人去网上找命令；一个摆在那里的逃生口，配上两道确认，反而是更安全的设计。

---

## 其他

- `SAFE_MODE_VERSION` → `1.3.0`；`safe.txt` §38 补上面板这条入口（并明确「面板是找开关的捷径，不是绕过检查的捷径」）
- `safe.txt` 内容变了 → **必须重新生成清单**（`safe-regen.ps1`，键入 `yes`），否则 `/safe verify` 会报 DEGRADED
- 测试：新增 11 项面板检查（⛔ 与四个等级并排、顺序在 STRICT 之后、确认词错误仍保持保护、
  两步确认才生效、HARD-OFF 时标题/✅ 状态正确、四个等级仍在列、选等级即恢复）
  —— **engine 102 项 + e2e 181 项全部通过**
- `Ctrl+Alt+S` 行为不变：HARD-OFF 下它只会**恢复**，绝不会把保护关得更彻底

---

## 升级

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File <repo>\install.ps1 -Root <pi root> -Force
powershell -NoProfile -File <pi root>\safe-mode\safe-bootstrap.ps1 -Fix
powershell -NoProfile -File <pi root>\safe-mode\safe-regen.ps1     # 键入 yes
powershell -NoProfile -File <pi root>\safe-mode\safe-bootstrap.ps1 -VerifyOnly   # 期望 RESULT: OK
```

然后重启 pi（或 `/reload`）→ `/safe doctor` 应显示 `v1.3.0 · MODE: ENFORCING · Integrity: integrity OK`。

---

## English summary

**HARD-OFF is now an item in the `/safe` panel, sitting next to the four levels.**

- Selecting it still requires the two-step human confirmation (dialog **plus** a typed word) —
  the panel makes the switch easier to *find*, not easier to *trigger*.
- While HARD-OFF is active the panel reflects it: the title says so, the ✅ moves to the HARD-OFF
  row, and no level is marked active. Choosing any level re-arms the layer.
- It remains session-scoped, never persisted, and impossible for the model to enable.
- 11 new panel checks; 102 engine + 181 end-to-end checks all pass.
