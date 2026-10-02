# final_code_check — 上线前「测试＋审查」终审套件

[English](README.en.md) | 中文

> 给 AI 写的代码做上线终审：实测型检查套件 + 渗透层，在真实生产 SaaS（Vue3 + FastAPI 多租户）上打磨，对照 ISO/IEC 25010 与 OWASP ASVS v4。

## 为什么需要

AI 编码代理写得快，坏得也快——手工 review 抓不住的：

- 修一个 bug 坏三个页面（共享 CSS / 公共组件 / 顺手重构）
- 看着全绿的测试，其实 mock 掉了要验的逻辑
- 「已完成」的说法根本没跑过
- 单测全过照样跨租户泄露数据

`final_code_check` 是**纪律，不是 linter**：8 大审查面 + 渗透实测层，从真实生产事故里提炼。

## 与同类工具的差异

| 常见审查工具 | final_code_check |
|---|---|
| 静态分析、读代码 | **实测型**：真打 JWT 篡改、双账号 IDOR、注入 payload |
| 采信「测试通过」 | **防假绿**：连测试本身都审（13 类成功伪装检测） |
| 采信审查员 | **Canary 金丝雀**：故意埋已知缺陷，测审查代理的漏报率 |
| 一次修一个 | **防「修这个坏那个」**：共享资源影响面清单 + 同类模式全库扫描 |
| 通用 | **项目配置隔离**：`references/<项目>.md` 存 SSH/容器/红线，核心零耦合 |

## 覆盖范围

- **T1–T4 测试面**：单测/API冒烟/回归/影响面清单、E2E/性能/故障注入/重启演练、防假绿、安全实测
- **1–7 审查面**：鉴权路由/越权/SSE、注入/密钥/CVE、前端 JS/CSS/缓存、生产三方 md5 一致性、合规红线、备份/回滚/kill-switch
- **P1–P5 渗透层**（差异化）：JWT 篡改四连、双账号 IDOR、存储型 XSS 读回、提示注入与 MCP 工具滥用、nikto/pip-audit/Trivy、管理面 fail-closed

## 使用

对 AI Agent 说：`跑 final_code_check` / `上线前检测` / `发布前检查`。完整流程（0-10 步）与行业对照见 [SKILL.md](SKILL.md)、[英文 README](README.en.md)；JSON 配置 schema 与审计基线表结构见 [docs/schema-baseline.md](docs/schema-baseline.md)。

## 增量审核 + 阶段感知调度（v1.1）

- **AST 比对增量跳过**：纯注释/空行/格式化改动不触发重审；函数级变更检测，未改动单元复用上次审计结论
- **S1–S4 阶段自动裁剪**：原型/功能完成/PR 前/发布门禁，按阶段自动匹配 T/P 审核子集，不盲目跑全套渗透
- **误报抑制**：代码标记豁免（带有效期）、上下文关联降级、子代理三分类输出（confirmed/suspect/false_positive）+ 误报知识库
- **二次验证 L1–L3**：流程完整性（不漏扫/不静默失败）→ 结果复现（confirmed 100% 复现 + pass 单元按阶段抽样 5%-30%）→ 证据包 sha256 存证，产出 TRUSTED / SUSPICIOUS / UNTRUSTED 门禁状态
- **自进化**：每轮终审收尾复盘新缺陷模式，当场升级技能，规则版本 +1 写入基线快照

前端校验脚本：

```bash
python3 scripts/fe_check.py <HTML根目录> --check-js --check-tags
```

## 贡献

欢迎 Issue（描述场景+期望行为）与 PR（逐条复核后合并）。Fork 自用随意——**勿提交你自己的 references/（含真实 IP/SSH/密钥）**。

## License

MIT
