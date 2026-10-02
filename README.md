# final_code_check — 上线前「测试＋审查」终审套件

通用、可配置的软件项目上线前**测试+审查**全覆盖套件。不限编程语言/框架/部署方式。

核心 = 独立 code review 子代理（fail-closed 只报真问题）+ 后端/API 测试（单测+冒烟+回归）+ 安全（注入/越权/上传/密钥）+ 依赖漏洞 + 生产一致性 + 前端 JS/CSS 校验 + 合规红线 + 渗透实测层（P1-P5），输出总报告。按改动范围裁剪执行。

对照标准：ISO/IEC 25010（8维质量模型）∩ OWASP ASVS v4 ∩ Release Readiness Checklist ∩ 测试金字塔。

## 特点

- **实测型，不是打勾型**：每个检查项给出 payload/命令+实际结果，注入/越权/JWT 篡改都真实打线上
- **防假绿**：测试代码本身也被审（mock 掉真逻辑、断言恒真、只测成功路径 = 不通过）；13 类「成功伪装」检测
- **审查质量自检（canary）**：故意埋已知缺陷测审查代理的漏报率，防止审查流于形式
- **防「修这个坏那个」**：影响面清单 + 同类模式全库扫描 + 根因先行纪律
- **项目专属配置隔离**：SSH/容器/命令/红线存 `references/<项目>.md`，套件本体零项目耦合

## 目录结构

```
final_code_check/
├── SKILL.md                      # 主技能：八大工作面 + P层渗透 + 执行流程 + 行业对照 + 坑
└── scripts/
    └── fe_check.py               # 前端全站校验：内联JS node check / 危险API / 标签平衡 / 硬编码密钥
```

## 安装（Claude Code / 兼容 Agent Skills 规范的运行时）

```bash
# 方式一：gh CLI（v2.90+）
gh skill install <owner>/final-code-check

# 方式二：手动
git clone https://github.com/<owner>/final-code-check.git
cp -r final-code-check / ~/.claude/skills/final_code_check/
```

## 快速使用

对 AI Agent 说：`跑 final_code_check` / `上线前检测` / `代码审查+安全审查` / `发布前检查`

或按流程手动执行：

```
0. 为项目建配置文件（自建、勿提交真实信息）
1. 环境核验 → 确认 git/容器/宿主三方一致
2. T1 测试套件 → 单测+API冒烟+回归+影响面清单
3. 独立 code review 子代理 → fail-closed 审改动（可加 canary 金丝雀自检）
4. 安全扫描 → 注入/越权/上传/密钥
5. P 层渗透实测 → P1 认证 + P2 越权(IDOR双账号) + P3 注入 必跑；P4 漏扫 + P5 信息泄露 按风险
6. 前端校验 / 依赖比对
7. 合规红线 + 数据隔离 + 文档漂移
8. git 提交前最终核对 → status 干净、md5 一致、测试全绿、探针数据清零
```

## 前端校验脚本用法

```bash
python3 scripts/fe_check.py <HTML根目录> --check-js --check-tags
# 输出：JS 语法失败 / 危险API（eval等，需甄别库代码）/ 标签不平衡 / 疑似硬编码密钥
```

## 引用与贡献

- 引用：README + SKILL.md + scripts/fe_check.py 即完整内容，可直接整包复制进你的 Agent 技能目录
- 反馈/修改意见：欢迎提 [Issue](../../issues)（描述场景+期望行为）；改动直接提 Pull Request，会逐条复核后合并
- **安全提示**：项目专属配置（SSH/IP/密钥）自建且加入 .gitignore，绝不提交
- Fork 自用随意；**注意 `references/` 目录用于你自己的项目配置时，不要提交真实 IP/密钥/密码**

## License

MIT
