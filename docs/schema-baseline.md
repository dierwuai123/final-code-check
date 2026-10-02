# final_code_check — JSON 配置 Schema 与审计基线表结构

> v1.1 (2026-10-02)。配套 SKILL.md 三点五/三点六节使用：增量审核、阶段感知调度、二次验证 L1-L3、自进化机制。
> 设计原则：**append-only**（审计记录只追加不修改）、**可复现**（证据包 sha256 签名后可事后重跑验证）、**阶段感知**（S1-S4 强度递增）。

## 1. 总配置 schema（`fcc.config.json`）

放在项目根目录或 CI 配置目录，定义规则集版本与裁剪策略：

```json
{
  "schema_version": "1.1",
  "rule_pack_version": "1",
  "rule_pack_version_note": "规则集版本号；每次技能自进化 +1，写入基线快照，增量比对自动感知规则更新触发复检",
  "default_stage": "S2",
  "stages": {
    "S1": {
      "name": "prototype",
      "checks": ["T1-basic", "1", "2", "4"],
      "skip": ["P1", "P2", "P3", "P4", "P5", "T2-e2e", "T2-migration"],
      "canary": false,
      "verify": { "l1": true, "l2_sampling_pct": 0, "l3_evidence_pkg": false }
    },
    "S2": {
      "name": "feature-complete",
      "checks": ["T1", "T3", "1", "2", "3", "4", "5", "P1", "P2"],
      "skip": ["P3", "P4", "P5", "T2-fault-injection"],
      "canary": false,
      "verify": { "l1": true, "l2_sampling_pct": 5, "l3_evidence_pkg": false }
    },
    "S3": {
      "name": "pre-merge",
      "checks": ["T1", "T2", "T3", "T4", "1", "2", "3", "4", "5", "6", "7", "P1", "P2", "P4"],
      "optional_checks": ["P3"],
      "skip": [],
      "canary": true,
      "canary_scope": "changed-units-only",
      "verify": { "l1": true, "l2_sampling_pct": 15, "l3_evidence_pkg": false }
    },
    "S4": {
      "name": "release-gate",
      "checks": ["T1", "T2", "T3", "T4", "1", "2", "3", "4", "5", "6", "7", "P1", "P2", "P3", "P4", "P5"],
      "extra": ["fault-injection", "migration-drill", "backup-restore-drill", "md5-three-way"],
      "skip": [],
      "canary": true,
      "canary_scope": "changed-units-only",
      "verify": { "l1": true, "l2_sampling_pct": 30, "l2_sampling_pct_hazardous_boost": 50, "l3_evidence_pkg": true }
    }
  },
  "adjustments": {
    "force_add": [
      { "when_changed_contains": ["upload", "file-processing"], "add_checks": ["T4", "P3"] },
      { "when_changed_contains": ["auth", "permission", "tenant-isolation", "id-relation"], "add_checks": ["P2-idor"] }
    ],
    "force_skip": [
      { "when_only": "frontend-style-copy", "run_only": ["T1", "4"] },
      { "when_only": "docs-comments-readme", "run_only": ["6-doc-drift"] }
    ],
    "hazardous_keywords": ["auth", "idor", "upload", "sql"]
  },
  "incremental": {
    "ast_compare": true,
    "ast_compare_note": "AST 抽象语法树比对，非文本 md5；纯注释/空行/格式化改动视为无业务逻辑变更",
    "granularity": ["file", "function-or-route", "data-model"],
    "skip_if": ["code-unchanged", "last-audit-pass", "same-check-set"],
    "rerun_if": ["dependency-updated", "new-cve", "rule-pack-version-bumped"]
  }
}
```

## 2. 审计基线记录（单元级）

每个代码单元（文件/函数/路由）一条基线记录，存 `audit_baseline` 表：

```json
{
  "unit_id": "src/api/quote.py#create_quote",
  "git_commit_hash": "b56099b",
  "run_id": "fcc-run-20261002-001",
  "last_audit_version": "v1.1",
  "audit_result": "pass",
  "checked_items": ["T1", "1", "2", "4", "P1", "P2"],
  "canary_verified": true,
  "baseline_sign": "sha256(unit_code_hash + checked_items + rule_pack_version)"
}
```

字段说明：

| 字段 | 类型 | 说明 |
|---|---|---|
| unit_id | string | `path#symbol` 格式，函数/路由级粒度 |
| git_commit_hash | string | 审计时 commit |
| run_id | string | 关联本次运行记录（见 §4 runs 表） |
| last_audit_version | string | 审计套件版本 |
| audit_result | enum | `pass` / `fail` / `conditional` |
| checked_items | string[] | T1-T4 / 1-7 / P1-P5 编号 |
| canary_verified | bool | 是否经过 canary 校验 |
| baseline_sign | string | 增量比对签名：单元代码哈希 + 审核项清单 + 规则版本 |

**跳过判定**（SKILL.md 三点五 §1）：
- 代码无改动 + 上次 `pass` + 本次审核项集合与上次一致 → 复用结论，跳过
- 代码未改动但审核范围扩大 → 只补跑新增项
- 依赖/CVE/规则版本变更 → 代码不变也触发对应项复检
- 代码变更（AST 比对） → 按当前阶段全量跑

## 3. SQL 表结构（SQLite / PostgreSQL 通用）

```sql
-- 审计基线（单元级，append-only：只 INSERT，结论变更也 INSERT 新行）
CREATE TABLE IF NOT EXISTS audit_baseline (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unit_id TEXT NOT NULL,               -- path#symbol
  git_commit_hash TEXT NOT NULL,
  run_id TEXT NOT NULL,
  audit_version TEXT NOT NULL,         -- 套件版本 e.g. v1.1
  rule_pack_version INTEGER NOT NULL,  -- 规则集版本，自进化 +1
  audit_result TEXT NOT NULL CHECK (audit_result IN ('pass','fail','conditional')),
  checked_items TEXT NOT NULL,         -- JSON 数组
  canary_verified INTEGER NOT NULL DEFAULT 0,
  unit_code_hash TEXT,                 -- 单元代码内容 sha256（AST 归一化后）
  baseline_sign TEXT NOT NULL,         -- 增量比对签名
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_baseline_unit ON audit_baseline(unit_id, git_commit_hash);

-- 运行记录（每次终审一行）
CREATE TABLE IF NOT EXISTS fcc_runs (
  id TEXT PRIMARY KEY,                 -- fcc-run-YYYYMMDD-NNN
  stage TEXT NOT NULL CHECK (stage IN ('S1','S2','S3','S4')),
  trigger TEXT NOT NULL,               -- commit / pr / manual
  git_commit_hash TEXT NOT NULL,
  rule_pack_version INTEGER NOT NULL,
  config_hash TEXT NOT NULL,           -- 本次生效配置的 sha256（L1 配置基线校验用）
  checks_planned TEXT NOT NULL,        -- JSON 数组
  checks_executed TEXT NOT NULL,       -- JSON 数组（L1: planned ⊆ executed）
  changed_units TEXT NOT NULL,         -- JSON 数组，AST 提取的变更单元
  scanned_units TEXT NOT NULL,         -- JSON 数组，实际扫描单元（L1: changed ⊆ scanned）
  skipped_units TEXT NOT NULL,         -- JSON 数组，附上次审计签名
  verify_status TEXT NOT NULL CHECK (verify_status IN ('TRUSTED','SUSPICIOUS','UNTRUSTED')),
  pass_count INTEGER NOT NULL DEFAULT 0,
  fail_count INTEGER NOT NULL DEFAULT 0,
  canary_detected INTEGER NOT NULL DEFAULT 0,   -- canary 是否被审核代理抓到
  evidence_pkg_hash TEXT,              -- 证据包 sha256（L3）
  started_at TEXT NOT NULL,
  finished_at TEXT
);

-- 子检查项埋点日志（L1 流程完整性）
CREATE TABLE IF NOT EXISTS fcc_check_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES fcc_runs(id),
  check_item TEXT NOT NULL,            -- T1 / P2 / 2 等
  scope TEXT NOT NULL,                 -- JSON：扫描的文件/函数列表
  rule_pack_version INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','failed','crashed','skipped')),
  exit_code INTEGER,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  duration_ms INTEGER
);

-- 误报知识库（三点五误报抑制：false_positive 入库，同类模式自动跳过）
CREATE TABLE IF NOT EXISTS false_positive_kb (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,               -- 误报模式（文件模式/代码特征/扫描器规则 id）
  scanner TEXT,                        -- 来源扫描器（nikto / pip-audit / 自研…）
  reason TEXT NOT NULL,                -- 误报原因
  evidence TEXT NOT NULL,              -- 判定为误报的证据
  reviewed_by TEXT NOT NULL,           -- 复核人
  expires_at TEXT NOT NULL,            -- 有效期，禁止永久豁免
  validated_against TEXT,              -- 入库前用历史同类样本验证不会掩盖真漏洞
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 人工豁免清单（# final-check:ignore=XSS 标记的登记处）
CREATE TABLE IF NOT EXISTS waivers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unit_id TEXT NOT NULL,
  rule TEXT NOT NULL,                  -- e.g. XSS
  reason TEXT NOT NULL,
  granted_by TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);

-- 规则集版本（自进化：每次 patch 技能 +1）
CREATE TABLE IF NOT EXISTS rule_pack_versions (
  version INTEGER PRIMARY KEY,
  changes TEXT NOT NULL,               -- JSON：本次新增/修改的规则
  test_samples_hash TEXT NOT NULL,     -- 规则一致性测试样本哈希（主代理与复核代理对齐用）
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

**append-only 约束**：`audit_baseline` / `fcc_runs` / `fcc_check_logs` 禁 UPDATE/DELETE；结论变更=INSERT 新行（旧行保留），由 `run_id` + `created_at` 区分版本。

## 4. 运行结果记录（`fcc_runs` 示例行）

```json
{
  "id": "fcc-run-20261002-001",
  "stage": "S3",
  "trigger": "pr",
  "git_commit_hash": "b56099b",
  "rule_pack_version": 1,
  "config_hash": "sha256(fcc.config.json)",
  "checks_planned": ["T1","T2","T3","T4","1","2","3","4","5","6","7","P1","P2","P4"],
  "checks_executed": ["T1","T2","T3","T4","1","2","3","4","5","6","7","P1","P2","P4"],
  "changed_units": ["src/api/quote.py#create_quote", "src/models/quote.py"],
  "scanned_units": ["src/api/quote.py#create_quote", "src/models/quote.py"],
  "skipped_units": [{"unit": "src/api/user.py#login", "baseline_sign": "sha256:abc..."}],
  "verify_status": "TRUSTED",
  "pass_count": 42,
  "fail_count": 0,
  "canary_detected": 1,
  "evidence_pkg_hash": "sha256:...",
  "started_at": "2026-10-02T14:20:00",
  "finished_at": "2026-10-02T14:41:00"
}
```

## 5. 二次验证状态机（L1→L2→L3 对应字段）

```
初审完成
 └─ L1 流程完整性（fcc_runs + fcc_check_logs）
     ├─ checks_planned ⊆ checks_executed？
     ├─ changed_units ⊆ scanned_units？（不漏扫）
     ├─ 子任务全部 status=ok？（crashed/silent-fail → 作废）
     └─ config_hash 与固化基准一致？（防临时关高危检测）
          ↓ 全过
 └─ L2 结果复现
     ├─ confirmed 漏洞 100% 复现（独立第二套扫描器/独立环境重打 payload）
     ├─ canary_detected=1？（漏检 → 整轮作废）
     └─ pass 单元抽样盲盒（S2=5% S3=15% S4=30%，高危改动 50%）
          ↓ 全过
 └─ L3 证据包
     ├─ 打包原始输出 + payload 证据 + 报告 json
     ├─ sha256 签名 → evidence_pkg_hash 写入 fcc_runs
     └─ 基线 append-only 落库 → verify_status = TRUSTED
```

任一失败 → `verify_status` 置 `UNTRUSTED`（报告作废，阻断）；部分 suspect 不可复现 → `SUSPICIOUS`（不阻断，人工复核留痕）。

## 6. 数据流（触发→落库）

1. 触发（commit / PR / 手动跑 final_code_check）
2. 读 git diff + AST → 提取变更单元（file → function → data-model 三层）
3. 读 `audit_baseline` → 四态判定：跳过 / 补跑新增 / 规则更新复检 / 全跑
4. 识别阶段 S1-S4 + 改动类型 → 查 `fcc.config.json` 裁剪任务集 + adjustments 叠加/剔除
5. 执行：静态 → 单测/冒烟 → 可选 E2E/故障注入 → 可选 P 层（每个子项写 `fcc_check_logs`）
6. fail-closed 子代理过滤误报 → confirmed / suspect / false_positive（入库 `false_positive_kb`）
7. S3/S4：在变更范围埋 canary → 验增量审核真扫到变更区
8. L1→L2→L3 二次验证 → TRUSTED / SUSPICIOUS / UNTRUSTED
9. 生成报告 + INSERT `fcc_runs` / `audit_baseline` + 规则版本快照
10. 清理 canary 代码、渗透探针账号（清零确认）

## 7. Python 侧读写示例

```python
import hashlib, json

def baseline_sign(unit_code: str, checked_items: list, rule_pack_version: int) -> str:
    payload = json.dumps({
        "code": hashlib.sha256(unit_code.encode()).hexdigest(),
        "items": sorted(checked_items),
        "rpv": rule_pack_version,
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()

def should_skip(unit, baseline_row, current_items, current_rpv) -> str:
    """返回 skip / partial / rerule / full 之一（三点五 §1 四态）"""
    if unit.code_hash == baseline_row["unit_code_hash"]:
        if current_rpv != baseline_row["rule_pack_version"]:
            return "rerule"                       # 规则更新 → 对应项复检
        if set(current_items) <= set(baseline_row["checked_items"]) and baseline_row["audit_result"] == "pass":
            return "skip"                         # 复用上次结论
        return "partial"                          # 补跑新增项
    return "full"                                 # 代码变更 → 全量
```

> CI 嵌入：`fcc_runs.verify_status = 'TRUSTED'` 作为合并/发布门禁；`UNTRUSTED` 阻断；`SUSPICIOUS` 提醒不阻断。
