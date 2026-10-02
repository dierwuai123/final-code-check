#!/usr/bin/env python3
"""fcc_incremental.py — final_code_check v1.1 增量审核核心引擎（SKILL.md 三点五/三点六 落地件）

能力：
  1. AST 变更检测：ast.dump 归一化哈希（注释/空行/格式化改动不触发重审），函数/类级粒度
  2. 增量四态判定：skip / partial(补跑新增项) / rerule(规则版本变更复检) / full(代码变更全跑)
  3. 阶段自动识别 S1-S4 + 按阶段裁剪审核任务集（可被 --stage 覆盖）
  4. 三层自检：L1 流程完整性 → L2 复现/canary/抽样 → L3 证据包 sha256 → TRUSTED/SUSPICIOUS/UNTRUSTED

用法：
  python3 fcc_incremental.py plan   --repo <目录> --db fcc.db [--stage S3] [--config fcc.config.json]
  python3 fcc_incremental.py verify --db fcc.db --run-id <id> [--finalize]
  python3 fcc_incremental.py selftest

仅依赖 Python 3.9+ 标准库。DB 表结构见 docs/schema-baseline.md（append-only）。
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import random
import re
import sqlite3
import sys
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_baseline (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unit_id TEXT NOT NULL, git_commit_hash TEXT NOT NULL, run_id TEXT NOT NULL,
  audit_version TEXT NOT NULL, rule_pack_version INTEGER NOT NULL,
  audit_result TEXT NOT NULL CHECK (audit_result IN ('pass','fail','conditional')),
  checked_items TEXT NOT NULL, canary_verified INTEGER NOT NULL DEFAULT 0,
  unit_code_hash TEXT, baseline_sign TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_baseline_unit ON audit_baseline(unit_id, git_commit_hash);
CREATE TABLE IF NOT EXISTS fcc_runs (
  id TEXT PRIMARY KEY, stage TEXT NOT NULL CHECK (stage IN ('S1','S2','S3','S4')),
  trigger TEXT NOT NULL, git_commit_hash TEXT NOT NULL, rule_pack_version INTEGER NOT NULL,
  config_hash TEXT NOT NULL, checks_planned TEXT NOT NULL, checks_executed TEXT NOT NULL,
  changed_units TEXT NOT NULL, scanned_units TEXT NOT NULL, skipped_units TEXT NOT NULL,
  verify_status TEXT NOT NULL CHECK (verify_status IN ('TRUSTED','SUSPICIOUS','UNTRUSTED','PENDING')),
  pass_count INTEGER NOT NULL DEFAULT 0, fail_count INTEGER NOT NULL DEFAULT 0,
  canary_detected INTEGER NOT NULL DEFAULT 0, evidence_pkg_hash TEXT,
  started_at TEXT NOT NULL, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS fcc_check_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES fcc_runs(id), check_item TEXT NOT NULL,
  scope TEXT NOT NULL, rule_pack_version INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','failed','crashed','skipped')),
  exit_code INTEGER, started_at TEXT NOT NULL, finished_at TEXT, duration_ms INTEGER
);
CREATE TABLE IF NOT EXISTS false_positive_kb (
  id INTEGER PRIMARY KEY AUTOINCREMENT, pattern TEXT NOT NULL, scanner TEXT,
  reason TEXT NOT NULL, evidence TEXT NOT NULL, reviewed_by TEXT NOT NULL,
  expires_at TEXT NOT NULL, validated_against TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS waivers (
  id INTEGER PRIMARY KEY AUTOINCREMENT, unit_id TEXT NOT NULL, rule TEXT NOT NULL,
  reason TEXT NOT NULL, granted_by TEXT NOT NULL, expires_at TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS rule_pack_versions (
  version INTEGER PRIMARY KEY, changes TEXT NOT NULL, test_samples_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

DEFAULT_CONFIG = {
    "rule_pack_version": 1,
    "stages": {
        "S1": {"checks": ["T1", "1", "2", "4"], "skip": ["P1", "P2", "P3", "P4", "P5", "T2", "T3"], "canary": False, "l2_pct": 0, "l3": False},
        "S2": {"checks": ["T1", "T3", "1", "2", "3", "4", "5", "P1", "P2"], "skip": ["P3", "P4", "P5", "T2"], "canary": False, "l2_pct": 5, "l3": False},
        "S3": {"checks": ["T1", "T2", "T3", "T4", "1", "2", "3", "4", "5", "6", "7", "P1", "P2", "P4"], "skip": [], "canary": True, "l2_pct": 15, "l3": False},
        "S4": {"checks": ["T1", "T2", "T3", "T4", "1", "2", "3", "4", "5", "6", "7", "P1", "P2", "P3", "P4", "P5"], "skip": [], "canary": True, "l2_pct": 30, "l3": True},
    },
    "adjustments": {
        "force_add": [{"when": ["upload", "file"], "add": ["T4", "P3"]}, {"when": ["auth", "permission", "tenant"], "add": ["P2"]}],
        "force_skip": [{"when_only": "docs-only", "run_only": ["6"]}],
    },
    "hazardous_keywords": ["auth", "idor", "upload", "sql"],
}


# ---------- 1. AST 单元提取（归一化哈希：注释/空行/格式化不敏感） ----------

def ast_units(root: str) -> dict[str, str]:
    """扫描目录下 *.py，返回 {unit_id: 归一化哈希}。unit_id = 相对路径#符号"""
    units: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", ".venv", "node_modules")]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            try:
                tree = ast.parse(open(path, encoding="utf-8").read())
            except SyntaxError:
                continue  # 语法错误文件由 T1/静态审查负责，这里跳过
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    units[f"{rel}#{node.name}"] = _norm_hash(node)
                elif isinstance(node, ast.ClassDef):
                    pass
                for sub in getattr(node, "body", []):
                    if isinstance(node, ast.ClassDef) and isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        units[f"{rel}#{node.name}.{sub.name}"] = _norm_hash(sub)
    return units


def _norm_hash(node: ast.AST) -> str:
    return hashlib.sha256(ast.dump(node).encode()).hexdigest()[:16]


# ---------- 2. 阶段自动识别（启发式，--stage 可覆盖） ----------

def detect_stage(repo: str, branch: str | None = None) -> str:
    if branch is None:
        r = os.popen(f"git -C {json.dumps(repo)} branch --show-current 2>/dev/null").read().strip()
        branch = r
    if branch and re.search(r"draft|wip|tmp", branch, re.I):
        return "S1"
    has_tests = os.path.isdir(os.path.join(repo, "tests")) or os.path.isdir(os.path.join(repo, "test"))
    has_mig = any(os.path.exists(os.path.join(repo, *cand)) for cand in
                  (("migrations",), ("alembic",), ("migrate",)))
    if branch in ("main", "master") or (branch or "").startswith("release"):
        return "S4" if has_tests else "S2"
    if has_tests and has_mig:
        return "S3"
    if has_tests:
        return "S2"
    return "S1"


# ---------- 3. 增量四态判定 ----------

def last_baseline(db: sqlite3.Connection, unit_id: str) -> sqlite3.Row | None:
    return db.execute(
        "SELECT * FROM audit_baseline WHERE unit_id=? ORDER BY created_at DESC, id DESC LIMIT 1", (unit_id,)
    ).fetchone()


def decide(unit_hash: str | None, base: sqlite3.Row | None, items: set[str], rpv: int) -> tuple[str, set[str]]:
    """返回 (判定, 需跑项)。四态：skip / partial / rerule / full"""
    if base is None or unit_hash is None or unit_hash != base["unit_code_hash"]:
        return "full", items
    if rpv != base["rule_pack_version"]:
        return "rerule", items
    prev = set(json.loads(base["checked_items"]))
    if base["audit_result"] == "pass" and items <= prev:
        return "skip", set()
    return "partial", items - prev


def build_plan(db, repo, cfg, stage, rpv):
    units = ast_units(repo)
    scfg = cfg["stages"][stage]
    items = set(scfg["checks"])
    plan = {"stage": stage, "rule_pack_version": rpv, "skip": [], "partial": [], "rerule": [], "full": [], "removed": []}
    base_units = {b["unit_id"] for b in db.execute("SELECT DISTINCT unit_id FROM audit_baseline")}
    for uid, h in sorted(units.items()):
        d, todo = decide(h, last_baseline(db, uid), items, rpv)
        plan[{"skip": "skip", "partial": "partial", "rerule": "rerule", "full": "full"}[d]].append(
            {"unit": uid, "run_items": sorted(todo) if todo else []})
    plan["removed"] = sorted(base_units - set(units))  # 基线里有、代码里没了（已删除单元）
    return plan, units


# ---------- 4. 三层自检 L1 → L2 → L3 ----------

def l1_integrity(db, run_id) -> tuple[bool, list[str]]:
    run = db.execute("SELECT * FROM fcc_runs WHERE id=?", (run_id,)).fetchone()
    if not run:
        return False, ["run 不存在"]
    bad = []
    planned = set(json.loads(run["checks_planned"]))
    executed = set(json.loads(run["checks_executed"]))
    if not planned <= executed:
        bad.append(f"L1: 计划未全执行 planned-executed={sorted(planned - executed)}")
    changed = set(json.loads(run["changed_units"]))
    scanned = set(json.loads(run["scanned_units"]))
    if not changed <= scanned:
        bad.append(f"L1: 变更区漏扫 changed-scanned={sorted(changed - scanned)}")
    logs = db.execute("SELECT * FROM fcc_check_logs WHERE run_id=?", (run_id,)).fetchall()
    logged = {l["check_item"] for l in logs}
    if planned - logged:
        bad.append(f"L1: 子项无埋点日志 {sorted(planned - logged)}")
    for l in logs:
        if l["status"] == "crashed":
            bad.append(f"L1: 子项 {l['check_item']} 崩溃无输出 → 结果作废")
    if bad:
        return False, bad
    return True, ["L1 通过：计划全执行、变更区全扫描、无静默崩溃"]


def l2_reproducibility(db, run_id, cfg) -> tuple[bool, list[str], dict]:
    run = db.execute("SELECT * FROM fcc_runs WHERE id=?", (run_id,)).fetchone()
    scfg = cfg["stages"][run["stage"]]
    bad, info = [], {}
    if scfg["canary"] and not run["canary_detected"]:
        bad.append(f"L2: {run['stage']} 要求 canary，但 canary_detected=0 → 整轮作废")
    pct = scfg["l2_pct"]
    passed = [r["unit_id"] for r in db.execute(
        "SELECT DISTINCT unit_id FROM audit_baseline WHERE run_id=? AND audit_result='pass'", (run_id,))]
    if pct and passed:
        rnd = random.Random(run_id)  # 种子=run_id，抽样可复现
        info["sampled_for_blind_rescan"] = sorted(rnd.sample(passed, max(1, int(len(passed) * pct / 100))))
    if bad:
        return False, bad, info
    return True, [f"L2 通过：canary={'已检出' if scfg['canary'] else '本阶段不要求'}，抽样比例 {pct}%"], info


def l3_evidence(db, run_id) -> str:
    """打包原始输出 → sha256。证据=埋点日志+运行行（原始，非美化报告）"""
    run = db.execute("SELECT * FROM fcc_runs WHERE id=?", (run_id,)).fetchone()
    logs = db.execute("SELECT * FROM fcc_check_logs WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
    payload = json.dumps({"run": dict(run), "logs": [dict(l) for l in logs]}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def finalize(db, run_id, cfg) -> dict:
    ok1, r1 = l1_integrity(db, run_id)
    if not ok1:
        status, reasons = "UNTRUSTED", r1
    else:
        ok2, r2, info = l2_reproducibility(db, run_id, cfg)
        if not ok2:
            status, reasons = "UNTRUSTED", r2
        else:
            run = db.execute("SELECT * FROM fcc_runs WHERE id=?", (run_id,)).fetchone()
            scfg = cfg["stages"][run["stage"]]
            if scfg["l3"]:
                h = l3_evidence(db, run_id)
                db.execute("UPDATE fcc_runs SET evidence_pkg_hash=? WHERE id=?", (h, run_id))
                status, reasons = "TRUSTED", r2 + [f"L3 证据包已签名 sha256={h[:12]}…"]
            else:
                status, reasons = "TRUSTED", r2
    db.execute("UPDATE fcc_runs SET verify_status=?, finished_at=? WHERE id=?",
               (status, _now(), run_id))
    db.commit()
    return {"status": status, "reasons": reasons}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- 5. CLI ----------

def cmd_plan(a):
    db = sqlite3.connect(a.db)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    cfg = json.load(open(a.config, encoding="utf-8")) if a.config and os.path.exists(a.config) else DEFAULT_CONFIG
    stage = a.stage or detect_stage(a.repo)
    plan, _ = build_plan(db, a.repo, cfg, stage, cfg["rule_pack_version"])
    print(json.dumps(plan, ensure_ascii=False, indent=2))


def cmd_verify(a):
    db = sqlite3.connect(a.db)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    cfg = DEFAULT_CONFIG
    if a.finalize:
        print(json.dumps(finalize(db, a.run_id, cfg), ensure_ascii=False, indent=2))
    else:
        ok, reasons = l1_integrity(db, a.run_id)
        print(json.dumps({"l1": {"ok": ok, "reasons": reasons}}, ensure_ascii=False, indent=2))


def cmd_selftest(_):
    import tempfile
    t = tempfile.mkdtemp(prefix="fcc_selftest_")
    db = sqlite3.connect(os.path.join(t, "fcc.db"))
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    # -- 场景1：注释/空行改动 → 同哈希 → skip
    src_v1 = "def quote(x):\n    return x * 2\n"
    src_v2 = "# 注释\n\ndef quote(x):\n    # 行内注释\n    return x * 2  # 尾注释\n"
    h1, h2 = _norm_hash(ast.parse(src_v1).body[0]), _norm_hash(ast.parse(src_v2).body[0])
    check("AST归一化: 注释/空行/格式化不改哈希", h1 == h2)
    row = {"unit_code_hash": h1, "rule_pack_version": 1, "audit_result": "pass",
           "checked_items": json.dumps(["T1", "1", "P2"])}
    d, todo = decide(h2, row, {"T1", "1", "P2"}, 1)
    check("四态: 未改动+pass+同项集 → skip", (d, todo) == ("skip", set()))
    # -- 场景2：逻辑改动 → full
    d, _ = decide(_norm_hash(ast.parse("def quote(x):\n    return x * 3\n").body[0]), row, {"T1"}, 1)
    check("四态: 代码变更 → full", d == "full")
    # -- 场景3：范围扩大 → partial 只跑新增
    d, todo = decide(h1, row, {"T1", "1", "P2", "P3"}, 1)
    check("四态: 范围扩大 → partial", d == "partial" and todo == {"P3"})
    # -- 场景4：规则版本升级 → rerule
    d, _ = decide(h1, row, {"T1", "1", "P2"}, 2)
    check("四态: 规则版本变更 → rerule", d == "rerule")
    # -- 场景5：阶段识别
    repo = tempfile.mkdtemp(prefix="fcc_repo_")
    os.makedirs(os.path.join(repo, "app"))
    open(os.path.join(repo, "app", "m.py"), "w").write(src_v1)
    check("阶段: 无测试 → S1", detect_stage(repo, branch="") == "S1")
    check("阶段: draft分支 → S1(即使有测试)", detect_stage(repo, branch="wip/quote") == "S1")
    os.makedirs(os.path.join(repo, "tests"))
    check("阶段: 有测试无迁移 → S2", detect_stage(repo, branch="feat/x") == "S2")
    check("阶段: main+测试 → S4", detect_stage(repo, branch="main") == "S4")
    # -- 场景6：plan 输出（基线放两单元，一未动一已删；注意此 db 也是后续 L1/L2/L3 场景的库）
    # 未动单元的基线必须覆盖 S2 完整任务集才判 skip（部分覆盖=partial 补跑，引擎按设计）
    s2_items = json.dumps(cfg["stages"]["S2"]["checks"])
    db.execute("INSERT INTO audit_baseline (unit_id,git_commit_hash,run_id,audit_version,rule_pack_version,"
               "audit_result,checked_items,unit_code_hash,baseline_sign) VALUES (?,?,?,?,?,?,?,?,?)",
               ("app/m.py#quote", "c0", "r0", "v1.1", 1, "pass", s2_items, h1, "s"))
    db.execute("INSERT INTO audit_baseline (unit_id,git_commit_hash,run_id,audit_version,rule_pack_version,"
               "audit_result,checked_items,unit_code_hash,baseline_sign) VALUES (?,?,?,?,?,?,?,?,?)",
               ("app/gone.py#dead", "c0", "r0", "v1.1", 1, "pass", s2_items, "x", "s"))
    open(os.path.join(repo, "app", "n.py"), "w").write("def fresh():\n    return 1\n")  # 新单元→full
    db.commit()
    plan, _ = build_plan(db, repo, cfg, "S2", 1)
    check("plan: 未动单元(基线全覆盖) → skip", any(u["unit"] == "app/m.py#quote" for u in plan["skip"]))
    check("plan: 新单元 app/n.py#fresh → full", any(u["unit"] == "app/n.py#fresh" for u in plan["full"]))
    check("plan: 已删单元进 removed", "app/gone.py#dead" in plan["removed"])
    # -- 场景7：L1 抓漏扫 + 崩溃
    db.execute("INSERT INTO fcc_runs (id,stage,trigger,git_commit_hash,rule_pack_version,config_hash,"
               "checks_planned,checks_executed,changed_units,scanned_units,skipped_units,verify_status,"
               "started_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
               ("r1", "S3", "pr", "c1", 1, "h", '["T1","P2"]', '["T1"]', '["a.py#f"]', '["b.py#g"]', "[]",
                "PENDING", _now()))
    db.execute("INSERT INTO fcc_check_logs (run_id,check_item,scope,rule_pack_version,status,exit_code,"
               "started_at) VALUES ('r1','T1','[]',1,'ok',0,?)", (_now(),))
    db.commit()
    ok, reasons = l1_integrity(db, "r1")
    check("L1: 漏扫+漏执行+漏日志 → 失败", not ok and len(reasons) >= 3)
    # -- 场景8：L2 抓 canary 漏检 → UNTRUSTED；补齐后 finalize → TRUSTED
    db.execute("UPDATE fcc_runs SET checks_executed='[\"T1\",\"P2\"]', scanned_units='[\"a.py#f\"]' WHERE id='r1'")
    db.execute("INSERT INTO fcc_check_logs (run_id,check_item,scope,rule_pack_version,status,exit_code,"
               "started_at) VALUES ('r1','P2','[\"a.py#f\"]',1,'ok',0,?)", (_now(),))
    db.commit()
    out = finalize(db, "r1", cfg)
    check("L2: S3 无 canary → UNTRUSTED", out["status"] == "UNTRUSTED")
    db.execute("UPDATE fcc_runs SET canary_detected=1 WHERE id='r1'")
    out = finalize(db, "r1", cfg)
    check("finalize: canary补齐 → TRUSTED", out["status"] == "TRUSTED")
    h_a, h_b = l3_evidence(db, "r1"), l3_evidence(db, "r1")
    check("L3: 证据包哈希可复现(确定性)", h_a == h_b)
    run = db.execute("SELECT verify_status, evidence_pkg_hash FROM fcc_runs WHERE id='r1'").fetchone()
    check("L3: S3 按设计不出证据包(l3=False)", run["evidence_pkg_hash"] is None and run["verify_status"] == "TRUSTED")

    fails = [n for n, ok_ in results if not ok_]
    for n, ok_ in results:
        print(("  PASS " if ok_ else "  FAIL ") + n)
    print(f"\nselftest: {len(results) - len(fails)}/{len(results)} passed")
    if fails:
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="final_code_check v1.1 incremental engine")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("plan"); sp.add_argument("--repo", required=True); sp.add_argument("--db", default="fcc.db")
    sp.add_argument("--stage"); sp.add_argument("--config"); sp.set_defaults(func=cmd_plan)
    sv = sub.add_parser("verify"); sv.add_argument("--db", default="fcc.db"); sv.add_argument("--run-id", required=True)
    sv.add_argument("--finalize", action="store_true"); sv.set_defaults(func=cmd_verify)
    ss = sub.add_parser("selftest"); ss.set_defaults(func=cmd_selftest)
    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
