#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""前端全站逻辑校验（通用）。用法: python3 fe_check.py <HTML根目录> [--check-js] [--check-tags]
覆盖：内联script node check、危险API(eval/new Function/document.write/javascript:)、标签平衡、
疑似硬编码密钥。甄别库代码(PDF.js)与空链接(void(0))为无害。
误报模板：注释里孤立 "<script>" 会误导正则切块 → 判定为 FAIL 时先手工核对是否真 JS 块。"""
import re, subprocess, tempfile, os, sys, argparse

VOID = {"area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr"}
DANGER = [r"eval\s*\(", r"new\s+Function\s*\(", r"document\.write\s*\(", r"javascript\s*:"]

def main(root, do_js=True, do_tags=True):
    ext = (".html", ".htm")
    files = sorted(f for f in os.listdir(root) if f.endswith(ext))
    print(f"共 {len(files)} 个文件\n")
    js_fail, danger, tag_bad, hardcode = [], [], [], []
    for fn in files:
        p = os.path.join(root, fn)
        src = open(p, encoding="utf-8", errors="ignore").read()
        if do_js:
            for pat in DANGER:
                for m in re.finditer(pat, src):
                    danger.append(f"{fn}: {m.group(0)}")
        for m in re.finditer(r"(Bearer|api[_-]?key|apiKey|access[_-]?token|secret|password)\s*[:=]\s*[\"']([A-Za-z0-9._\-]{20,})[\"']", src):
            if "getenv" not in src[max(0,m.start()-80):m.start()]:
                hardcode.append(f"{fn}: {m.group(1)}=***")
        if do_tags:
            for tag in ["div","nav","script","section","span","table","ul"]:
                o = len(re.findall(rf"<{tag}[\s>]", src))
                c = len(re.findall(rf"</{tag}>", src))
                if o != c:
                    tag_bad.append(f"{fn}: <{tag}> open={o} close={c}")
        if do_js:
            for i, s in enumerate(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", src, re.S)):
                if not s.strip() or len(s) < 200:
                    continue
                with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
                    f.write(s); tmp = f.name
                r = subprocess.run(["node", "--check", tmp], capture_output=True, text=True)
                if r.returncode != 0:
                    # 定位到 HTML 行
                    idx = src.find(s)
                    ln = src[:idx].count("\n") + 1
                    js_fail.append(f"{fn} 内联script#{i}(约行{ln}): {r.stderr.splitlines()[-1][:120] if r.stderr else 'syntax?'}")
                os.unlink(tmp)
    print("=== JS 语法失败（node check）===")
    print("\n".join(js_fail) or "无 ✅")
    print("\n=== 危险 API（先甄别：库内/空链接=无害）===")
    print("\n".join(danger) or "无 ✅")
    print("\n=== 标签不平衡 ===")
    print("\n".join(tag_bad) or "无 ✅")
    print("\n=== 疑似硬编码密钥 ===")
    print("\n".join(hardcode) or "无 ✅")
    return len(js_fail)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--no-js", action="store_true")
    ap.add_argument("--no-tags", action="store_true")
    a = ap.parse_args()
    sys.exit(1 if main(a.root, do_js=not a.no_js, do_tags=not a.no_tags) else 0)