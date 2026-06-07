#!/usr/bin/env python3
"""
cleanup.py
----------
تشغيلي هذا من داخل مجلد المشروع:
    cd ~/Desktop/gradution_project
    python3 cleanup.py

يحذف كل الملفات الميتة والمكررة والـ garbage.
"""

import os
import shutil
from pathlib import Path

BASE = Path(__file__).parent
removed = []
skipped = []


def rm_file(path: str, reason: str):
    p = BASE / path
    if p.exists():
        p.unlink()
        removed.append(f"  [DEL] {path}  ({reason})")
    else:
        skipped.append(f"  [SKIP] {path} not found")


def rm_dir(path: str, reason: str):
    p = BASE / path
    if p.exists():
        shutil.rmtree(p)
        removed.append(f"  [DEL DIR] {path}  ({reason})")
    else:
        skipped.append(f"  [SKIP DIR] {path} not found")


def rm_glob(pattern: str, reason: str):
    for p in BASE.rglob(pattern):
        if ".git" in str(p) or "venv" in str(p):
            continue
        p.unlink()
        removed.append(f"  [DEL] {p.relative_to(BASE)}  ({reason})")


print("=" * 60)
print("  Graduation Project — Cleanup Script")
print("=" * 60)

# ── 1. Dead root-level module files (duplicated by sub-packages) ──
print("\n[1] Removing dead root-level module files...")
dead_modules = [
    ("modules/recon.py",            "replaced by modules/recon/"),
    ("modules/scanner.py",          "replaced by modules/scanner/"),
    ("modules/vuln_mapper.py",      "replaced by modules/vulnerability/"),
    ("modules/post_exploit.py",     "replaced by modules/post_exploitation/"),
    ("modules/reporter.py",         "replaced by modules/reporting/"),
    ("modules/exploiter.py",        "replaced by modules/exploiter/"),
    ("modules/mitre_mapper.py",     "replaced by modules/mitre/"),
    ("modules/ai_exploiter.py",     "dead — zero imports"),
    ("modules/exploit_prioritizer.py", "dead — duplicate of exploit_ranker"),
    ("modules/post_exploit_ai.py",  "dead — zero imports"),
]
for path, reason in dead_modules:
    rm_file(path, reason)

# ── 2. Duplicate/garbage files inside mitre/ ─────────────────────
print("\n[2] Cleaning mitre/ duplicates and garbage...")
for name in [
    "modules/mitre/mitre_engine.py ",   # trailing space
    "modules/mitre/ml_classifier.py ",  # trailing space
    "modules/mitre/ml_classifier.py.save",
    "modules/mitre/ml_classifier.py.save.1",
]:
    rm_file(name, "duplicate/garbage file")

# Also handle via glob for safety
for p in (BASE / "modules/mitre").iterdir():
    if p.name.endswith(" ") or p.suffix in (".save",) or p.name.endswith(".save.1"):
        p.unlink()
        removed.append(f"  [DEL] modules/mitre/{p.name}  (garbage)")

# ── 3. Duplicate requirements.txt (with trailing space) ──────────
print("\n[3] Removing duplicate requirements.txt...")
req_dup = BASE / "requirements.txt  "
if req_dup.exists():
    req_dup.unlink()
    removed.append("  [DEL] requirements.txt  (duplicate with trailing space)")

# Also check for any requirements file with spaces in name
for p in BASE.iterdir():
    if "requirements" in p.name and p.name != "requirements.txt":
        p.unlink()
        removed.append(f"  [DEL] {p.name}  (duplicate requirements)")

# ── 4. Empty/junk directories ─────────────────────────────────────
print("\n[4] Removing empty/junk directories...")
rm_dir("modules/engine", "empty directory")
rm_dir("modules/Risk",   "empty directory (wrong case)")

# ── 5. CRITICAL — SSH keys accidentally in project root ──────────
print("\n[5] Removing accidentally committed SSH key files...")
for key_file in ["l", "l.pub"]:
    rm_file(key_file, "⚠️  SSH KEY — security risk!")

# ── 6. Python cache cleanup ───────────────────────────────────────
print("\n[6] Cleaning __pycache__ directories...")
for pycache in BASE.rglob("__pycache__"):
    if "venv" not in str(pycache):
        shutil.rmtree(pycache)
        removed.append(f"  [DEL DIR] {pycache.relative_to(BASE)}")

# ── 7. .pyc files ────────────────────────────────────────────────
rm_glob("*.pyc", "compiled bytecode")

# ── 8. Temp/editor files ─────────────────────────────────────────
print("\n[7] Cleaning editor/temp files...")
for pattern in ["*.swp", "*.swo", "*~", ".DS_Store", "Thumbs.db"]:
    rm_glob(pattern, "editor/temp file")

# ── 9. Verify mitre/ coverage_analyzer missing ───────────────────
print("\n[8] Checking for missing files...")
required = [
    "modules/mitre/coverage_analyzer.py",
    "modules/mitre/rule_resolver.py",
    "modules/mitre/stix_resolver.py",
    "modules/mitre/technique_merger.py",
    "modules/mitre/tactic_statistics.py",
    "modules/mitre/technique_statistics.py",
    "modules/mitre/confidence_fusion.py",
    "modules/mitre/heatmap_generator.py",
    "modules/mitre/chain_builder.py",
    "database/__init__.py",
    "database/models/__init__.py",
    "database/repository.py",
]
missing = []
for f in required:
    if not (BASE / f).exists():
        missing.append(f)
        print(f"  [MISSING] {f}")

# ── Summary ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
print(f"  REMOVED : {len(removed)} items")
print(f"  SKIPPED : {len(skipped)} items (not found)")
if missing:
    print(f"  MISSING : {len(missing)} required files — check list above")
else:
    print(f"  MISSING : none ✓")
print("=" * 60)

for line in removed:
    print(line)

if skipped:
    print("\n--- Skipped (already clean) ---")
    for line in skipped:
        print(line)

if missing:
    print("\n⚠️  Missing files need to be created!")
    for f in missing:
        print(f"   → {f}")

print("\n✅ Cleanup complete.")

# ── Security warning ─────────────────────────────────────────────
if any("SSH KEY" in r for r in removed):
    print("""
⚠️  WARNING: SSH key files were found in your project root.
   If you pushed to GitHub, your private key may be exposed.
   Run immediately:
     git filter-branch --force --index-filter \\
       'git rm --cached --ignore-unmatch l l.pub' \\
       --prune-empty --tag-name-filter cat -- --all
   Then rotate your SSH key!
""")
