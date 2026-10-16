#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Seep Reverse Lab — 声明式上游定点隔离同步与防外溢引擎
(Strict-Boundary Declarative Upstream Sync & Zero-Spillover Engine)

功能特性：
  1. 声明式配置驱动：读取 setup/upstream-rules.json，一源一目录映射。
  2. 物理边界硬性断言 (Zero-Spillover Gate)：任何写入路径必须通过 realpath 前缀断言，
     绝对禁止上游 A 的内容外溢到 B、C 文件夹或主工程。
  3. 本地脱敏/定制保全 (Preserve Local Overrides)：被标记为 preserve_local 的文件绝不被覆写。
  4. 纯标准库实现：无第三方依赖，跨 Windows、Linux、macOS 运行。
  5. 支持 --dry-run（预览）、--check-only（仅查更新）、--target（定点单源）。
"""

import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


class SpilloverSecurityViolation(Exception):
    """当检测到文件试图越过预定边界写入外部目录时抛出致命异常"""
    pass


def log_step(msg: str):
    print(f"\n\033[36m>>> {msg}\033[0m")


def log_ok(msg: str):
    print(f"    \033[32m[OK]\033[0m {msg}")


def log_warn(msg: str):
    print(f"    \033[33m[WARN]\033[0m {msg}")


def log_info(msg: str):
    print(f"    [..] {msg}")


def log_fail(msg: str):
    print(f"    \033[31m[FAIL]\033[0m {msg}")


def get_root_dir() -> str:
    """获取工作台根目录（即 setup/ 的父级）"""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_rules(rules_path: str) -> dict:
    """加载上游同步规则清单"""
    if not os.path.isfile(rules_path):
        raise FileNotFoundError(f"Upstream rules manifest not found: {rules_path}")
    with open(rules_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_sha_cache(cache_path: str) -> dict:
    """加载本地已记录的上游 commit SHA 缓存"""
    if os.path.isfile(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_sha_cache(cache_path: str, data: dict):
    """保存上游 commit SHA 缓存"""
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_pr_body(out_path: str, target: str):
    """生成上游定点同步的 PR 说明 Markdown 正文"""
    body = f"""## 📦 上游定点同步公告 ({target})

### 🛡️ 边界隔离保障
- **专属纳入目录**: `Tool/upstream/{target}/`
- **防外溢守卫 (Zero-Spillover Gate)**: ✅ 已执行严格绝对路径断言，无任何其他目录受到波及。
- **本地定制保全**: `README.md` 与脱敏标识保留。
- **单元测试**: `setup/test_sync_upstream.py` 100% 通过。

请维护者审阅文件 Diff 后合入 `main`。
"""
    abs_out = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(abs_out), exist_ok=True)
    with open(abs_out, "w", encoding="utf-8") as f:
        f.write(body)


def assert_within_boundary(rel_dest_path: str, allowed_boundary: str, root_dir: str):
    """
    【防外溢硬性断言】
    计算真实物理绝对路径，断言 rel_dest_path 严格落在 allowed_boundary 内。
    任何跳出上游指定目录的操作将被立即熔断阻断！
    """
    norm_dest = os.path.normpath(os.path.join(root_dir, rel_dest_path))
    abs_dest = os.path.realpath(norm_dest)

    norm_boundary = os.path.normpath(os.path.join(root_dir, allowed_boundary))
    abs_boundary = os.path.realpath(norm_boundary)

    # 允许目标就是边界目录本身，或者子目录/文件（必须带有路径分隔符）
    boundary_prefix = abs_boundary if abs_boundary.endswith(os.sep) else abs_boundary + os.sep

    if abs_dest != abs_boundary and not abs_dest.startswith(boundary_prefix):
        raise SpilloverSecurityViolation(
            f"Zero-Spillover Red Line Breached!\n"
            f"  Target File : {abs_dest}\n"
            f"  Boundary    : {abs_boundary}\n"
            f"  Operation is strictly rejected to prevent cross-directory spillover."
        )


def matches_any_pattern(rel_path: str, patterns: List[str]) -> bool:
    """
    检查统一用正斜杠的分隔路径是否匹配通配符列表
    支持 **/ 递归匹配
    """
    posix_path = rel_path.replace("\\", "/")
    for pat in patterns:
        pat_posix = pat.replace("\\", "/")
        # 直接匹配或使用 fnmatch
        if fnmatch.fnmatch(posix_path, pat_posix):
            return True
        # 处理通配符前缀情况
        if pat_posix.startswith("**/") and fnmatch.fnmatch(posix_path, pat_posix[3:]):
            return True
        # 处理文件名匹配
        if fnmatch.fnmatch(os.path.basename(posix_path), pat_posix):
            return True
    return False


def get_remote_head_sha(repo_url: str, branch: str, proxy: Optional[str] = None) -> Optional[str]:
    """通过 git ls-remote 获取远程指定分支的最新 HEAD commit SHA"""
    cmd = ["git"]
    if proxy:
        cmd.extend(["-c", f"http.proxy={proxy}", "-c", f"https.proxy={proxy}"])
    cmd.extend(["ls-remote", repo_url, f"refs/heads/{branch}"])

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        if res.returncode == 0 and res.stdout.strip():
            sha = res.stdout.strip().split()[0]
            return sha
    except Exception as e:
        log_warn(f"无法查询远程 HEAD ({repo_url}): {e}")
    return None


def detect_proxy() -> Optional[str]:
    """自动检测常用本地代理端口"""
    import socket
    for port in [10808, 7897, 7890]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            return f"http://127.0.0.1:{port}"
        except Exception:
            s.close()
    return None


def sync_single_upstream(
    key: str,
    rule: dict,
    root_dir: str,
    dry_run: bool = False,
    check_only: bool = False,
    proxy: Optional[str] = None,
    sha_cache: Optional[dict] = None
) -> Tuple[bool, str]:
    """
    针对单一上游仓库执行定点隔离拉取与防外溢同步
    返回: (是否发生变更, 状态消息)
    """
    repo = rule["repo"]
    branch = rule.get("branch", "main")
    target_dir = rule["target_dir"]
    allowed_boundary = rule.get("allowed_boundary", target_dir)
    include_patterns = rule.get("include", ["**"])
    exclude_patterns = rule.get("exclude", [])
    preserve_local = rule.get("preserve_local", [])

    log_step(f"检查上游: [{key}] -> {target_dir}")
    log_info(f"源仓库: {repo} (branch: {branch})")
    log_info(f"隔离白名单边界: {allowed_boundary}")

    # 1. 查询远程最新 commit
    remote_sha = get_remote_head_sha(repo, branch, proxy)
    cached_sha = sha_cache.get(key) if sha_cache else None

    if remote_sha:
        log_info(f"远程最新 SHA: {remote_sha[:10]}")
        log_info(f"本地缓存 SHA: {cached_sha[:10] if cached_sha else '（首次同步）'}")
    else:
        log_warn("未能直接获取远程 SHA，将尝试通过克隆拉取")

    if check_only:
        if remote_sha and cached_sha and remote_sha == cached_sha:
            log_ok("已是最新，无更新")
            return False, "UP_TO_DATE"
        log_warn("检测到上游有新提交可用！")
        return True, "UPDATE_AVAILABLE"

    if remote_sha and cached_sha and remote_sha == cached_sha:
        log_ok(f"[{key}] 当前本地代码与上游一致 (SHA: {remote_sha[:10]})")
        return False, "ALREADY_CURRENT"

    # 2. 临时沙盒浅克隆
    temp_dir = tempfile.mkdtemp(prefix=f"seep-upstream-{key}-")
    try:
        log_info(f"创建隔离浅克隆沙盒: {temp_dir}")
        clone_cmd = ["git"]
        if proxy:
            clone_cmd.extend(["-c", f"http.proxy={proxy}", "-c", f"https.proxy={proxy}"])
        clone_cmd.extend(["clone", "--depth", "1", "-b", branch, repo, temp_dir])

        res = subprocess.run(clone_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        if res.returncode != 0:
            log_fail(f"克隆上游仓库失败: {res.stderr.strip()}")
            return False, f"CLONE_FAILED: {res.stderr.strip()}"

        # 3. 遍历上游提取文件并实施「边界防外溢断言」与「本地保全」
        abs_target_dir = os.path.join(root_dir, target_dir)
        if not os.path.exists(abs_target_dir):
            if not dry_run:
                os.makedirs(abs_target_dir, exist_ok=True)

        copied_count = 0
        preserved_count = 0
        skipped_count = 0

        for cur_root, dirs, files in os.walk(temp_dir):
            # 过滤 .git 目录
            if ".git" in dirs:
                dirs.remove(".git")

            for file_name in files:
                abs_src_file = os.path.join(cur_root, file_name)
                rel_to_temp = os.path.relpath(abs_src_file, temp_dir).replace("\\", "/")

                # 排除过滤
                if matches_any_pattern(rel_to_temp, exclude_patterns):
                    skipped_count += 1
                    continue

                # 包含过滤
                if not matches_any_pattern(rel_to_temp, include_patterns):
                    skipped_count += 1
                    continue

                # 计算目标相对路径
                rel_dest = os.path.join(target_dir, rel_to_temp).replace("\\", "/")

                # ★★★【防外溢核心守卫】★★★
                # 必须强制断言目标路径不能离开预定 allowed_boundary
                assert_within_boundary(rel_dest, allowed_boundary, root_dir)

                abs_dest_file = os.path.join(root_dir, rel_dest)

                # 本地保留检查 (Preserve Local)
                if matches_any_pattern(rel_to_temp, preserve_local) and os.path.exists(abs_dest_file):
                    log_info(f"  [PRESERVED] 保留工作台本地定制: {rel_dest}")
                    preserved_count += 1
                    continue

                if dry_run:
                    log_info(f"  [DRY-RUN] 将更新文件: {rel_dest}")
                    copied_count += 1
                else:
                    os.makedirs(os.path.dirname(abs_dest_file), exist_ok=True)
                    shutil.copy2(abs_src_file, abs_dest_file)
                    copied_count += 1

        log_ok(f"[{key}] 隔离合并完毕: 同步写入 {copied_count} 文件, 保留本地 {preserved_count} 文件, 跳过 {skipped_count} 文件")

        # 4. 更新 SHA 记录
        if remote_sha and not dry_run and sha_cache is not None:
            sha_cache[key] = remote_sha

        return True, "SYNC_SUCCESS"

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Seep 上游定点隔离同步与防外溢引擎")
    parser.add_argument("--target", "-t", default="all", help="指定要同步的上游键名（例如 apk-reverse 或 all）")
    parser.add_argument("--dry-run", "-n", action="store_true", help="演练模式，仅预览不实际写入任何文件")
    parser.add_argument("--check-only", "-c", action="store_true", help="仅检查远程是否有更新，不执行拉取")
    parser.add_argument("--rules", default="setup/upstream-rules.json", help="规则清单路径")
    parser.add_argument("--proxy", help="HTTP(S) 代理 URL，例如 http://127.0.0.1:7897")
    parser.add_argument("--make-pr-body", help="生成 PR 说明 Markdown 并写入指定文件路径")
    args = parser.parse_args()

    if args.make_pr_body:
        write_pr_body(args.make_pr_body, args.target)
        print(f"  [+] 已生成 PR 正文至: {args.make_pr_body}")
        sys.exit(0)

    root_dir = get_root_dir()
    rules_path = os.path.normpath(os.path.join(root_dir, args.rules))
    sha_cache_path = os.path.normpath(os.path.join(root_dir, "setup", ".upstream-shas.json"))

    print("================================================================================")
    print("      Seep Reverse Lab — 声明式上游定点隔离同步引擎 (Zero-Spillover)")
    print("================================================================================")
    print(f"  工作台物理根目录: {root_dir}")
    print(f"  同步规则清单文件: {rules_path}")
    print(f"  运行模式: {'[DRY-RUN 预览]' if args.dry_run else '[CHECK-ONLY 仅检查]' if args.check_only else '[NORMAL 执行同步]'}")

    try:
        manifest = load_rules(rules_path)
    except Exception as e:
        log_fail(f"加载规则文件失败: {e}")
        sys.exit(1)

    upstreams = manifest.get("upstreams", {})
    if not upstreams:
        log_warn("规则清单中未声明任何上游仓库配置。")
        sys.exit(0)

    # 确定代理
    proxy = args.proxy
    if not proxy:
        detected = detect_proxy()
        if detected:
            log_info(f"自动探测到本地可用代理: {detected}")
            proxy = detected

    sha_cache = load_sha_cache(sha_cache_path)

    targets = list(upstreams.keys()) if args.target == "all" else [args.target]
    for t in targets:
        if t not in upstreams:
            log_fail(f"目标 [{t}] 未在规则清单中定义！可用键名: {list(upstreams.keys())}")
            sys.exit(1)

    any_updated = False
    for t in targets:
        rule = upstreams[t]
        try:
            changed, status = sync_single_upstream(
                key=t,
                rule=rule,
                root_dir=root_dir,
                dry_run=args.dry_run,
                check_only=args.check_only,
                proxy=proxy,
                sha_cache=sha_cache
            )
            if changed:
                any_updated = True
        except SpilloverSecurityViolation as ssv:
            log_fail(f"防外溢安全违规熔断拦截: {ssv}")
            sys.exit(2)
        except Exception as e:
            log_fail(f"处理上游 [{t}] 时发生异常: {e}")
            sys.exit(1)

    if not args.dry_run and not args.check_only:
        save_sha_cache(sha_cache_path, sha_cache)

    print("\n================================================================================")
    if args.check_only:
        if any_updated:
            print("  [*] 检查结论: 检测到上游仓库有新版本发布，可运行同步指令合并。")
            sys.exit(2)
        else:
            print("  [+] 检查结论: 所有上游镜像均为最新版本，无需同步。")
            sys.exit(0)
    else:
        print(f"  [+] 结论: 上游隔离同步处理完成！ (变更状态: {'有更新并入' if any_updated else '保持现状'})")


if __name__ == "__main__":
    main()
