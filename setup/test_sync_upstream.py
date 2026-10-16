#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Seep Reverse Lab — 上游定点隔离同步与防外溢机制单元测试
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "sync_upstream",
    os.path.join(os.path.dirname(__file__), "sync-upstream.py")
)
sync_upstream_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync_upstream_mod)

SpilloverSecurityViolation = sync_upstream_mod.SpilloverSecurityViolation
assert_within_boundary = sync_upstream_mod.assert_within_boundary
load_rules = sync_upstream_mod.load_rules
matches_any_pattern = sync_upstream_mod.matches_any_pattern


class TestSyncUpstreamBoundary(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def test_within_boundary_allowed(self):
        # 正常同目录写入
        boundary = "Tool/upstream/apk-reverse"
        valid_file = "Tool/upstream/apk-reverse/src/main.py"
        # 应该正常通过，不抛出异常
        try:
            assert_within_boundary(valid_file, boundary, self.root_dir)
        except SpilloverSecurityViolation:
            self.fail("assert_within_boundary raised SpilloverSecurityViolation unexpectedly!")

    def test_spillover_to_sibling_blocked(self):
        # 试图从 A 溢出写入到 B 目录
        boundary = "Tool/upstream/apk-reverse"
        sibling_file = "Tool/upstream/open-tgtylab/hacked.txt"
        with self.assertRaises(SpilloverSecurityViolation):
            assert_within_boundary(sibling_file, boundary, self.root_dir)

    def test_spillover_path_traversal_blocked(self):
        # 试图通过 ../ 跨越目录
        boundary = "Tool/upstream/apk-reverse"
        traversal_file = "Tool/upstream/apk-reverse/../../cases/evil.py"
        with self.assertRaises(SpilloverSecurityViolation):
            assert_within_boundary(traversal_file, boundary, self.root_dir)

    def test_spillover_to_root_blocked(self):
        # 试图写入根目录文件
        boundary = "Tool/upstream/apk-reverse"
        root_file = "README.md"
        with self.assertRaises(SpilloverSecurityViolation):
            assert_within_boundary(root_file, boundary, self.root_dir)

    def test_pattern_matching(self):
        excludes = [".git/**", ".github/**", "**/node_modules/**", "**/*.pyc"]
        self.assertTrue(matches_any_pattern(".git/config", excludes))
        self.assertTrue(matches_any_pattern(".github/workflows/ci.yml", excludes))
        self.assertTrue(matches_any_pattern("lib/node_modules/pkg/index.js", excludes))
        self.assertTrue(matches_any_pattern("src/__pycache__/foo.cpython-311.pyc", excludes))
        self.assertFalse(matches_any_pattern("src/main.py", excludes))

    def test_rules_manifest_integrity(self):
        rules_path = os.path.join(os.path.dirname(__file__), "upstream-rules.json")
        rules = load_rules(rules_path)
        self.assertIn("upstreams", rules)
        for key, conf in rules["upstreams"].items():
            self.assertIn("repo", conf)
            self.assertIn("target_dir", conf)
            self.assertIn("allowed_boundary", conf)
            self.assertEqual(conf["target_dir"], conf["allowed_boundary"],
                             f"Target dir and boundary should match for sandboxing in {key}")


if __name__ == "__main__":
    unittest.main()
