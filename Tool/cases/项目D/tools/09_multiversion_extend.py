# -*- coding: utf-8 -*-
"""多版本扩展一体化流水线（定位 → 生成 → 校验 → 输出 C# 表）

与 02/03 脚本的区别：本脚本把「定位失配位点 + 生成 N 版本共同稳定区特征码
+ 双态唯一性校验 + 输出 C# 表」合并为一步，且完全由 JSON 配置驱动，
新增版本时只需在配置里补一行偏移（未知的写 null，脚本自动定位）。

用法：
    python 09_multiversion_extend.py config.json

配置格式（config.json）：
{
  "samples_dir": "../../../samples",
  "versions": [
    {"tag": "b15.3", "file": "IDMan_643b15_original.exe"},
    {"tag": "b16.3", "file": "IDMan_643b16_original.exe"}
  ],
  "points": [
    {"id": 1, "name": "授权分支检测",
     "offsets": {"b15.3": "0x2D71D", "b16.3": null},
     "expected": "85", "patch": "33", "optional": false}
  ],
  "sig_cap": 48,
  "hamming_win": 64,
  "hamming_limit": 12
}

关键设计约束（详见 docs/algorithm.md §3.2 / §3.3）：
  * 模糊匹配（汉明距离）只产生候选，必须经期望字节精确匹配二次确认；
  * 双态唯一性 1/1 是硬门禁；
  * 签名长度设上限，避免过度特化（误命中 > 失配，严重性不对等）。
"""
import io
import json
import os
import struct
import sys

try:
    import numpy as np
except ImportError:
    np = None

# ----------------------------------------------------------------------------
# PE 工具
# ----------------------------------------------------------------------------

def parse_sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        raise ValueError("非 PE 文件")
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    optsz = struct.unpack_from("<H", data, e + 20)[0]
    so = e + 24 + optsz
    out = []
    for i in range(nsec):
        b = so + i * 40
        name = data[b:b + 8].rstrip(b"\0").decode('latin1')
        vsz, va, rsz, rp = struct.unpack_from("<IIII", data, b + 8)
        out.append(dict(name=name, va=va, vsz=vsz, rp=rp, rsz=rsz))
    return out


def occ(hay, needle, cap=50):
    n, p = 0, 0
    while n <= cap:
        i = hay.find(needle, p)
        if i < 0:
            break
        n += 1
        p = i + 1
    return n


# ----------------------------------------------------------------------------
# 定位
# ----------------------------------------------------------------------------

def hamming_locate(ref_data, ref_off, tgt_data, win, limit, plen, exp):
    """以 ref 的已验证偏移为锚，在 tgt 中滑动汉明距离定位。

    返回 (候选偏移, 汉明距离)；候选偏移已对齐到补丁点（非窗口起点）。
    """
    half = win // 2
    lo = max(0, ref_off - half)
    w = ref_data[lo:lo + win]
    if len(w) < win:
        return None, None

    if np is None:
        raise RuntimeError("需要 numpy：pip install numpy")

    A = np.frombuffer(tgt_data, dtype=np.uint8)
    wv = np.frombuffer(w, dtype=np.uint8)
    n = len(tgt_data) - win + 1
    CHUNK = 500_000
    best_pos, best_d = -1, 10 ** 9
    for s in range(0, n, CHUNK):
        e = min(s + CHUNK, n)
        if e <= s:
            break
        idx = np.arange(s, e)[:, None] + np.arange(win)[None, :]
        dist = (A[idx] != wv[None, :]).sum(axis=1)
        mn = int(dist.min())
        if mn < best_d:
            best_d = mn
            best_pos = s + int(dist.argmin())

    if best_pos < 0 or best_d > limit:
        # 汉明超阈值：依次尝试「周边锚点」与「期望字节唯一搜索」兑底
        alt = exact_anchor_search(ref_data, ref_off, tgt_data, win, plen)
        if alt is not None:
            return alt, 0
        alt = expected_search(tgt_data, exp)
        if alt is not None:
            return alt, -1          # -1 表示走了期望字节搜索
        return None, best_d

    cand = best_pos + (ref_off - lo)
    # 二次确认：候选点的期望字节必须精确匹配
    got = tgt_data[cand:cand + plen]
    if got != exp:
        # 精确锚点兜底：全文件搜索「锚点窗口内非补丁部分」
        alt = exact_anchor_search(ref_data, ref_off, tgt_data, win, plen)
        if alt is not None:
            return alt, 0
        return None, best_d
    return cand, best_d


def exact_anchor_search(ref_data, ref_off, tgt_data, win, plen):
    """兜底 1：用补丁点之后的一段字节做精确锚点搜索，再回推补丁点偏移。"""
    anchor = ref_data[ref_off + plen: ref_off + plen + 24]
    if len(anchor) == 24:
        idx = tgt_data.find(anchor)
        if idx >= 0 and tgt_data.find(anchor, idx + 1) < 0:
            return idx - plen
    # 兜底 1b：用补丁点之前的一段字节
    before = ref_data[max(0, ref_off - 24): ref_off]
    if len(before) == 24:
        idx = tgt_data.find(before)
        if idx >= 0 and tgt_data.find(before, idx + 1) < 0:
            return idx + 24
    return None


def expected_search(tgt_data, exp):
    """兜底 2：直接用「期望字节」在全文件搜索（适用于数据段常量位点）。

    仅当期望字节在目标中**恰好出现一次**时才接受；多次出现一律拒绝，
    宁可报错也不猜测——误命中的代价是写坏二进制。
    """
    idx = tgt_data.find(exp)
    if idx < 0:
        return None
    if tgt_data.find(exp, idx + 1) >= 0:
        return None
    return idx


# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------

def main(cfg_path):
    cfg = json.load(io.open(cfg_path, encoding='utf-8'))
    base = os.path.dirname(os.path.abspath(cfg_path))
    sdir = os.path.normpath(os.path.join(base, cfg.get("samples_dir", ".")))

    versions = cfg["versions"]
    tags = [v["tag"] for v in versions]
    data = []
    for v in versions:
        p = os.path.join(sdir, v["file"])
        if not os.path.exists(p):
            raise SystemExit("样本缺失: " + p)
        data.append(io.open(p, 'rb').read())

    CAP = cfg.get("sig_cap", 48)
    WIN = cfg.get("hamming_win", 64)
    HLIM = cfg.get("hamming_limit", 12)

    print("=" * 130)
    print("多版本扩展流水线  版本数=%d  签名上限=%d B  汉明窗口=%d  汉明阈值=%d"
          % (len(tags), CAP, WIN, HLIM))
    print("=" * 130)

    # ---- 阶段 1：定位缺失偏移 ----
    print("\n[阶段 1] 定位缺失偏移")
    print("-" * 130)
    for pt in cfg["points"]:
        offs = pt["offsets"]
        known = [t for t in tags if offs.get(t) is not None]
        missing = [t for t in tags if offs.get(t) is None]
        if not missing:
            print("  #%-3d %-40s 全部已知" % (pt["id"], pt["name"][:40]))
            continue
        if not known:
            print("  #%-3d %-40s ⚠️ 无任何已知偏移，无法定位（请人工逆向）"
                  % (pt["id"], pt["name"][:40]))
            continue
        ref_t = known[-1]
        ref_i = tags.index(ref_t)
        ref_off = int(offs[ref_t], 16) if isinstance(offs[ref_t], str) else offs[ref_t]
        exp = bytes.fromhex(pt["expected"])
        plen = len(exp)

        for mt in missing:
            mi = tags.index(mt)
            cand, dist = hamming_locate(data[ref_i], ref_off, data[mi], WIN, HLIM, plen, exp)
            if cand is None:
                if pt.get("optional"):
                    print("  #%-3d %-40s %s  ⚠️ 未定位（可选位点，本版本可能不存在）汉明=%s"
                          % (pt["id"], pt["name"][:40], mt, dist))
                else:
                    print("  #%-3d %-40s %s ← %s  ❌ 定位失败（汉明=%s，超阈值且锚点未命中）"
                          % (pt["id"], pt["name"][:40], mt, ref_t, dist))
            else:
                offs[mt] = "0x%X" % cand
                if dist == -1:
                    src = "期望字节唯一定位"
                elif dist == 0:
                    src = "精确锚点"
                else:
                    src = "汉明=%d" % dist
                print("  #%-3d %-40s %s ← %s  ✓ 0x%X  (%s, 位移=%+d)"
                      % (pt["id"], pt["name"][:40], mt, ref_t, cand, src, cand - ref_off))

    # 检查是否有仍为 None 的必需位点
    unresolved = [pt for pt in cfg["points"]
                  if not pt.get("optional")
                  and any(pt["offsets"].get(t) is None for t in tags)]
    if unresolved:
        print("\n❌ 存在未解析的必需位点，流程中止：")
        for pt in unresolved:
            miss = [t for t in tags if pt["offsets"].get(t) is None]
            print("   #%d %s -> 缺失 %s" % (pt["id"], pt["name"], ",".join(miss)))
        return 1

    # ---- 阶段 2：应用补丁构造已补丁态 ----
    print("\n[阶段 2] 构造已补丁态（用于双态唯一性校验）")
    print("-" * 130)
    patched = []
    for i, d in enumerate(data):
        buf = bytearray(d)
        for pt in cfg["points"]:
            o = pt["offsets"].get(tags[i])
            if o is None:
                continue
            o = int(o, 16) if isinstance(o, str) else o
            pb = bytes.fromhex(pt["patch"])
            buf[o:o + len(pb)] = pb
        patched.append(bytes(buf))
    print("  已补丁态构造完成：%d 个版本" % len(patched))

    # ---- 阶段 3：生成共同稳定区特征码 ----
    print("\n[阶段 3] 生成共同稳定区特征码 + 双态唯一性校验")
    print("-" * 130)
    hdr = "%-4s %-40s %-4s %-4s %-4s  %s" % ("#", "位点", "长度", "左", "右", "双态唯一性")
    print(hdr)
    print("-" * 130)

    table, allok = [], True
    for pt in cfg["points"]:
        exp = bytes.fromhex(pt["expected"])
        pat = bytes.fromhex(pt["patch"])
        plen = len(exp)
        present = [i for i, t in enumerate(tags) if pt["offsets"].get(t) is not None]

        # 位点字节校验
        for i in present:
            o = pt["offsets"][tags[i]]
            o = int(o, 16) if isinstance(o, str) else o
            got = data[i][o:o + plen]
            if got != exp:
                print("  !! #%d %s @ %s 位点字节不符：期望 %s 实得 %s"
                      % (pt["id"], pt["name"], tags[i], pt["expected"], got.hex().upper()))

        # 左右扩展（只要求在位版本一致）
        left = 0
        while left < 160:
            vals = []
            ok = True
            for i in present:
                o = pt["offsets"][tags[i]]
                o = int(o, 16) if isinstance(o, str) else o
                a = o - left - 1
                if a < 0:
                    ok = False
                    break
                vals.append(data[i][a])
            if not ok or len(set(vals)) != 1:
                break
            left += 1

        right = 0
        while right < 160:
            vals = []
            ok = True
            for i in present:
                o = pt["offsets"][tags[i]]
                o = int(o, 16) if isinstance(o, str) else o
                a = o + plen + right
                if a >= len(data[i]):
                    ok = False
                    break
                vals.append(data[i][a])
            if not ok or len(set(vals)) != 1:
                break
            right += 1

        ref = present[0]
        ref_off = pt["offsets"][tags[ref]]
        ref_off = int(ref_off, 16) if isinstance(ref_off, str) else ref_off

        def make_sig(l, r):
            s = data[ref][ref_off - l: ref_off + plen + r]
            return s, s[:l] + pat + s[l + plen:]

        # 长度上限：优先保留左侧上下文，右侧补齐
        l_use = min(left, CAP // 2)
        r_use = min(right, max(0, CAP - plen - l_use))
        if l_use == left and r_use < right:
            r_use += min(right - r_use, CAP - plen - l_use - r_use)
        sig, sigp = make_sig(l_use, r_use)

        counts, ok = [], True
        for i in range(len(data)):
            c1, c2 = occ(data[i], sig), occ(patched[i], sigp)
            if i in present:
                counts.append("%d/%d" % (c1, c2))
                if c1 != 1 or c2 != 1:
                    ok = False
            else:
                counts.append("%d/-" % c1)
                if c1 != 0:
                    ok = False
        if not ok:
            allok = False

        tag = " (可选)" if pt.get("optional") else ""
        print("%-4d %-40s %-4d %-4d %-4d  %s  %s"
              % (pt["id"], (pt["name"] + tag)[:40], len(sig), l_use, r_use,
                 " ".join("%-7s" % c for c in counts), "OK" if ok else "!! 失败"))

        table.append(dict(
            id=pt["id"], name=pt["name"], sig=sig.hex().upper(),
            sigPatched=sigp.hex().upper(), patchOffsetInSig=l_use,
            expected=pt["expected"], patch=pt["patch"],
            optional=bool(pt.get("optional")),
            offsets={tags[i]: pt["offsets"][tags[i]] for i in range(len(tags))},
            unique=ok))

    # ---- 阶段 4：输出 ----
    total = sum(len(t["sig"]) // 2 for t in table)
    print("-" * 130)
    print("全部通过: %s   (%d/%d)   总字节 %d   平均 %.1f B/位点"
          % (allok, sum(1 for t in table if t["unique"]), len(table), total,
             total / len(table)))
    if not allok:
        print("失败项: %s" % [t["name"] for t in table if not t["unique"]])

    out_json = os.path.join(base, "final_table_multiver.json")
    json.dump(table, io.open(out_json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print("已写出: " + out_json)

    # C# 表
    cs = []
    cs.append("        public static readonly AobPoint[] POINTS = new AobPoint[]")
    cs.append("        {")
    for t in table:
        ind = "                "
        cs.append("            new AobPoint(")
        cs.append(ind + '"%s",' % t["name"])
        cs.append(ind + '"%s",' % t["sig"])
        cs.append(ind + '"%s",' % t["sigPatched"])
        tail = '%d, "%s", "%s"' % (t["patchOffsetInSig"], t["expected"], t["patch"])
        if t["optional"]:
            tail += ", true"
        cs.append(ind + tail + "),")
        cs.append("")
    cs.append("        };")
    out_cs = os.path.join(base, "aob_table_multiver.cs")
    io.open(out_cs, 'w', encoding='utf-8-sig', newline='\r\n').write("\n".join(cs))
    print("已写出: " + out_cs)

    return 0 if allok else 2


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
