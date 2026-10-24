---
id: "apk-reverse/09-lsposed-root/02-kernelsu-root-mechanisms"
title: "KernelSU 内核模块机制与 Systemless 逆向对抗"
title_en: "KernelSU Kernel Module Mechanics and Systemless Reverse Hardening"
summary: >
  深度解析 KernelSU 内核级 Root 架构、首阶段 Preinit (SELinux 策略前执行)、initrc 系统服务注入、内核原生 OverlayFS (Whiteout 虚拟删除与 Opaque 替换)、BusyBox 独立环境与 ZygiskNext 桥接，以及 Shamiko/Zygisk-Assistant 环境隐藏对抗策略。
summary_en: >
  In-depth analysis of KernelSU kernel-level Root architecture, first-stage Preinit (execution before SELinux policy loading), initrc system service injection, kernel-native OverlayFS (Whiteout deletion and Opaque replacement), BusyBox standalone environment, ZygiskNext bridging, and Shamiko/Zygisk-Assistant environment hiding strategies.
board: "apk-reverse"
category: "09-lsposed-root"
signals: ["kernelsu", "ksu", "preinit", "overlayfs", "whiteout", "initrc", "zygisk", "zygisknext", "shamiko", "root hiding", "systemless", "apatch"]
mcp_tools: ["android_app_baseline"]
keywords: ["KernelSU", "OverlayFS", "preinit", "initrc", "ZygiskNext", "Shamiko", "Systemless", "Whiteout", "Root隐藏"]
difficulty: "advanced"
tags: ["kernelsu", "root", "kernel", "overlayfs", "systemless", "anti-detection", "zygisk"]
language: "zh-CN"
last_updated: "2026-10-23"
related_articles: ["apk-reverse/09-lsposed-root/01-modern-lsposed-module-analysis"]
---
# KernelSU 内核模块机制与 Systemless 逆向对抗

## 场景

传统 Magisk 工作在用户空间（Ramdisk 修补 + `magiskd` 守护进程），在对抗高安全等级的金融、政企与游戏类 RASP 时，守护进程 Socket、Proc 节点、用户态 Bind Mount 挂载点容易被作为 Root 依据检测。

**KernelSU**（运行在内核空间，GKI 2.0 / Linux 5.10+ 原生支持）通过将 `su` 逻辑下沉到内核驱动层，消除了用户空间守护进程，并提供了远早于应用启动的**底层介入生命周期**。

---

## 启动生命周期阶段全景

```
[1. First Stage Init] ─────► 执行 preinit/preinit.conf (SELinux 加载前、init.rc 解析前)
                                      │
[2. Init.rc Parsing]  ─────► 透明追加 initrc/*.rc (通过内核 hook read/fstat 注入系统服务)
                                      │
[3. post-fs-data]     ─────► post-fs-data.sh (/data 分区可写，系统服务启动前)
                                      │
[4. post-mount]       ─────► post-mount.sh (OverlayFS 挂载完成)
                                      │
[5. late_start]       ─────► service.sh (系统启动阶段，以 BusyBox 独立环境运行)
                                      │
[6. Boot Completed]   ─────► boot-completed.sh (sys.boot_completed=1 广播完成)
```

### 1. `preinit` 机制（SELinux 策略前执行）
这是 Android 目前可编程执行的最早期节点。当 `/system/bin/init selinux_setup` 执行时由内核内嵌 runner 驱动：
*   **动作 1：`insmod <ko> [params...]`**
    加载自定义内核模块。KernelSU 会从内核 `kallsyms` 查询未导出符号并自动重定位，使驱动可以直接与内核底层函数通信。
*   **动作 2：`exec [-t <ms>] <prog> [args...]`**
    以 root 权限运行**静态链接二进制程序**（不受 SELinux 约束，无需等待 `/apex` 运行时）。
*   **动作 3：`write <path> <content>`**
    直接修改 `procfs` / `sysfs`，在安全 SDK 读取之前先行动态伪装。

### 2. `initrc/` 系统级注入
传统方案修改 `init.rc` 必须解包 boot.img。KernelSU 创新性地在内核层 Hook 了 `read()` 和 `fstat()` 系统调用：
*   当系统 init 进程读取 `/system/etc/init/hw/init.rc` 时，内核自动将 `/data/adb/modules/<MODID>/initrc/*.rc` 内容追加到文件末尾；
*   允许直接注册自定义系统守护进程与系统属性触发器（`on property:sys.boot_completed=1`）。

---

## 内核 OverlayFS 挂载机制（vs Magisk Magic Mount）

Magisk 通过用户空间多点 bind mount 挂载文件，挂载表特征明显；KernelSU 采用 Linux 内核原生 `overlayfs`：

1.  **文件覆盖与合并**：
    将模块下的 `system/` 目录作为 upper 叠加在底层只读 `/system` 之上，同名文件直接无感覆盖。
2.  **文件删除 (Whiteout)**：
    若要隐藏或删除系统的某个系统文件或内置检测应用：
    *   在模块对应目录下执行 `mknod <filename> c 0 0`；
    *   内核 OverlayFS 会将设备号 0/0 解释为 Whiteout 特性，向上层展示该文件已被彻底删除。
3.  **目录完全替换 (Opaque)**：
    *   在模块目录中设置扩展属性：`setfattr -n trusted.overlay.opaque -v y <dir>`；
    *   可将整个系统目录替换为完全受控的空目录或全新内容。

---

## 环境确定性与 Zygisk 生态集成

### 1. BusyBox 独立模式 (ASH_STANDALONE)
KernelSU 运行第三方模块脚本时默认注入 `ASH_STANDALONE=1`：
*   脚本中的 `ls`, `grep`, `rm`, `chmod` 等命令强制调用内置 BusyBox，绕过目标系统厂商精简版 toybox 的参数缺陷，保证逆向脚本跨厂商 ROM 的一致性。

### 2. 桥接 LSPosed (ZygiskNext)
KernelSU 内核不自带 Zygisk，但通过安装开源的 **ZygiskNext** 模块，可以获得完全标准的 Zygisk 环境，进而稳定加载 **LSPosed (v1.9.2 / Vector / LSPosed_mod)**。

---

## 隐藏层选型规约：Shamiko vs Zygisk-Assistant

在 Root 设备上执行逆向时，必须屏蔽宿主特征：

| 维度 | Shamiko | Zygisk-Assistant |
|---|---|---|
| **闭源/开源** | 闭源（原 LSPosed 团队） | 开源 |
| **DenyList 规范** | 需要配置 Magisk DenyList，但**必须将 Enforce DenyList 关闭** | 支持 Magisk DenyList（关闭强制）与 KernelSU 排除配置 |
| **白名单模式** | 创建 `/data/adb/shamiko/whitelist` 开启对白名单外全量隐藏 | 无单独白名单文件 |
| **APatch 适配** | 官方不予适配 | 完美支持 |
| **选型纪律** | **严禁同时安装二者**；Magisk 环境推荐 Shamiko，KernelSU/APatch 环境推荐 Zygisk-Assistant |

---

## 验证与排查自检

```bash
# 1. 检查 KernelSU 版本与内核支持
su -c "ksud -V"

# 2. 检查 preinit 状态
su -c "ksud module preinit status"

# 3. 刷新 initrc 注入
su -c "ksud initrc refresh"

# 4. 检查 Zygisk 连通性
adb logcat -s LSPosed-Bridge
```
