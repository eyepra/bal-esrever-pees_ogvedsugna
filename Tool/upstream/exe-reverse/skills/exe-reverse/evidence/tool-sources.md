# Tool sources: the citations behind the toolchain and solver references

Purpose: `references/toolchain.md` and `references/symbolic-execution.md` make claims about products,
interfaces, licences, maintenance state and defaults. Each claim is traceable here, with the URL that
was opened and the strength it was given when it was read.

How to read the labels:

- `observed` -- the source named on the line was opened and states this
- `inferred` -- follows from something observed, with the step named
- `unverified` -- reported somewhere and not confirmed here; treat it as a lead

This is a **citation record, not a tutorial**. Read the references for what to do; come here to argue
with a specific claim or to re-check one that has aged. Tool facts age quickly: a licence changes, a
repository is archived, a project moves its active branch. When a line here turns out to be wrong, the
fix belongs in the reference, and a corrected citation belongs here.

## Part 1: agent-facing tool interfaces

核验日期：2027-02-21（本机 Windows 11 24H2，build 26100）。
方法：`web_search` 在本会话返回 HTTP 402，全程改用 `web_fetch` 与 PowerShell `Invoke-WebRequest -UseBasicParsing` 抓一手源（厂商文档站、官方仓库 raw 文件、`commits/*.atom`、Microsoft Learn 搜索 API、本机运行时取证）。GitHub REST API 返回 403 限速，未使用。
强度标签：`observed` = 在打开的源中直接读到；`inferred` = 由已读证据推导；`unverified` = 未从一手源确认，并注明缺什么。

## 摘要表

| 工具 | 无人值守 / 脚本接口 | 许可门槛 | 维护状态 | 强度 |
| --- | --- | --- | --- | --- |
| IDA Pro（GUI 二进制） | `ida -A -Sscript.py`；`-B` 批处理 | 商业；`-S`、`-O` 在 IDA Home 不可用 | 商业在售，9.5 文档在更新 | observed |
| idalib（官方 headless 库） | Python `import idapro` + IDAPython / Domain API；C++ 链接 `idalib.hpp` | 含于 IDA Home / Pro / Classroom；嵌入自有软件、SaaS、共享服务器需 IDA Pro OEM | 随 IDA 9.4+ 发布 | observed |
| IDA Pro Headless（独立 SKU） | 同 idalib，无 GUI | 商业授权，"A person, machine or seat" | 商业在售 | observed |
| IDA Free | 无 IDAPython、无 C++ SDK、无 idalib | 仅非商业；仅 x86-32/x86-64；反编译仅云端 | 免费产品 | observed |
| Ghidra headless | `support/analyzeHeadless <project_location> <project_name> [options]` | Apache License 2.0（仓库 `LICENSE`） | 最后提交 2026-10-15 | observed |
| PyGhidra | `pip install pyghidra`；`pyghidra.start()` | 免费 | 官方随 Ghidra 发布 | observed |
| Binary Ninja | `import binaryninja; binaryninja.load(...)`（官方无 batch 模式，库即接口） | Commercial / Ultimate / headless 授权 | 商业在售 | observed |
| Binary Ninja MCP | GUI HTTP `127.0.0.1:24642/mcp`；headless `binaryninja_mcp`(stdio) | Commercial / Ultimate | 第一方 | observed |
| radare2 | `r2 -A -c '...'`；r2pipe | README 自述 LGPLv3 | 最后提交 2026-10-16 | observed |
| rizin | `rizin -A -c '...'`；rzpipe | 仓库根 `COPYING` = GNU GPL v3 | 最后提交 2026-10-15 | observed |
| Cutter | GUI；Python 插件 API（基于 rizin 绑定） | 仓库 `COPYING` = GNU GPL v3 | 最后提交 2026-09-11 | observed |
| IDA MCP（官方） | stdio / Streamable HTTP 8737 | 含于 IDA Home / Pro / Classroom（需 idalib） | 最后提交 2026-10-08 | observed |
| WinDbg MCP（官方） | stdio（`DbgX.Mcp.Proxy.exe` + 命名管道） | 随 WinDbg | 需 WinDbg 1.2610.1001.0+ | observed |
| HyperDbg | CLI + 自有脚本语言 | 开源（许可未逐条核对）；运行须禁 DSE 与 VBS | 最后提交 2026-09-22（v0.24） | observed |
| Intel PT on Windows | **无第一方用户态采集路径**；in-box `ipt.sys` 未文档化 | 随 Windows 分发 | 见第 7 节 | observed |
| Time Travel Debugging | `TTD.exe -launch/-attach/-monitor ...` | 随 Windows 调试工具分发，命令行版可单独下载 | 官方页 2026-06-11 更新 | observed |

## 1. IDA Pro / IDA Free

**命令行开关（IDA 9.5 官方文档表）**
来源：https://docs.hex-rays.com/ida-9.5/core/user-interface/concepts/command-line-switches.md（同一页面亦经 https://hex-rays.com/products/ida/support/idadoc/417.shtml 打开）· `observed`

- `-A`：autonomous mode，"IDA will not display dialog boxes. Designed to be used together with `-S` switch." —— 它只关掉交互对话框，本身不执行任何脚本。
- `-S###`：Execute a script file when the database is opened。脚本解释器由扩展名决定（`.idc`、`.py`）。`-S` 之后可跟参数，例如 `-S"myscript.py argument1 \"argument 2\" argument3"`；参数进入 IDC 全局 `ARGV`（IDC 用 `ARGV.count` / `ARGV[0]`，Python 需 `import idc` 后读 `idc.ARGV`）。
- `-B`：batch mode，自动生成 `.IDB` 与 `.ASM` 文件。文档明确 `ida -B input-file` 等价于 `ida -c -A -Sanalysis.idc input-file` —— 即 `-B` 是 `-c -A -S analysis.idc` 的封装，脚本仍是 `-S`。
- `-a` 关闭自动分析（`-a-` 开启）；`-c` 新建数据库（删除旧库）；`-o####` 指定输出数据库（隐含 `-c`）；`-L####` 日志文件名；`-T###` 指定文件类型/归档成员，且此情形下不弹 Load file 对话框；`-p####` 处理器类型。
- 官方在批处理一节写下两条注意事项：常规插件在 batch mode 下**不会**自动加载（`analysis.idc` 退出，内核没机会加载插件）；"Although the GUI version of IDA is perfectly of running batch scripts, we recommend using **the "idalib" Python module** for this task as it uses fewer system resources."（原文语病保留）· `observed`

**GUI 二进制与官方 headless 库的区别**
- 用 GUI 二进制批处理 = 启动完整 IDA（`ida`）/文本版，靠 `-A -S` 无人值守；官方自己把它标为可行但资源占用更高的路径。
- idalib = "IDA as a library"："allows you to use the C++ and IDAPython APIs outside IDA as standalone applications... run analysis **headlessly**"（https://docs.hex-rays.com/ida-9.5/core/idalib/overview.md）· `observed`
- 独立 SKU "IDA Pro Headless" 存在且描述为 "the exact same disassembler, decompiler and analysis that power IDA Pro, delivered as **idalib**: a library with no interface"（https://hex-rays.com/ida-pro-headless）· `observed`

**idalib 的文档化约束**
- 注册与导入顺序：idalib 在后台查找 `ida.config.json` 指向所使用的 IDA 安装目录；一次性注册步骤把它绑定到某个具体 IDA 安装（多版本机器上决定用哪个），可在 9.4+ 安装时完成、经 HCLI、或手动跑 `py-activate-idalib.py`（https://docs.hex-rays.com/ida-9.5/core/idalib/concepts/architecture.md、.../getting-started.md）· `observed`
- 导入顺序强制要求："Make sure to import `idapro` as **the first import** in your script, before any other IDA modules." 随后 `import ida_funcs` / `import ida_auto` · `observed`
- 线程/资源：官方部署页写 "**IDA is single-threaded.** Allocate one vCPU per container."（https://docs.hex-rays.com/ida-9.5/core/idalib/concepts/deployment.md）· `observed`
- 许可与 OEM：idalib 含于 IDA Home、IDA Pro（Essential/Expert/Ultimate）、IDA Classroom；"If you embed idalib in your own software, use it as a SaaS engine, or run it on a shared server, you need an **IDA Pro OEM** license. It's free during development and beta phases."（.../idalib/overview.md）· `observed`
- 安装路径：`hcli ida install ...` + `uv pip install idapro`，或从安装目录跑 `py-activate-idalib.py`（Windows 路径形如 `C:\Program Files\IDA Professional 9.3\idalib\python\py-activate-idalib.py`）；9.4 起安装器可自动激活 · `observed`

**Python 与 C++ 入口**
- Python 两条 API 路线：IDAPython（标准模块 `ida_funcs`、`ida_segment` 等）与 Domain API（建立在 IDAPython SDK 之上的高层接口）。
- C++："link directly against idalib via `idalib.hpp` and the IDA C++ SDK"，文档指向 https://cpp.docs.hex-rays.com/idalib_8hpp.html · `observed`
- 生命周期 API 的描述是 "initialize, open a database, analyze, close"，其后工作针对 IDA SDK；具体函数名未在这些页面逐字给出，**未确认**（`unverified`：idalib Python 的具体函数签名未从一手源逐字核对，仅确认 `import idapro` 为第一导入）。

**IDA Free 允许与不允许什么**
来源：https://hex-rays.com/ida-free（页面内对比表 + FAQ）· `observed`

- 允许：x86-32/x86-64 反汇编、保存分析结果（FAQ "Can I save my analysis results with IDA Free? Yes"）、x86/x86-64 云端反编译（"cloud only x86-32 and x86-64"）、本地 x86/x64 调试器。
- 不允许：商业使用（"IDA Free is dedicated to non-commercial use only"）；**没有** IDA C++ SDK 或 IDAPython API（FAQ 原文："No, you don't have access to IDA C++ SDK or IDAPython API with IDA Free."）；对比表中 Development Kits、IDAlib、Teams add-on、IDA Feeds 均为 ❌，Lumina 仅 Public。
- 推论（`inferred`）：由于 IDA Free 既无 IDAPython 也无 idalib，`-S` 脚本与 headless 自动化在 IDA Free 上无落地路径；对 IDA **Home**（付费个人版）官方另有明文 "The `-S` switch is not available in the IDA Home edition."、`-O` 亦不可用。Free 与 Home 是两个不同产品，不要混用两者的限制。

## 2. Ghidra headless

**启动器与参数**
来源：官方仓库 launcher 源码 https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/AnalyzeHeadless.java（`Arg` 枚举，第 45–78 行）与 https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/RuntimeScripts/support/analyzeHeadless · `observed`

- 启动脚本 `support/analyzeHeadless` 最终调用 `launch.sh fg jdk Ghidra-Headless "${GHIDRA_HEADLESS_MAXMEM}" "${VMARG_LIST}" ghidra.app.util.headless.AnalyzeHeadless "$@"`；脚本内默认 `MAXMEM_DEFAULT=2G`（可用 `GHIDRA_MAXMEM`/`GHIDRA_HEADLESS_MAXMEM` 覆盖）、`VMARG_LIST` 含 `-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djava.awt.headless=true`。
- 位置参数：`args[0]` 是项目位置（若以 `ghidra:` 开头则视为 Ghidra Server URL，此时无第二个位置参数）；否则 `args[1]` 是 `project_name[/folder_path]`（反斜杠会被替换为 `/`，`folderIndex > 0` 时拆出根文件夹路径）。
- 真实参数清单（逐字取自 `Arg` 枚举）：`-import <目录|文件>`、`-process [<project_file>]`、`-preScript <ScriptName>`、`-postScript <ScriptName>`、`-scriptPath "<path1>[;<path2>...]"`、`-propertiesPath`、`-scriptlog <脚本日志路径>`、`-log <应用日志路径>`、`-overwrite`、`-mirror`、`-recursive`（可选跟深度）、`-readOnly`、`-deleteProject`、`-noanalysis`、`-processor <languageID>`、`-cspec <compilerSpecID>`、`-analysisTimeoutPerFile <秒>`、`-keystore <路径>`、`-connect [<userID>]`、`-p`（密码）、`-commit ["<comment>"]`、`-okToDelete`、`-allowAllAccess`、`-max-cpu <核数>`、`-librarySearchPaths`、`-loader <loader 名>`、`-loader-<参数值>`。
- `-import` 与 `-process` 互斥：源码 `System.err.print("Must use either -process or -import parameters, but not both.")`。
- `-loader` 的名称来自常量而非猜测：`Loader.COMMAND_LINE_ARG_PREFIX = "-loader"`（https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/Loader.java 第 50 行），带参数的 loader 选项形式为 `-loader-<xxx>`。`-processor` 取 `<languageID>`、`-cspec` 取 `<compilerSpecID>`。
- `-noanalysis`：源码注释确认该 flag 控制是否执行分析——`keepFile = analyzeProgram(domFile.getPathname(), program) || readOnlyFile;`，其上注明 "This method already takes into account whether the user has set the `noanalysis` flag or not"（HeadlessAnalyzer.java 第 1204 行附近）。`observed`（语义为"导入后不跑自动分析"，未逐字读到官方一句话定义）。

**`-readOnly` 的真实约束**
来源：HeadlessAnalyzer.java `checkUpdateOptions()` / `processLocal()` · `observed`

- `-readOnly` 与 `-commit`、`-okToDelete` 冲突，冲突即报错中止："Abort due to Headless analyzer error: The requested -readOnly option is in conflict with the -commit option."、"You have specified the conflicting parameters -readOnly and -okToDelete."、"Can not use -commit and -readOnly at the same time."
- 在只读项目/仓库中处理文件时 `-readOnly` 是**必需**的："Processing files within read-only project/repository - the -readOnly option is required."
- 处理 Ghidra URL（瞬时项目）时 `-commit` 会自动启用，除非指定了 `-readOnly`。
- `-overwrite` 对 `-process` 模式不适用、对 `-readOnly` 导入模式会被忽略（有对应日志文本）。

**脚本如何提供、输出如何捕获**
- 脚本以 `-preScript`（分析前）/`-postScript`（分析后）按名提供，搜索路径由 `-scriptPath` 给出（多个路径用分号分隔）。
- 输出捕获是**日志机制**，不是 stdout 重定向。HeadlessAnalyzer.java 在 `executeCurrentScript` 内注明："// Execute the script, but don't directly write to stdout or stderr. The headless analyzer only uses the logging mechanism to get output to the user."（第 595–597 行），脚本异常统一转成 `REPORT SCRIPT ERROR:` 日志。应用日志由 `-log` 指定，脚本日志由 `-scriptlog` 指定。

**项目锁 / 并发**
- `processLocal(...)` 的文档注释：项目打开失败时，若原因是未能获得**写锁**，抛出的 IOException 其 cause 是 `LockException`（"If caused by a failure to obtain a write-lock on the project the exception cause will a `LockException`."，HeadlessAnalyzer.java 第 390–391 行），源码 `import ghidra.framework.store.LockException;` 亦可见。· `observed`
- 这条一手证据只能证明"写锁冲突会失败"；**未确认**官方是否在文档中明确写出"一个项目同时只能被一个进程打开"这句话（`unverified`：缺一份官方明文表述）。

**PyGhidra（官方 Python 路线）**
来源：https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/Features/PyGhidra/README.md 与 .../Features/PyGhidra/src/main/py/README.md · `observed`

- 状态：PyGhidra 是 Ghidra 官方仓库内的一个 Feature 模块，不是第三方外挂。源码中的模块职责写明：提供 PyGhidra Python 库、一个在 GUI 里提供 CPython 解释器的 Plugin、一个能运行原生 CPython 3 写的 GhidraScript 的 ScriptProvider，以及负责安装/启动的 `support/pyghidra_launcher.py`（处理虚拟环境与 externally managed environments）。
- 出身："originally developed by the **Department of Defense Cyber Crime Center (DC3)** under the name **"Pyhidra"**"，通过 **JPype** 在原生 CPython 3 中直接访问 Ghidra API。
- 能力边界（原文）："This enables the Ghidra **GUI and headless Ghidra** to run GhidraScript's written in native CPython 3, as well as interact with the Ghidra GUI through a built-in REPL."
- 安装：`pip install pyghidra`（或安装目录内 `<GhidraInstallDir>/Ghidra/Features/PyGhidra/pypkg/dist`），类型存根 `pip install ghidra-stubs==<version>`；可用 `GHIDRA_INSTALL_DIR` 指定安装，或 `pyghidra.start(install_dir=...)`。
- 已确认的 API 名（逐字来自该 README 的 API 段）：`pyghidra.start(verbose=False, *, install_dir=None)`、`pyghidra.started()`、`pyghidra.open_project()`、`pyghidra.open_filesystem()`、`pyghidra.consume_program()`、`pyghidra.program_context()`、`pyghidra.analyze()`。
- 启动器 `support/pyghidraRun` 存在（bash），它检查 `python3` 是否存在后执行 `python3 "<install>/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py" <install> [--dev] <VMARGS> "$@"`。Windows 下对应脚本名未核对（`unverified`）。

**维护状态与许可**：Ghidra master 最后提交 `2026-10-15T12:01:19Z`（标题 `GP-7320: Fixing com.microsoft.z3.jar hash`）；仓库根 `LICENSE` 首行为 Apache License 2.0。· `observed`

## 3. Binary Ninja

**官方对"批处理模式"的立场**
来源：https://docs.binary.ninja/dev/batch.html · `observed`

- 原文回答："How do I enable batch-processing mode?" → "The answer is that we don't have one--but the good news is because it doesn't need it! We have an even better solution. BN is simply a library that is trivial to include in your own scripts for batch analysis."
- 许可门槛（同页原文）："As long as you have a **Commercial or Ultimate license** (or a **headless** license), it's possible to invoke the core analysis library with all of its APIs without even launching the UI."

**Python 入口与实操约束**
- 前置：跑安装目录内 `scripts/install_api.py`（官方示例 `python3 ~/binaryninja/scripts/install_api.py`），它写入 `.pth` 让 Python 找到 BN 库；官方警告不要用 Windows App Store 版 Python。建议为 headless 单独装一个 Python。
- 最小调用：`import binaryninja` + `with binaryninja.load("/bin/ls") as bv:`；不用 `with` 时必须自己 `bv.file.close()`，否则泄漏内存。
- 只读快速扫描：`load(path, update_analysis=False)` 会跳过线性扫描与递归下降。
- 分析挂起：`load(path, options={'analysis.initialAnalysisHold': True})`；此时直接读 `fn.hlil` 会按需强制分析（官方示例注释说明）。
- 触发已注册插件：`PluginCommandContext(bv)` + `PluginCommand.get_valid_list(cxt)['BinExport'].execute(cxt)`。
- 关日志：`binaryninja.disable_default_log`；并行：multiprocessing 必须用 `spawn` 或 `forkserver`（`fork` "WILL CRASH OR HANG"），并用 `binaryninja.mainthread.set_worker_thread_count` 降线程数（建议 ≥2）。
- 许可注入：磁盘 `~/.binaryninja/license.dat`；无盘可用 `core_set_license`（官方明确说明这不混淆序列号，内存/API 仍可被提取）。
- 禁用用户设置与插件（须在 `import binaryninja` **之前**设环境变量）：`BN_DISABLE_USER_SETTINGS`、`BN_DISABLE_USER_PLUGINS`、`BN_DISABLE_REPOSITORY_PLUGINS`。

**Intermediate language 层级（各层用途）**
来源：https://docs.binary.ninja/dev/bnil-overview.html · `observed`

- LLIL（Low Level IL）：由 Lifted IL 转换而来，"removes NOP instructions and folds flags into conditional instructions but otherwise contains the same operations"；有 LLIL SSA Form。
- Mapped Medium Level IL：一个转换层，"rarely needed for analysis but is useful for the translation process"。
- MLIL（Medium Level IL）：把寄存器与内存访问翻译成变量，为变量关联类型，并用平台信息生成调用（原文："translates registers and memory accesses into variables, types are associated with variables, platform information is used to generate calls"）；有 MLIL SSA Form。
- HLIL（High Level IL）：最高层，供接近源码的阅读；文档另有独立 LLIL / MLIL / HLIL 指南页与"Modifying ILs"页。

**AI 助手：第一方产品与官方 MCP**
- 第一方 AI 产品存在：**Sidekick**，官网 https://sidekick.binary.ninja/ 标题为 "Sidekick by Binary Ninja - AI-Powered Reverse Engineering"；binary.ninja 首页导航直接链接到 `https://sidekick.binary.ninja`，发布说明段提到 "binary similarity, TMS320C6x, **MCP**, and much more"。· `observed`
- 官方 MCP Server 是 Binary Ninja 自身文档化的功能（见第 5 节），属第一方而非社区工具。
- 注意 WARP **不是** AI 功能：它按函数字节内容生成 GUID 做函数识别（签名库），文档见 https://docs.binary.ninja/guide/warp.html。`Guided Analysis` 也不是 AI，而是人工控制基本块是否参与分析。· `observed`

**免费版限制**
来源：https://docs.binary.ninja/about/license/free.html · `observed`
- Free Edition 许可明写 "for your internal evaluation and non-commercial purposes only"，Vector 35 保留随时撤销的权利；且与付费版不同，Free 版**禁止**对软件本身进行反编译/逆向（"Unlike the licenses for our paid versions... you may not decompile, decrypt, reverse engineer, disassemble or otherwise reduce the Software to human-readable form"）。
- 推论（`inferred`）：结合 batch 页的许可措辞，Free / Personal 版不提供 headless（无头）API 使用权；文档另在 MCP 页明确 "The `binaryninja_mcp` headless server is not available in Binary Ninja Free or Personal"。

## 4. radare2 / rizin / Cutter

来源：radare2 `man/radare2.1` 与 `libr/main/radare2.c`、`USAGE.md`；rizin `librz/main/rizin.c`、`doc/rzshell.md`、`rizin.re/posts/faq/`；Cutter `src/CutterApplication.cpp`、`src/python/cutter.py`（均为官方仓库 raw 文件）· `observed`

- radare2 flag（`man/radare2.1` 原文）：`-A` 在提示符前跑 `aaa`（`-AA` 跑 `aaaa`）；`-a arch` 强制 `asm.arch`；`-b bits` 强制 `asm.bits`；`-e k=v` 设配置变量，**但在 `-j` 之后出现时它设的是脚本源**；`-c cmd` 先执行命令；`-q` 静默（无提示符）并在 `-i`/`-c` 命令跑完后退出（`-qq`、`-Q` 另有语义）；`-i file` 在文件加载**之后**运行脚本（`-I` 是加载之前）；`-w` 写模式；`-p prj` 项目；`-L`/`-LL` 列插件。注意任务假设的两个文件路径 `binr/radare2/radare2.1`、`doc/usage.txt` 在 master 上均为 404。
- `-j` 在 radare2 有两重含义（man 与 `-h` 文本不一致，代码同时支持二者）：置 JSON 输出（影响 `-v`/`-L` 等），以及无文件参数时进入 QJS（`js`/`js:<file>`/`js:`）。
- radare2 脚本：r2pipe 是主接口（Python 示例 `r2pipe.open` → `r2.cmd("pd 10")` → `r2.quit()`，命令加 `j` 后缀配 `.cmdj()` 取 JSON）；服务端模式读 `R2PIPE_IN` / `R2PIPE_OUT` 环境变量。内建解释器指令为 `#!`：`#!<interpreter>`、`#!` 列出可用解释器、`#!!` 重置 rlang 会话、`#!?j` 以 JSON 列出、`#!<lang> [file]`、`#!pipe node -e '...'`（在 r2pipe 环境里跑程序）。脚本首行 `#!/` 由 `langFromHashbang` 识别；沙箱模式下 hashbang 被禁用。
- rizin 是 radare2 的 fork（README 原文 "born as a fork of the radare2, with a focus on usability, features and cleanliness"）；官方 FAQ 给出 fork 理由（方向不再一致，分歧覆盖 technical、interpersonal、managerial，原文 "many of us felt stressed, disrespected, and unwelcome"），公告同时说明 Cutter 及其团队加入 rizin 并以 rizin 为后端。
- **读者必须知道的 fork 差异**（逐条有源码对照）：
  - 二进制名：`radare2`/`r2` 与 `ra*2` 工具族 vs `rizin` 与 `rz-*`（`rz-bin`、`rz-asm`、`rz-diff`、`rz-hash`、`rz-gg`、`rz-find`、`rz-sign`、`rz-ax`、`rz-run`）。
  - `-j`：只有 r2 有；rizin 无 `-j`，其 JSON 走长选项 `--cmd-catalog [json]` 或命令级 JSON 模式。
  - `-E`：rizin 是 endianness（`-E big`/`-E little`），r2 是打开编辑器编辑用户 rc —— 同名反义。
  - `-P`：r2 有（rapatch），rizin 无。
  - rizin 会拒绝 `-e asm.arch` / `asm.bits` / `asm.os` / `cfg.bigendian` 并要求改用 `-a` / `-b` / `-k` / `-E`。
  - `-q` 覆盖范围措辞不同（rizin 明写 "quit after `-i` and `-c`"）。
  - 但"rizin 全面重命名了核心命令与配置"**不成立**：`e` 仍是 "Get/Set value of config variable"，`asm.arch`、`asm.bits`、`cfg.debug`、`cfg.bigendian` 变量名未变。
  - 项目格式不同：rizin 用新的序列化 Projects；r2 仍是 `RPRJ` 头项目文件。
  - 包管理器不同：r2 用 `r2pm`，rizin 用 `rz-pm`（独立仓库 rizinorg/rz-pm，官方库 rizinorg/rz-pm-db）。
  - 绑定不同：r2pipe（r2）vs rzpipe（rizin）。
  - rizin 默认启用改进过的 new shell（tree-sitter 解析器 + 全局命令注册表 `RzCmdDesc`，命令由 `librz/core/cmd_descs/*.yaml` 生成），并移除了 radare2 的 embedded WebUI、`m` 命令、`T` 命令、`pdc`、old projects。
- Cutter：README 自述 "free and open-source reverse engineering platform **powered by rizin**"，支持 Python 与 Native C++ 插件；Python 入口 `src/python/cutter.py`（`from _cutter import *`、`from CutterBindings import *`、`core()` 返回 `CutterCore.instance()`），即其 Python API 建立在 rizin 绑定之上而非 r2pipe。命令行选项包括 `-A/--analysis`(0-2)、`-a`、`-b`、`-c/--cpu`、`-o/--os`、`-e/--endian`、`-F`、`-B`、`-m`、`-i`、`-p/--project`、`-w`、`-P`、`--pythonhome`、`--no-plugins` 等。**高危混淆点**：Cutter 的 `-c` 是 CPU、`-e` 是 endian，与 r2/rizin 的 `-c cmd` / `-e k=v` 完全不是一回事。
- Cutter 的 headless/无 GUI 模式：在 dev 分支 README 与 `CutterApplication.cpp` 中均未出现相关选项（`unverified`：只确认"未见"，未取得官方否定表述）。
- 维护状态（Atom feed 顶层 updated）：radare2 master `2026-10-16T11:07:08Z`；rizin dev `2026-10-15T18:49:35Z`；Cutter dev `2026-09-11T12:44:04Z`（Cutter 版本已 bump 至 2.5.0）。三者均在核验日前数月内有提交。
- 许可：radare2 的 README 自述 LGPLv3（未逐字核对 `COPYING`）；rizin 与 Cutter 的仓库根 `COPYING` 均为 **GNU GPL v3**（`https://raw.githubusercontent.com/rizinorg/rizin/dev/COPYING`、`.../cutter/dev/COPYING`，首行为 "GNU GENERAL PUBLIC LICENSE / Version 3"）。**不要**把 radare2 的 LGPLv3 说法直接套到 rizin 或 Cutter 上；rizin 的 `librz` 是否另有更宽松条款本文未核实（`unverified`）。

## 5. 反向工程 MCP 服务

本节所有仓库事实取自各仓库 README 原文、源码文件与 `commits/<branch>.atom`（Atom feed 顶层 `updated` 即最后提交时间）；未使用 GitHub REST API。GitHub code search 需要登录，故"某仓库没有某组件"一类否定结论均标注受限。

| 项目 | 归属 | 最后提交（核验时） | 传输 | 暴露内容 | 强度 |
| --- | --- | --- | --- | --- | --- |
| `HexRaysSA/ida-mcp` | Hex-Rays 官方 | 2026-10-08T20:24:10Z | stdio + Streamable HTTP (8737) | 快照实测 **6** 个工具 | observed |
| `mrexodia/ida-pro-mcp` | 社区 | 2026-09-26T15:42:10Z | GUI/SSE + stdio + idalib | 源码计数 **97** 个工具（含 22 个调试器工具） | observed |
| `LaurieWired/GhidraMCP` | 社区 | 2026-10-10T19:17:31Z（前一次 2025-06-23，约 16 个月空档） | Ghidra 扩展 loopback HTTP 8080 + MCP stdio/streamable-http 8081 | 源码 **30** 个 `@mcp.tool` | observed |
| `svnscha/mcp-windbg` | 社区 | 2026-10-10T15:53:34Z | stdio / streamable HTTP | README 与源码均 **11** 个工具 | observed |
| `duty1g/x64dbg-mcp-server` | 社区 | 2026-10-12T08:48:54Z | Streamable HTTP + SSE (9094)，强制 Bearer | 源码 **84** 个工具（README 自相矛盾：Feature 段 84 / Tools 段 72） | observed |
| WinDbg MCP | **Microsoft 官方** | 随 WinDbg 发布 | stdio（经 `DbgX.Mcp.Proxy.exe` 与命名管道） | 会话工具 + 调试器工具 + 4 个内置 prompt | observed |
| `lldb-mcp` | **LLVM/LLDB 官方** | 随 LLDB 发布 | stdio | **4** 个工具 + 资源 | observed |

**IDA**
- 官方桥 `HexRaysSA/ida-mcp`：stdio 用法 `uvx ida-mcp stdio --agent=<label>`，Streamable HTTP 用法 `uvx ida-mcp http --host 127.0.0.1 --port 8737`（源码 `ida_mcp/cli.py` 中 `--port` 默认 8737）。依赖 `ida-nexus>=0.13.4` 与 Python 3.11+；GUI 插件（`ida_mcp_plugin.py`，`idaapi.plugin_t` 包装 `ida_nexus.plugin`）可选，无插件仍可 headless 工作。README **没有**工具清单；从仓库 `tests/snapshots/mcp_metadata.json` 快照实测只有 6 个工具：`open_database`、`execute_python`、`reference`、`list_databases`、`save_database`、`close_database`（`protocolVersion` 2025-11-25）。每个工具调用须显式带 `database` 会话参数，没有隐式"当前数据库"。
- 社区桥 `mrexodia/ida-pro-mcp`：**仍在维护且代码与声称一致**。README 顶部横幅现已推荐改用官方 `ida-mcp`，提交标题即为 "Add banner to recommend using ida-mcp instead"——这是"社区桥正在让位于第一方"的直接证据，不是废弃证据（仓库未归档）。传输：GUI/SSE `--transport http://127.0.0.1:8744/sse`、代码内 `DEFAULT_IDA_PORT = 13337`、MCP 端点 `/mcp`；headless 走 `idalib-mcp --host --port` 与 `--stdio`。声称的调试器能力**有代码支撑**：`api_debug.py` 内 22 个 `@tool`（`dbg_start`、`dbg_continue`、`dbg_step_into`、`dbg_step_over`、`dbg_add_bp`、`dbg_set_bp_condition`、`dbg_regs*`、`dbg_stacktrace`、`dbg_read`、`dbg_write` 等），并由 `?ext=dbg` 查询参数门控（`zeromcp/mcp.py` 的 `_parse_extensions` 与 `server.py` 透传实现）。工具总量按 `api_*.py` 的 `^@tool` 计数为 97。约束：需 Python 3.11+、需 `uv` 且需全局激活 idalib；"IDA 8.3+ / IDA Free 不支持"仅见于 README，源码无版本断言（`unverified`）。

**Ghidra**
- 社区桥 `LaurieWired/GhidraMCP`：加载方式为 Ghidra extension（`File → Install Extensions`，Java 插件 `GhidraMCPPlugin` + `BackendHttpServer.java`）。Ghidra 侧是扩展内置的 loopback HTTP server（代码默认 `http://127.0.0.1:8080/`），MCP 侧默认 stdio，可选 streamable-http（`--mcp-port` 默认 8081）——**两个端口不是一回事**。README 只笼统写 decompile/rename/list 几类，实际 `src/ghidra_mcp/server.py` 有 30 个 `@mcp.tool`（`decompile_function`、`disassemble_function`、`get_xrefs_to/from`、`read_memory`、`rename_*`、`set_function_prototype`、`set_*_comment`、`list_*` 等），即 README 未夸大而是不完整。约束：Ghidra 12.1.4、Java 21 构建、Python>=3.10，headless 需 `pyghidra>=3.1` + `GHIDRA_INSTALL_DIR` + `--extension-jar`。
- 维护状态要谨慎读：最后提交 2026-10-10，但其前一条是 2025-06-23，中间约 16 个月无提交。这是**间歇性维护**，不能按"持续活跃"宣传。
- 衍生实现：`13bm/GhidraMCP`（未归档，master 最后提交 2026-09-06）；`bethington/ghidra-mcp`（未归档，main 最后提交 2026-10-09，README 声称 209 个工具，但其工具由 endpoint catalog 动态生成，静态计数只能看到 8 个 `@mcp.tool` —— **209 这个数字无法从可见代码复现**）。GhidraMCP 自己的 README **没有**引用任何 fork 或替代品。
- Ghidra 官方（`NationalSecurityAgency/ghidra`）：master README 中 "MCP" 零命中，最近 10 个 release notes 中同样零命中。**未见官方内置 MCP 组件**——此否定结论受 GitHub code search 需登录的限制（`unverified`）。

**调试器**
- **Microsoft 官方 WinDbg MCP 确实存在**（https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-mcp-overview）。架构：AI 客户端 ←stdio→ `DbgX.Mcp.Proxy.exe` ←每会话命名管道→ WinDbg MCP server（同时提供 tools / prompts / resources）。工具含 `list_sessions`、`connect_session`、`disconnect_session` 与会话内的调试器工具；内置 prompt 有 `investigate_symbol_loading_issues`、`write_extension`、`create_graph`、`configure_ttd`。约束（https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/set-up-windbg-mcp）：需 WinDbg `1.2610.1001.0` 或更高；官方只支持 VS Code + GitHub Copilot 与 GitHub Copilot CLI；一次只允许一个客户端连接；secure mode 默认开启且本次启动后不可关闭。
- 社区 `svnscha/mcp-windbg`：包装 `cdb.exe` / `kd.exe`，stdio 或 streamable HTTP；README 工具表与源码 `src/mcp_windbg/server.py` 都是 11 个工具（`list_dumps`、`open_cdb_dump`、`open_cdb_remote`、`open_kd_session`、`open_kd_dump`、`run_cdb_command`、`run_kd_command`、`close_cdb_session`、`close_kd_session`、`send_ctrl_break`、`wait_for_break`），README 与代码一致。它自己顶部就把用户导向微软官方 MCP，自述为社区替代。依赖 Windows + Debugging Tools for Windows 与 `_NT_SYMBOL_PATH`。
- 社区 `duty1g/x64dbg-mcp-server`：Zig 原生 x64dbg 插件，Streamable HTTP + SSE，默认 `http://localhost:9094/` 与 `/sse`，强制 Bearer token（HTTP 明文传输，注意令牌暴露面）；`src/mcp/tools.zig` 有 84 个工具定义，与 README 的 Feature 段一致，但 README 的 Tools 段写 72 —— **README 自相矛盾，以代码 84 为准**。构建需 Zig 0.16-dev。
- **LLVM 官方**：LLDB 自带 `lldb-mcp`（https://lldb.llvm.org/use/mcp.html），stdio，只有 4 个工具 `session_create`、`command`、`sessions_list`、`session_close`，另有每 debugger / 每 target 资源；`protocol-server start MCP` 可把运行中的 LLDB 暴露出去（默认 localhost 随机端口，注册到 `~/.lldb/lldb-mcp-<pid>.json`，只在客户端启动时发现一次）；异步模式下需 `script lldb.debugger.SetAsync(False)`。
- `mrexodia/x64dbg-mcp` **不存在**（HTTP 404）——不要引用这个仓库名。
- 仅确认存在与最后提交时间、传输与工具未核验：`gengstah/windbg-mcp`（2026-05-03）、`richinseattle/gdb-mcp`（2026-10-07）；另有若干 x64dbg MCP 仓库名来自搜索页 HTML，未核验（`unverified`）。

**TTD 与 MCP**
- TTD.exe 那页文档**全文没有 MCP 提及**，也不存在独立的官方 "TTD MCP" 服务器；TTD 的自动化入口就是 `TTD.exe` 命令行，而 MCP 侧的 TTD 工作流由 **WinDbg MCP** 承担（它内置 `configure_ttd` prompt，其 set-up 页把 Time Travel Debugging trace 列为调试目标）。

## 6. HyperDbg

来源：官方文档站 https://docs.hyperdbg.org/（GitBook，可加 `.md` 取原文）· `observed`

**定位与能观察到什么**
- README 原文：HyperDbg 是 "an open-source, user-mode, and kernel-mode debugger focusing on using hardware technologies"，设计为 "on top of Windows by **virtualizing an already running system using Intel VT-x and Intel PT**"，"aims not to use any APIs and software debugging mechanisms, but instead, it uses **Second Layer Page Table (EPT)** extensively to monitor both kernel and user executions"。
- 相对普通调试器的差异（同页）：隐藏钩子（hidden hooks）"entirely invisible for both Windows kernel and the programs"、模仿硬件调试寄存器做读写监控且无大小与数量限制、TLB-splitting、代码覆盖率测量、监控某函数全部 mov 到/从内存。
- 机制层面（文档目录可见的专文）：`!epthook`、`!epthook2`（EPT hook 设计）、`!monitor`、`!syscall`/`!sysret`、`!exception`/`!interrupt`、`!mode`（检测内核↔用户转换）、VMM 模块与 NMI 控制、VMX root/non-root 间缓冲传输。这些能力不依赖软件断点或调试寄存器，因此不受"改内存/改代码"式的反调试检测。

**运行要求**
- CPU：**只支持 Intel x64**。FAQ 原文："The current version of HyperDbg only supports Intel x64 processors. You cannot run it on an AMD processor or an ARM processor. This is mainly because HyperDbg heavily uses VT-x..."，部署页亦有 "currently available only for Intel processors"。
- 必须先做三件事：BIOS 中启用 Intel **VT-x**；**禁用 Driver Signature Enforcement (DSE)** —— 原因是 "the current versions of HyperDbg are **not digitally signed**"；**关闭 VBS**（含 HVCI、Device Guard 等子项）。原文解释二者冲突原因："HyperDbg and VBS are both hypervisors running on ring -1. These hypervisors are not compatible."
- 补丁防护相关：官方推荐"启动时用 WinDbg 附加"来同时绕过 DSE 与 PatchGuard，并说明这是因为该方式下 PatchGuard 不会启动，`!syscall`/`!sysret` 等 PatchGuard 可检测的命令才可用；若只用 F7 临时禁用 DSE，PatchGuard 仍在，部分命令不可用。替代方案为 EfiGuard。
- 虚拟化环境：嵌套场景（VMware Workstation、KVM）需在**宿主机与来宾机同时**禁用 VBS 与 Hyper-V。
- 事件/动作模型：事件（event）+ 条件（condition）+ 动作；动作分 Break（暂停所有核，**本地调试不可用**）、Script（在内核中执行并记录，不必中断到调试器）、Custom Codes（触发时运行自定义汇编）。
- 提示符特征可用于判断当前模式：`HyperDbg>`（本地 VMI）、`<core>: kHyperDbg>`、`<pid>:<tid> (paused|running) u86HyperDbg>` / `u64HyperDbg>`、`[<ip>:<port>] HyperDbg>`（远程）。

**第一方关于透明性与检测限制的声明**
- README："Although it has novel features, HyperDbg tries to be as stealthy as possible. It doesn't use any debugging APIs to debug Windows or any application, so classic anti-debugging methods won't detect it. Also, it resists the exploitation of time delta methods (e.g., RDTSC/RDTSCP) to detect hypervisors' presence, therefore making it much harder for applications, packers, protectors, malware, anti-cheat engines, etc. to discover the debugger."
- Transparent Mode 页（由 `!hide` 启用）**明确保留了不确定性的边界**："If you enable this mode, then HyperDbg tries to make itself transparent from anti-debugging and anti-hypervisor methods; however, **it won't guarantee 100% transparency**, but it makes it substantially harder for the anti-debugging methods."并写明 "Transparent mode is under active development"。
- 另有两篇限制性说明：`the-unsafe-behavior`（"unsafe" 行为的含义）与 `script-engine-in-vmx-non-root-mode`（VMX non-root 下脚本引擎的限制），均为官方专文。

**维护状态**：`HyperDbg/HyperDbg` master 最后提交 `2026-09-22T16:39:33Z`（对应 v0.24）。仓库许可未逐条核对（`unverified`）。· `observed`

## 7. Windows 上的 Intel PT（用户态采集）

**结论：没有第一方文档化的"用户态采集 Intel PT"路径。**以下是支撑它的三类证据。

**Microsoft 一侧**
- 唯一与 IPT 相关的官方文档是把 IPT **暴露给 Hyper-V 来宾机**，而不是给主机用户态程序使用：https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/performance-monitoring-hardware —— 使用 `Set-VMProcessor MyVMName -Perfmon @("ipt", "pmu")`；要求 "An Intel processor that supports IPT and the **PT2GPA** feature"、Windows Server 1903 (SAC) / Windows 10 1903+、来宾机不得启用嵌套虚拟化且须处于停止状态；并给出约束 "any command that attempts to enable `ipt` must also specify `pmu`"。同页说明自 Windows Server 2019 / Windows 10 1809 起**主机操作系统**默认可使用性能监控硬件（PMU/PEBS/LBR），但这句针对的是性能计数器，不是 PT 采集 API。· `observed`
- 用 Microsoft Learn 官方搜索 API（`https://learn.microsoft.com/api/search?search=...&locale=en-us`）分别检索 `Intel Processor Trace`、`Processor Trace`、`Intel PT`、`IPT trace Windows user mode`、`ipt.sys`，**没有任何一条指向"从用户态采集 Intel PT"的第一方文档**；`ipt.sys` 的检索结果与 IPT 完全无关。· `observed`（阴性证据：只能在"这些查询命中范围内"断言不存在）

**本机运行时取证（Windows 11 24H2，build 26100）**
- `C:\Windows\System32\drivers\ipt.sys` 存在（99,744 字节），版本信息 FileDescription = **"IPT Driver"**、CompanyName = Microsoft Corporation、FileVersion 10.0.26100.1150；Authenticode 状态 Valid，签名者 `CN=Microsoft Windows`。服务名 `IPT`，`StartType: Manual`，当前 `Stopped`。· `observed`
- 该驱动二进制内的 ASCII 符号显示它服务于虚拟化与崩溃转储路径，例如 `WinHvCreateIptBuffers`、`BugCheckSecondaryDumpDataCollectThreadTraceMetadata`、`BugCheckSecondaryDumpDataCollectCoreTraceMetadata`、`WriteCoreTraceMetadataV1`、以及"Number of threads with user/kernel code being traced"之类统计串；同时出现 `IoCreateDevice`（创建设备对象）。· `observed`
- 由此可判定：Windows 确实内置了一个 IPT 驱动，但它是**未文档化的 in-box 组件**，与 Hyper-V（`WinHv*`）和 bugcheck 次级转储采集耦合；**未发现**任何官方说明它的用户态接口、设备名或 IOCTL 约定。任何"在 Windows 用户态打开 IPT 抓取"的说法都不能声称有第一方依据。· `observed` + `inferred`（"没有公开接口"这一否定结论限于上述检索与二进制符号观察）

**Intel 一侧**
- 解码库为官方参考实现：Intel Processor Trace **Decoder Library**（`intel/libipt`，README 自述 "Intel's reference implementation for decoding Intel PT"），工具为 `ptdump`（包转储）、`ptxed`（trace 反汇编）、`ptseg`（找周边 PSB 包）、`pttc`（trace 测试生成）、`ptunit`（单元测试），另有 `sideband` 关联库与 `pevent`。构建依赖 cmake、xed（`ptxed` 必需）、yasm（跑 `pttc` 需要）。· `observed`
- 采集说明文档只覆盖 **Linux**：`doc/howto_capture.md` 讲内核 4.1+ 的 `perf_event` 接口（`perf_event_attr`、`perf_event_open`、attr 含 `exclude_kernel`）与内核 4.3+ 的 `perf` 工具用法（`perf record -e intel_pt//[uk] [--per-thread] [-a --switch-events]`，产出 `perf.data` 与 `PERF_RECORD_AUXTRACE`）。该文档**没有 Windows 章节**。· `observed`
- 解码库维护状态：`intel/libipt` master 最后提交 `2026-10-16T04:59:50Z`（`sideband: fix leak in pt_sb_alloc_pevent_decoder()`），距核验日约 4 个月，仍在维护。· `observed`
- Intel 官网 `intel.com/content/www/us/en/developer/...` 的 PT 页面对本会话返回 HTTP 403（bot 拦截）或重定向到 `corpredirect.intel.com`，本次未取得 Intel 官网页面正文；上述 Intel 一手结论全部来自 `intel/libipt` 仓库本身。· `unverified`（Intel 官网页面内容未读到）

**所以实际可选的路只有两条**：自带/未文档化的 in-box `ipt.sys`（与 Hyper-V、转储耦合，无公开接口），或自行编写内核驱动（在 Windows 上要面对驱动签名与 VBS/HVCI 限制）。想用 Intel PT 做纯用户态追踪，Linux 是官方唯一有文档的路线。

## 8. Time Travel Debugging（TTD）

来源：https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview 与 .../time-travel-debugging-ttd-exe-command-line-util · `observed`

**记录什么**
- 捕获进程执行的 trace 并可正反向回放；trace 内含调试器数据模型对象，可用 LINQ 查询（例如查询某模块何时加载、所有异常）；支持 Timelines、JavaScript/NatVis 自动化，以及托管代码（通过 SOS，64 位模式）。

**文档化限制**
- **仅用户态**："TTD currently supports only user mode operation, so you can't trace a kernel mode process."
- **受保护进程不能记录**："Some Windows system protected processes, such as Protected Process Light (PPL) process, are protected. TTD can't inject itself into the protected process..."（TTD 靠注入记录）
- **只读回放**："You can travel back in time, but you can't change history. You can use read memory commands, but you can't use commands that modify or write to memory."
- **开销**：overview 页 "You can expect about a **10x-20x** performance hit in typical recording scenarios."；TTD.exe 页给的是 "anywhere from **5x-20x or more** slowdown... depending on the application and the recording options"。两处数字不同，引用时须标明出处。
- **文件大小**：trace 可快速涨到数 GB，TTD 不设上限；`.run` 存执行记录，停止记录时生成 `.idx` 索引（通常约为 trace 的两倍大），可用 `!tt.index` 从 `.run` 重建索引。
- **不可脱离**："Once TTD attaches to a process, it can't remove itself." 系统关键进程在记录后需要重启。记录需要管理员权限（通常从管理员命令提示符运行 `ttd.exe`）。
- **记录内容含敏感信息**：可能包含文件路径、注册表、内存或文件内容（文件内容、内存都算）。
- **兼容性冲突**：与反病毒或其他阻拦内存访问的软件冲突（如 EMET）；Electron 应用可能记录成功但目标死锁或崩溃。遇到记录失败/权限错误时官方建议临时禁用反病毒。
- 每次传递共享时只交 `.run`（`.idx` 会自动生成）；WinDbg 一次只能打开一个 trace 文件，多个 trace 需要多开 WinDbg 实例。
- 平台：`Windows Server 2016, 2019, 2022, and 2025 support TTD.exe.`

**TTD.exe 命令行接口（可自动化）**
- 模式：`-launch <Program> [<arguments>]`（默认模式，也是唯一能传程序参数的模式）、`-attach <PID>`、`-monitor <Program>`（程序每次启动都记录，可用 `-cmdLineFilter "<string>"` 过滤；必须用 `-out` 指定输出位置，Ctrl+C 停止，可重复指定多个程序）。
- 自动化关键开关：`-out <path>`、`-noUI`（**官方标注 "Use this option for automation scenarios"**）、`-accepteula`（自动化场景需显式接受 EULA）。
- 其它：`-stop`、`-wait <timeout>`、`-tracingOff`、`-children`（子进程各自一个 trace）、`-cleanup`（卸载 process monitor 驱动）、`-timestampFilename`、`-ring`、`-maxFile <MB>`（全量模式默认 1024 GB；ring 模式默认 2048 MB，上限 32768 MB）、`-maxConcurrentRecordings`、`-numVCpu`（默认 x64/ARM64 为 55、x86 为 32）、`-replayCpuSupport`、`-module <module name>`（只记录指定模块及其调用，显著降开销）、`-recordmode <Automatic|Manual>`（配合 in-process recording API）、`-passThroughExit`、`-onInitCompleteEvent <eventName>`。
- 官方还给出离线/自动化安装方式：`https://aka.ms/ttd/download`（App Installer），或用 PowerShell 从 MSIX 中提取二进制的脚本（页内含完整脚本，包内为 `TTD.exe`、`TTDInject.exe`、`TTDRecord.dll`、`TTDRecordCPU.dll`、`ProcLaunchMon.sys` 等）。· `observed`

## 9. 读者不能假设什么

**许可门槛（会直接阻断无人值守使用的）**
- IDA Free 不能用于商业用途，且没有 IDAPython 与 C++ SDK、没有 idalib —— 任何"用 IDA Free 跑脚本/headless"的教程都不成立。IDA Home（付费）虽无 `-S`、`-O`、`-T` 限制之外的脚本能力，但同样**不提供 `-S` 与 `-O`**；需要脚本化请用 IDA Pro 或 idalib。
- 在自有产品或共享服务器上嵌入 idalib / 以 SaaS 形式使用，需要 IDA Pro **OEM** 授权（开发与 beta 阶段免费）。IDAPython/C++ SDK 的可获得性按版本不同（Free ❌ / Classroom ✅ / Home ✅ / Pro ✅）。
- Binary Ninja 的 headless API 与 `binaryninja_mcp` 需要 **Commercial 或 Ultimate（或 headless 授权）**；Free/Personal 不提供。Free Edition 还禁止对 Binary Ninja 软件本身做逆向。
- HyperDbg 当前**未签名**，必须禁用 DSE，并与 VBS/HVCI 互斥；它不是"装上就能跑"的工具。
- TTD 记录需要管理员权限；Windows 上 IPT 采集没有任何可依赖的官方用户态入口。

**不要以为等价或可互换的**
- `-A` 不等于脚本执行：IDA 的 `-A` 只是"不弹对话框"，执行脚本是 `-S`；`-B` 是 `-c -A -S analysis.idc` 的封装，且 batch 模式下常规插件不会自动加载。
- Ghidra 的 `-noanalysis` 与 `-readOnly` 是两件事：前者决定是否分析，后者决定是否写回；`-readOnly` 与 `-commit`/`-okToDelete` 互斥，只读项目里它是必需的。
- Ghidra 的脚本输出走日志（`-log` / `-scriptlog`），不是 stdout 重定向。
- Binary Ninja 没有"batch 模式"这个开关，库本身就是接口；且并行必须用 spawn/forkserver。
- r2 与 rizin 同名反义的 flag：`-E`（rizin=endian，r2=编辑 rc）、`-j` 只在 r2、`-P` 只在 r2；Cutter 的 `-c`/`-e` 又是另一套语义。
- Cutter 的 Python 绑定是 rizin（CutterBindings），不是 r2pipe。

**明确的 unverified 项（不要基于它们下结论）**
- idalib Python 端的具体生命周期函数签名（本文只确认 `import idapro` 必须为首个导入，及 C++ 侧入口 `idalib.hpp`）。
- Ghidra 官方是否以明文写下"一个项目同时只能被一个进程打开"；本文只确认写锁冲突会以 `LockException` 失败。
- Ghidra Windows 侧 PyGhidra 启动脚本的准确文件名（`support/pyghidraRun` 是 bash 版，Windows 对应物未核对）。
- Cutter 是否存在官方 headless/自动化模式（只确认当前 dev 版本未见该选项）。
- radare2 是否存在长选项表（未发现 `getopt_long` 一类结构，不能断言"没有"）。
- radare2 自有脚本语言（r2script / rlang）的正式文档位置（`doc/` 全清单中无专文）。
- Intel 官网 PT 开发者页面正文（站点对本会话返回 403/跨域重定向），因此 Intel 侧结论仅基于 `intel/libipt` 仓库。
- `ipt.sys` 是否存在未公开的用户态设备接口（只确认它是微软签名的 in-box IPT 驱动、面向 Hyper-V 与 bugcheck 转储路径，且 Microsoft Learn 无文档）。
- 各项目的许可全文逐条核对（本文只记录 README/许可页自述）。
- MCP 相关：Ghidra 官方仓库是否内置 MCP 组件（README 与最近 10 个 release notes 零命中，但 GitHub code search 需登录，属受限否定）；`bethington/ghidra-mcp` 声称的 209 个工具（工具由 endpoint catalog 动态生成，静态计数复现不出）；`HexRaysSA/ida-mcp` 的 "IDA 9.4+" 与 `mrexodia/ida-pro-mcp` 的 "IDA 8.3+" 版本门槛（均只见于 README，源码无断言）；`LaurieWired/GhidraMCP` 30 个工具中逐个确认了 29 个；各仓库的"未归档"仅由 HTML 页面措辞判定，未用 API 交叉验证；`gengstah/windbg-mcp`、`richinseattle/gdb-mcp` 等仅确认存在与最后提交时间，transport 与工具清单未核验。

## Part 2: solvers, emulation and deobfuscation

面向 `exe-reverse` skill（Windows x86/x64 本地软件逆向）的工具选型事实清单。
补的是当前 skill 的缺口：方法已经写了，但没有点名任何具体工具，也没写怎么从脚本驱动。

## 采集方法

- `web_search` 在本会话不可用（HTTP 402），全部事实经 `web_fetch` / `Invoke-WebRequest` 打开一手来源。
- 强度标签：`observed` = 打开了第一方来源（项目 README、仓库内源码、官方文档站、PyPI JSON、GitHub commit/release feed）；`inferred` = 由已观察事实推导；`unverified` = 未能确认。
- **未确认的入口点一律标注为未确认**，不做补全猜测。
- 采集时参考日期：2027-02-21。下文中"最近提交"是 GitHub atom feed 里可见的最新时间戳，仅代表主干分支的可见活动，不是版本发布承诺。

## 汇总表

| 工具 | 用途 | 许可证 | Python 接口 | 维护状态 | 强度 |
| --- | --- | --- | --- | --- | --- |
| Z3 | 通用 SMT 求解器（BV/数组/整数/实数/FP/串） | MIT | `pip install z3-solver`，`import z3` | 活跃，PyPI 5.3.1.0（2026-10-15） | observed |
| Boolector | BV/数组/UF 求解器 | MIT | `pyboolector`（需 Cython 自建） | **已归档，开发停止**，由 Bitwuzla 接替 | observed |
| Bitwuzla | BV/FP/数组/UF 及其组合 | MIT | `bitwuzla`（PyPI 0.9.1） | 活跃，主干最近提交 2026-10-14 | observed |
| CVC5 | 一阶理论组合 SMT | BSD-3-Clause | `cvc5`（PyPI 1.4.2，2026-10-08） | 活跃 | observed |
| Yices 2 | SMT（SMT-LIB + 自有格式） | GPLv3 | `yices`（独立仓库绑定，PyPI 1.1.6，2024-12-18） | 绑定标 Beta；PyPI 包已 2 年未更 | observed |
| Triton | 动态符号执行/污点/IR/AST | Apache-2.0 | `pip install triton-library`，`import triton` | 活跃分支是 `dev-v1.0`，PyPI 停在 1.0.0rc4（2024-05-22） | observed |
| angr | 二进制分析框架（符号执行/CFG/反编译） | BSD-2-Clause | `pip install angr`，`import angr` | 活跃，PyPI 10.0.4.post1（2026-10-14） | observed |
| Miasm | IR/反汇编/JIT/符号执行 | GPLv2 | 原生 Python 包 | 代码活跃（主干 2026-09-21），PyPI 停在 0.1.5（2023-04-18） | observed |
| VTIL | 反虚拟化用优化 IL（C++） | README 未声明 | **无 Python 绑定** | 自述"初始版本尚未完成" | observed |
| Titan | VMProtect 反虚拟化器（基于 Triton） | README 未声明 | 无（C++ CLI） | 自述仅覆盖 VMProtect < 3.8 | observed |
| TritonDSE | Triton 之上的探索式 DSE 库 | Apache-2.0 | `pip install tritondse` | PyPI 0.1.14（2026-03-16）；**自述仅 ELF/Linux** | observed |
| QSynth | I/O 程序综合做去混淆 | AGPL-3.0 | `from qsynthesis import ...` | PyPI 0.2.2（2025-02-16）；自述实验性 | observed |
| Unicorn | CPU 仿真器（QEMU 派生） | GPLv2 | `pip install unicorn`，`from unicorn import *` | 主干最近提交 2026-02-17；PyPI 2.1.4 | observed |
| Qiling | 带 OS 层的高级仿真框架（基于 Unicorn） | GPLv2 | `pip install qiling`，`from qiling import Qiling` | 代码活跃（主干 2026-09-05），PyPI 停在 1.4.6（2023-08-04） | observed |

---

## Z3

- 仓库：https://github.com/Z3Prover/z3 ，README 第 4 行自述 "licensed under the MIT license"。PyPI 元数据 `license` 字段同为 "MIT License"。`observed`
- Python 绑定是 `pip install z3-solver`（README「Python」小节），模块名 `z3`。PyPI 最新版本 `5.3.1.0`（上传 2026-10-15）。`observed`
- **已确认的 Python 入口**（读 `src/api/python/z3/z3.py` 源码，行号为该文件内位置）：`BitVec(name, bv, ctx=None)`（L4214）、`BitVecs(names, bv, ctx=None)`（L4238）、`Int(name, ctx=None)`（L3418）、`Array(name, *sorts)`（L4974）、`SolverFor(logic, ctx=None, logFile=None)`（L8115）、`simplify(a, *arguments, **keywords)`（L9594）、`class Solver`（L7548）、`class ModelRef`（L6989）。`Solver` 上的关键方法：`add(*args)`（L7686）、`check(*assumptions)`（L7753）、`model()`（L7782）、`push()`（L7591）、`pop(num=1)`（L7613）、`reset()`（L7653）、`to_smt2()`（L8063）。位向量算子：`BV2Int(a, is_signed=False)`（L4150）、`Int2BV(a, num_bits)`（L4173）、`Concat(*args)`（L4259）、`Extract(high, low, a)`（L4305）、`UDiv`/`SRem`/`LShR`（L4436/L4478/L4499）、`ZeroExt(n, a)`（L4593）、`SignExt(n, a)`（L4563）。`observed`
- `Solver.check()` 返回 `CheckSatResult`；`Solver.model()` 的 docstring 写明「raises an exception if a model is not available (e.g., last `check()` returned unsat)」。`observed`
- **三类理论的官方措辞，正好对应"强项/弱项"这个问题**：
  - 位向量：`Z3 supports Bitvectors of arbitrary size.`（Z3 Guide, Bitvectors）`observed`
  - 位向量与整数混合：`Note that reasoning in the combination has significant overhead so you will be better off if you can model your problems entirely only using bit-vectors or entirely using integers (reals).`（Z3 Guide, Bitvectors）——这是 Z3 官方对 BV 建模的第一方性能指导。`observed`
  - 数组：官方称有判定过程，并把"高效"明确定义为 NP 完全复杂度：`amenable to efficient saturation procedures (here efficient means, with an NP-complete satisfiability complexity)`（Z3 Guide, Arrays）。同时说明 Z3 的数组被等同为函数空间，而非严格的 select/store 一阶模型，`(_ as-array f)` 会放宽可满足性。`observed`
  - 浮点：`Floating point operations are defined modulo rounding modes. Many algebraic properties of bit-vectors, integers and reals don't carry over to floating points. For example, addition is not associative.`（Z3 Guide, IEEE Floats）——即 FP 不是"慢"的问题，而是代数性质不成立，符号化化简与约束推理的直觉在此失效。`observed`
- 求解结果可以是 `unknown`：`Z3 may also return unknown if it can't determine whether a formula is satisfiable or not.`（Z3 Guide, Basic Commands）`observed`
- 未找到：Z3 官方对"BV 与 FP 谁更快"的量化性能声明。`unverified`

## Boolector 与 Bitwuzla

- Boolector 仓库 README 开头即为归档声明：`This repository serves as archive for the last and final version of Boolector.` / `Active development and maintenance has stopped.` / `Boolector was succeeded by Bitwuzla.`（https://github.com/Boolector/boolector ）`observed`
- Boolector 许可证为 MIT（`COPYING` 第 7 行 `MIT License`）。支持逻辑：BV、QF_ABV、QF_AUFBV、QF_BV、QF_UFBV。C 与 Python API 均有，但 `pyboolector` 需 Cython，且要以 `./configure.sh --python` 自建；Homebrew 安装的版本明确不带 Python 绑定。`observed`
- Python 包 `pyboolector` 在 PyPI 上的最新版本字符串为 `3.2.4.38488416565`，上传时间 2026-10-14——与源码仓库已归档并存，看起来是自动发布的 wheel；这不是版本活跃的证据。`observed`（该矛盾的解释为 `inferred`）
- Bitwuzla 仓库：https://github.com/bitwuzla/bitwuzla ，README 自述覆盖 `fixed-size bit-vectors, floating-point arithmetic, arrays, uninterpreted functions and their combinations`，许可证 MIT（README 徽章）。`observed`
- Bitwuzla 主干最近提交 2026-10-14；PyPI 包 `bitwuzla` 最新 0.9.1（2026-05-21）。系统描述论文为 CAV 2023（README 给出 DOI）。`observed`
- 对 bit-vector 问题的性能特征：**两个项目的 README 都没有给出第一方性能声明**，只声明了理论覆盖范围。README 未提供 SMT-COMP 成绩或相对速度结论。`unverified`
- 实务含义（推导）：Triton 的求解器后端现在只列 Z3 与 Bitwuzla 两个（见下），Boolector 已不在其中；把 Boolector 当作"现代 BV 专用求解器"来推荐，与项目现状不符。`inferred`

## CVC5 与 Yices 2

- CVC5 仓库：https://github.com/cvc5/cvc5 ，许可证为 modified BSD（`COPYING`：`distribution is under the terms of the modified BSD license`），README 徽章标 BSD-3-Clause。`COPYING` 同时提示：cvc5 可以被配置为链接部分 GPL 库（CLN、glpk-cut-log、CoCoALib、Normaliz），默认不链接，但这类构建在非 GPL 兼容项目中受约束。`observed`
- CVC5 的性能声明是相对其前代而非绝对：`It has been designed to increase the performance and reduce the memory overhead of its predecessors.`（README）`observed`
- CVC5 提供 Python API（README「Interfaces」小节：`cvc5 features APIs for several different programming languages such as Python and Java`）。PyPI 包 `cvc5` 最新 1.4.2（2026-10-08），项目主页指向 cvc5.github.io。**具体 Python 函数名未逐个核实**。`observed`（入口名 `unverified`）
- CVC5 官方文档站：https://cvc5.github.io/docs/ ；Windows 需 MSYS2 或 Mingw-w64 交叉编译（README「Build and Dependencies」）——对 Windows 逆向工作流是实际摩擦。`observed`
- Yices 2 仓库：https://github.com/SRI-CSL/yices2 ，许可证 GPLv3（README 徽章 `License: GPL v3`）。`observed`
- Yices 的 Python 绑定是**独立仓库** `SRI-CSL/yices2_python_bindings`（README 明确列出 Java/Python/Go/OCaml 各自独立绑定仓库）。PyPI 包名 `yices`，作者为 SRI 的 Sam Owre、Ian A. Mason、Bruno Dutertre、Ahmed Irfan，`home_page` 指向该独立仓库，分类信息标 `Development Status :: 4 - Beta`；最新 1.1.6（2024-12-18）。`observed`
- 对 bit-vector 问题的性能特征：README 未给出任何性能声明，仅有 QF_BV 等逻辑的使用示例。`unverified`

## Triton

- 仓库：https://github.com/JonathanSalwan/Triton 。自述为动态二进制分析库：动态符号执行、动态污点、x86 / x86-64 / ARM32 / AArch64 / RISC-V 32-64 的 ISA 语义 AST、表达式综合、SMT 化简、到 LLVM / Z3 的双向 lifting、到 Z3 与 Bitwuzla 的求解器接口、C++ 与 Python API。`observed`
- 许可证 Apache-2.0（PyPI `triton-library` 元数据）。`observed`
- **维护状态的准确描述**（这是最容易搞错的一点）：GitHub releases feed 最新 tag 是 **2022-02-09**；主干 `master` 最近提交 **2026-05-11**；而 `dev-v1.0` 分支最近提交 **2026-10-12**（该提交是 `python: add timeout parameter to isSat`）。README 同时挂着 `dev v1.0` 徽章。结论：活跃开发在 `dev-v1.0` 而非 `master`，只看 release 标签会严重低估其现状、只看 master 会略低估。`observed`（"活跃在 dev-v1.0"为 `inferred`）
- 官方自述局限（README 原文）：`As Triton is a kind of a part-time project, please, don't blame us if it is not fully reliable.` `observed`
- 安装：`pip install triton-library`（README「Install using pip」）。注意包名是 `triton-library` 而不是 `triton`。PyPI 最新为 `1.0.0rc4`，上传时间 **2024-05-22**——比它的活跃分支落后约两年半。`observed`（"pip 渠道落后于源码"为 `inferred`）
- 依赖集（README「Install from source」）：`libcapstone >= 5.0.x` 为必需；`libboost >= 1.68`、`libpython >= 3.6`、`libz3 >= 4.6.0`、`libbitwuzla >= 0.4.x`、`llvm >= 12` 全部标记为 optional。默认构建**不含** LLVM 与 Bitwuzla，要全功能需 `cmake -DLLVM_INTERFACE=ON -DBITWUZLA_INTERFACE=ON`。`observed`
- CPU/OS 支持：CI 徽章覆盖 Linux、OSX、Windows(vcpkg)；README 给出 Windows 下用 cmake 生成 `.sln` 与用 `setup.py` 生成 `triton.pyd` 的步骤，也提到 vcpkg 端口由 Microsoft 团队成员维护。`observed`
- **已确认的 Python API**（读官方 doxygen 的 Python 绑定页，libTriton version 1.0 build 1599）：
  - 上下文与执行：`from triton import TritonContext, ARCH`；`TritonContext()` + `setArchitecture(ARCH.X86_64)`，或 `TritonContext(ARCH.AARCH64)`；`processing(Instruction inst)`、`processing(BasicBlock block, integer addr=0)`。
  - 符号化：`symbolizeRegister(Register reg, string symVarAlias="")`、`symbolizeMemory(MemoryAccess mem, string symVarAlias="")`、`symbolizeExpression(integer symExprId, integer symVarSize, string symVarAlias="")`；读取侧 `getSymbolicRegister(Register reg)`、`getSymbolicExpression(id)`、`getSymbolicExpressions()`、`getSymbolicRegisters()`、`getSymbolicMemory()`。
  - 污点：`taintRegister(Register reg)`、`taintMemory(integer addr)`、`taintMemory(MemoryAccess mem)`、`taintAssignment(...)`（6 个重载）、`taintUnion(...)`（6 个重载）、`setTaintRegister(reg, flag)`、`untaintRegister(reg)`；查询 `isRegisterTainted(reg)`、`isMemoryTainted(addr)`、`getTaintedRegisters()`、`getTaintedMemory()`、`getTaintedSymbolicExpressions()`。
  - 路径约束：`pushPathConstraint(AstNode node, string comment="")`、`popPathConstraint()`、`clearPathConstraints()`、`getPathPredicate()`（返回全路径谓词 AST）、`getPathPredicateSize()`、`getPathConstraints()`（返回 `PathConstraint` 列表）、`getPredicatesToReachAddress(integer addr)`。
  - `PathConstraint` 对象：`getBranchConstraints()` 返回 `{isTaken, srcAddr, dstAddr, constraint}` 的字典列表、`isMultipleBranches()`、`getTakenPredicate()`、`getSourceAddress()`、`getTakenAddress()`、`getComment()`。官方示例给出的典型用法是遍历路径约束、对每个分支调 `getModel(b1)` 取种子。
  - 切片：`sliceExpressions(SymbolicExpression expr)` —— 文档描述为「backward slicing」，返回 `{SymExprId : SymbolicExpression}`。
  - 求解：`getModel(AstNode node, bool status=False, integer timeout=0)`、`getModels(AstNode node, integer limit, bool status=False, integer timeout=0)`、`isSat(AstNode node)`、`evaluateAstViaSolver(AstNode node)`；求解器配置 `setSolver(SOLVER solver)`、`setSolverTimeout(integer ms)`、`setSolverMemoryLimit(integer megabytes)`、`getSolver()`。`SOLVER` 命名空间**只有两个值**：`SOLVER.Z3`、`SOLVER.BITWUZLA`。
  - 化简与提升：`simplify(AstNode node, bool solver=False, bool llvm=False)`、`synthesize(AstNode node, bool constant=True, bool subexpr=True, bool opaque=False)`、`liftToLLVM(...)`、`liftToSMT(SymbolicExpression expr, bool assert_=False, bool icomment=False)`、`liftToPython(...)`、`liftToDot(...)`。
  - 具体化（会丢符号性）：`concretizeRegister(reg)`、`concretizeMemory(addr|mem)`、`concretizeAllMemory()`、`concretizeAllRegister()`。
  - 模式：`setMode(MODE mode, bool flag)`、`isModeEnabled(mode)`。
- **两个默认值陷阱**（都来自官方 MODE 命名空间文档，容易踩）：
  - `MODE.MEMORY_ARRAY` 的描述是「Enables symbolic pointers reasoning (QF_ABV logic). When this mode is not enabled, **which is the case by default**, the QF_BV memory model is applied.」——即默认内存模型走 QF_BV，要处理符号指针必须显式开启。
  - `MODE.PC_TRACKING_SYMBOLIC` 的描述是「Tracks path constraints only if they are symbolized. **This mode is enabled by default.**」——默认只跟踪含符号变量的路径约束。
  - 其他相关模式：`MODE.SYMBOLIZE_LOAD` / `MODE.SYMBOLIZE_STORE`（默认行为是 concrete 化 load/store 索引）、`MODE.ONLY_ON_TAINTED`、`MODE.ONLY_ON_SYMBOLIZED`、`MODE.CONSTANT_FOLDING`、`MODE.AST_OPTIMIZATIONS`、`MODE.ALIGNED_MEMORY`、`MODE.TAINT_THROUGH_POINTERS`、`MODE.SYMBOLIZE_INDEX_ROTATION`（官方注明「increases the complexity of solving」）。`observed`

## angr

- 仓库：https://github.com/angr/angr ；许可证 BSD 两条款（`LICENSE` 为 Arizona Board of Regents / Emotion Labs / Microsoft / UC Regents 的 BSD 文本）。`observed`
- 活跃：主干最近提交 2026-10-14，PyPI `angr` 最新 10.0.4.post1（2026-10-14），`Requires-Python >= 3.12`。`observed`
- README 声明的能力：反汇编与 IR lifting、程序插桩、符号执行、控制流分析、数据依赖分析、值集分析（VSA）、反编译。`observed`
- **规范用法（官方文档原文，`observed`）**：
  - 起点：`proj = angr.Project('path', auto_load_libs=False)`；`state = proj.factory.entry_state()`；`simgr = proj.factory.simgr(state)`（文档同时出现 `proj.factory.simulation_manager(state)` 写法）。从任意地址起步用 `proj.factory.blank_state(addr=...)`，再把符号变量写进寄存器（官方示例 `init_state.regs.edi = input_arg`）。
  - 目标与回避：`simgr.explore(find=..., avoid=...)`。`find`/`avoid` 都可以是单个地址、地址列表，或接收 state 返回 bool 的函数；`num_find` 控制找到多少个才返回，默认 1。命中后进入 `found` stash，回避的进入 `avoided`。
  - 取输入：`s = simgr.found[0]`；stdin 用 `s.posix.dumps(0)`，stdout 用 `s.posix.dumps(1)`（官方 CTF 示例先 `simgr.explore(find=lambda s: b"Congrats" in s.posix.dumps(1))`，再取 `flag = s.posix.dumps(0)`）。
  - 求解：`state.solver.add(...)`、`state.solver.eval(x)`、`state.satisfiable()`；符号变量 `claripy.BVS('input', 64)`。官方示例也演示 `solver.min(input_arg)` / `solver.max(input_arg)` 取值的区间。
  - 单步与跑完：`simgr.step()`、`simgr.run()`；stash 语义为 `active` / `deadended` / `pruned` / `unconstrained` / `unsat` / `errored`（`unconstrained` 需 `save_unconstrained`、`unsat` 需 `save_unsat`、`pruned` 由 `LAZY_SOLVES` 触发）。
  - 探索技术（`simgr.use_technique(tech)`，见 `angr.exploration_techniques`）：`Explorer`、`DFS`、`LengthLimiter`、`LoopSeer`（丢弃疑似循环过多次的状态）、`ManualMergepoint`、`MemoryWatcher`（运行时内存过低就停止探索）、`Oppologist`（遇到不支持的指令时具体化输入并用 unicorn 模拟该单条指令）、`Spiller`（活动状态过多时把部分状态落盘以压低内存）、`Threading`、`Tracer`、`Veritesting`（可用 `SimulationManager(veritesting=True)` 开启，官方注明它与其他技术「frequenly doesn't play nice」）。`observed`
- angr 支持 IEEE754 浮点（`claripy.FPV` / `claripy.FPS` / `claripy.fp.FSORT_DOUBLE`），且官方说明 z3 的 FP 运算带舍入模式参数。`observed`
- **官方自述的失败原因（"Gotchas when using angr" 页，本节是最有价值的一手材料）**：
  - SimProcedure 摘要不精确：`Unfortunately, our SimProcedures are far from perfect. If angr is displaying unexpected behavior, it might be caused by a buggy/incomplete SimProcedure.` 官方给的处置之一是把 SimProcedure 关掉，但明确指出代价：`This has the drawback of likely leading to a path explosion`。也点名 scanf 实现不完整。
  - 未实现的系统调用存在，处置方式是 hook 调用点（`project.hook`），或用 `state.posix.queued_syscall_returns` 排队返回值。官方在该节留了 `Todo document this process`。
  - 默认内存模型（自称灵感来自 Mayhem）只支持**有限的**符号读写：读索引若是符号且取值范围太宽，索引被具体化；**写索引只要是符号就一律具体化**（`If the memory index of a write is symbolic at all, the index is concretized to a single value.`），可通过 `state.memory` 的具体化策略调整。这对"符号地址写入"类的去虚拟化/还原是不小的约束。
  - 符号长度（符号化 buffer 长度）官方原话：`in general, this is handled very poorly`，常被直接或回溯具体化。
  - 除零：Z3 对除零的处理会导致 `a/b` 在 `b == 0` 时返回 0xFFFFFFFF 之类的反直觉模型；官方建议显式断言分母非零。
  - 上述每条都是 `observed`。

## Miasm

- 仓库：https://github.com/cea-sec/miasm ，许可证 GPLv2（README「Miasm is a free and open source (GPLv2) reverse engineering framework」）。`observed`
- 能力：PE/ELF 32/64 读写、x86/ARM/MIPS/SH4/MSP430 汇编与反汇编、中间语言表示、JIT 仿真、表达式化简（用于自动去混淆）。自带反汇编器与 IR，纯 Python 书写。`observed`
- 运行依赖：Python >= 3.10、`future`、`pyparsing >= 2.4.1`。可选 extras：`cparser`（pycparser>=2.17）、`z3`（**钉死 `z3-solver==4.16.0.0`**）、`llvm`（**钉死 `llvmlite==0.44.0`**）、`graph`、`crypto`。`observed`
- JIT 后端需要 GCC、Clang 或 LLVM+Numba llvmlite 之一；README 明确：原生 jitter 组件编译失败时安装会继续，**jitter 相关功能随之不可用**，要强制失败需设 `MIASM_REQUIRE_JIT=1`。Windows + LLVM 一栏标注 `Not tested`。`observed`
- **已确认的 Python 入口**（README 示例原文）：`from miasm.analysis.machine import Machine`；`machine.jitter(loc_db, jit_type='python')`；`jitter.init_stack()`；`jitter.vm.add_memory_page(run_addr, PAGE_READ|PAGE_WRITE, s)`；`jitter.add_breakpoint(addr, cb)`；`jitter.set_trace_log()`；`jitter.init_run(run_addr)`；`jitter.continue_run()`；寄存器/内存经 `jitter.cpu.EAX`、`jitter.vm`。符号侧：`from miasm.ir.symbexec import SymbolicExecutionEngine`；`sb = SymbolicExecutionEngine(lifter)`；`symbolic_pc = sb.run_at(ircfg, 0, step=True)`；具体值用 `from miasm.expression.expression import ExprInt`，`sb.symbols[machine.mn.regs.ECX] = ExprInt(-3, 32)`。lifting 侧：`lifter = machine.lifter_model_call(loc_db)`、`lifter.new_ircfg_from_asmcfg(asmcfg)`。`observed`
- 维护状态：主干最近提交 2026-09-21（活跃），但 **PyPI `miasm` 停在 0.1.5（2023-04-18）**。`observed`（"pip 装到的与仓库不同步"为 `inferred`）
- 官方自述局限：README 没有专门的局限章节。可从已观察内容得到两条硬约束：钉死 z3/llvmlite 版本（与其它工具共装时可能冲突），以及 jitter 在原生扩展缺失时静默降级。`observed` / `inferred`

## VTIL

- 仓库：https://github.com/vtil-project/VTIL-Core 。自述为一套围绕优化编译器的工具，目标就是 binary de-obfuscation 与 de-virtualization。其设计差异点是不抽象掉原生 ISA，保留栈、物理寄存器与非 SSA 结构，并强调可以按任意虚拟地址回发射原生代码、不受文件格式约束。`observed`
- **明确的未完成声明**（README 原文）：`It is currently incomplete as the initial release is not done yet, and documentation and FAQ will be within this repository and the organization website once they're done.` `observed`
- **无 Python 绑定**：README 只给出 cmake/C++ 的构建方式（Windows 生成 `.sln`，Linux/macOS 用 Ninja；Apple Silicon 需 `-DCMAKE_OSX_ARCHITECTURES=x86_64`）。未出现任何 Python API 或绑定说明。`observed`
- 对脚本化工作流的含义：VTIL 是 IL/编译器层的复用目标，不是能 `pip install` 后直接驱动的东西。`inferred`

## 反虚拟化相关项目（Triton 生态）

Triton README 的「They already used Triton」小节把这一族工具列在一起：Exrop（ROP 链生成）、Pimp（r2 插件的 concolic 执行）、Ponce（IDA 插件）、QSynthesis、TritonDSE、Titan。`observed`

**Titan**（https://github.com/archercreat/titan ）
- 定位：VMProtect 反虚拟化器，C++ CLI，用 Triton 做仿真、符号执行与 lifting。作者自述 2018 年起作为业余项目重写过至少 4 次。`observed`
- 方法（README）：符号化 vip / vsp 寄存器并传播 load/store；因为几乎所有 handler 都以 store 结尾，所以取被 store 值的 Triton AST 与已知模式匹配；handler 一旦识别即 lift 成基本块，基本块结束时算出部分 CFG 并**切片 RIP 寄存器**得到下一个基本块地址，循环直到没有新基本块；每个基本块 lift 为独立 LLVM 函数。`observed`
- **官方明确的局限**：`it works for vmprotect < 3.8 but produces less than ideal output`；且收尾的 pass 未完成：`The only pass that is left to implement is flag synthesis pass which will give the cleanest LLVM bitcode.` `observed`

**TritonDSE**（https://github.com/quarkslab/tritondse ）
- 定位：为 Triton 补上"探索能力"的 Python 库，因为 Triton 本身是低层框架，要手工喂每一条要符号执行的指令。提供 loader（基于 LIEF、cle 或自定义）、内存分段、覆盖率策略（block/edge/path）、指针覆盖、stdin/argv 自动输入注入、QBDI 输入重放、sanitizer、简易堆分配器、部分 libc 符号桩。`observed`
- 安装 `pip install tritondse`（README 称 pip 包会装齐依赖），Apache-2.0，PyPI 0.1.14（2026-03-16）。`observed`
- **官方明确局限，对 Windows 工作流是决定性的**：`At the moment solely ELF and Linux are supported. But further development can lead to more platform. Furthermore it provides facilities on the C runtime and it has not been tested on other types of programs.` `observed`

**QSynth / Qsynthesis**（https://github.com/quarkslab/qsynthesis ）
- 定位：对位向量表达式做 I/O 综合（灰盒：黑盒 I/O 综合 + 白盒 AST 搜索），目标是去混淆；核心建立在 Triton 符号引擎之上，可经 SMT 校验综合结果的语义等价性。AGPL-3.0（`LICENSE` 为 GNU Affero GPL v3）。`observed`
- 安装有一个显式陷阱（README 原文）：需先装好 Triton，且 `Triton does not automatically install itself in a virtualenv, copy it in your venv or use --system-site-packages when configuring your venv.` `observed`
- **官方 Limitations 段落（原文要点）**：综合准确度受预计算表覆盖度限制；表的生成受 RAM 限制（README 给出的实测：`--limit 5000000` 的表生成耗时 4m52s、`[RAM:9.52Gb]`，并有 `--watchdog` 用于在内存占用百分比超阈值时中断）；重组（reassembly）不能涉及内存变量、目标必须是寄存器、架构取决于 llvmlite（因此基本限于 x86_64）；基于 trace 的综合功能已被禁用，因为其底层框架尚未开源。`observed`
- README 开头即声明 `This framework is experimental, and shall only be used for experimentation purposes.` `observed`

## Unicorn

- 仓库：https://github.com/unicorn-engine/unicorn 。自述为基于 QEMU 的轻量多平台多架构 CPU 仿真框架。架构覆盖 ARM、ARM64(ARMv8)、M68K、MIPS、PowerPC、RISCV、SPARC、S390X、TriCore、X86(16/32/64)。`observed`
- **许可证口径不一致，值得在 skill 里标明**：README 写 `Distributed under free software license GPLv2`，仓库 `COPYING` 文件确为 GNU GPL v2；但 PyPI 包 `unicorn`（最新 2.1.4）元数据的 license 字段是 `BSD License`。以仓库 `COPYING` 为准（GPLv2），PyPI 字段应为陈旧元数据。`observed` / 结论 `inferred`
- **已确认的 Python API**（读 `bindings/python/unicorn/unicorn_py3/unicorn.py`，行号为该文件内位置）：构造 `Uc(arch, mode, cpu=None)`（L684）；寄存器 `reg_read(reg_id, aux=None)`（L507）、`reg_write(reg_id, value)`（L523）；执行 `emu_start(begin, until, timeout=0, count=0)`（L748）、`emu_stop()`（L771）；内存 `mem_map(address, size, perms=uc.UC_PROT_ALL)`（L818）、`mem_unmap(address, size)`（L855）、`mem_read(address, size) -> bytearray`（L964）、`mem_write(address, data)`（L984）；插桩 `hook_add(htype, callback, user_data=None, begin=1, end=0, aux1=0, aux2=0) -> int`（L1030）、`hook_del(handle)`（L1156）；上下文 `context_save() -> UcContext`（L1188）、`context_restore(context)`（L1214）；缓存 `ctl_remove_cache(lbound, ubound)`（L1400）。已确认存在的 hook 常量包括 `UC_HOOK_INTR`、`UC_HOOK_CODE`、`UC_HOOK_BLOCK`、`UC_HOOK_MEM_READ`、`UC_HOOK_MEM_WRITE`。`observed`
- **官方 FAQ 给出的限制（第一方，逐条）**：
  - `Unicorn is a pure CPU emulator`。这也是 `UC_ERR_HOOK` 的根因：**只能插桩极少数指令**，x86 上为 `in`、`out`、`syscall`、`sysenter`、`cpuid`。
  - 出现 "Unhandled CPU Exception" 通常是因为没有为 `syscall` / `SVC` 之类注册 handler；FAQ 直接把用户导向 Qiling：`If you expect syscall and userland emulation, you probably would like qiling framework.`
  - 性能：慢通常来自"每条指令插桩"或"每次内存访问插桩"，官方建议改用 `UC_HOOK_BLOCK` 代替 `UC_HOOK_CODE`。另注：使用 `uc_emu_start` 的 `count` 参数等价于装了 `UC_HOOK_CODE`。
  - **改码不生效**：Unicorn 继承 QEMU 的 TB chaining，基本块被翻译后**缓存**，对已缓存地址的任何修改不会立即生效，须 `uc_ctl_remove_cache`，若在仿真中途修改还需重写 PC 寄存器以触发重新翻译。
  - `KeyboardInterrupt` 在 `uc.emu_start` 期间不会抛出（C 层长循环不吃 Python 信号），官方给的绕过方式是把仿真放到另一个线程。
  - 内存钩子对单条指令可能被多次调用（如 `rep stos`；或地址未对齐导致 MMU 拆分访问，最坏情况逐字节）。
  - 从 unmapped 读写恢复：返回 `true` 还不够，必须先在钩子里把内存映射好。
  - MMU：自 2.0.2 起 Unicorn 按目标架构模拟 MMU，副作用是部分内存区域不可写/不可执行、必须查架构相关寄存器确认 MMU 状态，且 **`uc_mem_map` 处理物理地址而 `uc_emu_start` 接受虚拟地址**。`UC_TLB_VIRTUAL` 是实验性开关，官方注明"理论上更快，但未做基准测试"。
  - 与上游 QEMU 的关系：`<= 2.0.0` 基于 qemu 2.2.1，`>= 2.0.0` 基于 qemu 5.0.1；官方解释不同步上游是因为在 QEMU 代码里做了 `lots of dirty hacks`。FAQ 也承认"某些较新的指令集 qemu5 不支持"、"部分指令集最新 QEMU 未实现"。
  - 以上均为 `observed`。

## Qiling

- 仓库：https://github.com/qilingframework/qiling ，许可证 GPLv2（README 与官方文档介绍页均写 GPLv2）。`observed`
- 定位：Unicorn 之上的高级二进制仿真框架，**自带 OS 层**。README/文档声明：平台覆盖 Windows、macOS、Linux、Android、BSD、UEFI、DOS、MBR；架构覆盖 8086、x86、x86_64、ARM、ARM64、MIPS、RISC-V、PowerPC；格式覆盖 PE、Mach-O、ELF、COM、MBR；另有 Demigod 支持 .sys / .ko / .kext。`observed`
- **已确认的 Python API**（官方 howto 页与相关 API 页）：
  - `from qiling import Qiling`；`from qiling.const import QL_VERBOSE`。
  - 仿真二进制：`Qiling(argv, rootfs, verbose=QL_VERBOSE.DEBUG, profile='netgear.ql')`——`argv` 是模拟命令行参数序列，`rootfs` 是**被仿真程序的文件系统根目录**（被仿真程序访问的所有路径都基于它），`env` 是可选环境变量字典。
  - 仿真 shellcode：`Qiling(code=shellcode, rootfs=..., archtype='x8664', ostype='Windows')`——官方注明 shellcode 场景无法自动推断架构与系统，`archtype` 与 `ostype` 必须显式给出。
  - 运行：`ql.run()`；文件系统映射：`ql.add_fs_mapper('/proc', '/proc')`。
  - 寄存器：`ql.arch.regs.read("EAX")`、`ql.arch.regs.write("EAX", 0xFF)`、属性式 `ql.arch.regs.eax`，以及架构无关的 `ql.arch.regs.arch_pc` / `ql.arch.regs.arch_sp`（可读写）、`ql.arch.regs.register_mapping()`。
  - 内存：`ql.mem.map(addr, size, perms=UC_PROT_ALL, info=None)`、`ql.mem.unmap(addr, size)`、`ql.mem.read(address, size)`、`ql.mem.write(address, data)`、`ql.mem.search(b"...", begin=..., end=...)`、`ql.mem.string(address)`、`ql.mem.get_formatted_mapinfo()`。
  - 设置经 profile 文件（`.ql`）补充，例如 `[MIPS]` / `mmap_address = 0x7f7ee000`。
  - 以上均为 `observed`。
- 维护状态：主干最近提交 2026-09-05（活跃），但 **PyPI `qiling` 停在 1.4.6（2023-08-04）**。FAQ 也给了替代装法：`pip3 install --user https://github.com/qilingframework/qiling/archive/dev.zip`。`observed`
- 环境模型的硬性依赖：官方 rootfs 是**独立仓库**，FAQ 说明跑官方示例出现 "file not found" 时需 `git submodule update --init --recursive`。`observed`
- **官方自述的失败模式（FAQ，正是"stubbing 环境"这一问题的正面证据）**：
  - `My program crashes. It says Syscall/API not implemented` → 官方答复是所需 syscall 或 OS API 大概率**没有实现**，用户可以自己补并贡献回项目。
  - `UC_ERR_FETCH_UNMAPPED, UC_ERR_WRITE_UNMAPPED and related issues` → 官方明确 `This is not a "bug".`，可能原因是 Windows API 或 syscall 未实现，或必需的配置文件/库缺失；并直说 `Its not possible for Qiling Framework to be able to emulate all these syscall/API. Community help is needed.`
  - 多线程默认关闭（`ql.multithread = False`），否则会出现 `'NoneType' object has no attribute 'cur_thread'`。
  - 调试器连不上（gdb `Remote replied unexpectedly to 'vMustReplyEmpty": timeout`）官方解释是脚本太慢，需在 gdb 里 `set remotetimeout 100`。
  - 以上均为 `observed`。

---

## 这些工具没有解决的问题（官方原文支撑的失败模式）

**1. 路径爆炸是默认结局，不是异常。**
angr 官方 gotchas 页在讨论关闭 SimProcedure 时的原话是 `likely leading to a path explosion`。angr 为此内置了 `Spiller`（状态过多时落盘）、`MemoryWatcher`（内存过低就停止）、`LoopSeer`（丢弃疑似循环过多的状态）、`LengthLimiter`、`Veritesting` 这一整套缓解手段——这些技术的存在本身就是状态爆炸的规模证据。`observed`

**2. 环境模型必须完整，缺一块就跑不到终点。**
这一条有三份互相独立的第一方陈述：Unicorn 自称 `pure CPU emulator` 并把 syscall 用户态仿真直接推给 Qiling；Qiling 的 FAQ 把"syscall/API 未实现"和 `UC_ERR_FETCH_UNMAPPED` 归为 `not a bug`，并承认不可能实现全部 syscall/API；angr 的 gotchas 列出未实现 syscall 的两种绕行方式（hook 调用点、`state.posix.queued_syscall_returns`）且关于流程本身还留着 `Todo document this process`。对 Windows 目标而言，这意味着 PE loader、导入表、TEB/PEB、以及被调用到的每个 Win32 API 都得有人负责，否则仿真在中途停下而**这看起来像"分析完了"**。`observed`

**3. "求解器给出了模型"不等于"模型就是答案"。** 四类独立的证据：
- Z3：`Z3 may also return unknown if it can't determine whether a formula is satisfiable or not.`（官方文档）。以及 `Solver.model()` 在没有模型时抛异常。`observed`
- angr：对同一组约束，官方原话是 `If you run this code, you might get a different value for x`——模型只保证满足约束，不保证唯一。约束矛盾时 state 变为 unsat，对其查询会抛异常。`observed`
- angr 的默认内存模型会把符号写索引具体化、把过宽的符号读索引具体化；符号长度官方评价是 `handled very poorly`。也就是说，能走到 `found` 的那条路径可能建立在"某个符号地址被挑了一个具体值"之上，而该具体值不是唯一解。`observed`
- Triton 默认开 `MODE.PC_TRACKING_SYMBOLIC`（只跟踪含符号变量的路径约束）、默认关 `MODE.MEMORY_ARRAY`（走 QF_BV 内存模型）、且默认会具体化 load/store 索引。这些默认值意味着"求解成功"所对应的约束集合本身是受策略裁剪后的集合。`observed`
- 综合结论：在报告里必须区分"约束可满足且返回了一个模型"与"该模型对应真实目标语义上的正确答案"。当模型依赖被具体化的符号地址、被摘要的库函数或未实现的 syscall 时，它只是自洽的。`inferred`

**4. 求解器的能力边界是按理论划分的，不是按"够不够快"划分的。**
Z3 官方给出的唯一一条针对性性能指导是：BV 与整数/实数混用有 `significant overhead`，建议整套建模要么全 BV 要么全整数/实数。数组判定过程被官方自己描述为 NP 完全。FP 的问题不是速度而是代数性质不成立（结合律等失效）。`observed`

**5. 反虚拟化工具普遍是"指定目标版本 + 部分可用"的状态。**
Titan 自述仅覆盖 VMProtect < 3.8 且 `produces less than ideal output`，flag synthesis pass 尚未实现；QSynth 自述实验性，重组不支持内存变量、限于寄存器且基本限于 x86_64，表生成受 RAM 限制；TritonDSE 自述仅支持 ELF/Linux 且未在其他类型程序上测试过；VTIL 自述初始版本尚未完成；Triton 自述是 part-time 项目、`not fully reliable`。`observed`

**6. 工具的渠道版本常常落后于源码。**
Triton（pip 1.0.0rc4 / 2024-05 vs 活跃分支 2026-10）、Miasm（PyPI 0.1.5 / 2023-04 vs 主干 2026-09）、Qiling（PyPI 1.4.6 / 2023-08 vs 主干 2026-09）都属于这一类。只按 `pip install <name>` 得到的可能不是文档里描述的行为。`observed` / 结论 `inferred`

---

## 未能确认的事项（明确留白，不做补全）

- CVC5 与 Yices 2 的**具体 Python 函数名/类名**未逐个打开核实；只确认了二者都提供官方 Python API 及其许可与包名。
- 各求解器在 bit-vector 问题上的**量化性能对比**：没有任何一方的 README 或文档给出这类声明，因此本文件不提供"谁更快"的结论。
- Z3 / angr 对 FP 的量化性能特征：未找到第一方声明，只找到语义层面的说明。
- angr 文档站没有可访问的独立 "Optimization considerations" 页面（`/advanced-topics/optimization.html` 与 `/advanced-topics/optimizations.html` 均 404）；其性能相关内容分布在 gotchas 页与 Simulation Managers 页。
- Qiling 的 Windows 特有 syscall 覆盖度没有权威清单可引；只有 FAQ 的"未实现即崩"陈述。
- Unicorn 的 PyPI license 字段（`BSD License`）与仓库 `COPYING`（GPLv2）不一致的确切原因未核实。
