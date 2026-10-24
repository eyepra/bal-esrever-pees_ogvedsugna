# exe-reverse

<p align="center">
  <a href="README.md">English</a> · <b>简体中文</b>
</p>

一个面向 **Windows x86/x64 本地软件逆向工程**的 Agent Skill：初筛、字节级补丁、特征码、调试、注入、
转储修复、授权机制归类、算法恢复、壳与代码虚拟化、托管程序集、内核驱动，以及**硬件观测层** ——
指令追踪、硬件断点、虚拟机监控器辅助观测 —— 这些是纯软件工具链替代不了的路子。

它是一个 **skill**，不是教程：一份短小、面向决策的 `skills/exe-reverse/SKILL.md`，一批只在某一步
需要时才加载的 references，以及可以直接运行的参数化脚本。

## agent 应当如何使用它

`SKILL.md` 被写成**带门禁的流程**，而不是建议，因为观察到的失败模式不是无知 —— 是模型读完全文、
表示同意，然后仍然凭第一直觉推理。其中四样东西是要**照做**的：

- **五条操作规则（O1–O5）。** 与计划冲突时以它们为准，直到证据推翻它们。
- **症状索引。** 命中一行就是**停止信号**：先加载它指向的文件，再执行下一条命令。
- **五道门禁（G1–G5），** 每道都是一个带通过判据的动作。"我理解这个思路"不等于通过任何一道。
- **两振出局与停止条件。** 同一形状失败两次意味着模型错了，而不是参数需要微调。

还有一样需要**暂缓**的东西：**"完成"有定义（六条）**，日志干净不在其中。不到六条就是检查点，
并且必须说明还差什么。

最便宜的第一条命令是 `python skills/exe-reverse/scripts/doctor.py`：它一次回答三个问题 —— 这台机器
实际支持哪些能力、套件里每个脚本能否原样运行、以及哪些宿主事实会让实验静默失效。
`python skills/exe-reverse/scripts/hwprobe.py` 是它下面更深的硬件级探测，
`python skills/exe-reverse/scripts/capabilities.py --verbose` 会为任何受阻的项打印下一步动作。

## 它擅长什么

- **快速**判断一个需求是否可能仅靠改客户端达成，而不是把时间烧在服务端拥有的决策上。
- 在计划依赖宿主之前，先确定**你实际有什么宿主**：装了调试器、提权会话、测试签名、第二台机器，
  或是一个会截获计划所依赖机制的虚拟机监控器。
- **不打坏文件地打补丁**：等长改写，重算校验和，从磁盘回读写入的字节，并把长度变化如实报告为结构性修改。
- 让特征码**对自己诚实**：命中了多少处、这个计数在两次构建之间是否变化、它是定位器还是掷骰子。
- 在动手之前**归类授权决策**（客户端校验、客户端渲染的服务端数据、服务端权威），并区分
  "字节在文件里"与"代码被执行"。
- 调试器看不到时转向**硬件层**，并诚实说明各自需要什么、仍然看不到什么。

## 结构

`SKILL.md`、`references/` 与 `scripts/` 都在 skill 目录 `skills/exe-reverse/` 内。仓库根部的一切是
维护工具，不属于已安装的 skill。

```
skills/exe-reverse/SKILL.md     带门禁的流程，不是背景阅读：
                                五个动作 -> O1-O5 -> 症状索引 -> 五道门禁 G1-G5
                                十三个分类问题 -> 路由表
                                预算规则 -> 工作流 -> "完成" -> 停止条件 -> 约束
skills/exe-reverse/references/  按需加载，一文一题；"何时加载"的清单位于
                                skills/exe-reverse/references/routing.md
skills/exe-reverse/scripts/     参数化、与路径无关；在裸 Python 3.10+ 上即可运行
skills/exe-reverse/evals/       有 skill / 无 skill 的对照用例，以及运行方法
skills/exe-reverse/evidence/    证据摘要的机器可读配套文件
docs/tool-verification/         测量通行的证据记录（不随 skill 分发）
tests/                          可执行的回归套件
```

reference 库是被索引的，不是靠记忆的：`skills/exe-reverse/references/routing.md` 载有每个 reference
的加载时机与每个脚本的作用。选定路线之后读它一次。

## 安装

本仓库是一个 **skills 仓库**：skill 位于 `skills/exe-reverse/`，正是 `skills` CLI 解析的布局，
按名字安装而不是复制目录。

```
npx skills add <owner>/exe-reverse                 # 安装仓库里的全部 skill
npx skills add <owner>/exe-reverse --list          # 只列出，不安装
npx skills add <owner>/exe-reverse --skill exe-reverse -y
npx skills use  <owner>/exe-reverse`exe-reverse    # 用一次，不安装
```

CLI 默认把 skill 以符号链接放进你的 agent 技能目录（`--copy` 改为独立副本），`-g` 面向所有项目，
`-a` 指定 agent。本仓库目前只有一个 skill，`--skill exe-reverse` 暂时是多余的；写出来是因为一旦
出现第二个 skill，它就是选出单个 skill 的方式。安装后，agent 在任务与描述匹配时加载 `SKILL.md`，
只在需要时拉入 `references/*`：没有全局状态，没有构建步骤。

## 工具

没有强制项，也没有哪个工具必须待在 `PATH` 上：脚本接受显式路径，可运行的归档或脚本也算已安装。
真正决定"有哪些路线"的只有三样 —— Python 3.10+、一个反汇编/反编译工具、一个调试器；
`skills/exe-reverse/scripts/capabilities.py` 把完整清单作为**可探测的注册表**承载，每一条都带可执行
的下一步和代价估计，而不是一张需要手工维护的表；`skills/exe-reverse/scripts/hwprobe.py` 报告这台
机器实际具备哪些能力，包括虚拟化宿主上**不**可用的那些。

如果工具链不在 `PATH` 上（项目内的 tools 目录、带版本的 SDK 目录），设置 `EXEREV_TOOLS`：

```
set EXEREV_TOOLS=<dir>;<dir>                     # Windows
export EXEREV_TOOLS=<dir>:<dir>                  # POSIX
```

只有 GUI 的工具是"向人要"，而不是"用更弱的方法顶替"的理由。

## 覆盖范围

面向你自己的软件、你被授权分析的样本，以及竞赛沙箱；仅供学习、研究与授权的安全测试使用。它不附带
漏洞利用载荷、不附带目标数据、不附带第三方二进制 —— 它是一套方法、一批脚本和一份证据记录。

它覆盖什么、刻意不覆盖什么，写在 skill 自身（`skills/exe-reverse/references/coverage-and-limits.md`）。
简版：Windows PE 的 x86 与 x64，在真正做过的层上做得深 —— 初筛、补丁、特征码、授权归类、壳、托管代码，
以及硬件观测的路线图。另外两层应用运行时 —— Unity IL2CPP 的元数据恢复与打包后的 Python —— 依据公开
文章整理，因此标记为 `unverified`。服务端权威的破解、通用自动化去虚拟化器、把"攻破某个具名商业保护产品"作为
产品级宣称，以及对本仓库未测量过的 Windows 版本做任何保证，都**不在**覆盖内，而 skill 被写成如实说明
并停下，而不是把最近的一份文档流程套到一个它并非为此而写的目标上。

动手之前先读 `skills/exe-reverse/references/pitfalls.md`。这是这里最有价值的文件 —— 每一条都是一个
"看起来一切正常"却被产出的失败。

## 仓库维护

六个工具位于仓库根部，不属于已安装的 skill。每个都带自己的 docstring；`CONTRIBUTING.md` 说明
"全绿"意味着什么。

| 工具 | 它守住什么 |
|---|---|
| `check_repo.py` | 发现每个 skill、frontmatter 合法、脚本可运行、文档与 README 路径可解析、被跟踪表面上无目标身份 |
| `check_refs.py` | 指向某章节的交叉引用能命中真实标题 |
| `check_routing.py` | 按需清单位与入口点逐行一致 |
| `check_commands.py` | 文档里的每条命令都存在于脚本自身的 argparse 表 |
| `check_budget.py` | 常驻加载的部分不膨胀：SKILL.md 的行与 token、索引行、含糊表述的规则 |
| `build_scripts.py` | 与本机绑定的残留：绝对路径、凭据 |

一致性有天然的反向压力 —— 坏路径会大声失败，然后有人修。膨胀没有，这就是预算门存在的原因。

这六道门只是"全绿"的一半，另一半是 `python -m pytest -q` 与 lint 组合（`mypy` 与 `flake8`
跑在同一批文件上，分别由 `mypy.ini` 和 `.flake8` 配置）。`.github/workflows/ci.yml` 在每次
push 时跑完整套：六道门、Python 3.11–3.14 的测试矩阵、以及 lint 任务，并在文件开头写明它刻意
不跑什么。缺少可选依赖的机器，正是 lint 配置与预算门回退路径都必须能正常工作的环境。

`tests/benchmark.md` 保存回归矩阵（维度 -> 公开目标 -> 该行用到的脚本 -> 实测结果 -> 强度标签），
`docs/tool-verification/` 是它背后的证据记录：每个脚本实际做了什么、哪个独立方法确认了它、以及目标
无法演练哪些场景。

---

Proudly supported by the [LINUX DO](https://linux.do) community.

## 免责声明

材料按"原样"提供，不附带任何形式的担保。结果是在一台机器、某一时刻测得的；这里不承诺某条路线在你
的目标、你的宿主或你的工具链上同样可行。信任之前先验证，并且对副本动手。

这里没有任何服务、产品，也不构成对任何特定用途的认可。工具、库、文件格式与加固产品的名称出现，
只是为了让材料可复用；它们属于各自的拥有者，本项目与它们没有关联。
