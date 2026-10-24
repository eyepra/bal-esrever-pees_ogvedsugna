# Windows 逆向入门（讲义）

面向**人**的入门连载，按学习顺序读。它不是 `skills/exe-reverse/` 的一部分：那个 skill 是给
agent 按症状和门禁查的，这里是把同一批概念按由浅入深的顺序铺开给读者。

## 篇目

| 文件 | 内容 |
|---|---|
| `exe1.md` | 原理：程序怎么加载、基址与偏移、代码与数据的区别 |
| `exe2.md` | 缺失（原连载未找到这一篇） |
| `exe3.md` | 方法：找偏移的六条路 |
| `exe4.md` | 利用：外部工具、DLL 注入与 hook |
| `exe5.md` | 工具：CE、IDA、x64dbg |

## 读到这三处要注意

- **`exe5.md` 的调试器是 x64dbg**，不是早期教程里的 OD。OllyDbg 只支持 32 位且早已停止更新。
- **`exe1.md` 的“偏移固定”只在同一个构建内成立**。同一份 exe 每次加载偏移不变，但重新编译就变；
  跨版本要靠特征码重新定位，不能死记地址。
- **`exe3.md` 的“拦截系统函数”默认目标是走 IAT 的**。运行时解析 API 或直接发系统调用的目标，
  导入表里没有那一行，这一招会落空。

概念上和 `skills/exe-reverse/SKILL.md` 的 `references/pe-structure.md`、
`references/recon.md`、`references/injection-and-hooking.md` 对应；遇到具体操作时看 skill，不要只看讲义。
