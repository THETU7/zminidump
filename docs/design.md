# 架构与实施方案

## 首版范围

Zminidump 是本地原生崩溃分析工具。分析输入为 Breakpad 或 Crashpad 的 `.dmp`，可选提供对应程序或产物目录。首版交付 **CLI 和可离线浏览的单文件 HTML 报告**，并提供 JSON 导出用于自动化。首版以 **Linux x86-64 崩溃目标**为验收对象，CLI 覆盖 Windows、macOS 和 Linux。程序路径用于辅助匹配，已加载的共享库仍按各自的身份查找。后续用真实样本验证 Linux ARM64，再扩展其他崩溃目标。

| 崩溃目标 | 模块身份 | 调试产物来源 |
| --- | --- | --- |
| Linux | 完整 GNU Build ID，另存 Breakpad Debug ID | 现有 debuginfod，或用户指定的 ELF 和独立调试文件 |
| Windows | PDB 的 GUID + Age，另存 PE 镜像的 Code ID | 私有兼容符号服务器或 CI 产出的 `.sym`，源码按构建归档 |
| macOS | Mach-O UUID 和架构 | 按 UUID 索引的 Mach-O 和 dSYM，或 CI 产出的 `.sym`，源码按构建归档 |

各平台匹配规则参见 [Symbolicator 的符号查找文档](https://github.com/getsentry/symbolicator/blob/master/docs/advanced/symbol-lookup.md)和 [Apple 的 dSYM 匹配说明](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information)。

## 分析流程

| 组件 | 实施建议 |
| --- | --- |
| Dump 解析与栈展开 | 用 `rust-minidump` 读取异常、崩溃线程、寄存器、栈内存范围和模块列表，用 `minidump-processor` 展开栈。通过 `SymbolProvider` 提供模块的展开规则与符号查询。优先用原始 `.dmp`，GDB 和转换后的 core 用于对照。 |
| 调试产物查找 | 先验证用户指定的本地产物，再查缓存和配置的服务。按需要获取模块的 `executable` 和 `debuginfo`，核验完整 Build ID 后写入缓存。同一来源、同一模块和同一产物类型的并发请求合并。 |
| 源码获取 | 根据导出选项，在生成报告时查找调用栈引用的源码。DWARF 路径若为相对路径，按所属编译单元的 `DW_AT_comp_dir` 解析。用帧所在模块的 Build ID 请求 debuginfod 的 `/source/...`，同一源码文件只下载一次。CI 归档当次构建的源码快照及生成文件。 |
| 共享报告 | 首批实现可以沿用当前单个 Cargo 包，在 `src/lib.rs` 提供核心入口，`src/main.rs` 保留 CLI。HTML 与 JSON 使用同一份版本化报告模型，至少记录异常、崩溃线程、模块 ID、帧地址及偏移、展开来源、函数、内联帧、文件行号和产物状态。符号、展开和源码各自保留诊断结果。 |

先用 `minidump-stackwalk` 和可信构建产生的 Breakpad `.sym` 建立对照结果。用包含独立 `.debug` 的样本同时验证行号和 CFI。需要从现有 debuginfod 实时处理 ELF 时，可以评估 `symbolic` 接入。Mozilla `dump_syms` 在 Windows 宿主处理 ELF 有公开兼容问题，需先在目标宿主验证。若客户端转换达不到验收要求，可以让内网 CI 预生成 `.sym`，客户端继续直接从 debuginfod 按需取源码。旧 Breakpad dump 如果只有截短标识，从匹配的本地 ELF 提取完整 Build ID，或从 CI 清单查询经过校验的 `Breakpad Debug ID → GNU Build ID` 映射。无法确认时保留模块和偏移，并显示缺失原因。[rust-minidump 栈遍历说明](https://github.com/rust-minidump/rust-minidump/blob/main/minidump-stackwalk/README.md) · [SymbolProvider](https://docs.rs/minidump-unwind/latest/minidump_unwind/symbols/trait.SymbolProvider.html) · [Symbolic](https://docs.rs/symbolic/latest/symbolic/) · [dump_syms Windows 宿主问题](https://github.com/mozilla/dump_syms/issues/751) · [Breakpad 模块标识实现](https://chromium.googlesource.com/breakpad/breakpad/+/master/src/processor/minidump.cc) · [debuginfod API](https://manpages.debian.org/unstable/debuginfod/debuginfod.8.en.html)

## HTML 报告

报告页首展示异常和崩溃线程，默认展开该线程的调用栈。其余线程可折叠，帧可跳转到模块记录或带行号的源码，栈扫描得到的帧标为候选。把样式随 HTML 内嵌，使用浏览器的折叠和页内链接。打开报告时无需启动服务、安装 Zminidump 或连接 debuginfod。补齐产物后可以用原始 `.dmp` 重新分析并生成新报告。

源码默认嵌入关键帧附近的片段（`--include-source=context`）。`--include-source=none` 仅显示路径和行号，`--include-source=full` 嵌入调用栈引用的完整源文件。同一构建同一文件的重叠片段合并，导出需有总大小上限，并提示由此省略的内容。函数名、路径、源码及其他来自 dump 或调试产物的文本都按文本转义。报告仅内嵌导出时取得的诊断信息和所选源码，原始 dump、二进制和认证凭据留在分析环境。

拟议的 CLI 用法如下。JSON 可用于回归对比或接入其他工具。

```sh
zminidump analyze crash.dmp --html report.html --include-source=context
zminidump analyze crash.dmp --json report.json
```

## 加密发布物崩溃

已知加密后的主程序发生过崩溃，且团队实测可以用现有流程在动态库内部手动调试。加密器是否保留原始代码布局、客户侧 dump 是否含有关联映射，仍需通过样本确认。

1. 对同一份 `.dmp` 并行比较原始 minidump stackwalk 和 `minidump-2-core` 加 GDB。记录崩溃线程 ID、异常 PC、最后一个可靠帧，以及主程序在两边是否出现。对 GDB 检查 `info threads`、`bt`、`info sharedlibrary` 和 `info proc mappings`。如果转换后的 core 缺少映射，以原始 dump 的模块信息和采集端留存的映射为依据。
2. 从该版本 CI 取同一次链接的加密前 ELF、独立 `.debug` 和加密后发布物。检查 PC 对应的运行时映射区间、映射文件偏移和 ELF 加载段，再换算符号地址。即使加密前后保留同一个 Build ID，也要验证运行时代码布局。优先用有已知调用点的样本验证，若采集到了相关指令字节，可以交叉核对。
3. 若运行时恢复为原布局，将发布物身份关联到加密前的调试产物。手工复核可在 GDB 用 `add-symbol-file <调试文件> -o <经验证的加载偏移>`。偏移以运行时地址减去对应的 ELF 链接地址确定。若原始 dump 可以展开到主程序而 core 无法复现，检查转换和 GDB 的模块加载。
4. 若代码进入匿名映射，或保护器移动、改写了代码，请保护器提供运行时区间到原始 ELF 的地址映射。清单关联发布物、模块和原始地址范围。若保护器也改了栈布局，需要另外取得匹配运行时代码的展开规则。缺少这些信息时，报告原始地址、已知所属区间和回溯断点，并标出缺失的产物。

## 客户系统库崩溃后缺少调用方

| 在同一崩溃线程观察到的现象 | 下一步 |
| --- | --- |
| 已经有主程序地址，函数或行号显示 `??` | 栈已跨过库边界。检查主程序地址映射、调试产物的身份和符号查询。 |
| 可靠帧停在系统库内部 | 从 debuginfod 或客户环境获取同 Build ID 的 `.so`，检查实际展开所需的 `.eh_frame` 等信息。GDB 对照可用 `set sysroot` 指向客户系统文件快照。若仍停在同一帧，检查崩溃线程的寄存器上下文、SP 附近采集范围和继续展开所需的栈内存。 |
| 回溯到工作线程入口，提交方在另一个线程 | 在任务提交和回调入口记录任务 ID、调用点及线程 ID，把崩溃和提交方关联。对关键跨库调用也可用同样的诊断记录。 |

报告区分异常上下文、展开规则、帧指针和栈扫描获得的帧。扫描帧标为候选。若现有 dump 缺少栈内存，下一轮从采集侧验证能否扩大相关线程的捕获范围，并实测新 dump 能否跨过原来的断点。[rust-minidump 栈遍历说明](https://github.com/rust-minidump/rust-minidump/blob/main/minidump-stackwalk/README.md)

## 外网访问和分发

- 有企业 VPN 或零信任接入时，客户端经现有通道访问 debuginfod。需要公网接入时，走有鉴权的 HTTPS 网关，按项目授权读取调试产物与源码。分析在本机运行，网络请求为产物查询。离线环境从内网导出的符号和源码包导入，已缓存内容可断网重开。
- 缓存按符号来源、模块身份和产物类型索引，源码再加构建中的路径。控制下载并发、大小和超时。报告分别展示身份不匹配、产物未归档、访问失败和源码不可用，便于处理客户现场问题。
- 面向 Windows、macOS 和 Linux 发布预编译 CLI 包，在干净机器上验证解包和分析。报告接收者用系统浏览器打开 HTML 文件即可。GDB 继续作为人工诊断工具。

## 接手顺序与验收

1. **建立真实样本对照。** 准备实测可查看动态库的客户侧 `.dmp`、加密前后主程序的同版本产物，以及涉及的客户 `.so`。再准备一份包含剥离的 PIE 主程序、独立 `.debug` 和自有 `.so` 的 Linux x86-64 样本。如果两者可以用同一次崩溃覆盖，保留一套即可。对每份样本记录预期崩溃线程、可确认的关键帧和源码行。客户 dump 和私有产物放在授权存储中。
2. **验证内网产物。** 用 `readelf -n` 记录 ELF 的 GNU Build ID。通过现有服务实测同一模块的 `debuginfo`、`executable` 和至少一个源码路径。原始 `.dmp` 和 GDB 对照报告要能指出断点是产物缺失、地址映射不匹配，还是栈无法继续展开。
3. **实现本地核心和 CLI。** 先输出可比对的报告，再接入 debuginfod、缓存和源码获取。验收要求匹配的样本能展开到预期的应用帧，并定位到当次构建的源码行。错误版本的 ELF 应被拒绝。缺展开信息、缺符号或缺源码时，已知帧和诊断信息仍可查看。
4. **交付 HTML 报告和 CLI 预编译包。** 在三类宿主上用同一份 Linux 样本生成报告，核对关键线程、栈帧和源码锚点。把 HTML 单独复制到一台断网的干净机器，验证默认报告只显示路径和行号，指定嵌入源码时可以跳到对应源码行。用含有 HTML 特殊字符的路径和源码验证渲染。另在外网开发机验证授权下载和缓存复用。
