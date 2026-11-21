# Zminidump

Zminidump 面向在外网开发机上排查原生程序崩溃的开发者。通过 CLI 分析 Breakpad 或 Crashpad 的 `.dmp`,按模块 GNU Build ID 查找匹配的调试产物(用户指定文件 → `--symbol-path` 扫描 → 本地缓存 → debuginfod),展开调用栈并导出可用浏览器离线打开的单文件 HTML 报告,另提供 JSON 导出用于自动化回归。

首版验收对象为 Linux x86-64 崩溃目标;CLI 可在 Windows、macOS 和 Linux 上运行。程序路径(`--binary`)仅辅助匹配,已加载的共享库仍按各自 Build ID 查找。

## 用法

```sh
# 离线 HTML 报告(默认嵌入关键帧附近的源码片段)
zminidump analyze crash.dmp --html report.html --symbol-path ./symbols --no-debuginfod

# 关闭源码嵌入仅留路径行号;或 --include-source=full 嵌入完整源文件
zminidump analyze crash.dmp --html report.html --include-source=none

# JSON 导出,用于回归对比或接入其他工具
zminidump analyze crash.dmp --json report.json

# 指定主程序与独立调试文件(仍按 Build ID 核验,错误版本会被拒绝)
zminidump analyze crash.dmp --html r.html --binary ./crasher --debug-file ./crasher.debug

# 使用 debuginfod(默认读取 DEBUGINFOD_URLS 环境变量)
DEBUGINFOD_URLS="https://debuginfod.example.com" zminidump analyze crash.dmp --html r.html
```

常用选项:`--cache <dir>`(默认 `$XDG_CACHE_HOME/zminidump`)、`--context-lines <N>`、`--max-source-bytes <N>`(源码嵌入总上限)、`--timeout`、`--jobs`(下载并发)。完整列表见 `zminidump analyze --help`。

## 产物查找与符号化

- 模块身份:完整 GNU Build ID(dump 中的 Code ID),另存 Breakpad Debug ID;旧 dump 只有截短标识时按 GUID 前缀匹配,并从匹配产物补全完整 Build ID。
- 查找顺序:用户显式指定的文件 → `--symbol-path` 目录扫描(ELF / 独立 `.debug` / CI 预生成 Breakpad `.sym`)→ debuginfod 缓存 → debuginfod 服务(`/buildid/{id}/executable|debuginfo`),下载核验 Build ID 后写入缓存,同一来源同一模块同一产物类型的并发请求合并。
- 符号化:优先使用预生成 `.sym`;否则用 dump_syms 从核验过的可执行文件(`.eh_frame` 提供 CFI)与独立调试文件(DWARF 提供函数、行号、内联帧)合并生成。
- 报告分别展示身份不匹配、产物未归档、访问失败和源码不可用,便于处理客户现场问题。

## HTML 报告

单文件、样式内嵌,打开无需联网或安装任何组件。页首展示异常与崩溃线程,崩溃线程调用栈默认展开,其余线程折叠;帧可跳转到模块记录或带行号的源码,栈扫描帧标记为候选。所有来自 dump 或调试产物的文本均按 HTML 转义。原始 dump、二进制与凭据不会进入报告;补齐产物后可用原始 `.dmp` 重新分析并生成新报告。

## 本地验证

使用支持 Rust 2024 edition 的稳定版工具链:

```sh
cargo build --locked
cargo test
```

单元测试无需外部工具;端到端测试需要 `gcc`/`objcopy`/`strip`,会在临时目录构建真实样本(剥离的 PIE 主程序 + 独立 `.debug` + 自有 `.so`),fork 出真实 SIGSEGV 崩溃并写出 minidump,验证展开到预期的应用帧、定位当次构建的源码行、CFI 展开来源、错误版本 ELF 拒绝、debuginfod 下载与缓存复用。缺少工具链时端到端测试自动跳过。

设计文档见[架构与实施方案](docs/design.md)。
