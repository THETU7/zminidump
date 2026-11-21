# Zminidump

Zminidump 面向在外网开发机上排查原生程序崩溃的开发者。计划在 Windows、macOS 和 Linux 上通过 CLI 分析 Breakpad 或 Crashpad 的 `.dmp`，利用内网 debuginfod 获取匹配的 Linux 调试产物和源码，再导出可用浏览器离线打开的单文件 HTML 报告。

当前是可构建的 Rust 项目骨架。CLI 提供帮助和版本入口，dump 解析、符号下载和报告导出处于设计阶段。

## 本地验证

使用支持 Rust 2024 edition 的稳定版工具链。

```sh
cargo build --locked
cargo run --locked -- --help
```

接手开发从[架构与实施方案](docs/design.md)中的「接手顺序与验收」开始。第一份验证样本优先使用已确认在 GDB 中可以查看动态库内部的客户侧 dump。
