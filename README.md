# Loon-Plugins

Loon 插件兼容性适配、格式转换及自动同步项目。

本仓库主要用于个人学习、网络规则研究及 Loon 插件管理，按需适配来自不同作者、不同代理工具的规则与脚本。

## 项目功能

- 获取上游规则与脚本，按插件进行独立适配。
- 将 Quantumult X 重写规则转换为 Loon 插件格式。
- 检查 JavaScript 语法、脚本接口、规则格式及 MITM 域名。
- 通过 GitHub Actions 定时检查更新，转换失败时不覆盖上一版本。
- 后续可按需扩展 Surge、Stash 等来源；具体兼容性以各插件适配情况为准。

## 目录说明

| 目录 | 用途 |
| --- | --- |
| `plugins/` | 生成的 Loon 插件及版本信息 |
| `scripts/` | 适配后的 JavaScript 脚本 |
| `converters/` | 独立的插件转换程序 |
| `.github/workflows/` | 自动同步与检查工作流 |
| `docs/` | 部署及维护说明 |

## 插件来源与适配记录

| 插件 | 原作者 | 上游来源 | 远程订阅 | 测试状态 |
| :--- | :--- | :---: | :---: | :---: |
| 腾讯视频净化 | ZenMoFiShi | [源码](https://github.com/ZenmoFeiShi/Qx/blob/main/TxvideoAD.snippet) | [LPX](https://raw.githubusercontent.com/TTTi222/Loon-Plugins/main/plugins/TxvideoAD.lpx) | 静态通过 |
| 美团净化 | ZenMoFiShi | [源码](https://github.com/ZenmoFeiShi/Qx/blob/main/MT.snippet) | [LPX](https://raw.githubusercontent.com/TTTi222/Loon-Plugins/main/plugins/MT.lpx) | 模拟通过 |
| 哈啰净化 | ZenMoFiShi | [源码](https://github.com/ZenmoFeiShi/Qx/blob/main/helloobike.snippet) | [LPX](https://raw.githubusercontent.com/TTTi222/Loon-Plugins/main/plugins/helloobike.lpx) | 模拟通过 |

### 适配说明

- **腾讯视频**：适配二进制请求及响应接口。
- **美团**：直接引用经过检查的上游 JS；域名通配符需要 Loon Build 1008 或以上版本。
- **哈啰**：适配本地存储及模拟响应；请求上下文缺失时原样放行。

以上插件均尚未完成 Loon 真机验证。当前三个插件的上游均声明仅供学习与自用，公开再分发授权尚未独立确认。

新增插件时，应分别记录原作者、上游地址、许可证或使用声明、适配范围及测试状态。本表不代表原作者已经授权本仓库公开再分发其作品。

## 自动更新

目前腾讯视频、美团与哈啰各有独立的工作流，每 6 小时错峰检查上游，也支持手动运行。美团使用固定上游提交的 JS 链接，不在本仓库复制 JS；需 Loon Build 1008+ 支持 DOMAIN-WILDCARD。更新前执行静态检查；检查失败时保留上一版本。其他插件的同步周期和适配方式可根据其实际需求单独配置。

静态检查不能替代真机测试；上游接口、规则或应用版本变化均可能导致插件失效。

## 版权及使用说明

- 第三方插件、规则、脚本及其相关内容的权利归各自原作者或相关权利人所有。
- 本仓库的工作主要为格式转换、兼容性适配、自动同步和技术研究，不主张第三方原始作品的著作权，也不代表与原作者或相关应用存在官方合作关系。
- 使用、修改及再分发第三方内容应遵守对应的许可证、作者声明及适用法律；保留作者署名、来源链接及必要的版权声明。
- 对仅允许个人使用、未明确授权再分发或明确禁止转载的内容，原则上仅作个人研究与转换验证，不应在未获授权的情况下公开发布。
- 本仓库不用于商业销售或未经授权的推广分发。个人自用或非商业性质不自动构成再分发许可。
- 如权利人对相关内容存在异议，可通过本仓库 Issues 联系维护者，以便核实并处理相关内容。

## 维护说明

本仓库不保证所有第三方插件持续有效。请根据自身使用环境进行测试，并自行判断是否启用相关规则及 MITM 功能。

新增插件时，优先检查上游授权与兼容性，再决定是否纳入自动发布流程。
