# NoAuth_V2 功能增强实施计划

## 概述

本计划涵盖以下优化方向（专注403/401 bypass场景）：
1. CI/CD 集成 (GitHub Actions)
2. 导入功能增强 (Burp/ZAP/HAR/Postman/OpenAPI)
3. 断言规则系统增强
4. 更智能的判定引擎
5. 403/401 bypass 高级检测技术
6. 报告增强
7. CLI 插件系统

---

## 任务列表

- [x] 1. CI/CD 集成 (GitHub Actions)
  - [x] 1.1 创建 GitHub Actions workflow 文件 `.github/workflows/ci.yml`
    - 设置 Go 环境 (ubuntu-latest, Go 1.21+)
    - 配置 go mod tidy 和 go build
    - 添加 golangci-lint 代码检查
    - 配置单元测试执行
  - [x] 1.2 创建 Docker 构建 workflow `.github/workflows/docker.yml`
    - 配置 Docker buildx 多平台构建
    - 添加 Docker Hub / GHCR 自动推送
    - 支持 Linux AMD64/ARM64 双架构
  - [x] 1.3 创建 GitHub Action 复用工作流 `.github/workflows/scan.yml`
    - 定义通用的鉴权绕过扫描 workflow
    - 支持通过参数传入目标 URL 和配置
    - 自动生成扫描报告作为 artifacts

- [ ] 2. 导入功能增强
  - [ ] 2.1 创建 `lib/har/parser.go` - HAR 文件解析模块
    - 实现 `ParseHARFile(path string) ([]*Request, error)` 函数
    - 支持从 HAR 的 `log.entries` 提取请求
    - 解析请求方法、URL、headers、body
    - 处理 gzip/deflate 压缩响应
  - [ ] 2.2 创建 `lib/burp/parser.go` - Burp Suite XML 解析模块
    - 实现 `ParseBurpXML(path string) ([]*Request, error)` 函数
    - 支持 Burp Proxy 历史记录导出格式
    - 提取请求的 method, url, headers, body
  - [ ] 2.3 创建 `lib/zap/parser.go` - ZAP JSON 解析模块
    - 实现 `ParseZAPJSON(path string) ([]*Request, error)` 函数
    - 支持 ZAP 的 requests.json 格式
  - [ ] 2.4 创建 `lib/postman/parser.go` - Postman Collection 解析模块
    - 实现 `ParsePostmanCollection(path string) ([]*Request, error)` 函数
    - 支持 Postman Collection v2.1 格式
    - 解析 item > request 结构
  - [ ] 2.5 创建 `lib/openapi/parser.go` - OpenAPI/Swagger 解析模块
    - 实现 `ParseOpenAPI(path string) ([]*Request, error)` 函数
    - 支持 OpenAPI 3.0/3.1 格式
    - 从 paths 节点提取 API 端点
    - 生成测试请求模板
  - [ ] 2.6 在 `lib/RequestParser.go` 中添加统一入口
    - 添加 `ParseFile(path string) ([]*Request, error)` 自动识别文件格式
    - 根据文件扩展名或内容自动选择解析器

- [ ] 3. 断言规则系统增强
  - [ ] 3.1 创建 `lib/assert/engine.go` - 断言引擎核心
    - 定义 `AssertRule` 结构体 (Type, Value, Margin)
    - 实现 `Assert` 接口及其实现类
    - 支持规则组合 (AND/OR/NOT)
  - [ ] 3.2 实现内置断言规则
    - `SuccessStatusRule` - 成功状态码列表
    - `FailStatusRule` - 失败状态码列表
    - `FailRegexRule` - 响应体正则匹配
    - `FailSizeRule` - 响应大小范围
    - `ContainsRule` - 响应包含指定内容
    - `NotContainsRule` - 响应不包含指定内容
  - [ ] 3.3 创建规则配置解析器 `lib/assert/parser.go`
    - 支持 YAML/JSON 格式的规则配置
    - 实现 `ParseAssertRules(configPath string) ([]AssertRule, error)`
  - [ ] 3.4 在 `lib/Classify.go` 中集成断言引擎
    - 添加 `-asserts` 参数支持自定义断言规则文件
    - 在判定逻辑中优先使用自定义断言

- [ ] 4. 更智能的判定引擎
  - [ ] 4.1 创建 `lib/analyze/similarity.go` - 响应相似度分析
    - 实现 `JaccardSimilarity(body1, body2 []byte) float64` - Jaccard 相似度
    - 实现 `CosineSimilarity(body1, body2 []byte) float64` - 余弦相似度
    - 实现 `SimHash(body []byte) uint64` - SimHash 近似重复检测
  - [ ] 4.2 创建 `lib/analyze/keywords.go` - 登录页关键词库
    - 扩充现有关键词库 (50+ 关键词)
    - 支持关键词权重配置
    - 实现 `CalculateLoginScore(body []byte) float64` - 登录页评分
  - [ ] 4.3 创建 `lib/analyze/whitelist.go` - 误报过滤规则
    - 实现自定义黑名单规则文件
    - 支持 URL 模式和响应特征过滤
    - 在判定结果中自动过滤已知误报
  - [ ] 4.4 在 `lib/Classify.go` 中集成新算法
    - 使用相似度算法替代简单的长度比较
    - 添加 `-similarity-threshold` 参数 (默认 0.7)
    - 添加 `-whitelist` 自定义误报规则文件参数

- [ ] 5. 403/401 Bypass 高级检测技术
  - [ ] 5.1 创建 `lib/detect/id enumeration.go` - IDOR 检测
    - 检测 URL 中的可预测 ID 参数 (id, user_id, uuid 等)
    - 自动化枚举测试不同 ID 的访问权限
    - 识别是否可通过修改 ID 访问他人资源
  - [ ] 5.2 创建 `lib/detect/method.go` - HTTP 方法混淆检测
    - 增强现有 HTTP 方法变体探测
    - 支持非标准方法的大规模测试
  - [ ] 5.3 创建 `lib/detect/protocol.go` - 协议级绕过检测
    - HTTP/1.0, HTTP/1.1 协议降级测试
    - HTTP/2 协议特性检测
    - 协议头注入绕过
  - [ ] 5.4 创建 `lib/detect/headerchain.go` - 头部链绕过
    - 组合多个绕过头部进行测试
    - 头部注入链式绕过

- [ ] 6. 报告增强
  - [ ] 6.1 创建 `lib/report/html.go` - HTML 交互式报告
    - 实现 `GenerateHTMLReport(results []Result, outputPath string)` 函数
    - 添加筛选和搜索功能
    - 添加结果统计图表 (ECharts)
    - 支持漏洞导出和分享
  - [ ] 6.2 创建 `lib/report/trend.go` - 趋势对比报告
    - 支持历史扫描结果对比
    - 生成漏洞趋势图表
    - 添加新发现/已修复/持续存在 分类
  - [ ] 6.3 添加 `-report` 参数支持
    - `-report json` (默认)
    - `-report html` - 生成 HTML 报告
    - `-report markdown` - 生成 Markdown 报告
    - `-report all` - 生成所有格式

- [ ] 7. CLI 插件系统
  - [ ] 7.1 创建 `lib/plugin/loader.go` - 插件加载器
    - 实现 `PluginLoader` 结构体
    - 支持从指定目录扫描 `.so` 或 `.dll` 插件
    - 实现 `LoadPlugin(path string) (Plugin, error)` 函数
  - [ ] 7.2 创建 `lib/plugin/plugin.go` - 插件接口定义
    - 定义 `Plugin` 接口
    - `Name()`, `Version()`, `Execute(ctx *ScanContext) error`
    - `Init(config map[string]interface{}) error`
  - [ ] 7.3 创建 `lib/plugin/registry.go` - 内置插件注册表
    - 注册所有内置检测模块为插件
    - 提供 `Register(name string, p Plugin)` 函数
  - [ ] 7.4 添加 `-plugins` 参数支持
    - 添加 `-plugins-dir` 指定插件目录
    - 列出已加载插件信息
  - [ ] 7.5 创建示例插件 `plugins/example/example.go`
    - 实现一个简单的自定义检测插件示例
    - 提供插件开发文档注释

---

## 检查点

- [ ] 确保 CI/CD workflow 可正常执行
- [ ] 确保所有导入解析器通过测试
- [ ] 确保断言引擎与现有判定逻辑兼容
- [ ] 确保新判定算法不引入性能倒退
- [ ] 确保 HTML 报告在现代浏览器正常显示
- [ ] 确保插件系统加载内置插件无错误

---

## 技术依赖

```
新增依赖 (需添加到 go.mod):
- github.com/spf13/cobra (CLI 框架)
- github.com/google/simhash (SimHash 算法)
```

---

## 优先级排序

1. **P0** - CI/CD、导入功能、断言规则
2. **P0** - 报告增强 (HTML)
3. **P1** - 判定引擎智能分析 (相似度)
4. **P1** - 403/401 bypass 高级检测
5. **P2** - CLI 插件系统
