# Request Fuzz Bypass (数据包fuzz绕过)

## 1. 概述

本功能为 noauth 工具添加基于数据包的 fuzz 测试能力，类似于 sqlmap 的 `-r` 参数。用户可以通过指定一个 HTTP 请求数据包文件，工具自动解析请求内容并应用多种 401/403 绕过技巧进行变异测试。

## 2. 功能需求

### 2.1 命令行参数

| 参数 | 说明 |
|------|------|
| `-r <file>` | 指定包含 HTTP 请求的数据包文件 |
| `-m <mode>` | fuzz 模式：`bypass`（默认，401/403绕过）或 `logic`（逻辑漏洞测试） |
| `--target-ids` | 指定越权测试的目标 ID 列表，用逗号分隔 |

### 2.2 数据包解析

工具需要支持解析多种格式的数据包：

1. **RAW HTTP 格式**（BurpSuite 复制）
```
GET /admin HTTP/1.1
Host: target.com
Cookie: session=xxx

```

2. **cURL 格式**
```
curl -X GET 'http://target.com/admin' -H 'Cookie: xxx'
```

### 2.3 绕过技术清单

| 绕过技术 | 描述 | 适用场景 |
|----------|------|----------|
| ArrayWrap | `{"id":111}` → `{"id":[111]}` | JSON body |
| JSONNest | `{"id":111}` → `{"id":{"id":111}}` | JSON body |
| URLParamPollution | `?id=111&Id=222` | URL 参数 |
| Wildcard | `{"user_id":"111"}` → `{"user_id":"*"}` | JSON body |
| URLEncodeAmp | `?id=111%26Id=222` | 前端过滤 & 符号 |
| ParamOrder | `?id=222&id=111` | 参数顺序测试 |
| FormArray | `id=111` → `id[]=111` | Form 表单 |
| FormPollution | `id=111&id=222` | Form 表单 |

### 2.4 响应对比

- 记录原始请求的响应（状态码、长度、Body）
- 每个变异请求与原始响应对比
- 检测指标：状态码变化、响应长度差异、关键词变化

## 3. 技术设计

### 3.1 架构

```
main.go
├── -r 参数解析
└── RequestFuzzStart(file, mode, targets)
    ├── ParseRequest(file) → ParsedRequest
    │   ├── Method
    │   ├── URL
    │   ├── Headers
    │   └── Body
    ├── GenerateVariants(parsed) → []Variant
    │   ├── JSON变异 (ArrayWrap, JSONNest, Wildcard)
    │   ├── URL变异 (ParamPollution, ParamOrder, URLEncodeAmp)
    │   └── Form变异 (FormArray, FormPollution)
    └── TestVariants(variants, baseline) → []Result
        └── 并发发送变异请求，对比响应差异
```

### 3.2 核心数据结构

```go
// ParsedRequest 解析后的请求
type ParsedRequest struct {
    Method    string
    URL       string
    Headers   map[string]string
    Body      string
    ContentType string
}

// Variant 变异请求
type Variant struct {
    Name    string    // 绕过技术名称
    Payload string    // 具体的 payload
    Type    string    // json / url / form
}

// FuzzResult fuzz 测试结果
type FuzzResult struct {
    VariantName string
    OriginalCode int
    OriginalLen int
    NewCode int
    NewLen int
    Diff bool
    Classification string
}
```

### 3.3 关键函数

| 函数 | 职责 |
|------|------|
| `ParseRawRequest` | 解析 RAW HTTP 格式数据包 |
| `ParseCurlCommand` | 解析 cURL 格式数据包 |
| `ExtractJSONParams` | 从 JSON Body 提取可变异参数 |
| `ExtractURLParams` | 从 URL 提取可变异参数 |
| `ExtractFormParams` | 从 Form Body 提取可变异参数 |
| `GenerateJSONVariants` | 生成 JSON 变异 payload |
| `GenerateURLVariants` | 生成 URL 参数变异 payload |
| `GenerateFormVariants` | 生成 Form 变异 payload |

## 4. 数据流

```
1. 用户指定 -r request.txt
2. 读取文件，检测格式（RAW 或 cURL）
3. 解析请求，提取：Method, URL, Headers, Body
4. 根据 Content-Type 识别 Body 类型（JSON/Form）
5. 生成变异列表：
   - JSON Body → ArrayWrap, JSONNest, Wildcard, ParamOrder
   - URL Query → ParamPollution, URLEncodeAmp, ParamOrder
   - Form Body → FormArray, FormPollution
6. 发送原始请求，记录 baseline
7. 并发发送所有变异请求
8. 对比响应差异，输出命中结果
```

## 5. 实现文件

| 文件 | 职责 |
|------|------|
| `lib/RequestParser.go` | 数据包解析（RAW HTTP、cURL） |
| `lib/RequestFuzz.go` | 变异生成与测试主逻辑 |
| `lib/FuzzVariants.go` | 各种绕过技术的 payload 生成 |

## 6. 判定逻辑

复用 `ClassifyResult` 函数进行响应分类：
- 状态码从 401/403 变为 200 → 可能绕过(高)
- 状态码不变但响应长度差异大 → 长度差异大
- 重定向到非登录页面 → 重定向(需关注)

## 7. 输出

1. **控制台输出**：实时显示每个命中的变异及其判定结果
2. **Excel 导出**：新增 "Request Fuzz" Sheet，包含：
   - 绕过技术
   - 原始请求
   - 变异 payload
   - 响应长度
   - 状态码
   - 判定结果
   - curl 复现命令
