# 03 - Google Safe Browsing API

## 概述

Google 公开了其内部使用的 Safe Browsing API，任何组织或个人都可以在产品中接入，用于检测恶意网址。

## 功能

- 检查 URL 是否属于已知的钓鱼网站、恶意软件分发站点、或社会工程攻击页面
- Google 持续更新恶意网址库，覆盖面广
- Chrome、Firefox、Safari 等主流浏览器内置了 Safe Browsing 检测

## API 使用示例

### Lookup API (v4)

```bash
curl -X POST \
  "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client": {
      "clientId": "your-app",
      "clientVersion": "1.0"
    },
    "threatInfo": {
      "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      "platformTypes": ["ANY_PLATFORM"],
      "threatEntryTypes": ["URL"],
      "threatEntries": [
        {"url": "http://malware.testing.google.test/testing/malware/"}
      ]
    }
  }'
```

如果 URL 匹配恶意网址库，返回匹配的威胁类型；否则返回空结果。

### 威胁类型

| 类型 | 说明 |
|------|------|
| `MALWARE` | 恶意软件 |
| `SOCIAL_ENGINEERING` | 钓鱼/社会工程 |
| `UNWANTED_SOFTWARE` | 不需要的软件 |
| `POTENTIALLY_HARMFUL_APPLICATION` | 潜在有害应用 |

## 与 XSS/CSS 攻击的关系

在 02 笔记中的 CSS 数据窃取场景中，攻击者的恶意服务器 (`evil.com`) 可能会被 Safe Browsing 标记为恶意网址。这是一层额外的防御：

- 浏览器在加载 `@import url("http://evil.com/steal.php")` 之前可能会拦截
- 但攻击者可以使用新注册的域名来绕过，因为 Safe Browsing 依赖已知恶意网址库
- 所以 Safe Browsing 是防御的一层，但不能作为唯一防线

## 局限性

- 依赖已知恶意网址库，无法检测零日恶意网址
- 攻击者可以频繁更换域名来规避检测
- 隐私考虑：Lookup API 会将 URL 发送给 Google（Update API 使用哈希前缀，隐私更好）
