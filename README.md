# zc-gateway-log-viewer

一个本地运行的小工具：浏览器打开后输入**你自己的**鉴权信息 → 加载 AI 网关会话日志 → 关键字搜索 → 点击会话查看全文。

仅依赖 Python 标准库，**不需要安装任何第三方包**。

## 功能

- 输入鉴权信息（Cookie / 完整 session JSON）即可连接网关日志
- 关键字搜索会话（支持"仅标题"快速搜索与"标题+全文"深度搜索）
- 点击任意会话，右侧展示该会话的完整对话内容，并对关键字高亮

## 运行环境

- Windows / macOS / Linux
- 需要已安装 **Python 3.10+**（命令行执行 `python --version` 能看到版本即可）

## 启动

**Windows**：双击 `run_tool.bat`

**通用命令行**：

```bash
python gateway_tool.py
```

启动后用浏览器打开：<http://127.0.0.1:8787>

关闭命令行窗口（或按 `Ctrl+C`）即停止服务。

## 填写鉴权信息

### 方法 1：直接粘贴整个 session JSON 全文（最省事，推荐）

把从浏览器导出的 `session-*.json` 文件用记事本打开，**全选复制**，粘贴到①框，**②框留空**，点「连接并加载会话」。

> 提示：即使不小心把整段 JSON 同时粘到了①框和②框，工具也能自动识别，不会报错。
> 但②框只接受 token 本身（形如 `eyJ...` 的三段式），不要往里粘整段 JSON。

### 方法 2：手动粘贴 cookie + JWT

- ①框：粘贴 cookie 字符串，例如
  `hy_user=xxx; hy_token=xxx; yuanqi_token=xxx; web_uid=xxx; yuanqi_source=web`
- ②框：粘贴 JWT（token）。获取方式：在目标页面按 F12 打开控制台，执行
  `JSON.parse(localStorage.user_info).token`，把打印出来的 `eyJ...` 整串粘进去。

> ⚠️ 只填 cookie 是不够的。接口必须带 `Authorization: Bearer <JWT>`；
> cookie 里的 `hy_token` / `yuanqi_token` 直接调用会返回 401。

## 搜索与查看

- ③输入框输入关键字，多个关键字用**空格分隔**（表示都要同时命中，AND）。
- **搜索范围**下拉：
  - `仅标题（快）`：只匹配会话标题，秒出，适合按会话 ID / 名字找。
  - `标题 + 全文（慢）`：逐个拉取会话正文做全文匹配，命中率最高；全量会话约需 1~2 分钟，请耐心等待（页面会显示"正在搜索"）。
- 命中结果在左侧列表，**点击任意一条，右侧即显示该会话的完整对话内容**（按角色 / 时序排版，并高亮关键字）。

## 注意事项

- 工具**只在本地运行**；鉴权信息仅保存在本页面内存与本地服务进程内存中，不写入磁盘、不上传到任何第三方；所有网关请求都直接发往目标站点。
- 请仅在**你自己的账号 / 已获授权的范围**内使用，仅做读取，不做任何写入或修改。
- 鉴权（JWT）有有效期，过期后重新获取 JWT 再连接即可。
- 若端口被占用，可修改 `gateway_tool.py` 顶部的 `PORT`。

> 🔒 **请勿把任何包含鉴权信息的 `session-*.json`、cookie、JWT 提交到本仓库。** 工具本身不含任何凭据。

## 文件清单

| 文件 | 说明 |
|---|---|
| `gateway_tool.py` | 主程序（本地 HTTP 服务 + 网关接口代理 + 前端页面） |
| `run_tool.bat` | Windows 一键启动脚本 |
| `README.md` | 本说明 |

## 接口说明（供参考）

base：`https://zc.tencent.com/api/v1`

| 用途 | 接口 |
|---|---|
| 会话列表 | `POST /whitehat/ai_gateway/sessions` |
| 会话详情 | `POST /whitehat/ai_gateway/session_detail` |
| 模型用量 | `POST /whitehat/ai_gateway/model_usage` |
| 路由列表 | `POST /whitehat/ai_gateway/routes/list` |

工具用到的参数：`project_code`（默认 `PROJ2026_AISRC01`）、`page`、`page_size`（最大 50）、`session_id`。

## 免责声明

本工具仅供在本人在合法授权范围内的安全测试与日志查看使用。使用者需自行确保其使用行为符合相关法律法规及目标平台的服务条款，因使用本工具产生的任何后果由使用者自行承担。
