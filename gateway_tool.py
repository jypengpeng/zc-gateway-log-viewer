#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zc.tencent.com AI 网关日志浏览器 (本地工具)

功能:
  1. 浏览器打开后, 输入鉴权信息 (Cookie 字符串 或 直接粘贴导出的 session JSON)
  2. 拉取 AI 网关会话日志列表
  3. 按关键字搜索会话 (标题 / 全文)
  4. 点击会话查看该会话的完整对话内容

仅使用 Python 标准库, 无第三方依赖。
默认监听 http://127.0.0.1:8787
"""

import io
import json
import ssl
import re
import sys
import time
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------------------------------------------------------
# 配置
# ----------------------------------------------------------------------------
BASE = "https://zc.tencent.com/api/v1"
DEFAULT_PROJECT = "PROJ2026_AISRC01"
HOST = "127.0.0.1"
PORT = 8787
PAGE_SIZE = 50            # 网关接口允许的最大分页
DETAIL_MAX_PAGES = 40     # 单个会话详情最多拉取页数保护
TIMEOUT = 45
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")

# 会话列表内存缓存: key -> (timestamp, items)。避免每次搜索都重新分页拉取。
_SESSION_CACHE = {}
_CACHE_TTL = 120  # 秒
_CACHE_LOCK = threading.Lock()


def _cache_key(cookie_header, project):
    return "%s|%s" % (hash(cookie_header), project)


def get_sessions_cached(cookie_header, jwt, project, force=False):
    key = _cache_key(cookie_header, project)
    now = time.time()
    with _CACHE_LOCK:
        hit = _SESSION_CACHE.get(key)
        if hit and not force and now - hit[0] < _CACHE_TTL:
            return hit[1], ""
    items, err = fetch_sessions(cookie_header, jwt, project)
    if err:
        return None, err
    with _CACHE_LOCK:
        _SESSION_CACHE[key] = (now, items)
    return items, ""


# ----------------------------------------------------------------------------
# 鉴权解析: 支持 cookie 字符串 / session JSON / 单独 JWT
# ----------------------------------------------------------------------------
def _parse_session_json(text):
    """从导出的 site-session-backup JSON 中解析 cookie 与 JWT。"""
    data = json.loads(text)
    cookies = {}
    for c in data.get("cookies", []) or []:
        if isinstance(c, dict) and c.get("name"):
            cookies[c["name"]] = c.get("value", "")
    jwt = ""
    ls = data.get("localStorage", {})
    if isinstance(ls, dict):
        ui = ls.get("user_info")
        if ui:
            try:
                info = json.loads(ui) if isinstance(ui, str) else ui
                jwt = (info or {}).get("token", "") or ""
            except Exception:
                pass
    # 兼容: localStorage 里直接放了 token 字段的情况
    if not jwt and isinstance(ls, dict):
        for k in ("token", "jwt", "access_token"):
            v = ls.get(k)
            if isinstance(v, str) and v.count(".") >= 2:
                jwt = v
                break
    return cookies, jwt


def _parse_cookie_string(text):
    """解析 'a=1; b=2' 形式的 cookie 字符串。"""
    cookies = {}
    for part in text.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        cookies[k.strip()] = v.strip()
    return cookies


def _looks_like_json(s):
    s = (s or "").lstrip()
    return s.startswith("{") or s.startswith("[")


def _clean_jwt(s):
    """从可能的 JWT 输入中提取出真正的 token；返回 (token, error)。"""
    if not s:
        return "", ""
    s = s.strip().strip('"').strip("'")
    if s.lower().startswith("bearer "):
        s = s[7:].strip()
    # 去掉可能残留的换行 / 空格
    s = "".join(s.split())
    if not s:
        return "", ""
    # JWT 是点分隔的三段；至少校验它全为可见 ASCII 且含两个点
    if any(ord(ch) > 127 for ch in s):
        return "", ("JWT 框里似乎不是有效的 token（含非 ASCII 字符，"
                     "看起来像是把整段 JSON 粘进来了）。请在①框粘贴完整 session JSON，"
                     "或只在②框粘贴 localStorage.user_info 里的 token 本身。")
    if s.count(".") < 2:
        return "", ("JWT 框里的内容不像标准 JWT（应为 xxx.yyy.zzz 三段式）。"
                     "请确认粘贴的是 user_info 里的 token，而不是整段 JSON。")
    return s, ""


def parse_auth(cookie_text, jwt_text):
    """
    返回 (cookie_header, jwt, error)
    两个输入框都可接受完整 session JSON；工具会自动识别。
    """
    cookie_text = (cookie_text or "").strip()
    jwt_text = (jwt_text or "").strip()
    cookies, jwt = {}, ""

    # ①框：完整 JSON 或 cookie 字符串
    if cookie_text:
        if _looks_like_json(cookie_text):
            try:
                cookies, jwt = _parse_session_json(cookie_text)
            except Exception as e:
                return "", "", "解析 session JSON 失败: %s" % e
        else:
            cookies = _parse_cookie_string(cookie_text)

    # ②框：如果①已经给了 JSON，这里通常应为空；但若用户把 JSON 也粘到了②，
    #      则自动识别并采纳（而不当成 JWT），否则才作为独立 JWT 处理。
    if jwt_text:
        if _looks_like_json(jwt_text):
            try:
                c2, j2 = _parse_session_json(jwt_text)
                if not cookies:
                    cookies = c2
                if j2:
                    jwt = j2
            except Exception:
                # ②是 JSON 但解析失败；忽略它，用①的结果
                pass
        else:
            j, err = _clean_jwt(jwt_text)
            if err:
                return "", "", err
            if j:
                jwt = j

    if not cookies:
        return "", "", ("未能解析出 cookie。请在①框粘贴完整的 session JSON 全文，"
                         "或粘贴形如 'a=1; b=2' 的 cookie 字符串。")
    if not jwt:
        return "", "", ("缺少 JWT（Authorization: Bearer）。请直接粘贴完整 session JSON "
                         "（会自动提取），或在②框粘贴 localStorage.user_info 里的 token。")

    cookie_header = "; ".join("%s=%s" % (k, v) for k, v in cookies.items())
    return cookie_header, jwt, ""


# ----------------------------------------------------------------------------
# 网关 API 调用
# ----------------------------------------------------------------------------
def gateway_post(cookie_header, jwt, path, params):
    url = BASE + path
    body = json.dumps(params).encode("utf-8")
    # 防御：JWT 必须是纯 ASCII 且无空白，否则自定义头无法编码（latin-1）。
    jwt = "".join((jwt or "").split())
    try:
        jwt.encode("ascii")
    except UnicodeEncodeError:
        return None, ("JWT 无效（含非 ASCII 字符）。请粘贴 localStorage.user_info "
                      "里的 token 本身，或在①框粘贴完整 session JSON。")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json;charset=UTF-8")
    req.add_header("Accept", "application/json, text/plain, */*")
    req.add_header("Origin", "https://zc.tencent.com")
    req.add_header("Referer",
                   "https://zc.tencent.com/project/whiteHat/aiGateway?project_code="
                   + params.get("project_code", DEFAULT_PROJECT))
    req.add_header("User-Agent", UA)
    req.add_header("Cookie", cookie_header)
    req.add_header("Authorization", "Bearer " + jwt)
    last_err = None
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CTX) as r:
                raw = r.read().decode("utf-8", "replace")
                return r.status, json.loads(raw)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            return e.code, body
        except Exception as e:
            last_err = e
            time.sleep(0.6)
    return None, "网络错误: %r" % (last_err,)


def fetch_sessions(cookie_header, jwt, project):
    """分页拉取全部会话摘要。"""
    items, page, total = [], 1, None
    while True:
        st, data = gateway_post(cookie_header, jwt, "/whitehat/ai_gateway/sessions",
                                {"project_code": project, "page": page, "page_size": PAGE_SIZE})
        if st != 200 or not isinstance(data, dict):
            return None, "获取会话列表失败 (status=%s): %s" % (st, str(data)[:300])
        d = data.get("data") or {}
        batch = d.get("items") or []
        items.extend(batch)
        pag = d.get("pagination") or {}
        total = pag.get("total", total)
        if not batch or (total is not None and len(items) >= total):
            break
        page += 1
        if page > 500:
            break
    return items, ""


def walk_strings(o, out):
    if isinstance(o, str):
        out.append(o)
    elif isinstance(o, dict):
        for v in o.values():
            walk_strings(v, out)
    elif isinstance(o, list):
        for v in o:
            walk_strings(v, out)


def fetch_session_detail(cookie_header, jwt, project, session_id):
    """拉取单个会话全部步骤。"""
    steps, page = [], 1
    while True:
        st, data = gateway_post(cookie_header, jwt, "/whitehat/ai_gateway/session_detail",
                                {"project_code": project, "session_id": session_id,
                                 "page": page, "page_size": PAGE_SIZE})
        if st != 200 or not isinstance(data, dict):
            if page == 1:
                return None, "获取会话详情失败 (status=%s): %s" % (st, str(data)[:300])
            break
        d = data.get("data")
        if not isinstance(d, dict):
            if page == 1:
                return None, "会话详情为空: %s" % str(data)[:300]
            break
        steps.extend(d.get("steps") or [])
        tp = (d.get("pagination") or {}).get("total_pages") or 1
        if page >= tp or page >= DETAIL_MAX_PAGES:
            break
        page += 1
    return steps, ""


# ----------------------------------------------------------------------------
# 会话详情 -> 可读文本
# ----------------------------------------------------------------------------
ROLE_LABEL = {
    "system": "SYSTEM", "assistant": "ASSISTANT", "user": "USER",
    "tool": "TOOL", "tool_result": "TOOL_RESULT", "tool_call": "TOOL_CALL",
    "assistant_text": "ASSISTANT", "system_note": "SYSTEM_NOTE",
    "session_note": "SESSION_NOTE", "note": "NOTE",
}


def flatten_step(step):
    """把一个 step 展开为 {role, text} 列表。"""
    out = []
    et = step.get("event_type") or ""
    items = step.get("items")
    produced = False
    if isinstance(items, list):
        for it in items:
            if isinstance(it, dict):
                role = it.get("role") or it.get("type") or et or "item"
                txt = it.get("text") or it.get("content") or ""
                if isinstance(txt, (dict, list)):
                    s = []
                    walk_strings(txt, s)
                    txt = "\n".join(s)
                if txt:
                    out.append({"role": ROLE_LABEL.get(str(role).lower(), str(role)),
                                "text": str(txt)})
                    produced = True
    if not produced:
        role = step.get("role") or et or "event"
        txt = step.get("text") or step.get("content") or step.get("error") or ""
        if txt:
            out.append({"role": ROLE_LABEL.get(str(role).lower(), str(role)), "text": str(txt)})
    return out


def build_transcript(steps):
    """返回结构化消息列表 + 纯文本全文。"""
    messages = []
    for step in steps:
        ts = step.get("captured_at") or ""
        for m in flatten_step(step):
            m["time"] = ts
            messages.append(m)
    text = "\n".join("[%s] %s\n%s" % (m.get("time", ""), m["role"], m["text"]) for m in messages)
    return messages, text


# ----------------------------------------------------------------------------
# HTTP 处理器
# ----------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "GatewayTool/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # ---- GET ----
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        else:
            self._send(404, {"error": "not found"})

    # ---- POST ----
    def do_POST(self):
        p = self.path.rstrip("/")
        body = self._read_json()

        if p == "/api/connect":
            cookie, jwt, err = parse_auth(body.get("cookie"), body.get("jwt"))
            if err:
                return self._send(200, {"ok": False, "error": err})
            project = body.get("project") or DEFAULT_PROJECT
            items, err = get_sessions_cached(cookie, jwt, project, force=body.get("refresh", False))
            if err:
                return self._send(200, {"ok": False, "error": err})
            return self._send(200, {"ok": True, "project": project, "total": len(items)})

        if p == "/api/sessions":
            cookie, jwt, err = parse_auth(body.get("cookie"), body.get("jwt"))
            if err:
                return self._send(200, {"ok": False, "error": err})
            project = body.get("project") or DEFAULT_PROJECT
            items, err = get_sessions_cached(cookie, jwt, project, force=body.get("refresh", False))
            if err:
                return self._send(200, {"ok": False, "error": err})
            return self._send(200, {"ok": True, "items": items})

        if p == "/api/search":
            cookie, jwt, err = parse_auth(body.get("cookie"), body.get("jwt"))
            if err:
                return self._send(200, {"ok": False, "error": err})
            project = body.get("project") or DEFAULT_PROJECT
            kw = (body.get("keyword") or "").strip()
            deep = bool(body.get("deep"))
            if not kw:
                return self._send(200, {"ok": False, "error": "请输入关键字"})
            items, err = get_sessions_cached(cookie, jwt, project)
            if err:
                return self._send(200, {"ok": False, "error": err})

            kws = [k for k in re.split(r"\s+", kw) if k]
            low_kws = [k.lower() for k in kws]

            def match_title(it):
                t = (it.get("title") or "").lower()
                return all(k in t for k in low_kws)

            title_hits = [it for it in items if match_title(it)]
            results = list(title_hits)
            seen = {it["session_id"] for it in results}

            if deep:
                # 并发拉取每个会话的详情做全文匹配
                def worker(it):
                    steps, e = fetch_session_detail(cookie, jwt, project, it["session_id"])
                    if not steps:
                        return it, None
                    _, text = build_transcript(steps)
                    low = text.lower()
                    if all(k in low for k in low_kws):
                        # 生成命中片段
                        first = low_kws[0]
                        pos = low.find(first)
                        snippet = text[max(0, pos - 120): pos + 220].replace("\n", " ")
                        return it, snippet
                    return it, None

                with ThreadPoolExecutor(max_workers=12) as ex:
                    for f in as_completed({ex.submit(worker, it): it for it in items}):
                        it, snip = f.result()
                        if snip is not None and it["session_id"] not in seen:
                            r = dict(it)
                            r["snippet"] = snip
                            results.append(r)
                            seen.add(it["session_id"])
            return self._send(200, {"ok": True, "items": results,
                                    "title_only_count": len(title_hits)})

        if p == "/api/session_detail":
            cookie, jwt, err = parse_auth(body.get("cookie"), body.get("jwt"))
            if err:
                return self._send(200, {"ok": False, "error": err})
            project = body.get("project") or DEFAULT_PROJECT
            sid = body.get("session_id")
            if sid is None:
                return self._send(200, {"ok": False, "error": "缺少 session_id"})
            steps, err = fetch_session_detail(cookie, jwt, project, sid)
            if err:
                return self._send(200, {"ok": False, "error": err})
            messages, _ = build_transcript(steps)
            return self._send(200, {"ok": True, "messages": messages,
                                    "session_id": sid, "step_count": len(steps)})

        self._send(404, {"error": "not found"})


# ----------------------------------------------------------------------------
# 前端页面
# ----------------------------------------------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI 网关日志浏览器</title>
<style>
  :root { --bd:#d9dee5; --bg:#f5f7fa; --pri:#2b6cb0; --mut:#6b7280; }
  * { box-sizing: border-box; }
  body { margin:0; font: 14px/1.6 -apple-system,"Segoe UI",Roboto,"Microsoft YaHei",sans-serif; color:#1f2937; background:var(--bg); }
  header { background:#fff; border-bottom:1px solid var(--bd); padding:14px 20px; }
  header h1 { margin:0; font-size:17px; }
  header .sub { color:var(--mut); font-size:12px; margin-top:2px;}
  .panel { background:#fff; border:1px solid var(--bd); border-radius:10px; margin:14px 20px; padding:14px 16px; }
  label { display:block; font-size:12px; color:var(--mut); margin:8px 0 4px; }
  textarea,input[type=text] { width:100%; border:1px solid var(--bd); border-radius:8px; padding:9px 10px; font:13px/1.5 ui-monospace,Consolas,monospace; }
  textarea { min-height:74px; resize:vertical; }
  .row { display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end; }
  .row > div { flex:1; min-width:220px; }
  button { background:var(--pri); color:#fff; border:0; border-radius:8px; padding:9px 16px; font-size:14px; cursor:pointer; }
  button:disabled { opacity:.55; cursor:default; }
  button.ghost { background:#eef2f7; color:#1f2937; }
  .status { font-size:12px; color:var(--mut); margin-top:8px; white-space:pre-wrap; }
  .status.err { color:#b91c1c; }
  .main { display:flex; gap:14px; margin:0 20px 24px; height: calc(100vh - 60px); min-height:420px; }
  .list { width:360px; flex:0 0 360px; background:#fff; border:1px solid var(--bd); border-radius:10px; overflow:auto; }
  .detail { flex:1; background:#fff; border:1px solid var(--bd); border-radius:10px; overflow:auto; padding:0; }
  .item { padding:10px 12px; border-bottom:1px solid #eef1f5; cursor:pointer; }
  .item:hover { background:#f0f6ff; }
  .item.active { background:#e3efff; }
  .item .sid { font-weight:600; color:var(--pri); }
  .item .meta { font-size:11px; color:var(--mut); }
  .item .ttl { font-size:12px; color:#374151; margin-top:3px; max-height:34px; overflow:hidden; }
  .item .snip { font-size:11px; color:#92400e; background:#fffbeb; border-radius:5px; padding:3px 6px; margin-top:4px; }
  .msg { padding:10px 16px; border-bottom:1px solid #eef1f5; }
  .msg .hd { font-size:11px; color:var(--mut); margin-bottom:3px; }
  .msg .role { font-weight:700; color:#374151; margin-right:8px; }
  .msg pre { margin:0; white-space:pre-wrap; word-break:break-word; font:12.5px/1.55 ui-monospace,Consolas,monospace; }
  .msg.role-USER { background:#f8fbff; }
  .msg.role-ASSISTANT { background:#fff; }
  .msg.role-TOOL, .msg.role-TOOL_RESULT, .msg.role-TOOL_CALL { background:#fafafa; }
  mark { background:#fde68a; padding:0 2px; border-radius:3px; }
  .empty { color:var(--mut); padding:28px; text-align:center; }
  .badge { display:inline-block; background:#eef2f7; border-radius:20px; padding:1px 8px; font-size:11px; color:#374151; margin-left:6px;}
  details.help { margin-top:6px; font-size:12px; color:var(--mut);}
  details.help summary { cursor:pointer; }
  code { background:#eef2f7; padding:1px 5px; border-radius:4px; }
</style>
</head>
<body>
<header>
  <h1>AI 网关日志浏览器 <span class="badge">本地工具</span></h1>
  <div class="sub">粘贴鉴权信息 &rarr; 加载会话 &rarr; 关键字搜索 &rarr; 点击查看全文</div>
</header>

<div class="panel">
  <label>① 鉴权信息（粘贴 Cookie 字符串，或直接粘贴整个 session JSON 文件内容）</label>
  <textarea id="cookie" placeholder='方法一：粘贴 cookie，如  hy_user=xxx; hy_token=xxx; yuanqi_token=xxx; web_uid=xxx
方法二：直接把导出的 session JSON 全文粘贴到这里（会自动提取 cookie 和 JWT）'></textarea>
  <label>② JWT（可选）</label>
  <input type="text" id="jwt" placeholder="留空即可（若已把 JSON 粘到①框）；或粘贴 localStorage.user_info 里的 token（eyJ... 三段式）">
  <div class="row" style="margin-top:10px">
    <div style="flex:0 0 auto"><label>项目</label><input type="text" id="project" value="PROJ2026_AISRC01"></div>
    <div style="flex:0 0 auto"><button id="btnConnect">连接并加载会话</button></div>
    <div style="flex:0 0 auto"><button id="btnFile" class="ghost">上传 session JSON</button>
      <input type="file" id="file" accept=".json,application/json" style="display:none"></div>
  </div>
  <div class="status" id="status"></div>
  <details class="help">
    <summary>鉴权信息怎么填？（推荐：只填①框）</summary>
    <div>最简单：把整个 session JSON 文件全文 <b>只</b> 粘贴到①框，②框<b>留空</b>，点“连接并加载会话”。<br>
    若手动填：①框放 cookie，②框放 JWT（<code>JSON.parse(localStorage.user_info).token</code> 的结果，形如 <code>eyJ...三段式</code>）。<br>
    ⚠️ 不要把整段 JSON 粘到②框——②框只接受 token 本身。<br>
    鉴权信息仅保存在本页面内存 / 本地服务进程内存，不落盘、不外传。</div>
  </details>
</div>

<div class="panel" style="padding-top:8px">
  <div class="row">
    <div><label>③ 关键字搜索（空格分隔多个 = AND）</label><input type="text" id="kw" placeholder="例如：tts  或  ws/audio/tts"></div>
    <div style="flex:0 0 auto"><label>搜索范围</label>
      <select id="mode" style="padding:9px;border:1px solid var(--bd);border-radius:8px">
        <option value="title">仅标题（快）</option>
        <option value="deep">标题 + 全文（慢）</option>
      </select>
    </div>
    <div style="flex:0 0 auto"><button id="btnSearch">搜索</button></div>
  </div>
  <div class="status" id="searchStatus"></div>
</div>

<div class="main">
  <div class="list" id="list"><div class="empty">尚未加载会话</div></div>
  <div class="detail" id="detail"><div class="empty">点击左侧会话查看全文</div></div>
</div>

<script>
const $ = id => document.getElementById(id);
let state = { project: "PROJ2026_AISRC01", active: null, keyword: "" };

function setStatus(el, msg, isErr) {
  el.textContent = msg || "";
  el.className = "status" + (isErr ? " err" : "");
}
function authPayload() {
  return {
    cookie: $("cookie").value,
    jwt: $("jwt").value,
    project: $("project").value.trim() || "PROJ2026_AISRC01"
  };
}
async function api(path, payload) {
  const r = await fetch(path, { method:"POST", headers:{"Content-Type":"application/json"},
                                body: JSON.stringify(payload) });
  return await r.json();
}

$("btnFile").onclick = () => $("file").click();
$("file").onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return;
  const text = await f.text();
  $("cookie").value = text;
  $("jwt").value = "";
  setStatus($("status"), "已读取文件 " + f.name + "，点击“连接并加载会话”。");
};

$("btnConnect").onclick = async () => {
  const st = $("status");
  setStatus(st, "正在连接并加载会话…（全部会话可能需分页拉取，请稍候）");
  $("btnConnect").disabled = true;
  try {
    const res = await api("/api/sessions", authPayload());
    if (!res.ok) { setStatus(st, "失败：" + res.error, true); return; }
    state.project = authPayload().project;
    renderList(res.items);
    setStatus(st, "已加载 " + res.items.length + " 条会话。");
  } catch (e) {
    setStatus(st, "请求出错：" + e, true);
  } finally { $("btnConnect").disabled = false; }
};

$("btnSearch").onclick = async () => {
  const st = $("searchStatus");
  const kw = $("kw").value.trim();
  if (!kw) { setStatus(st, "请输入关键字", true); return; }
  const deep = $("mode").value === "deep";
  setStatus(st, deep ? "正在全文搜索（会逐个拉取会话内容，可能较慢）…" : "正在搜索标题…");
  $("btnSearch").disabled = true;
  try {
    const p = authPayload(); p.keyword = kw; p.deep = deep;
    const res = await api("/api/search", p);
    if (!res.ok) { setStatus(st, "失败：" + res.error, true); return; }
    state.keyword = kw;
    renderList(res.items, true);
    setStatus(st, "命中 " + res.items.length + " 条（标题命中 " + res.title_only_count + "）");
  } catch (e) {
    setStatus(st, "请求出错：" + e, true);
  } finally { $("btnSearch").disabled = false; }
};

function esc(s) {
  return (s == null ? "" : String(s)).replace(/[&<>"]/g, c =>
      ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));
}
function hl(text, kw) {
  let html = esc(text);
  if (kw) {
    const parts = kw.split(/\s+/).filter(Boolean);
    for (const k of parts) {
      const safe = esc(k).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      html = html.replace(new RegExp(safe, "gi"), m => "<mark>" + m + "</mark>");
    }
  }
  return html;
}

function renderList(items, isSearch) {
  const list = $("list");
  if (!items || !items.length) { list.innerHTML = '<div class="empty">无结果</div>'; return; }
  list.innerHTML = "";
  for (const it of items) {
    const div = document.createElement("div");
    div.className = "item"; div.dataset.sid = it.session_id;
    const title = (it.title || "").replace(/\s+/g, " ").slice(0, 90);
    div.innerHTML =
      '<div><span class="sid">#' + esc(it.session_id) + '</span>' +
      '<span class="meta"> ' + esc(it.model || "") + ' · ' + esc(it.event_count || "") + ' 事件 · ' +
      esc((it.first_captured_at||"").replace("T"," ").replace("Z","")) + '</span></div>' +
      '<div class="ttl">' + hl(title, state.keyword) + '</div>' +
      (it.snippet ? '<div class="snip">…' + hl(it.snippet.slice(0,220), state.keyword) + '…</div>' : "");
    div.onclick = () => openSession(it.session_id, div);
    list.appendChild(div);
  }
}

async function openSession(sid, el) {
  document.querySelectorAll(".item.active").forEach(e => e.classList.remove("active"));
  if (el) el.classList.add("active");
  state.active = sid;
  const d = $("detail");
  d.innerHTML = '<div class="empty">正在加载会话 #' + esc(sid) + ' …</div>';
  try {
    const p = authPayload(); p.session_id = sid;
    const res = await api("/api/session_detail", p);
    if (!res.ok) { d.innerHTML = '<div class="empty">加载失败：' + esc(res.error) + '</div>'; return; }
    renderDetail(sid, res);
  } catch (e) {
    d.innerHTML = '<div class="empty">请求出错：' + esc(e) + '</div>';
  }
}

function renderDetail(sid, res) {
  const d = $("detail");
  const kw = $("kw").value.trim();
  let html = '<div style="padding:12px 16px;border-bottom:1px solid #eef1f5;position:sticky;top:0;background:#fff">' +
             '<b>会话 #' + esc(sid) + '</b> <span class="meta" style="color:#6b7280;font-size:12px">' +
             esc(res.messages.length) + ' 条消息 / ' + esc(res.step_count) + ' 步</span></div>';
  if (!res.messages.length) {
    html += '<div class="empty">该会话无可展示文本内容</div>';
  } else {
    for (const m of res.messages) {
      const cls = "msg role-" + esc(m.role).replace(/[^A-Z_]/g,"");
      html += '<div class="' + cls + '">' +
              '<div class="hd"><span class="role">' + esc(m.role) + '</span>' + esc(m.time || "") + '</div>' +
              '<pre>' + hl(m.text, kw) + '</pre></div>';
    }
  }
  d.innerHTML = html;
}

$("kw").addEventListener("keydown", e => { if (e.key === "Enter") $("btnSearch").click(); });
</script>
</body>
</html>
"""


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("=" * 60)
    print("AI 网关日志浏览器已启动")
    print("请在浏览器打开:  http://%s:%d" % (HOST, PORT))
    print("按 Ctrl+C 停止")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
        httpd.shutdown()


if __name__ == "__main__":
    main()
