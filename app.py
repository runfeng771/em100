import os
import re
import time
import base64
import threading
from datetime import datetime
from collections import deque

import requests
import ddddocr
from flask import Flask, request, jsonify, render_template_string
from apscheduler.schedulers.background import BackgroundScheduler
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# =========================
# Flask
# =========================
app = Flask(__name__)

# =========================
# 固定接口
# =========================
CMS_URL = "https://cmsapi3.qiucheng-wangluo.com/cms-api/club/unlockClubManager"
CLUBINFO_URL = "https://cmsapi3.qiucheng-wangluo.com/cms-api/club/clubInfo"
CMS_REFERER = "https://cms.ayybyyy.com/"
CLUB_ID = 104137139  # 你指定的 lClubID

# =========================
# 账号密码：Render 用环境变量覆盖
# =========================
DEFAULT_ACCOUNT = "tbh2356@126.com"
DEFAULT_PASSWORD = "112233qq"
CMS_ACCOUNT = os.getenv("CMS_ACCOUNT", DEFAULT_ACCOUNT)
CMS_PASSWORD = os.getenv("CMS_PASSWORD", DEFAULT_PASSWORD)

# =========================
# 日志缓冲（前端展示）
# =========================
LOG_LOCK = threading.Lock()
LOG_BUF = deque(maxlen=800)

def _push_line(line: str):
    with LOG_LOCK:
        LOG_BUF.appendleft(line)

def log_blank():
    _push_line("")

def log_sep(title: str):
    _push_line("────────────────────────────────────────")
    _push_line(f"【{title}】{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _push_line("────────────────────────────────────────")

def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    _push_line(f"[{ts}] {msg}")

def clear_logs():
    with LOG_LOCK:
        LOG_BUF.clear()

# =========================
# Token 缓存：每次登录成功覆盖为最新
# =========================
TOKEN_LOCK = threading.Lock()
TOKEN_CACHE = {
    "token": None,
    "last_login_at": None,
    "last_login_ok": False,
    "last_login_err": "",
}

def set_token(token: str):
    with TOKEN_LOCK:
        TOKEN_CACHE["token"] = token
        TOKEN_CACHE["last_login_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        TOKEN_CACHE["last_login_ok"] = True
        TOKEN_CACHE["last_login_err"] = ""

def set_login_fail(err: str):
    with TOKEN_LOCK:
        TOKEN_CACHE["last_login_ok"] = False
        TOKEN_CACHE["last_login_err"] = err

def get_token():
    with TOKEN_LOCK:
        return TOKEN_CACHE["token"]

def get_status_snapshot():
    with TOKEN_LOCK:
        return dict(TOKEN_CACHE)

# =========================
# CLUB 上下文缓存：clubInfo 是否成功（用于判断是否需要重登）
# =========================
CLUBCTX_LOCK = threading.Lock()
CLUBCTX_CACHE = {
    "ok": False,
    "last_at": None,
    "last_err": "",
    "last_resp": None,
}

def set_clubctx_ok(resp):
    with CLUBCTX_LOCK:
        CLUBCTX_CACHE["ok"] = True
        CLUBCTX_CACHE["last_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        CLUBCTX_CACHE["last_err"] = ""
        CLUBCTX_CACHE["last_resp"] = resp

def set_clubctx_fail(err: str, resp=None):
    with CLUBCTX_LOCK:
        CLUBCTX_CACHE["ok"] = False
        CLUBCTX_CACHE["last_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        CLUBCTX_CACHE["last_err"] = err
        CLUBCTX_CACHE["last_resp"] = resp

def get_clubctx():
    with CLUBCTX_LOCK:
        return dict(CLUBCTX_CACHE)

# =========================
# 登录器（整合你脚本核心流程）
# =========================
class CMSAutoLogin:
    def __init__(self):
        self.session = requests.Session()
        self.ocr = ddddocr.DdddOcr()
        self.max_attempts = 5

        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": CMS_REFERER
        }

        # 固定公钥（第一次加密用）
        self.first_public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNR7I+SpqIZM5w3Aw4lrUlhrs7VurKbeViYXNhOfIgP/4acsWvJy5dPb/FejzUiv2cAiz5As2DJEQYEM10LvnmpnKx9Dq+QDo7WXnT6H2szRtX/8Q56Rlzp9bJMlZy7/i0xevlDrWZMWqx2IK3ZhO9+0nPu4z4SLXaoQGIrs7JxwIDAQAB"

    def get_captcha_token(self):
        url = "https://cmsapi3.qiucheng-wangluo.com/cms-api/token/generateCaptchaToken"
        r = self.session.post(url, headers=self.headers, timeout=15)
        r.raise_for_status()
        j = r.json()
        if j.get("iErrCode") != 0:
            raise RuntimeError(f"generateCaptchaToken失败: {j.get('sErrMsg')}")
        return j.get("result")

    def get_captcha_img_b64(self, captcha_token: str):
        url = "https://cmsapi3.qiucheng-wangluo.com/cms-api/captcha"
        r = self.session.post(url, headers=self.headers, data={"token": captcha_token}, timeout=15)
        r.raise_for_status()
        j = r.json()
        if j.get("iErrCode") != 0:
            raise RuntimeError(f"captcha失败: {j.get('sErrMsg')}")
        return j.get("result")

    def recognize_captcha(self, captcha_base64: str) -> str:
        img = base64.b64decode(captcha_base64)
        txt = self.ocr.classification(img)
        txt = re.sub(r"[^a-zA-Z0-9]", "", txt)
        if len(txt) > 4:
            txt = txt[:4]
        return txt.upper()

    def load_public_key(self, key_str: str):
        try:
            if "-----BEGIN" in key_str:
                return RSA.import_key(key_str)
            try:
                der_data = base64.b64decode(key_str)
                return RSA.import_key(der_data)
            except Exception:
                try:
                    hex_str = re.sub(r"\s+", "", key_str)
                    if len(hex_str) % 2 != 0:
                        hex_str = "0" + hex_str
                    der_data = bytes.fromhex(hex_str)
                    return RSA.import_key(der_data)
                except Exception:
                    return RSA.import_key(key_str)
        except Exception as e:
            raise RuntimeError(f"加载公钥失败: {e}")

    def rsa_encrypt_long(self, text: str, public_key_str: str) -> str:
        public_key = self.load_public_key(public_key_str)
        key_size = public_key.n.bit_length() // 8
        max_block_size = key_size - 11
        encrypted_blocks = []
        for i in range(0, len(text), max_block_size):
            block = text[i:i + max_block_size]
            cipher = PKCS1_v1_5.new(public_key)
            encrypted_blocks.append(cipher.encrypt(block.encode("utf-8")))
        return base64.b64encode(b"".join(encrypted_blocks)).decode("utf-8")

    def login(self, account, password, captcha, captcha_token):
        url = "https://cmsapi3.qiucheng-wangluo.com/cms-api/login"

        first_encrypted_password = self.rsa_encrypt_long(password, self.first_public_key)
        second_encrypted_password = self.rsa_encrypt_long(first_encrypted_password, captcha_token)
        encrypted_account = self.rsa_encrypt_long(account, captcha_token)

        data = {
            "account": encrypted_account,
            "data": second_encrypted_password,
            "safeCode": captcha,
            "token": captcha_token,
            "locale": "zh",
        }

        r = self.session.post(url, headers=self.headers, data=data, timeout=20)
        r.raise_for_status()
        return r.json()

    def login_and_get_token(self, account: str, password: str) -> str:
        for attempt in range(1, self.max_attempts + 1):
            try:
                log(f"INFO  登录尝试 {attempt}/{self.max_attempts}")

                captcha_token = self.get_captcha_token()
                log(f"INFO  captcha_token 获取成功: {captcha_token[:22]}...")

                img_b64 = self.get_captcha_img_b64(captcha_token)
                captcha_text = self.recognize_captcha(img_b64)
                if not captcha_text or len(captcha_text) != 4:
                    raise RuntimeError(f"OCR验证码异常: {captcha_text}")
                log(f"INFO  OCR验证码: {captcha_text}")

                login_result = self.login(account, password, captcha_text, captcha_token)
                if login_result.get("iErrCode") != 0:
                    raise RuntimeError(f"login失败: {login_result.get('sErrMsg', '未知错误')}")

                token = login_result.get("result")
                if not token:
                    raise RuntimeError("login成功但 result 为空（未返回 token）")

                log("SUCCESS 登录成功：获得 token（完整如下）")
                log(token)  # 完整 token 单独一行
                return token

            except Exception as e:
                log(f"ERROR 本次登录失败: {e}")
                if attempt < self.max_attempts:
                    time.sleep(2 ** attempt)

        raise RuntimeError("达到最大重试次数，登录失败")

login_client = CMSAutoLogin()

# =========================
# clubInfo：登录后必须先调用一次（对齐你提供的 fetch）
# 同时写入 CLUBCTX_CACHE（用于“上下文未建立→重登”）
# =========================
def fetch_club_info_with_token(token: str, club_id: int = CLUB_ID):
    headers = {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "token": token,
        "referer": CMS_REFERER,
        "user-agent": "Mozilla/5.0",
    }
    data = {"clubId": str(club_id)}

    log_sep("CLUB CONTEXT (clubInfo)")
    log("INFO  clubInfo 使用 token（完整如下）")
    log(token)
    log(f"INFO  clubInfo 请求: clubId={club_id}")

    r = requests.post(CLUBINFO_URL, headers=headers, data=data, timeout=15)
    log(f"INFO  clubInfo 响应: status={r.status_code}")
    log(f"INFO  clubInfo body: {r.text}")

    try:
        r.raise_for_status()
    except Exception as e:
        set_clubctx_fail(f"http_error: {e}", resp=r.text)
        raise

    try:
        j = r.json()
    except Exception:
        j = {"raw": r.text}

    if isinstance(j, dict) and j.get("iErrCode") == 0:
        set_clubctx_ok(j)
        log("SUCCESS clubInfo iErrCode=0 ✅ 上下文建立成功")
    else:
        set_clubctx_fail("clubInfo iErrCode != 0", resp=j)
        log(f"WARNING clubInfo 上下文未建立/失败: {j}")

    return j

# =========================
# APScheduler：每 90 分钟自动登录一次
# =========================
scheduler = BackgroundScheduler()
LOGIN_JOB_ID = "login_90min"

def refresh_token_once():
    """
    登录刷新：更新缓存最新 token + 立刻调用 clubInfo 建立上下文
    如果 clubInfo 未成功，则自动“重走一次登录流程”（只重试 1 次，避免死循环）
    """
    try:
        for round_i in (1, 2):
            log_blank()
            log_sep("LOGIN CYCLE" if round_i == 1 else "CONTEXT RETRY (RE-LOGIN)")

            log("INFO  开始执行登录刷新 token ...")
            token = login_client.login_and_get_token(CMS_ACCOUNT, CMS_PASSWORD)

            # 1) 缓存最新 token
            set_token(token)
            cached = get_token()

            log_sep("TOKEN CHECK")
            log("INFO  登录获取 token（完整如下）")
            log(token)
            log("INFO  缓存 token（完整如下）")
            log(cached)

            if cached != token:
                log("WARNING 缓存 token 与登录 token 不一致！后续将以缓存为准")
            else:
                log("SUCCESS 缓存 token 与登录 token 一致 ✅")

            # 2) 必须先调用 clubInfo（用最新 token）
            club_info = fetch_club_info_with_token(cached, CLUB_ID)

            # 3) 成功则结束
            if isinstance(club_info, dict) and club_info.get("iErrCode") == 0:
                return True, "ok"

            # 4) 失败：第一次失败则重登一次；第二次还失败则退出
            if round_i == 1:
                log("WARNING clubInfo 未成功，准备重走一次登录流程以建立上下文 ...")
                time.sleep(1.2)
                continue

            err = f"clubInfo 上下文建立失败（已重登1次仍失败），返回: {club_info}"
            set_login_fail(err)
            return False, err

    except Exception as e:
        set_login_fail(str(e))
        log_sep("LOGIN FAILED")
        log(f"ERROR token 刷新失败: {e}")
        return False, str(e)

def start_scheduler():
    # 启动即执行一次
    refresh_token_once()
    scheduler.add_job(refresh_token_once, "interval", minutes=90, id=LOGIN_JOB_ID, replace_existing=True)
    scheduler.start()
    log_sep("SCHEDULER")
    log("INFO  自动登录任务已启动：每 90 分钟刷新一次 token")

start_scheduler()

def get_next_login_epoch_ms():
    try:
        job = scheduler.get_job(LOGIN_JOB_ID)
        if not job or not job.next_run_time:
            return None
        return int(job.next_run_time.timestamp() * 1000)
    except Exception:
        return None

# =========================
# 前端 HTML（配色 + 秒级日期时间 + 自动登录倒计时+绝对时间 + 日志清空）
# toast 已居中显示，避免挡住右上角时间
# =========================
HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>HH@by测试组✅CMS 登录解封工具</title>
  <style>
    :root{
      --bg0:#070A12;
      --bg1:#0B1020;
      --card: rgba(255,255,255,.06);
      --border: rgba(255,255,255,.12);
      --text:#EAF0FF;
      --muted: rgba(234,240,255,.72);

      --good:#32FF9B;
      --bad:#FF4D6D;
      --warn:#FFB020;

      --shadow: 0 18px 60px rgba(0,0,0,.55);
      --shadow2: 0 10px 30px rgba(0,0,0,.35);
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace;
    }

    body{
      margin: 0;
      padding: 22px;
      color: var(--text);
      font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      background:
        radial-gradient(900px 500px at 20% 15%, rgba(108,168,255,.18), transparent 55%),
        radial-gradient(800px 520px at 85% 20%, rgba(50,255,155,.14), transparent 55%),
        radial-gradient(900px 600px at 40% 95%, rgba(255,77,109,.10), transparent 60%),
        linear-gradient(160deg, var(--bg0), var(--bg1));
      min-height: 100vh;
    }

    .topbar{
      max-width: 1100px;
      margin: 0 auto 14px auto;
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap: 12px;
    }

    .brand{
      display:flex;
      align-items:center;
      gap: 10px;
    }
    .dot{
      width: 14px;
      height: 14px;
      border-radius: 999px;
      background: radial-gradient(circle at 30% 30%, rgba(255,255,255,.9), rgba(50,255,155,.9) 55%, rgba(50,255,155,.2));
      box-shadow: 0 0 18px rgba(50,255,155,.35);
    }
    .title{
      font-size: 18px;
      font-weight: 900;
      letter-spacing: .2px;
    }
    .clock{
      font-family: var(--mono);
      font-size: 13px;
      padding: 8px 10px;
      border-radius: 12px;
      background: rgba(255,255,255,.06);
      border: 1px solid var(--border);
      box-shadow: var(--shadow2);
      color: rgba(234,240,255,.85);
      display:flex;
      align-items:center;
      gap: 10px;
      white-space: nowrap;
    }
    .chip{
      display:inline-flex;
      align-items:center;
      gap: 8px;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(255,255,255,.06);
      border: 1px solid rgba(255,255,255,.10);
      font-family: var(--mono);
      font-size: 12px;
      white-space: nowrap;
    }

    .card{
      max-width: 1100px;
      margin: 0 auto;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 16px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }

    .row{
      display:flex;
      align-items:center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }
    .label{ color: var(--muted); font-weight: 700; }

    input{
      padding: 10px 12px;
      width: 300px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(0,0,0,.22);
      color: var(--text);
      outline: none;
      box-shadow: inset 0 0 0 1px rgba(0,0,0,.18);
    }
    input:focus{
      border-color: rgba(108,168,255,.55);
      box-shadow: 0 0 0 5px rgba(108,168,255,.14);
    }

    button{
      padding: 10px 14px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.10);
      color: var(--text);
      cursor: pointer;
      font-weight: 800;
      letter-spacing: .2px;
      transition: transform .06s ease, background .15s ease, border-color .15s ease, box-shadow .15s ease;
    }
    button:hover{
      background: rgba(255,255,255,.14);
      border-color: rgba(255,255,255,.20);
      box-shadow: 0 10px 25px rgba(0,0,0,.25);
    }
    button:active{ transform: translateY(1px); }

    .btn-good{
      background: rgba(50,255,155,.12);
      border-color: rgba(50,255,155,.22);
    }
    .btn-good:hover{
      background: rgba(50,255,155,.18);
      border-color: rgba(50,255,155,.32);
      box-shadow: 0 0 0 6px rgba(50,255,155,.10), 0 12px 30px rgba(0,0,0,.35);
    }

    .btn-danger{
      background: rgba(255,77,109,.12);
      border-color: rgba(255,77,109,.22);
    }
    .btn-danger:hover{
      background: rgba(255,77,109,.18);
      border-color: rgba(255,77,109,.34);
      box-shadow: 0 0 0 6px rgba(255,77,109,.10), 0 12px 30px rgba(0,0,0,.35);
    }

    .status-pill{
      display:inline-flex;
      align-items:center;
      gap: 10px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,.06);
      border: 1px solid rgba(255,255,255,.12);
      font-family: var(--mono);
      font-size: 12px;
      white-space: nowrap;
    }
    .pill-dot{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: rgba(255,255,255,.25);
      box-shadow: 0 0 12px rgba(255,255,255,.16);
    }
    .pill-ok .pill-dot{
      background: rgba(50,255,155,.95);
      box-shadow: 0 0 18px rgba(50,255,155,.45);
    }
    .pill-bad .pill-dot{
      background: rgba(255,77,109,.95);
      box-shadow: 0 0 18px rgba(255,77,109,.45);
    }

    /* ===== Log viewer (colored lines) ===== */
    .log-wrap{
      width: 100%;
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,.10);
      background:
        radial-gradient(800px 400px at 15% 10%, rgba(108,168,255,.06), transparent 60%),
        radial-gradient(700px 380px at 85% 25%, rgba(50,255,155,.05), transparent 60%),
        rgba(0,0,0,.28);
      box-shadow: inset 0 0 0 1px rgba(0,0,0,.20);
      overflow: hidden;
    }

    .log-head{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap: 10px;
      padding: 10px 12px;
      border-bottom: 1px solid rgba(255,255,255,.08);
      background: rgba(255,255,255,.04);
    }

    .log-title{
      font-family: var(--mono);
      font-size: 12px;
      color: rgba(234,240,255,.80);
    }

    .log-box{
      height: 520px;
      overflow:auto;
      padding: 12px;
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.55;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .line{ color: rgba(234,240,255,.80); }
    .line.info{ color: rgba(234,240,255,.80); }
    .line.success{ color: rgba(50,255,155,.92); }
    .line.warn{ color: rgba(255,176,32,.92); }
    .line.error{ color: rgba(255,77,109,.92); }
    .line.sep{ color: rgba(234,240,255,.40); }

    /* ===== Toast（居中，避免挡住时钟） ===== */
    .toast-wrap{
      position: fixed;
      left: 50%;
      top: 30%;
      transform: translate(-50%, -50%);
      z-index: 9999;
      display: flex;
      flex-direction: column;
      gap: 10px;
      pointer-events: none;
      align-items: center;
    }

    .toast{
      pointer-events: auto;
      min-width: 320px;
      max-width: 560px;
      padding: 12px 14px;
      border-radius: 16px;
      color: #fff;
      background: rgba(15,15,18,.92);
      border: 1px solid rgba(255,255,255,.14);
      backdrop-filter: blur(12px);
      box-shadow: 0 22px 70px rgba(0,0,0,.55);
      transform: translateY(-8px);
      opacity: 0;
      transition: all .18s ease;
      position: relative;
      overflow: hidden;
    }
    .toast.show{ transform: translateY(0); opacity: 1; }

    .toast:before{
      content:"";
      position:absolute;
      inset: 0;
      background: radial-gradient(800px 300px at 10% 10%, rgba(108,168,255,.14), transparent 60%);
      pointer-events:none;
    }

    .toast.success{
      border-color: rgba(50,255,155,.40);
      box-shadow: 0 0 0 6px rgba(50,255,155,.10), 0 22px 70px rgba(0,0,0,.55);
    }
    .toast.success:after{
      content:"";
      position:absolute;
      left:-40%;
      top:-60%;
      width: 160%;
      height: 220%;
      background: radial-gradient(circle at 30% 30%, rgba(50,255,155,.30), transparent 55%);
      transform: rotate(10deg);
      pointer-events:none;
    }

    .toast.error{
      border-color: rgba(255,77,109,.42);
      box-shadow: 0 0 0 6px rgba(255,77,109,.10), 0 22px 70px rgba(0,0,0,.55);
    }
    .toast.error:after{
      content:"";
      position:absolute;
      left:-40%;
      top:-60%;
      width: 160%;
      height: 220%;
      background: radial-gradient(circle at 30% 30%, rgba(255,77,109,.28), transparent 55%);
      transform: rotate(10deg);
      pointer-events:none;
    }

    .toast .title{
      position: relative;
      font-weight: 950;
      margin-bottom: 8px;
      font-size: 14px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .toast .msg{
      position: relative;
      font-size: 13px;
      line-height: 1.35;
      opacity: .95;
      word-break: break-word;
    }

    .badge{
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 900;
      background: rgba(255,255,255,.10);
      border: 1px solid rgba(255,255,255,.14);
      margin-right: 6px;
      font-family: var(--mono);
    }

    .icon{
      width: 18px;
      height: 18px;
      display: inline-block;
      border-radius: 999px;
      background: rgba(255,255,255,.12);
      position: relative;
      flex: 0 0 auto;
    }
    .icon.success:before{
      content:"";
      position:absolute;
      left: 5px; top: 6px;
      width: 7px; height: 4px;
      border-left: 2px solid rgba(120,255,170,.95);
      border-bottom: 2px solid rgba(120,255,170,.95);
      transform: rotate(-45deg);
    }
    .icon.error:before,
    .icon.error:after{
      content:"";
      position:absolute;
      left: 5px; top: 5px;
      width: 8px; height: 2px;
      background: rgba(255,120,120,.95);
      border-radius: 2px;
    }
    .icon.error:before{ transform: rotate(45deg); }
    .icon.error:after{ transform: rotate(-45deg); }

    .toast .close{
      position:absolute;
      top: 8px;
      right: 10px;
      width: 26px;
      height: 26px;
      border-radius: 11px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.08);
      color: rgba(255,255,255,.9);
      cursor: pointer;
      display:flex;
      align-items:center;
      justify-content:center;
      line-height: 1;
      z-index: 1;
    }
  </style>
</head>
<body>

  <div class="topbar">
    <div class="brand">
      <div class="dot"></div>
      <div class="title">HH@by测试组✅CMS 登录解封工具</div>
      <div class="chip" id="nextRunChip">next autologin: --</div>
    </div>

    <div class="clock">
      <span>🕒</span>
      <span id="nowClock">--</span>
    </div>
  </div>

  <div class="card">
    <div class="row">
      <span class="label">登录状态：</span>
      <span id="st" class="status-pill"><span class="pill-dot"></span><span>loading...</span></span>
      <button class="btn-good" onclick="loginNow()">立即登录一次</button>
    </div>

    <div class="row">
      <span class="label">showid：</span>
      <input id="showid" placeholder="例如 10198130419"/>
      <button class="btn-good" onclick="unlock()">发送解封请求</button>
    </div>

    <div class="log-wrap">
      <div class="log-head">
        <div class="log-title">日志（最新在上）</div>
        <button class="btn-danger" onclick="clearLogs()">清空日志</button>
      </div>
      <div id="logBox" class="log-box"></div>
    </div>
  </div>

  <div id="toastWrap" class="toast-wrap"></div>

<script>
let nextLoginEpochMs = null;

function pad2(n){ return String(n).padStart(2,'0'); }

function fmtHMS(sec){
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${pad2(h)}:${pad2(m)}:${pad2(s)}`;
}

function fmtYMDHMS(ms){
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, m => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[m]));
}

function showToast({ type = 'success', title = '', msg = '', duration = 2600 }){
  const wrap = document.getElementById('toastWrap');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  const iconClass = type === 'success' ? 'success' : 'error';

  el.innerHTML = `
    <button class="close" aria-label="close">×</button>
    <div class="title">
      <span class="icon ${iconClass}"></span>
      <span>${escapeHtml(title)}</span>
    </div>
    <div class="msg">${msg}</div>
  `;

  wrap.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));

  const remove = () => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 180);
  };
  el.querySelector('.close').addEventListener('click', remove);
  setTimeout(remove, duration);
}

function classifyLine(line){
  const s = line || '';
  if (s.startsWith("──") || s.startsWith("【")) return "sep";
  if (s.includes("ERROR") || s.includes("失败") || s.includes("异常")) return "error";
  if (s.includes("WARNING") || s.includes("⚠️")) return "warn";
  if (s.includes("SUCCESS") || s.includes("成功") || s.includes("一致 ✅") || s.includes("iErrCode=0")) return "success";
  // iErrCode != 0 也会出现：作为 error 显示
  if (s.includes("iErrCode") && !s.includes("iErrCode=0")) return "error";
  return "info";
}

async function refreshStatus(){
  const r = await fetch('/api/status');
  const j = await r.json();

  nextLoginEpochMs = j.next_login_epoch_ms;

  const st = document.getElementById('st');
  const dot = `<span class="pill-dot"></span>`;
  if(j.last_login_ok){
    st.className = 'status-pill pill-ok';
    st.innerHTML = `${dot}<span>已登录 | 最近登录: ${escapeHtml(j.last_login_at || '-')} | 已缓存token: ${j.has_token ? '是' : '否'} | clubCtx: ${j.clubctx_ok ? 'OK' : 'NO'}</span>`;
  }else{
    st.className = 'status-pill pill-bad';
    st.innerHTML = `${dot}<span>未登录/失败 | ${escapeHtml(j.last_login_err || 'no token')} | clubCtx: ${j.clubctx_ok ? 'OK' : 'NO'}</span>`;
  }
}

async function refreshLogs(){
  const r = await fetch('/api/logs');
  const j = await r.json();
  const box = document.getElementById('logBox');
  const lines = j.lines || [];

  const html = lines.map(line => {
    const cls = classifyLine(line);
    return `<div class="line ${cls}">${escapeHtml(line)}</div>`;
  }).join('');
  box.innerHTML = html;
}

async function clearLogs(){
  await fetch('/api/logs/clear', {method:'POST'});
  await refreshLogs();
  showToast({ type:'success', title:'已清空日志', msg:'日志已清空。', duration: 1800 });
}

async function loginNow(){
  try{
    showToast({ type:'success', title:'登录中', msg:'正在执行立即登录...', duration: 1400 });
    const r = await fetch('/api/login_now', {method:'POST'});
    const j = await r.json();
    if(j.ok){
      showToast({
        type:'success',
        title:'登录成功',
        msg:`<span class="badge">time</span> ${escapeHtml(j.last_login_at || '-')}`,
        duration: 2200
      });
    }else{
      showToast({
        type:'error',
        title:'登录失败',
        msg: escapeHtml(j.msg || 'unknown error'),
        duration: 5200
      });
    }
    await refreshStatus();
    await refreshLogs();
  }catch(e){
    showToast({ type:'error', title:'请求异常', msg: escapeHtml(e?.message || String(e)), duration: 5200 });
  }
}

function normalizeResponseToObj(resp){
  if(resp && typeof resp === 'object') return resp;
  if(typeof resp === 'string'){
    try { return JSON.parse(resp); } catch (_) { return null; }
  }
  return null;
}

async function unlock(){
  const showid = document.getElementById('showid').value.trim();
  if(!showid){
    showToast({ type:'error', title:'参数错误', msg:'请输入 showid', duration: 2400 });
    return;
  }

  const form = new URLSearchParams();
  form.append('showid', showid);

  try{
    const r = await fetch('/unlock_club_manager', {
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'},
      body: form.toString()
    });

    const j = await r.json();
    const bodyObj = normalizeResponseToObj(j.response);
    const iErrCode = bodyObj?.iErrCode;

    // ✅ 成功判定：status=200 且 iErrCode=0
    const ok = (j.status_code === 200) && (iErrCode === 0);

    const respText = typeof j.response === 'string' ? j.response : JSON.stringify(j.response);
    const summaryRaw = (respText || '').slice(0, 240);
    const summary = escapeHtml(summaryRaw) + ((respText || '').length > 240 ? '…' : '');

    showToast({
      type: ok ? 'success' : 'error',
      title: ok ? '✅✅✅解封成功 ✅✅✅' : '❌❌❌解封失败 ❌❌❌',
      msg: `
        <div style="margin-bottom:50px;">
          <span class="badge">showid: ${escapeHtml(showid)}</span>
          <span class="badge">status: ${escapeHtml(j.status_code)}</span>
          <span class="badge">iErrCode: ${escapeHtml(iErrCode ?? 'N/A')}</span>
        </div>
        <div style="opacity:.95;">${summary || '无返回内容'}</div>
      `,
      duration: ok ? 2600 : 5600
    });

    await refreshStatus();
    await refreshLogs();
  }catch(e){
    showToast({ type:'error', title:'请求异常', msg: escapeHtml(e?.message || String(e)), duration: 5200 });
  }
}

function tickClockAndCountdown(){
  // 右上角：年月日 + 时分秒（秒级）
  const d = new Date();
  document.getElementById('nowClock').textContent =
    `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;

  // next autologin：绝对时间 + 倒计时
  const chip = document.getElementById('nextRunChip');
  if(!nextLoginEpochMs){
    chip.textContent = 'next autologin: --';
    return;
  }
  const nowMs = Date.now();
  const remainSec = Math.max(0, Math.floor((nextLoginEpochMs - nowMs) / 1000));
  chip.textContent = `next autologin: ${fmtYMDHMS(nextLoginEpochMs)} (in ${fmtHMS(remainSec)})`;
}

setInterval(tickClockAndCountdown, 1000);
setInterval(async ()=>{ await refreshStatus(); await refreshLogs(); }, 2500);
refreshStatus(); refreshLogs(); tickClockAndCountdown();
</script>
</body>
</html>
"""

# =========================
# Routes
# =========================
@app.get("/")
def home():
    return render_template_string(HTML)

@app.get("/api/status")
def api_status():
    st = get_status_snapshot()
    ctx = get_clubctx()
    next_ms = get_next_login_epoch_ms()
    return jsonify({
        "last_login_ok": st["last_login_ok"],
        "last_login_at": st["last_login_at"],
        "last_login_err": st["last_login_err"],
        "has_token": bool(st["token"]),
        "server_epoch_ms": int(time.time() * 1000),
        "next_login_epoch_ms": next_ms,
        "clubctx_ok": bool(ctx.get("ok")),
        "clubctx_last_at": ctx.get("last_at"),
        "clubctx_last_err": ctx.get("last_err"),
    })

@app.get("/api/logs")
def api_logs():
    with LOG_LOCK:
        return jsonify({"lines": list(LOG_BUF)})

@app.post("/api/logs/clear")
def api_logs_clear():
    clear_logs()
    log("INFO  日志已清空（用户操作）")
    return jsonify({"ok": True})

@app.post("/api/login_now")
def api_login_now():
    ok, msg = refresh_token_once()
    st = get_status_snapshot()
    return jsonify({
        "ok": ok,
        "msg": msg,
        "last_login_at": st["last_login_at"],
        "has_token": bool(st["token"]),
    })

# =========================
# 解封接口：结构保持固定（你要求的格式）
# 如果上下文未建立：自动重走登录流程（含 clubInfo）后再解封
# =========================
@app.route("/unlock_club_manager", methods=["POST"])
def unlock_club_manager():
    showid = request.form.get("showid")
    if not showid:
        return jsonify({"error": "showid required"}), 400

    token = get_token()
    if not token:
        return jsonify({"error": "no token cached, please login first"}), 503

    # ✅ 如果上下文未建立：先重走一次自动登录流程（含 clubInfo）
    ctx = get_clubctx()
    if not ctx.get("ok"):
        log_sep("CONTEXT MISSING -> AUTO RELOGIN")
        log(f"WARNING 检测到 club 上下文未建立（last_err={ctx.get('last_err')}），触发 refresh_token_once() ...")
        ok, msg = refresh_token_once()
        if not ok:
            return jsonify({"error": "club context not ready", "detail": msg}), 503
        # 重取最新 token
        token = get_token()
        if not token:
            return jsonify({"error": "no token cached after relogin"}), 503

    headers = {
        "accept": "application/json, text/javascript, */*; q=0.01",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "token": token,
        "referer": "https://cms.ayybyyy.com/"
    }

    data = {"showid": showid}

    log_sep("UNLOCK REQUEST")
    log(f"INFO  发送解封请求：showid={showid}")
    log("INFO  解封请求 token（完整如下）")
    log(token)

    r = requests.post(CMS_URL, headers=headers, data=data, timeout=5)
    log(f"INFO  解封响应：status={r.status_code}")
    log(f"INFO  解封 body: {r.text}")

    return jsonify({
        "status_code": r.status_code,
        "response": r.json() if "application/json" in r.headers.get("content-type", "") else r.text
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)
