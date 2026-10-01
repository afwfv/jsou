"""
江苏开放大学自动刷课脚本 - app 版（app.jsou.cn /jxpt-app）

与 web 版的区别：走 App 接口，不依赖 xuexi.jsou.cn 的 jxpt-web 页面。

接口契约（从 app_jsou_cn 打包 JS chunk-84993380 / chunk-07aef142 逆向 + 线上实测确认）：

    POST /jxpt-app/service/read
        student_id, course_version_id, resource_id=<activityId>, resource_type=<资源type>
        -> 标记已阅读。type=1（章节点）会返回 50001「资源类型不存在」

    POST /jxpt-app/service/heartbeat
        student_id, course_version_id, activity_id, type=<资源type>,
        token="", time_point=<秒>, is_stu_learning_record=2
        -> 计入学习时长

    实测结论：
      * 每次成功 heartbeat = +30 秒学习时长（8 次 = +4 分钟，反复验证一致）
      * type 必须与资源真实 type 一致：视频(2)->2、文档(3)->3。
        给视频发 type=3、给文档发 type=2 都返回 200 但【不计时长】
      * is_stu_learning_record 必须是 2；填 1 返回 200 但【不计时长】
      * 章节点(type=1) 无论怎么发都不计时长
      * 时长指标看 get_courses_by_student 的 has_learning_time / full_score_time
        （course_description 的 online_min 恒为 0，不能用）

用法:
    cd jsou
    python jsou_login_app.py --check          # 只看课程缺口，不发心跳
    python jsou_login_app.py                  # 刷 config.json 里所有启用账号
    python jsou_login_app.py --only 你的学号
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings()

# 每次 heartbeat 计入学时的秒数（线上实测）
SECONDS_PER_HEARTBEAT = 30

# 只有这些资源 type 能计学时；1=章节点, 4=作业, 6=讨论区 都不能
TRACKABLE_TYPES = ("2", "3", "7")

# App 端 JS 对 type=7 的播放页用了 6 而不是 7；type 不匹配时作为兜底重试
FALLBACK_HEARTBEAT_TYPE = {"7": "6"}

APP_BASE = "http://app.jsou.cn"


# --------------------------------------------------------------------------- 登录密码加密
# 复刻站点 security.js 里 RSAUtils.encryptedString 的纯 Python 实现，已逐字节对拍。
# 有了它就不需要 Node.js，也不需要 execjs。

DEFAULT_RSA_MOD = (
    "008aed7e057fe8f14c73550b0e6467b023616ddc8fa91846d2613cdb7f7621e3"
    "cada4cd5d812d627af6b87727ade4e26d26208b7326815941492b2204c3167ab"
    "2d53df1e3a2c9153bdb7c8c2e968df97a5e7e01cc410f92c4c2c2fba529b3e"
    "e988ebc1fca99ff5119e036d732c368acf8beba01aa2fdafa45b21e4de4928d0d403"
)
DEFAULT_RSA_EXP = "010001"


def rsa_encrypt(password: str,
                modulus_hex: str = DEFAULT_RSA_MOD,
                exponent_hex: str = DEFAULT_RSA_EXP) -> str:
    """
    对应 security.js 的 RSAUtils.encryptedString：
      * 明文按 UTF-16 码元取字节，尾部补 0 到 chunkSize 整数倍
      * chunkSize = 2 * biHighIndex(modulus)
      * 每块按小端序拼成整数做 modpow，输出定长小写 hex
      * 块之间用单空格连接
    """
    modulus = int(modulus_hex, 16)
    exponent = int(exponent_hex, 16)

    high_index = (modulus.bit_length() - 1) // 16 if modulus > 0 else 0
    chunk_size = 2 * high_index
    if chunk_size <= 0:
        raise ValueError("modulus 太小，无法计算 chunkSize")

    data = [ord(ch) & 0xFFFF for ch in password]
    remainder = len(data) % chunk_size
    if remainder:
        data.extend([0] * (chunk_size - remainder))

    blocks = []
    for offset in range(0, len(data), chunk_size):
        value = 0
        for i, byte in enumerate(data[offset:offset + chunk_size]):
            value |= (byte & 0xFF) << (8 * i)          # 低字节
            value |= ((byte >> 8) & 0xFF) << (8 * i + 16)  # 高字节进位
        crypt = pow(value, exponent, modulus)
        digits = max(1, (crypt.bit_length() + 15) // 16)
        blocks.append(f"{crypt:0{4 * digits}x}")

    return " ".join(blocks)


def _to_int(value: Any, default: int = 0) -> int:
    """has_learning_time 之类字段可能是 ' ' 或 None。"""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- 配置


@dataclass
class Account:
    username: str
    password: str
    enabled: bool = True


@dataclass
class Config:
    accounts: List[Account] = field(default_factory=list)
    rsa_mod: str = ""
    rsa_exp: str = "010001"
    request_timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    max_workers: int = 3
    log_dir: str = "logs"
    heartbeat_gap: float = 0.35          # 每次心跳之间的间隔（秒）
    progress_check_every: int = 20       # 每 N 次心跳复查一次课程进度
    heartbeat_limit: int = 0             # 每门课最多发多少次心跳（0 = 不限），试跑用

    @classmethod
    def from_file(cls, filepath: str = "config.json") -> "Config":
        path = Path(filepath)
        if not path.exists():
            default = cls()
            default.save_to_file(filepath)
            logging.info("已创建默认配置文件: %s", filepath)
            return default

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 兼容两种写法：{"accounts":[...]} 或 单个 {"username":..,"password":..}
        raw_accounts = data.get("accounts")
        if not raw_accounts and data.get("username"):
            raw_accounts = [{"username": data["username"], "password": data.get("password", "")}]

        accounts = [
            Account(
                username=acc.get("username", ""),
                password=acc.get("password", ""),
                enabled=acc.get("enabled", True),
            )
            for acc in (raw_accounts or [])
        ]

        return cls(
            accounts=accounts,
            rsa_mod=data.get("rsa_mod", ""),
            rsa_exp=data.get("rsa_exp", cls.rsa_exp),
            max_workers=_to_int(data.get("max_workers"), cls.max_workers) or cls.max_workers,
            log_dir=data.get("log_dir", cls.log_dir),
        )

    def save_to_file(self, filepath: str = "config.json") -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "accounts": [
                        {"username": a.username, "password": a.password, "enabled": a.enabled}
                        for a in self.accounts
                    ],
                    "max_workers": self.max_workers,
                    "log_dir": self.log_dir,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )


# --------------------------------------------------------------------------- 日志


def setup_logger(name: str, log_dir: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        logger.handlers.clear()

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(console)

    # 日志目录不可写时只走控制台，不要让整个脚本挂掉
    try:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            os.path.join(log_dir, f"{name}_{datetime.now().strftime('%Y%m%d')}.log"), encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning(f"日志目录不可写，只输出到控制台: {exc}")

    return logger


def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except requests.RequestException as exc:
                    last = exc
                    if attempt < max_retries - 1:
                        time.sleep(delay * (attempt + 1))
            raise last if last else RuntimeError("unknown error")

        return wrapper

    return decorator


class Log:
    def __init__(self, logger: logging.Logger, prefix: str = ""):
        self.logger = logger
        self.prefix = prefix

    def _m(self, msg: str) -> str:
        return f"{self.prefix} {msg}" if self.prefix else msg

    def info(self, msg: str) -> None:
        self.logger.info(self._m(msg))

    def success(self, msg: str) -> None:
        self.logger.info(f"✓ {self._m(msg)}")

    def warning(self, msg: str) -> None:
        self.logger.warning(f"! {self._m(msg)}")

    def error(self, msg: str) -> None:
        self.logger.error(f"✗ {self._m(msg)}")

    def debug(self, msg: str) -> None:
        self.logger.debug(self._m(msg))


# --------------------------------------------------------------------------- 机器人


class JsouAppBot:
    """App 版：CAS 拿 ticket -> App 登录 -> 按课程缺口刷心跳。"""

    def __init__(self, account: Account, config: Config):
        self.account = account
        self.config = config
        self.session = self._create_session()
        self.rsa_mod = config.rsa_mod or DEFAULT_RSA_MOD
        self.rsa_exp = config.rsa_exp or DEFAULT_RSA_EXP
        self.account_invalid = False
        self.user_id: Optional[str] = None
        self.current_course = ""
        self.heartbeat_token = self._generate_token()

        self.logger = setup_logger(f"app_{account.username[-4:]}", config.log_dir)
        self.log = Log(self.logger, f"[{account.username[-4:]}]")

    # ---- 基础设施

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = False
        session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Mobile Safari/537.36"
                ),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            }
        )
        return session

    def _generate_token(self) -> str:
        chars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
        return "".join(random.choices(chars, k=8))

    @retry_on_failure(max_retries=3, delay=1.0)
    def _safe_get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.config.request_timeout)
        return self.session.get(url, **kwargs)

    @retry_on_failure(max_retries=3, delay=1.0)
    def _safe_post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.config.request_timeout)
        return self.session.post(url, **kwargs)

    def _api_headers(self, referer: str = "/study/course_detail") -> Dict[str, str]:
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json, text/plain, */*",
            "Origin": APP_BASE,
            "Referer": APP_BASE + referer,
            "X-Requested-With": "XMLHttpRequest",
        }

    def _json(self, resp: requests.Response) -> Dict[str, Any]:
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            return {"code": None, "message": f"非JSON响应: {resp.text[:120]}"}
        if isinstance(data, dict) and data.get("code") == 50000:
            self.log.error("检测到登录失效 (code=50000)")
            self.account_invalid = True
        return data if isinstance(data, dict) else {"code": None, "body": data}

    # ---- 登录

    def login(self) -> bool:
        login_url = "https://ids3.jsou.cn/login"
        cas_login = APP_BASE + "/web/auth/casLogin"

        try:
            self._safe_get(APP_BASE + "/")
            self._safe_get(APP_BASE + "/my")
            self._safe_get(cas_login)

            res = self._safe_get(login_url, params={"service": cas_login}, headers={"Referer": APP_BASE + "/"})
            match = re.search(r'name="execution" value="([^"]+)"', res.text)
            if not match:
                self.log.error("未找到 execution 参数（登录页结构可能变了）")
                return False

            enc_password = rsa_encrypt(self.account.password, self.rsa_mod, self.rsa_exp)
            res = self._safe_post(
                login_url,
                data={
                    "username": self.account.username,
                    "password": enc_password,
                    "submit": "登录",
                    "execution": match.group(1),
                    "encrypted": "true",
                    "_eventId": "submit",
                    "loginType": "1",
                },
                allow_redirects=False,
            )
            if res.status_code != 302:
                self.log.error("登录失败：账号或密码错误")
                return False

            location = res.headers.get("Location", "")
            if not location:
                self.log.error("未获取到重定向地址")
                return False

            ticket_match = re.search(r"ticket=([^&]+)", location)
            if not ticket_match:
                self.log.error("重定向地址里没有 ticket")
                return False
            ticket = ticket_match.group(1)

            cas_res = self._safe_get(location)
            new_match = re.search(r"ticket=([^&]+)", cas_res.url)
            new_ticket = new_match.group(1) if new_match else ticket

            res = self._safe_post(
                APP_BASE + "/jxpt-app/service/login",
                data={"login_type": 2, "ticket": new_ticket},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": APP_BASE + "/",
                    "Accept": "application/json, text/plain, */*",
                    "Origin": APP_BASE,
                },
            )
            data = self._json(res)
            if data.get("code") != 200:
                self.log.error(f"App 登录失败: {data.get('code')} - {data.get('message')}")
                return False

            body = data.get("body") or {}
            self.user_id = body.get("user_id", "")
            if body.get("token"):
                self.session.headers.update({"Token": body["token"]})
            self._safe_get(APP_BASE + "/home")
            self.log.success(f"登录成功，学生ID: {self.user_id}")
            return True

        except requests.RequestException as exc:
            self.log.error(f"登录网络异常: {exc}")
            return False
        except Exception as exc:  # noqa: BLE001
            self.log.error(f"登录异常: {exc}")
            return False

    # ---- 数据

    def get_courses(self) -> List[Dict[str, Any]]:
        res = self._safe_get(
            f"{APP_BASE}/jxpt-app/service/get_courses_by_student?student_id={self.user_id}",
            headers=self._api_headers("/study"),
        )
        data = self._json(res)
        if data.get("code") != 200:
            self.log.error(f"获取课程失败: {data.get('code')} - {data.get('message', '')}")
            return []
        return (data.get("body") or {}).get("courses") or []

    def get_directory(self, course_version_id: str, course_id: str) -> List[Dict[str, Any]]:
        res = self._safe_get(
            f"{APP_BASE}/jxpt-app/service/get_directory_by_course_student"
            f"?user_id={self.user_id}&course_version_id={course_version_id}&course_id={course_id}",
            headers=self._api_headers(),
        )
        data = self._json(res)
        if data.get("code") != 200:
            self.log.warning(f"目录接口异常: {data.get('code')} - {data.get('message', '')}")
            return []
        resources: List[Dict[str, Any]] = []
        for unit in (data.get("body") or {}).get("all_resources") or []:
            resources.extend(unit.get("chapter_resources") or [])
        return resources

    @staticmethod
    def course_gap(course: Dict[str, Any]) -> tuple:
        """返回 (已学分钟, 需学分钟, 缺口分钟)。"""
        have = _to_int(course.get("has_learning_time"))
        need = _to_int(course.get("full_score_time"))
        return have, need, max(0, need - have)

    # ---- 学习行为

    def mark_read(self, resource: Dict[str, Any], course_version_id: str) -> bool:
        """对应 App 进播放页时的一次 /read。"""
        rtype = str(resource.get("type", ""))
        data = self._json(
            self._safe_post(
                f"{APP_BASE}/jxpt-app/service/read",
                data={
                    "student_id": self.user_id,
                    "resource_id": resource.get("activityId"),
                    "resource_type": rtype,
                    "course_version_id": course_version_id,
                },
                headers=self._api_headers(),
            )
        )
        return data.get("code") == 200

    def send_heartbeat(self, resource: Dict[str, Any], course_version_id: str, time_point: float) -> Optional[int]:
        """发一次心跳。返回服务器 code，失败返回 None。"""
        rtype = str(resource.get("type", ""))

        for attempt_type in (rtype, FALLBACK_HEARTBEAT_TYPE.get(rtype)):
            if attempt_type is None:
                continue
            data = self._json(
                self._safe_post(
                    f"{APP_BASE}/jxpt-app/service/heartbeat",
                    data={
                        "student_id": self.user_id,
                        "course_version_id": course_version_id,
                        "activity_id": resource.get("activityId"),
                        "type": attempt_type,
                        "token": "",
                        "time_point": round(time_point, 2),
                        "is_stu_learning_record": 2,
                    },
                    headers=self._api_headers(),
                )
            )
            code = data.get("code")
            if code == 200:
                return code
            self.log.debug(f"心跳 type={attempt_type} 返回 {code} - {data.get('message')}")
        return None

    def study_course(self, course: Dict[str, Any]) -> Dict[str, Any]:
        name = course.get("name", "未知课程")
        cv_id = course.get("course_version_id", "")
        course_id = course.get("course_id", "")
        self.current_course = name

        have, need, gap = self.course_gap(course)
        if need <= 0:
            return {"course": name, "status": "无需学时要求", "added": 0}
        if gap <= 0:
            return {"course": name, "status": f"已完成 {have}/{need}", "added": 0}

        self.log.info(f"\n【{name}】{have}/{need} 分钟，缺 {gap} 分钟")

        resources = self.get_directory(cv_id, course_id)
        usable = [r for r in resources if str(r.get("type", "")) in TRACKABLE_TYPES and r.get("activityId")]
        if not usable:
            self.log.warning(f"  没有可计时资源（章节点/作业/讨论区都不计时），跳过")
            return {"course": name, "status": "无可计时资源", "added": 0}

        videos = [r for r in usable if str(r.get("type")) == "2"]
        docs = [r for r in usable if str(r.get("type")) != "2"]
        pool = videos or usable
        self.log.info(f"  可计时资源 {len(usable)} 个（视频 {len(videos)} / 文档 {len(docs)}）")

        target = gap * 60 // SECONDS_PER_HEARTBEAT
        done = 0
        self.log.info(f"  需要 ~{target} 次心跳（每次 {SECONDS_PER_HEARTBEAT}s）")

        current = None
        read_done = set()

        while done < target and not self.account_invalid:
            if current is None:
                current = random.choice(pool)
                if current["activityId"] not in read_done:
                    self.mark_read(current, cv_id)
                    read_done.add(current["activityId"])
                elapsed = _to_int(current.get("duration")) or 300
                self.log.info(f"    → {str(current.get('activity_name'))[:40]} ({elapsed}s)")

            duration = _to_int(current.get("duration")) or 300
            # time_point 模拟播放器进度：在 30s 的整数倍上循环推进，不超过总时长
            step = 30.0 * ((done % max(1, duration // SECONDS_PER_HEARTBEAT)) + 1)
            time_point = min(step, float(duration))

            if self.send_heartbeat(current, cv_id, time_point) == 200:
                done += 1
                if done % 20 == 0:
                    self.log.info(f"      已完成 {done}/{target} 次心跳")
                if self.config.heartbeat_limit and done >= self.config.heartbeat_limit:
                    self.log.info(f"      达到 --limit {self.config.heartbeat_limit} 次，停止该课程")
                    break
            else:
                self.log.warning(f"    心跳被拒，换下一个资源")
                current = None
                if self.account_invalid:
                    break
                continue

            # 周期性复查真实进度
            if done % self.config.progress_check_every == 0:
                fresh = next((c for c in self.get_courses() if c.get("course_version_id") == cv_id), None)
                if fresh:
                    have2, need2, gap2 = self.course_gap(fresh)
                    self.log.info(f"      线上进度 {have2}/{need2}（缺 {gap2} 分钟）")
                    if gap2 <= 0:
                        self.log.success(f"  【{name}】已达标")
                        return {"course": name, "status": "已完成", "added": have2 - have}
                    target = done + gap2 * 60 // SECONDS_PER_HEARTBEAT

            time.sleep(self.config.heartbeat_gap * random.uniform(0.6, 1.4))

        final = next((c for c in self.get_courses() if c.get("course_version_id") == cv_id), None)
        if final:
            have2, need2, gap2 = self.course_gap(final)
            ok = gap2 <= 0
            if ok:
                self.log.success(f"  【{name}】完成 {have2}/{need2}")
            else:
                self.log.warning(f"  【{name}】仍缺 {gap2} 分钟（{have2}/{need2}）")
            return {"course": name, "status": "已完成" if ok else f"仍缺 {gap2} 分钟", "added": have2 - have}

        return {"course": name, "status": f"已发 {done} 次心跳", "added": done * SECONDS_PER_HEARTBEAT // 60}

    # ---- 主流程

    def check_only(self) -> List[tuple]:
        courses = self.get_courses()
        rows = []
        for c in courses:
            have, need, gap = self.course_gap(c)
            rows.append((c.get("name", ""), have, need, gap))
        return rows

    def run(self, dry_run: bool = False) -> Dict[str, Any]:
        if not self.login():
            return {"username": self.account.username, "success": False, "detail": []}

        courses = self.get_courses()
        if not courses:
            self.log.warning("没有课程")
            return {"username": self.account.username, "success": True, "detail": []}

        if dry_run:
            self.log.info("")
            self.log.info(f"{'课程':<26}{'已学':>6}{'需学':>6}{'缺口':>6}")
            self.log.info("-" * 46)
            todo = 0
            for name, have, need, gap in self.check_only():
                flag = " ←需要刷" if gap > 0 else ""
                if gap > 0:
                    todo += 1
                self.log.info(f"{name:<26}{have:>6}{need:>6}{gap:>6}{flag}")
            self.log.info("-" * 46)
            self.log.info(f"{len(courses)} 门课程，{todo} 门需要刷")
            return {"username": self.account.username, "success": True, "detail": []}

        todo = [c for c in courses if self.course_gap(c)[2] > 0]
        if not todo:
            self.log.success("所有课程学时都已达标")
            return {"username": self.account.username, "success": True, "detail": []}

        self.log.info(f"需要刷课 {len(todo)} 门")
        detail = []
        for c in todo:
            if self.account_invalid:
                self.log.error("账号失效，中止")
                break
            try:
                detail.append(self.study_course(c))
            except Exception as exc:  # noqa: BLE001
                self.log.error(f"处理课程异常: {exc}")
                detail.append({"course": c.get("name", ""), "status": f"异常: {exc}", "added": 0})

        return {"username": self.account.username, "success": not self.account_invalid, "detail": detail}


# --------------------------------------------------------------------------- 多账号


class MultiAccountRunner:
    def __init__(self, config: Config, dry_run: bool = False, only: Optional[str] = None):
        self.config = config
        self.dry_run = dry_run
        self.only = only
        self.logger = setup_logger("main", config.log_dir)
        self.log = Log(self.logger)

    def run_single(self, account: Account) -> Dict[str, Any]:
        try:
            bot = JsouAppBot(account, self.config)
            return bot.run(dry_run=self.dry_run)
        except Exception as exc:  # noqa: BLE001
            return {"username": account.username, "success": False, "detail": [], "error": f"异常: {exc}"}

    def run_all(self) -> None:
        accounts = [a for a in self.config.accounts if a.enabled]
        if self.only:
            accounts = [a for a in accounts if a.username == self.only]
        if not accounts:
            self.log.error("没有启用的账户（或 --only 没匹配到）")
            return

        self.log.info(f"app 版刷课开始，共 {len(accounts)} 个账户" + ("（--check 只看不刷）" if self.dry_run else ""))
        self.log.info("=" * 52)

        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
            futures = {pool.submit(self.run_single, acc): acc for acc in accounts}
            for fut in as_completed(futures):
                results.append(fut.result())

        self.log.info("")
        self.log.info("=" * 52)
        self.log.info("结果汇总:")
        for r in results:
            tag = "✓" if r.get("success") else "✗"
            self.log.info(f"{tag} {r['username'][-4:]}" + (f"  {r['error']}" if r.get("error") else ""))
            for d in r.get("detail") or []:
                self.log.info(f"    {d['course']}: {d['status']}")

        self.log.info(f"\n成功: {sum(1 for r in results if r.get('success'))}/{len(results)}")


def main() -> int:
    os.chdir(Path(__file__).resolve().parent)

    parser = argparse.ArgumentParser(description="江苏开放大学 app 版刷课")
    parser.add_argument("--check", action="store_true", help="只看课程学时缺口，不发心跳")
    parser.add_argument("--only", metavar="USERNAME", help="只处理指定账号")
    parser.add_argument("--limit", type=int, default=0, help="每门课最多发 N 次心跳（试跑用，0=不限）")
    parser.add_argument("--config", default="config.json", help="配置文件路径")
    args = parser.parse_args()

    config = Config.from_file(args.config)
    if args.limit:
        config.heartbeat_limit = args.limit
    if not config.accounts:
        print("config.json 里没有账号")
        return 1

    MultiAccountRunner(config, dry_run=args.check, only=args.only).run_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
