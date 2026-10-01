"""
江苏开放大学自动刷课脚本 - 多账户版

功能：
- 多账户并发刷课
- 配置文件支持
- 日志文件保存
- 自动登录、心跳保活
"""

import json
import logging
import os
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypedDict

import requests
import urllib3

urllib3.disable_warnings()


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


class CourseStatus(TypedDict):
    requires: int
    total_time: int
    diff: int
    completed: bool


class Activity(TypedDict, total=False):
    activityId: str
    activityName: str
    type: str
    length: int
    totalTime: int
    resourceType: Optional[str]
    hasViewDocument: Optional[str]
    hasViewVideo: Optional[str]
    forumDiscusstionFlag: Optional[int]


@dataclass
class Account:
    username: str
    password: str
    enabled: bool = True


@dataclass
class Config:
    accounts: List[Account] = field(default_factory=list)
    rsa_mod: str = ""              # 留空则用内置的 DEFAULT_RSA_MOD
    rsa_exp: str = ""              # 留空则用内置的 DEFAULT_RSA_EXP
    token_chars: str = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    trackable_types: List[str] = field(default_factory=lambda: ["1", "2", "3"])
    request_timeout: int = 30
    heartbeat_interval: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    max_workers: int = 3
    log_dir: str = "logs"
    # 每次心跳之间的间隔（秒）。实测心跳不需要先访问 display 页，也不怕连发。
    heartbeat_gap: float = 0.25
    # 每 N 次心跳复查一次课程进度（旧版每次心跳都查，等于多一个请求）
    status_check_every: int = 20
    # UNTIMED 表示别的会话正占着计时 token，服务器会在 body 里回传那个 token。
    # True = 直接接管它继续计时；False = 按网页端行为停止该账号。
    heartbeat_takeover: bool = True
    # 每门课最多发多少次心跳（0 = 不限），调试/试跑用
    heartbeat_limit: int = 0

    @classmethod
    def from_file(cls, filepath: str = "config.json") -> "Config":
        config_path = Path(filepath)
        if not config_path.exists():
            default_config = cls()
            default_config.save_to_file(filepath)
            logging.info(f"已创建默认配置文件: {filepath}")
            return default_config
        
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        accounts = [
            Account(
                username=acc.get("username", ""),
                password=acc.get("password", ""),
                enabled=acc.get("enabled", True)
            )
            for acc in data.get("accounts", [])
        ]
        
        return cls(
            accounts=accounts,
            rsa_mod=data.get("rsa_mod", cls.rsa_mod),
            rsa_exp=data.get("rsa_exp", cls.rsa_exp),
            max_workers=data.get("max_workers", cls.max_workers),
            log_dir=data.get("log_dir", cls.log_dir),
        )

    def save_to_file(self, filepath: str = "config.json") -> None:
        data = {
            "accounts": [
                {"username": acc.username, "password": acc.password, "enabled": acc.enabled}
                for acc in self.accounts
            ],
            "rsa_mod": self.rsa_mod,
            "rsa_exp": self.rsa_exp,
            "max_workers": self.max_workers,
            "log_dir": self.log_dir,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


@dataclass
class Urls:
    index: str = "http://xuexi.jsou.cn/jxpt-web/index"
    login: str = "https://ids3.jsou.cn/login"
    auth_login: str = "http://xuexi.jsou.cn/jxpt-web/auth/idsLogin"
    courses: str = "http://xuexi.jsou.cn/jxpt-web/student/courseuser/getAllCurrentCourseByStudent"
    activities: str = "http://xuexi.jsou.cn/jxpt-web/student/course/getAllActivity/{}"
    display: str = "http://xuexi.jsou.cn/jxpt-web/student/activity/display?courseVersionId={}&activityId={}"
    heartbeat: str = "http://xuexi.jsou.cn/jxpt-web/common/learningBehavior/heartbeat"
    time_status: str = "http://xuexi.jsou.cn/jxpt-web/tutor/assessment/getStuDetail"


def setup_logger(name: str, log_dir: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(
        logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    )
    logger.addHandler(console_handler)

    # 日志目录不可写时只走控制台，不要让整个脚本挂掉
    try:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            os.path.join(log_dir, f"{name}_{datetime.now().strftime('%Y%m%d')}.log"),
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        )
        logger.addHandler(file_handler)
    except OSError as e:
        logger.warning(f"日志目录不可写，只输出到控制台: {e}")

    return logger


def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """网络异常重试。重试次数 / 间隔优先取 self.config 里的值。"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            cfg = getattr(self, "config", None)
            tries = getattr(cfg, "max_retries", None) or max_retries
            base_delay = getattr(cfg, "retry_delay", None) or delay
            last_exception = None
            for attempt in range(tries):
                try:
                    return func(self, *args, **kwargs)
                except requests.RequestException as e:
                    last_exception = e
                    if attempt < tries - 1:
                        time.sleep(base_delay * (attempt + 1))
            raise last_exception if last_exception else Exception("Unknown error")
        return wrapper
    return decorator


class Log:
    def __init__(self, logger: logging.Logger, prefix: str = ""):
        self.logger = logger
        self.prefix = prefix

    def _msg(self, msg: str) -> str:
        return f"{self.prefix} {msg}" if self.prefix else msg

    def info(self, msg: str) -> None: self.logger.info(self._msg(msg))
    def success(self, msg: str) -> None: self.logger.info(f"✓ {self._msg(msg)}")
    def warning(self, msg: str) -> None: self.logger.warning(f"! {self._msg(msg)}")
    def error(self, msg: str) -> None: self.logger.error(f"✗ {self._msg(msg)}")
    def skip(self, msg: str) -> None: self.logger.debug(f"[SKIP] {self._msg(msg)}")
    def video(self, msg: str) -> None: self.logger.info(f"  {self._msg(msg)}")
    def course(self, msg: str) -> None: self.logger.info(f"\n{self._msg(msg)}")
    def task(self, msg: str) -> None: self.logger.info(f"    {self._msg(msg)}")
    def progress(self, msg: str) -> None: self.logger.debug(f"      {self._msg(msg)}")


class JsouBot:
    def __init__(self, account: Account, config: Config):
        self.account = account
        self.config = config
        self.urls = Urls()
        self.session = self._create_session()
        self.rsa_mod = config.rsa_mod or DEFAULT_RSA_MOD
        self.rsa_exp = config.rsa_exp or DEFAULT_RSA_EXP
        self.account_invalid = False
        self.current_course = ""
        self.current_unit = ""
        self.user_id: Optional[str] = None
        self.heartbeat_token = self._generate_token()
        self.heartbeat_claimed = False
        self.heartbeats_sent = 0
        
        self.logger = setup_logger(
            f"user_{account.username[-4:]}",
            config.log_dir
        )
        self.log = Log(self.logger, f"[{account.username[-4:]}]")

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = False
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "X-Requested-With": "XMLHttpRequest",
        })
        return session

    def _log_prefix(self) -> str:
        return f"[{self.current_course}]"


    def _generate_token(self) -> str:
        return ''.join(random.choices(self.config.token_chars, k=8))

    def _get_headers(self, cv_id: str, act_id: str) -> Dict[str, str]:
        return {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "http://xuexi.jsou.cn",
            "Referer": self.urls.display.format(cv_id, act_id)
        }

    @retry_on_failure(max_retries=3, delay=1.0)
    def _safe_get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault('timeout', self.config.request_timeout)
        return self.session.get(url, **kwargs)

    @retry_on_failure(max_retries=3, delay=1.0)
    def _safe_post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault('timeout', self.config.request_timeout)
        return self.session.post(url, **kwargs)

    def login(self) -> bool:
        try:
            self._safe_get(self.urls.index)
            
            res = self._safe_get(self.urls.login, params={"service": self.urls.index})
            
            exec_match = re.search(r'name="execution" value="([^"]+)"', res.text)
            if not exec_match:
                self.log.error("未找到 execution 参数")
                return False
            
            enc_password = rsa_encrypt(self.account.password, self.rsa_mod, self.rsa_exp)
            
            data = {
                "username": self.account.username,
                "password": enc_password,
                "submit": "登录",
                "execution": exec_match.group(1),
                "encrypted": "true",
                "_eventId": "submit",
                "loginType": "1"
            }
            
            res = self._safe_post(self.urls.login, data=data, allow_redirects=False)
            
            if res.status_code != 302:
                self.log.error("登录失败")
                return False
            
            location = res.headers.get('Location', '')
            self._safe_get(location)
            self._safe_get(self.urls.auth_login)
            
            res = self._safe_get(self.urls.index)
            match = re.search(r'id="stuId"\s+value="([a-f0-9]{32})"', res.text)
            if match:
                self.user_id = match.group(1)
            
            self.log.success("登录成功")
            return True

        except requests.RequestException as e:
            self.log.error(f"登录网络异常: {e}")
            return False
        except Exception as e:
            self.log.error(f"登录异常: {e}")
            return False

    def check_course_time_status(self, cv_id: str) -> Optional[CourseStatus]:
        try:
            res = self._safe_post(
                self.urls.time_status,
                data={
                    "stuId": self.user_id,
                    "courseVersionId": cv_id
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "http://xuexi.jsou.cn",
                    "Referer": f"http://xuexi.jsou.cn/jxpt-web/student/assessment/toStuDetailPage?courseVersionId={cv_id}&userId={self.user_id}&tag=1"
                }
            )
            
            if not res.text:
                return None
            
            data = res.json()
            
            if data.get("code") != "SUCCESS":
                return None
            
            body = data.get("body") or {}
            items = body.get("formativeExamDtos") or []
            
            for item in items:
                if not isinstance(item, dict):
                    continue
                    
                if item.get("typeName") == "内容学习":
                    requires_str = item.get("requires", "0") or "0"
                    total_time_str = item.get("totalTime", "0") or "0"
                    
                    requires = int(re.search(r'\d+', str(requires_str)).group() or 0)
                    total_time = int(re.search(r'\d+', str(total_time_str)).group() or 0)
                    
                    return CourseStatus(
                        requires=requires,
                        total_time=total_time,
                        diff=requires - total_time,
                        completed=total_time >= requires
                    )
            
            # 找不到「内容学习」考核项时返回 None（状态未知），
            # 由调用方决定是否仍然走一遍活动级判定 —— 旧版这里返回 completed=True，
            # 会把一批课直接漏掉，什么都不刷。
            self.log.debug(f"课程 {cv_id[:8]}: 考核项里没有「内容学习」")
            return None

        except (json.JSONDecodeError, ValueError):
            return None
        except requests.RequestException:
            return None
        except Exception:
            return None

    def _get_all_activities(self, cv_id: str) -> List[Activity]:
        all_activities: List[Activity] = []
        try:
            res = self._safe_get(
                self.urls.activities.format(cv_id),
                headers={
                    "Referer": f"http://xuexi.jsou.cn/jxpt-web/student/courseuser/courseContent?courseVersionId={cv_id}"
                }
            )
            
            if not res.text:
                return all_activities
            
            data = res.json()
            
            if data.get("code") not in ["SUCCESS", "LIST_VALUE"]:
                return all_activities
            
            for unit in data.get("body") or []:
                activities = unit.get("activitys") or []
                all_activities.extend(activities)

        except requests.RequestException as e:
            self.log.error(f"获取活动列表网络异常: {e}")
        except Exception as e:
            self.log.error(f"获取活动列表异常: {e}")
        
        return all_activities

    def _is_activity_completed(self, act: Activity) -> bool:
        act_type = str(act.get("type", ""))
        
        completion_rules = {
            "2": lambda a: (a.get("length") or 0) - (a.get("totalTime") or 0) <= 0,
            "3": lambda a: a.get("hasViewDocument") == "1" or a.get("hasViewVideo") == "1",
            "1": lambda a: a.get("hasViewVideo") == "1",
            "6": lambda a: a.get("forumDiscusstionFlag") == 1,
        }
        
        return completion_rules.get(act_type, lambda _: False)(act)

    def _build_heartbeat_data(
        self, 
        act: Activity, 
        cv_id: str, 
        time_point: Optional[float] = None
    ) -> Dict[str, Any]:
        act_type = str(act.get('type', ''))
        act_id = act.get('activityId')
        
        base_data = {
            "isResourcePage": "true",
            "courseVersionId": cv_id,
            "activityId": act_id,
            "type": act_type,
            "isStuLearningRecord": "2",
            "token": self.heartbeat_token
        }
        
        if act_type == "2":
            base_data["playStatus"] = "true"
            base_data["timePoint"] = round(time_point or 0, 2)
        else:
            base_data["playStatus"] = "false"
        
        return base_data

    def _send_heartbeat(
        self, 
        act: Activity, 
        cv_id: str, 
        time_point: Optional[float] = None
    ) -> str:
        """
        发一次心跳，返回归一化结果：
            SUCCESS - 已计时
            UNTIMED - 计时被别的会话占着（body 里是它占用的 token）
            OFFLINE / KICKOUT / ACCOUNT_INVALID / LOGIN_REQUIRED - 账号问题
            FAIL / RETRY - 本次没成，可以再试

        实测（2026-10 线上）：
          * token 匹配服务器当前会话 -> HTTP 200，body 可能是 {"code":"SUCCESS"} 也可能是空
          * token 不匹配             -> {"code":"UNTIMED","body":"<当前占用的 token>"}
          * UNTIMED 时把 body 里那个 token 换过来，下一次立刻恢复计时
          * 心跳之前**不需要**先 GET display 页
        """
        act_id = act.get("activityId")
        headers = self._get_headers(cv_id, act_id)

        for attempt in range(2):
            # 每门课的心跳总预算（活动轮 + 随机轮共用），--limit 试跑用
            if self.config.heartbeat_limit and self.heartbeats_sent >= self.config.heartbeat_limit:
                return "LIMIT"
            self.heartbeats_sent += 1

            data = self._build_heartbeat_data(act, cv_id, time_point)
            try:
                resp = self._safe_post(self.urls.heartbeat, data=data, headers=headers)
            except requests.RequestException:
                return "RETRY"

            try:
                payload = resp.json()
            except (json.JSONDecodeError, ValueError):
                # 非 JSON：HTTP 200 空 body 就是「token 匹配、已计时」
                if resp.status_code == 200 and self.heartbeat_claimed:
                    return "SUCCESS"
                return "RETRY"

            code = str(payload.get("code") or "")

            if code == "SUCCESS":
                self.heartbeat_claimed = True
                return "SUCCESS"

            if code == "UNTIMED":
                active = str(payload.get("body") or "").strip()
                if (
                    attempt == 0
                    and self.config.heartbeat_takeover
                    and active
                    and active != self.heartbeat_token
                ):
                    self.log.warning(f"计时被其它会话占用，接管 token -> {active}")
                    self.heartbeat_token = active
                    self.heartbeat_claimed = True
                    continue  # 用接管到的 token 立刻重试
                return "UNTIMED"

            if code in ("OFFLINE", "KICKOUT", "ACCOUNT_INVALID", "LOGIN_REQUIRED"):
                return code

            if code == "FAIL":
                return "FAIL"

            return "RETRY"

        return "UNTIMED"

    def _process_activity_heartbeats(self, act: Activity, cv_id: str) -> None:
        act_type = str(act.get('type', ''))
        act_name = act.get('activityName', '未知任务')
        prefix = self._log_prefix()
        
        if act_type == "2":
            length = act.get("length") or 0
            total_time = act.get("totalTime") or 0
            remaining_time = max(0, length - total_time)
            total_heartbeats = (remaining_time // 30) + 1 if remaining_time > 0 else 0
            
            self.log.video(f"{prefix} 总长:{length}s 已看:{total_time}s 剩余:{remaining_time}s → {total_heartbeats}次")
            
            if total_heartbeats == 0:
                self.log.success(f"{prefix} {act_name} 已完成")
                return
        else:
            total_heartbeats = random.randint(3, 5)
        success_count = 0
        base_time = act.get("totalTime") or 0
        # 连续失败上限，避免旧版那种「重试中...」无限刷日志
        consecutive_fail = 0
        max_consecutive_fail = 5

        while success_count < total_heartbeats:
            if self.account_invalid:
                return

            if act_type == "2":
                time_point = min(
                    base_time + success_count * 30 + random.uniform(0.01, 0.99),
                    act.get("length") or 0
                )
                resp_code = self._send_heartbeat(act, cv_id, time_point)
            else:
                resp_code = self._send_heartbeat(act, cv_id)

            if resp_code == "SUCCESS":
                success_count += 1
                consecutive_fail = 0
                if success_count % 20 == 0 or success_count == total_heartbeats:
                    # 提到 INFO：否则长时间跑起来看着像卡死
                    self.log.info(f"{prefix} {success_count}/{total_heartbeats} 次心跳")
            elif resp_code == "LIMIT":
                self.log.info(f"{prefix} 达到 --limit {self.config.heartbeat_limit} 次，停止")
                return
            elif resp_code == "OFFLINE":
                self.log.warning(f"{prefix} OFFLINE，跳过")
                return
            elif resp_code in ("ACCOUNT_INVALID", "LOGIN_REQUIRED", "KICKOUT"):
                self.log.error(f"{prefix} 账号失效/被踢出 ({resp_code})")
                self.account_invalid = True
                return
            elif resp_code == "UNTIMED":
                self.log.warning(f"{prefix} 计时被别的会话占用且接管失败，跳过该活动")
                return
            elif resp_code == "FAIL":
                self.log.error(f"{prefix} 心跳失败")
                return
            else:
                consecutive_fail += 1
                self.log.progress(f"{prefix} 重试中... ({consecutive_fail}/{max_consecutive_fail})")
                if consecutive_fail >= max_consecutive_fail:
                    self.log.warning(f"{prefix} 连续 {max_consecutive_fail} 次无效响应，放弃该活动")
                    return
                time.sleep(self.config.retry_delay)

            if self.config.heartbeat_gap:
                time.sleep(self.config.heartbeat_gap * random.uniform(0.6, 1.4))

        self.log.success(f"{prefix} {act_name} 完成")

    def _process_activity(self, act: Activity, cv_id: str) -> None:
        try:
            act_type = str(act.get("type", ""))
            act_name = act.get("activityName", "未知任务")
            act_id = act.get('activityId')
            
            if act_type not in self.config.trackable_types:
                return
            
            if not act.get("resourceType"):
                return
            
            if self._is_activity_completed(act):
                self.log.skip(f"{self._log_prefix()} {act_name}")
                return
            
            self.log.task(f"{self._log_prefix()} {act_name}")
            
            try:
                self._safe_get(self.urls.display.format(cv_id, act_id))
            except requests.RequestException as e:
                self.log.error(f"访问活动页面失败: {e}")
                return
            
            self._process_activity_heartbeats(act, cv_id)
            
        except Exception as e:
            self.log.error(f"处理活动异常: {e}")

    def _process_course_item(self, course: Dict, status_info: CourseStatus) -> None:
        try:
            name = course.get('courseName') or course.get('name', '未知')
            self.current_course = name
            cv_id = course.get('courseVersionId')
            self.heartbeats_sent = 0   # 每门课重置心跳预算
            
            self.log.course(f"开始运行: {name} (需要刷 {status_info['diff']} 分钟)")
            
            try:
                self._safe_get(
                    f"http://xuexi.jsou.cn/jxpt-web/student/courseuser/courseContent?courseVersionId={cv_id}"
                )
            except requests.RequestException as e:
                self.log.error(f"访问课程页面失败: {e}")
                return
            
            all_activities = self._get_all_activities(cv_id)
            
            if not all_activities:
                self.log.warning(f"[{name}] 未发现活动")
                return
            
            incomplete_activities = [
                act for act in all_activities 
                if not self._is_activity_completed(act)
            ]
            
            # 活动轮的心跳量预估，避免跑起来看不到头
            est = sum(
                (((a.get("length") or 0) - (a.get("totalTime") or 0)) // 30 + 1)
                if str(a.get("type")) == "2" else 4
                for a in incomplete_activities
            )
            self.log.info(
                f"  [{name}] 共 {len(all_activities)} 个活动, 未完成 {len(incomplete_activities)} 个，"
                f"活动轮预计 {max(0, est)} 次心跳（每次 30s）"
            )
            
            for idx, act in enumerate(incomplete_activities):
                if self.account_invalid:
                    break
                # 预算用尽就别再逐个活动访问 display 页了（否则白跑几百个请求）
                if self.config.heartbeat_limit and self.heartbeats_sent >= self.config.heartbeat_limit:
                    self.log.info(
                        f"  [{name}] 心跳预算用尽，跳过剩余 {len(incomplete_activities) - idx} 个活动"
                    )
                    break
                self._process_activity(act, cv_id)
            
            current_status = self.check_course_time_status(cv_id)
            if current_status and current_status["completed"]:
                self.log.success(f"[{name}] 课时已完成!")
                return
            
            remaining_diff = current_status["diff"] if current_status else status_info["diff"]
            self.log.info(f"  [{name}] 正常刷课后仍差 {remaining_diff} 分钟, 开始随机刷课...")
            
            video_activities = [
                act for act in all_activities 
                if str(act.get("type", "")) == "2" and act.get("resourceType")
            ]
            
            if not video_activities:
                video_activities = [act for act in all_activities if act.get("resourceType")]
            
            if not video_activities:
                self.log.warning(f"[{name}] 没有可刷的活动")
                return
            
            heartbeat_count = 0
            target = remaining_diff * 2
            last_total = current_status["total_time"] if current_status else None
            stall = 0

            if target <= 0:
                self.log.info(f"  [{name}] 状态未知/无缺口，跳过随机刷课")
                return

            self.log.info(f"  [{name}] 目标 {target} 次心跳（每次 30s，不再每次查状态）")

            while heartbeat_count < target:
                if self.account_invalid:
                    break

                selected_act = random.choice(video_activities)
                act_type = str(selected_act.get("type", ""))

                if act_type == "2":
                    length = selected_act.get("length") or 300
                    code = self._send_heartbeat(selected_act, cv_id, random.uniform(0, length))
                else:
                    code = self._send_heartbeat(selected_act, cv_id)

                if code == "SUCCESS":
                    heartbeat_count += 1
                    if heartbeat_count % 20 == 0:
                        self.log.info(f"  [{name}] 已发 {heartbeat_count}/{target} 次心跳")
                elif code == "LIMIT":
                    self.log.info(f"  [{name}] 达到 --limit {self.config.heartbeat_limit} 次，停止该课程")
                    break
                elif code in ("ACCOUNT_INVALID", "LOGIN_REQUIRED", "KICKOUT"):
                    self.log.error(f"  [{name}] 账号失效/被踢出 ({code})")
                    self.account_invalid = True
                    break
                elif code == "OFFLINE":
                    self.log.warning(f"  [{name}] OFFLINE，稍后重试")
                    time.sleep(self.config.retry_delay)
                elif code == "UNTIMED":
                    self.log.warning(f"  [{name}] 计时被其它会话占用且接管失败，等待重试")
                    time.sleep(self.config.retry_delay)
                else:
                    time.sleep(self.config.retry_delay)

                # 进度复查：每 status_check_every 次查一次，并检测卡死
                if heartbeat_count and heartbeat_count % self.config.status_check_every == 0:
                    current_status = self.check_course_time_status(cv_id)
                    if current_status:
                        if current_status["completed"]:
                            self.log.success(f"[{name}] 课时已完成!（共 {heartbeat_count} 次心跳）")
                            return
                        if last_total is not None and current_status["total_time"] <= last_total:
                            stall += 1
                            self.log.warning(
                                f"  [{name}] 复查进度未变（{current_status['total_time']} 分钟），第 {stall} 次"
                            )
                            if stall >= 3:
                                self.log.error(f"  [{name}] 连续 3 次复查进度都不动，放弃该课程")
                                return
                        else:
                            stall = 0
                        last_total = current_status["total_time"]
                        target = heartbeat_count + max(0, current_status["diff"]) * 2

                if self.config.heartbeat_gap:
                    time.sleep(self.config.heartbeat_gap * random.uniform(0.6, 1.4))
            
            if self.account_invalid:
                self.log.error("账号失效，停止刷课")
                
        except Exception as e:
            self.log.error(f"处理课程项异常: {e}")

    def dump_course_status(self) -> None:
        """--check：只列课程学时状态，不发心跳。"""
        res = self._safe_post(
            self.urls.courses,
            headers={
                "Origin": "http://xuexi.jsou.cn",
                "Referer": "http://xuexi.jsou.cn/jxpt-web/student/courseuser/myCourse",
            },
        )
        data = res.json()
        if data.get("code") not in ("SUCCESS", "LIST_VALUE"):
            self.log.error(f"获取课程失败: {data.get('code')}")
            return
        courses = data.get("body") or []
        self.log.info("")
        self.log.info(f"{'课程':<24}{'已学':>6}{'需学':>6}{'缺口':>6}")
        self.log.info("-" * 46)
        todo = 0
        for c in courses:
            name = c.get("courseName", "未知")
            st = self.check_course_time_status(c.get("courseVersionId", ""))
            if st is None:
                self.log.info(f"{name:<24}{'-':>6}{'-':>6}{'?':>6}  状态未知")
                continue
            gap = st["diff"]
            if st["completed"]:
                self.log.info(f"{name:<24}{st['total_time']:>6}{st['requires']:>6}{0:>6}  已完成")
                continue
            todo += 1
            self.log.info(f"{name:<24}{st['total_time']:>6}{st['requires']:>6}{gap:>6}  ←需要刷")
        self.log.info("-" * 46)
        self.log.info(f"{len(courses)} 门课程，{todo} 门需要刷")

    def start_study(self) -> None:
        self.log.info("开始刷课...")
        
        try:
            self.log.info("获取课程列表...")
            res = self._safe_post(
                self.urls.courses,
                headers={
                    "Origin": "http://xuexi.jsou.cn",
                    "Referer": "http://xuexi.jsou.cn/jxpt-web/student/courseuser/myCourse"
                }
            )
            
            if not res.text:
                self.log.error("响应为空")
                return
            
            data = res.json()
            
            if data.get("code") not in ["SUCCESS", "LIST_VALUE"]:
                self.log.error(f"获取课程失败: {data.get('code')}")
                return
            
            courses = data.get("body") or []
            if not courses:
                self.log.info("未发现课程")
                return
            
            self.log.info(f"发现 {len(courses)} 门课程")
            self.log.info("")
            self.log.info("课程名称             开始日期      结束日期      周期    状态")
            self.log.info("-" * 60)
            
            courses_to_study: List[Dict] = []
            
            for c in courses:
                name = c.get('courseName', '未知')
                cv_id = c.get('courseVersionId', '')
                start = c.get('startDate', '')
                end = c.get('endDate', '')
                cycle = c.get('learningCycle', '')
                
                status_info = self.check_course_time_status(cv_id)

                if status_info is None:
                    # 状态取不到时不跳过（旧版就是在这里把课漏掉的）：
                    # 放进队列走一遍活动级完成判定，之后复查时会自己收敛
                    status = "状态未知→排队复查"
                    courses_to_study.append({
                        "course": c,
                        "status": CourseStatus(requires=0, total_time=0, diff=0, completed=False),
                    })
                elif status_info["completed"]:
                    status = "已完成"
                else:
                    status = f"差{status_info['diff']}分钟"
                    courses_to_study.append({
                        "course": c,
                        "status": status_info
                    })
                
                self.log.info(f"{name:<20} {start:<12} {end:<12} {cycle}周    {status}")
            
            if not courses_to_study:
                self.log.success("所有课程课时均已完成!")
                return
            
            self.log.info("")
            self.log.info(f"需要刷课: {len(courses_to_study)} 门课程")
            
            for item in courses_to_study:
                if self.account_invalid:
                    break
                self._process_course_item(item["course"], item["status"])
                
        except requests.RequestException as e:
            self.log.error(f"获取课程列表网络异常: {e}")
        except json.JSONDecodeError as e:
            self.log.error(f"JSON解析失败: {e}")
        except Exception as e:
            self.log.error(f"刷课异常: {e}")

    def run(self) -> bool:
        if not self.login():
            return False
        self.start_study()
        self.log.info("刷课完成")
        return True


class MultiAccountRunner:
    def __init__(self, config: Config, dry_run: bool = False, only: Optional[str] = None):
        self.config = config
        self.dry_run = dry_run
        self.only = only
        self.main_logger = setup_logger("main", config.log_dir)
        self.log = Log(self.main_logger)

    def run_single_account(self, account: Account) -> Dict[str, Any]:
        result = {
            "username": account.username,
            "success": False,
            "message": ""
        }
        
        try:
            bot = JsouBot(account, self.config)
            if not bot.login():
                result["message"] = "登录失败"
                return result
            if self.dry_run:
                bot.dump_course_status()
                result["success"] = True
                result["message"] = "已列出"
                return result
            bot.start_study()
            result["success"] = not bot.account_invalid
            result["message"] = "完成" if result["success"] else "账号失效中断"
        except Exception as e:
            result["message"] = f"异常: {e}"
        
        return result

    def run_all(self) -> None:
        enabled_accounts = [acc for acc in self.config.accounts if acc.enabled]
        if self.only:
            enabled_accounts = [a for a in enabled_accounts if a.username == self.only]
        
        if not enabled_accounts:
            self.log.error("没有启用的账户（或 --only 没匹配到）")
            return
        
        self.log.info(
            f"web 版刷课开始，共 {len(enabled_accounts)} 个账户"
            + ("（--check 只看不刷）" if self.dry_run else "")
        )
        self.log.info("=" * 50)
        
        results: List[Dict[str, Any]] = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_account = {
                executor.submit(self.run_single_account, acc): acc
                for acc in enabled_accounts
            }
            
            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        "username": account.username,
                        "success": False,
                        "message": f"异常: {e}"
                    })
        
        self.log.info("")
        self.log.info("=" * 50)
        self.log.info("刷课结果汇总:")
        self.log.info("-" * 50)
        
        for r in results:
            status = "✓" if r["success"] else "✗"
            self.log.info(f"{status} {r['username'][-4:]}: {r['message']}")
        
        success_count = sum(1 for r in results if r["success"])
        self.log.info(f"\n完成: {success_count}/{len(results)}")


def main() -> int:
    import argparse

    # 以脚本所在目录为工作目录；config.json / logs 都相对这里
    os.chdir(Path(__file__).resolve().parent)

    parser = argparse.ArgumentParser(description="江苏开放大学 web 版刷课")
    parser.add_argument("--check", action="store_true", help="只看课程学时状态，不发心跳")
    parser.add_argument("--only", metavar="USERNAME", help="只处理指定账号")
    parser.add_argument("--limit", type=int, default=0, help="每门课最多发 N 次心跳（试跑用，0=不限）")
    parser.add_argument("--config", default="config.json", help="配置文件路径")
    args = parser.parse_args()

    config = Config.from_file(args.config)
    if args.limit:
        config.heartbeat_limit = args.limit

    if not config.accounts:
        config.accounts = [
            Account(username="你的学号", password="你的密码", enabled=True)
        ]
        config.save_to_file(args.config)
        print("已创建默认配置文件 config.json，请填写账号密码后重新运行")
        return 1

    MultiAccountRunner(config, dry_run=args.check, only=args.only).run_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
