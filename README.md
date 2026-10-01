# jsou

江苏开放大学刷课脚本。自动登录 → 扫描每门课的学时缺口 → 把差的时长发满。

## 效果

一次心跳计 30 秒学时，实测每计满 1 分钟约 **0.6 秒**、2 个请求。
一门要求 400 分钟的课约 4 分钟刷完；8 门课共 2300 分钟缺口约 25 分钟跑完。
已完成的课自动跳过，学时刷超不扣分。

```text
[INFO] [1234] 发现 8 门课程
[INFO] [1234] 课程名称              周期    状态
[INFO] [1234] 国家公务员制度         17周    差137分钟
[INFO] [1234] 西方行政学说           17周    差400分钟
[INFO] [1234] 需要刷课: 2 门课程

[1234] 开始运行: 国家公务员制度 (需要刷 137 分钟)
[INFO]   [国家公务员制度] 未完成 119 个活动，预计 274 次心跳（每次 30s）
[INFO]   [国家公务员制度] 20/20 次心跳
[INFO]   [国家公务员制度] 课时已完成!
[INFO] ✓ 1234: 完成
```

## 使用

需要 Python 3.8+ 和 `requests`、`urllib3`。

```bash
git clone https://github.com/afwfv/jsou.git && cd jsou
pip install requests urllib3
cp config.example.json config.json     # 填学号密码

python jsou_login.py --check           # 先看一眼谁缺、缺多少
python jsou_login.py                   # 网页端刷课
python jsou_login_app.py               # App 端刷课
```

| 参数 | 说明 |
|---|---|
| `--check` | 只列课程和学时缺口，不发心跳 |
| `--only 学号` | 只处理指定账号 |
| `--limit N` | 每门课最多发 N 次心跳，试跑用 |
| `--config 路径` | 指定配置文件（默认 `config.json`） |

```json
{
  "accounts": [{ "username": "学号", "password": "密码", "enabled": true }],
  "max_workers": 3
}
```

两条通道功能一样，一边跑不动就换另一边。网页端会逐个数课程活动，App 端直接按学时缺口发心跳，更快更省请求。

## 注意

- **长任务丢后台跑**。一门 400 分钟的课要发约 800 次心跳，"半天没输出"是正常的，进度每 20 次心跳打一行。
- 提示"多处登录"不影响：服务器同一时间只认一个计时标识，脚本会自动接管上次运行留下的会话。
- 学期没开、没有资源的课会打一行"未发现活动"然后跳过，不会卡住。
- `config.json` 里密码是明文，已在 `.gitignore` 里，别把这个文件发给别人。
- 两个脚本都是单文件，内置纯 Python RSA 加密，不需要 Node.js / execjs，也不依赖站点任何文件。
