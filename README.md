# 区域地震台网 — 可靠告警投递系统

把已确认的地震告警可靠送入应急广播网关：**不丢失、不篡改、不重复接纳**。
纯 Python 标准库实现，Docker Compose 一键启动 API、接收模拟器和一次性
`verify` 校验服务。

## 架构

```
POST /api/alerts ──► 告警 API (app/)                   [容器 api]
                      │  SQLite 持久化 (data/api.db)
                      │  alertKey 幂等 + 冲突检测
                      │  投递 worker 线程
                      │   每次重试: 同一请求体 + 同一 deliveryId + 同一 HMAC 签名
                      ▼
                 应急广播网关模拟器 (receiver/)         [容器 receiver]
                      SQLite 持久化 (data/receiver.db)
                      HMAC 校验 + deliveryId 去重（只业务接纳一次）
```

### 如何保证可靠

| 风险 | 机制 |
|---|---|
| 调用方重复提交（网络闪断后重发） | `alertKey` 为幂等键：同键同内容回放**原** `alertId`/`deliveryId`（HTTP 200，`replayed:true`）；同键异内容返回 **409 冲突** |
| 重试之间请求被改 | 投递请求体在首次受理时就固化为规范字节串；签名 `HMAC-SHA256(secret, "seismic-alert-v1" + deliveryId + SHA256(body))` 覆盖 deliveryId 与请求体，每次尝试完全相同 |
| 超时 / 断连 / 5xx | 网络错误、超时、连接中断和 HTTP 5xx 重试，**首次 + 最多 3 次重试 = 4 次尝试**，指数退避 |
| 4xx | **立即失败**，不消耗重试预算 |
| 网关已接纳、应答才断 | 网关按 `deliveryId` 持久化接纳记录；重发同一 deliveryId 只回放原接纳回执（`duplicate:true`，HTTP 200），不会二次业务接纳 |
| API 在投递中重启 | 全部状态在 SQLite；重启后 worker 回收 stale 的 `delivering` 认领（默认 5s），用**同一个 deliveryId/请求体/签名**继续并收敛 |
| 同 deliveryId 携带篡改请求体 | 网关对已见 deliveryId 比对 body 摘要，不一致返回 409；签名不过则 401 |

## 快速开始

```bash
# 可选：自定义宿主机端口 / 共享密钥
export API_HOST_PORT=18080
export SHARED_SECRET='your-production-secret'

# 构建并启动 api + receiver（均带健康检查），然后跑一次性 verify 任务
docker compose up --build
```

- API 宿主机端口由 `API_HOST_PORT` 控制（默认 `8080`）。
- `api` 与 `receiver` 配置了 Docker 健康检查；`api` 等 `receiver` 健康后才启动。
- **`verify` 是一次性服务**：顺序执行 ① 构建检查（compileall）② 全部代码测试
  （23 项，含重启恢复）③ 对正在运行的容器做真实 HTTP 投递冒烟（7 个场景），
  **退出码汇总结果：全部通过为 0，否则为 1**。

只跑校验任务：

```bash
docker compose run --rm verify
```

## 值班员查询

```bash
curl -s http://localhost:8080/api/alerts/<alertId> | python3 -m json.tool
```

成功时明确写出唯一接纳：

```json
{
  "status": "delivered",
  "attempts": 3,
  "unique": true,
  "conclusion": "DELIVERED: the emergency broadcast gateway business-accepted
   this alert exactly once under deliveryId ... after 3 attempt(s) ..."
}
```

失败时明确写出失败类别：

- `"FAILED TERMINALLY after N attempt(s): ... non-retryable 4xx response"` —
  不可重试响应导致的最终失败；
- `"... all delivery attempts (timeouts, connection drops or gateway 5xx)
  have been exhausted"` — 重试耗尽（1 + 3 = 4 次）。

投递过程中可观测到 `pending` → `delivering`（含 `attempts`、`lastResult`、
`lastStatusCode`、`lastError`）→ `delivered`/`failed`。

## 故障注入（测试/演练用）

模拟器提供带令牌保护（`X-Sim-Token`）的控制端点：

```bash
# 接下来 2 次请求返回 503（随后恢复，验证同体同签名重试）
curl -s -X POST http://localhost:9090/sim/control \
  -H "X-Sim-Token: ${SIM_FAULT_TOKEN:-compose-sim-token}" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"http","code":503,"count":2}'

# 先持久化接纳、再掐断 TCP（验证"已接纳后断连"只回放不重复接纳）
curl ... -d '{"mode":"drop","count":1}'

# 延迟应答超过客户端超时（验证超时重试）
curl ... -d '{"mode":"delay","delay":4,"count":1}'

# 清除
curl ... -d '{"mode":null}'
```

另有 `GET /sim/accepted`（接纳清单）和
`GET /sim/requests?deliveryId=...`（每次请求的 body 摘要/签名/状态，用于证明
重试请求逐字节一致）。

## 本地开发（无需 Docker）

```bash
python3 -m unittest discover -s tests -p 'test_*.py'   # 全部 23 项测试

# 手动起两个进程
RECEIVER_PORT=9090 python3 -m receiver.simulator
API_PORT=8080 RECEIVER_URL=http://127.0.0.1:9090/ingest python3 -m app.main

# 或直接跑 verify（前两部分不依赖外部服务，第三部分需要起服务）
API_URL=http://127.0.0.1:8080 RECEIVER_URL=http://127.0.0.1:9090 python3 scripts/verify.py
```

## 关键环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `API_HOST_PORT` | `8080` | **宿主机**映射端口（compose） |
| `API_PORT` / `API_HOST` | `8080` / `0.0.0.0` | 容器内监听 |
| `RECEIVER_URL` | `http://127.0.0.1:9090/ingest` | 网关地址 |
| `SHARED_SECRET` | 开发默认值 | HMAC 共享密钥，两端必须一致 |
| `DELIVERY_TIMEOUT` | `2` | 每次尝试超时（秒） |
| `DELIVERY_MAX_RETRIES` | `3` | 首次之后的重试次数（共 4 次尝试） |
| `DELIVERY_BACKOFF_BASE` | `0.5` | 第 n 次退避 = base×n |
| `DELIVERY_STALE_AFTER` | `timeout+15` | 崩溃遗留认领的回收时间（秒） |
| `SIM_FAULT_TOKEN` | 开发默认值 | 故障注入控制令牌 |

## 代码结构

```
app/
  config.py     环境配置
  models.py     请求体验证 / 冲突错误
  signing.py    HMAC-SHA256 签名（与模拟器共用）
  database.py   SQLite 幂等受理 + 投递状态机
  worker.py     投递 worker（重试、退避、认领回收）
  server.py     HTTP API
  main.py       入口（API + worker，SIGTERM 优雅退出）
receiver/
  simulator.py  广播网关模拟器（验签、去重、故障注入）
tests/          单元 + 进程内集成（含重启恢复）+ 共享冒烟场景
scripts/
  verify.py     一次性校验任务（构建/测试/冒烟，退出码汇总）
Dockerfile      三角色共用镜像（python:3.11-slim，零第三方依赖）
docker-compose.yml
```
