# Cicada

> **让 AI 管理我的 AI，让我退出管理循环。**  
> Cicada 是一个面向个人与小团队的 Autonomous Personal AI Manager。它接收我的意图，理解我的长期上下文，调度我的设备、服务器和 AI harness，创建并管理长期运行的 monitor / worker，也允许我正在使用的任意 AI session 随时加入 Cicada Fabric、成为可寻址的 Endpoint 并与其他 AI 协作；它只在真正需要我判断时打扰我。

---

## 1. 我为什么需要 Cicada

我不希望 AI 让我变得更忙。

今天使用多个 AI 工具时，我经常需要自己完成这些事情：

- 想到一个点子后，手动打开 AI 让它调研；
- 在多个聊天窗口、Codex thread、Claude Code session 之间复制粘贴信息；
- 自己判断哪个服务器空闲、哪个设备适合当前任务；
- SSH 到不同机器，创建目录、拉仓库、启动 tmux、启动 agent；
- 定期回来检查 agent 有没有卡住、有没有跑偏；
- agent 出错后重新解释目标、补充上下文、让它继续；
- 同时盯着多个长期任务；
- 从邮件、Telegram、微信、QQ、X 等平台接收大量信息，再决定什么值得处理；
- 为了“让 AI 自动化”，反而花更多时间管理 AI。

Cicada 的目标正好相反。

**我只负责提出意图、设定边界和做真正需要人类判断的决定；剩下的研究、规划、资源选择、任务分解、执行、监督、纠偏、恢复、汇总和跨 Agent 协作由 Cicada 负责。**

我希望最终能够：

> 说完一句话，关掉手机，继续做自己的事情。

---

# 2. 第一人称：我如何使用 Cicada

这一节不是“功能列表”，而是 Cicada 应该真正给我的使用体验。

---

## 2.1 我想到一个点子

我拿起手机，对 Cicada 说：

> “我刚看到一个新的比赛，帮我看看值不值得参加。”

我不需要先决定：

- 用哪个模型；
- 用哪个浏览器；
- 是否创建一个新项目；
- 在哪台服务器运行；
- 应该搜索哪些网站；
- 需要打开几个 agent。

Cicada 的 Control 接收这个想法，把它建立为一个 **Idea**，然后自动：

1. 理解我在说什么；
2. 搜索比赛官网、规则、截止时间、赛题、往届情况；
3. 调取我的历史上下文，例如以前参加过什么比赛、有什么经验、有什么硬件；
4. 判断它与我当前目标和时间安排是否匹配；
5. 形成一份简洁结论。

然后它告诉我：

> “这个比赛与你已有的算子优化经验高度相关，报名还剩 21 天，预计需要一台 910B。你当前有两台可用 NPU 服务器。我认为值得参加。要开始吗？”

如果我说：

> “开始。”

它才进入执行阶段。

如果我说：

> “先算了。”

Cicada 不会把这个想法扔掉，而是把它标记为 **Parked Idea**，记录为什么现在不做，以及什么条件发生变化后值得重新评估。

例如：

> “当前主要问题：时间不足。若截止时间延期，或当前论文任务完成，则重新评估。”

之后条件发生变化时，Cicada 可以主动告诉我：

> “之前搁置的比赛延期两周，现在重新具备可行性。是否恢复？”

---

## 2.2 我只说目标，不指定机器

我说：

> “帮我把这个 CUDA benchmark 跑起来，看看还有没有明显优化空间。”

我不需要说：

> “ssh gpu2，然后进入 `/data/foo`，开一个 tmux，再开 Codex。”

Cicada 自己查看机器：

```text
gpu1
- H100
- 当前 GPU 利用率 91%
- 有一个高优先级 worker

gpu2
- RTX 4090
- 空闲
- 环境满足要求

npu1
- Ascend 910B
- 与任务不匹配
```

它决定使用 `gpu2`，然后：

1. 创建或恢复 workspace；
2. 拉取 / 更新代码；
3. 建立 worker；
4. 为 worker 创建真正的 Codex thread；
5. 注入目标、上下文和约束；
6. 开始工作；
7. 将 worker 与负责监督它的 monitor 绑定。

我不需要知道这一切的具体执行细节。

---

## 2.3 我不盯着 worker

worker 开始做 benchmark 后，我不会一直看终端。

例如它运行到一半遇到：

```text
CUDA extension compilation failed
```

worker 尝试修复，但连续两次失败。

Cicada 的 monitor 发现：

- worker 没有取得进展；
- 最近几个 turn 都围绕同一个错误循环；
- 当前策略可能错误。

monitor 会读取：

- worker 的 thread；
- stdout / stderr；
- git diff；
- 当前环境；
- 之前的尝试。

然后给 worker 一个纠偏指令：

> “问题不是 CUDA 版本，而是扩展链接到了错误的 libstdc++。先检查 conda toolchain 和系统 GCC 的 ABI，不要继续重新安装 CUDA。”

worker 继续执行。

**这一过程默认不需要我介入。**

只有当问题真正需要我选择时，例如：

> “修复需要升级系统 CUDA，这可能影响该服务器其他项目；或者可以创建隔离容器，但预计多花 40 分钟。”

Cicada 才给我发通知：

> **需要你的决定**
>
> A. 升级系统 CUDA  
> B. 创建隔离容器（推荐）  
> C. 暂停任务

我点击 B，之后再次退出。

---

## 2.4 我随时可以问：“现在怎么样了？”

我打开手机：

> “benchmark 现在怎么样？”

Cicada 不把 800 行日志扔给我。

它沿着：

```text
Client
  ↓
Control
  ↓
Monitor
  ↓
Worker
```

收集状态，最后告诉我：

> “还在运行。已经完成 baseline 和两个 kernel 版本。当前最好版本比 baseline 快 17.8%。worker 正在 profile memory stall，预计还有一个主要优化方向。没有需要你处理的问题。”

如果我追问：

> “具体是什么 bottleneck？”

它再展开技术细节。

我拥有完整信息，但**默认只接收我真正需要知道的部分**。

---

## 2.5 一个 monitor 可以管理多个 worker

例如我说：

> “把这个方法分别在 NVIDIA 和 Ascend 上验证一下。”

Cicada 可以建立：

```text
Goal
└── Monitor A
    ├── Worker 1 — GPU Server — Codex
    └── Worker 2 — NPU Server — Codex
```

两个 worker 可以：

- 使用不同服务器；
- 使用不同 harness；
- 使用不同模型；
- 拥有不同 workspace；
- 并行运行。

Monitor A 负责：

- 确保两边实验口径一致；
- 把 Worker 1 的发现同步给 Worker 2；
- 比较结果；
- 防止重复劳动；
- 最终汇总成一个结论。

worker 之间可以共享经验，但我不需要亲自做“中间人”。

---

## 2.6 monitor 也可以管理 monitor

对于更大的任务：

```text
Goal
└── Monitor 0
    ├── Monitor A — 算法与正确性
    │   ├── Worker A1
    │   └── Worker A2
    │
    └── Monitor B — 性能优化
        ├── Worker B1
        └── Worker B2
```

Monitor 不是某种固定进程，也不绑定某台服务器。

它是一种逻辑角色：

> **负责一个范围内的目标一致性、进度、验证、纠偏和向上汇报。**

因此 Cicada 的执行结构不是固定的“一个主 Agent + N 个 Subagent”，而是一张可以动态变化的监督图。

---

## 2.7 worker 可以迁移、恢复和替换

如果一台服务器突然掉线，我不希望任务就此消失。

Cicada 应该能够判断：

- 原机器是否短暂失联；
- workspace 是否可恢复；
- worker thread 是否可恢复；
- 是否存在兼容机器；
- 是否应该迁移；
- 是否值得重新执行丢失的实验。

例如：

> “gpu2 离线超过 10 分钟。我已将剩余 benchmark 转移到 gpu1 的低优先级队列，原始日志与 checkpoint 已保留。”

对我而言，**worker 是任务角色，不是某一个 PID。**

---

## 2.8 我让 Cicada 帮我研究，但不一定执行

不是所有东西都应该变成 worker。

我可以说：

> “帮我研究一下这个 idea，但不要做任何代码修改。”

Cicada 建立一个 Research Goal，只允许：

- 浏览；
- 搜索；
- 阅读文件；
- 调用只读工具；
- 汇总。

完成后：

> “技术上可行，但目前已有三个成熟开源方案，而且用户迁移成本高。我建议暂不开发。”

我说：

> “记下来。”

它进入 Idea Memory。

---

## 2.9 Cicada 主动发现值得告诉我的事情

我不希望 Cicada 只是一个“我问它才回答”的聊天机器人。

它应该主动判断哪些事件值得打断我。

例如：

- 某个长期实验完成；
- worker 连续失败；
- 一个需要人类批准的操作出现；
- 之前搁置的 idea 条件已经变化；
- 某个截止日期临近；
- 服务器资源出现异常；
- 外部协作者的 AI 发来了需要我判断的信息；
- 某个项目出现重大风险。

但普通状态变化不应该打扰我。

例如：

```text
worker 开始编译             → 不通知
worker 编译成功             → 不通知
worker 开始 benchmark       → 不通知
worker 自动修复一次错误     → 不通知
任务全部完成                → 通知
需要不可逆操作              → 通知
需要主观决策                → 通知
```

Cicada 的目标不是“让我看到更多通知”，而是**替我过滤世界**。

---

## 2.10 我正常使用一个 AI，某一刻再让它加入 Cicada

Cicada 不应该要求我在开始工作前就先进入一个专门的 Cicada 启动流程。

更自然的使用方式是：我先像平时一样使用自己喜欢的 harness。

例如在 `gpu1` 上：

```bash
cd ~/AAA/le-wm
codex
```

我正常和这个 Codex thread 工作：

> “先把 planner 这部分代码读一下，看看哪里还有优化空间。”

它此时可以只是一个普通 Codex thread，不必一开始就属于某个 Goal，也不必事先由 Control 创建。

工作到一半，我突然希望它能够访问我的其他 AI、服务器或 monitor。我只需要在当前 TUI 中表达：

> `@cicada`

或者更明确：

> `@cicada join`

这里的 `@cicada` 是统一的用户心智模型；不同 harness 可以通过 MCP、plugin、skill、slash command 或其他原生扩展机制实现同一件事。

Cicada 自动：

1. 识别当前 harness，例如 Codex / Claude Code / OpenCode / Hermes / DeepSeek harness；
2. 获取当前原生 session / thread ID；
3. 获取当前 Machine；
4. 获取当前 workspace；
5. 为这个现有 session 建立一个 Cicada **Endpoint**；
6. 分配稳定的内部 `endpoint_id`；
7. 自动生成一个人类可读名称；
8. 返回它在 Cicada Fabric 中的地址；
9. 给当前 AI 暴露 Cicada 的网络能力。

例如：

```text
Joined Cicada Fabric.

Address:
le-wm@gpu1:~/AAA/le-wm

Endpoint ID:
ep_01K...

Harness:
codex
```

从这一刻开始，我不需要离开当前 TUI。

如果我说：

> “接下来问一下 gpu2 上做 benchmark 的那个 thread，现在最优结果是多少。”

当前 AI 应该能够自己：

```text
resolve target
   ↓
ask remote endpoint
   ↓
wait asynchronously
   ↓
receive reply
   ↓
continue current work
```

最终它直接告诉我：

> “我问过 gpu2 上负责 benchmark 的 endpoint 了。目前最优结果是 2.31 ms，使用配置 X。这个结果和我们这里的假设有一个冲突，我准备先检查……”

我不需要：

- 查 UUID；
- 手工执行 `cicada thread register`；
- 查目标 thread ID；
- SSH 到另一台机器；
- 打开另一个 TUI；
- 把问题复制过去；
- 再把答案复制回来。

**Cicada 的组网应该发生在我当前正在工作的 AI 内部，而不是要求我先成为一个 Cicada 运维人员。**

`cicada thread register ...` 之类的命令可以继续存在，用于：

- 调试；
- 手工恢复；
- 不支持自动发现的 harness；
- 自动化脚本；
- 兼容旧版本；

但它不应该成为普通用户加入 Fabric 的主要方式。

---

# 3. Cicada 的核心对象

Cicada 需要有一套稳定的产品抽象。具体底层可以换模型、换 harness、换通信协议，但这些上层对象不应该随实现变化。

---

## 3.1 User

我。

Cicada 的最高目标不是最大化 agent 工作量，而是服务于我的目标、偏好、边界和生活。

---

## 3.2 Client

我与 Cicada 交互的入口。

第一阶段可以是 CLI / Web，最终主要是手机 App，也可以扩展到：

- 桌面；
- 手表；
- 耳机；
- 眼镜；
- 其他语音入口。

Client 不承担主要推理。

它负责：

- 输入；
- 语音；
- 展示；
- 通知；
- Approval；
- 状态查看。

---

## 3.3 Control

Cicada 的“大脑”和 Manager。

Control 不等于一个固定模型。

它负责：

- 理解意图；
- 维护长期上下文；
- 建立 Idea / Goal；
- 调研；
- 规划；
- 分解任务；
- 选择机器；
- 选择 harness / model；
- 创建 monitor / worker；
- 管理执行图；
- 处理事件；
- 判断是否需要重新规划；
- 判断是否需要打扰我；
- 汇总结果。

Control 是 Cicada 最核心、最不可替代的产品层。

---

## 3.4 Goal

Goal 表示我真正希望达成的结果，而不是一句聊天消息。

例如：

> “验证这个 repo 在 4090 上还有没有优化空间。”

Goal 应包含：

- Objective；
- Success Criteria；
- Constraints；
- Priority；
- Budget；
- Deadline；
- Resources；
- Current State；
- Execution Graph；
- Evidence；
- Final Outcome。

---

## 3.5 Idea

Idea 是尚未承诺执行的想法。

它可以处于：

```text
CAPTURED
   ↓
RESEARCHING
   ↓
┌───────────────┐
│               │
VIABLE         PARKED
│               │
↓               │
GOAL            │
                │
        条件变化 / 新信息
                │
                └──→ RE-EVALUATE
```

Cicada 不应该强迫每一个想法都立即变成任务。

---

## 3.6 Monitor

Monitor 的职责是：

> **确保下层执行持续朝正确目标前进。**

它可以：

- 查看 worker 状态；
- 查看日志；
- 查看 thread；
- 查看文件变化；
- 检查实验结果；
- 判断 worker 是否跑偏；
- 给 worker 新指令；
- 创建额外 worker；
- 停止无价值 worker；
- 将信息同步到其他 worker；
- 向上层 monitor / Control 汇报。

Monitor 本身也可以被更高层 monitor 管理。

---

## 3.7 Worker

Worker 负责真正落实工作。

Worker 可能是：

- 一个 Codex thread；
- 一个 Claude Code session；
- 一个 OpenCode session；
- 一个 shell / benchmark job；
- 一个 browser agent；
- 一个 research agent；
- 未来其他 harness。

Worker 必须有明确边界：

- Goal；
- Workspace；
- Machine；
- Harness；
- Permissions；
- Context；
- Owner Monitor。

---

## 3.8 Machine

所有可以执行任务的计算环境：

- 本地电脑；
- Linux 服务器；
- GPU 服务器；
- NPU 服务器；
- AI PC；
- 云实例；
- 未来其他边缘设备。

Cicada 应维护机器能力画像，例如：

```text
Hardware
GPU / NPU
VRAM / RAM
Architecture
OS
Installed Toolchains
Current Load
Disk
Network
Cost
Availability
Labels
```

---

## 3.9 Workspace

一个任务真正工作的文件空间。

Workspace 应该能够：

- create；
- clone；
- resume；
- snapshot；
- archive；
- migrate；
- associate with git repo；
- associate with Goal / Worker。

---

## 3.10 Endpoint

Endpoint 是 Cicada Fabric 中**可被寻址、被发现、被询问或被发送消息的逻辑端点**。

Endpoint 是比 `Thread` 更稳定的网络抽象。因为不同 harness 对会话的命名并不一致：

- Codex 使用 thread；
- Claude Code 使用 session；
- OpenCode 有自己的 session / conversation；
- Hermes、DeepSeek harness 或未来其他 harness 可能采用完全不同的运行模型；
- Monitor 甚至可以不是一个永久进程。

因此 Cicada 不应该把网络层绑定到 `Codex Thread`，而应该统一为：

```text
Endpoint
├── Codex Thread
├── Claude Code Session
├── OpenCode Session
├── Worker
├── Monitor
├── Research Agent
└── Future Harness
```

一个 Endpoint 至少应具有：

```text
endpoint_id
name
role
harness
native_session_id
machine_id
workspace
goal_id
status
capabilities
tags
owner
visibility
joined_at
last_seen
```

其中 `endpoint_id` 是稳定的内部身份，例如：

```text
ep_01K7...
```

用户一般不需要记住它。

用户主要使用人类可读地址，例如：

```text
planner@gpu1:~/AAA/le-wm
benchmark@gpu2:/data/le-wm
ascend-opt@a2:~/ops-math
monitor@control:/goals/kernel-opt
```

Endpoint 可以迁移、更名或更换底层 harness，但 Cicada 应尽量保持其稳定身份和上下文连续性。

---

## 3.11 Thread / Session

Thread / Session 是某个具体 harness 的**原生会话对象**，它通常被一个 Endpoint 包装，而不是直接作为整个 Cicada 网络的统一身份。

例如：

- Codex thread；
- Claude Code session；
- OpenCode session；
- 其他 harness 的 conversation / task session。

Cicada 不应该为了统一接口而抹掉这些原生能力。

对于 Codex，应尽量保留并利用真正的：

- thread；
- turn；
- message；
- subagent；
- resume；
- device auth；
- queue / wake 等原生能力。

因此关系更像：

```text
Endpoint
   ↓ binds to
Native Thread / Session
```

而不是：

```text
Cicada = 一个重新发明的统一 Agent Harness
```

---

## 3.12 Fabric Directory

Fabric Directory 是 Cicada 对整个网络的实时目录。

它维护：

- 当前有哪些 Machine；
- 当前有哪些 Endpoint；
- Endpoint 当前在哪台 Machine；
- 使用什么 harness；
- 属于哪个 Goal / Project；
- 当前 workspace；
- online / offline / busy / idle；
- 可以提供什么能力；
- 当前 visibility / permission 边界；
- last seen / liveness。

但 Directory **不是把整个网络状态永久复制进每个模型的 prompt**。

每个 Endpoint 只需要知道：

1. 自己是谁；
2. 自己的地址；
3. 自己属于哪个 Fabric / Control；
4. 自己有哪些 Cicada 网络工具；
5. 当需要信息时如何查询 Directory。

例如一个刚加入 Fabric 的 Codex 可以得到一张很小的 Network Card：

```text
CICADA FABRIC

You are:
  address: planner@gpu1:~/AAA/le-wm
  endpoint_id: ep_01K...
  role: thread
  harness: codex
  machine: gpu1
  workspace: ~/AAA/le-wm

Available network capabilities:
  whoami
  list
  resolve
  inspect
  send
  ask
```

网络的当前形态通过工具按需查询，而不是在每个 turn 中重复注入整张网络拓扑。

---

## 3.13 Event

Cicada 内部所有重要变化都应成为事件：

```text
EndpointJoined
EndpointLeft
EndpointMoved
WorkerStarted
WorkerBlocked
WorkerRecovered
MachineOffline
ApprovalRequested
ArtifactProduced
GoalCompleted
PeerMessageReceived
...
```

Control 根据 Event 决定下一步，而不是依赖用户不停轮询。

---

## 3.14 Approval

Approval 表示：

> **AI 已经能继续，但这一步应该由我决定。**

例如：

- 删除大量文件；
- 修改生产环境；
- 花钱；
- 使用高成本云资源；
- 发送敏感信息；
- 对外发消息；
- merge / deploy；
- 改变 Goal；
- 做不可逆操作。

---

# 4. 三层核心架构

Cicada 最基本的逻辑结构仍然是：

```text
Client
   │
   ▼
Control
   │
   ▼
Executor
```

---

## 4.1 Client：我看到的 Cicada

Client 应提供：

### 自然输入

- 语音；
- 文本；
- 文件；
- 图片；
- 链接。

### 本地语音能力

尽可能在设备本地完成：

- Voice Activity Detection；
- Speech-to-Text；
- Text-to-Speech。

推理与复杂任务交给 Control。

### 首页

首页不应该是“17 个 agent session”。

应该首先展示：

```text
Today

3 goals running
1 needs approval
2 completed

● Paper reproduction
  Running autonomously

△ Competition registration
  Needs your approval

✓ CUDA benchmark
  +23.4%

[ Ask Cicada... ]
```

### Goal 页面

我可以看到：

- 当前结论；
- 进度；
- monitor / worker graph；
- 关键事件；
- 产物；
- Approval；
- 需要时展开原始 thread / log。

### 通知

通知分为：

- Result；
- Approval；
- Risk；
- Reminder；
- Peer Request。

---

## 4.2 Control：真正的 Cicada

Control 至少包含以下能力。

### Intent Understanding

把一句自然语言转化为：

- Idea；
- Research；
- Goal；
- Question；
- Approval；
- Command。

### Research

Control 能：

- 上网搜索；
- 阅读网页；
- 浏览需要登录的资源（在授权范围内）；
- 阅读文档；
- 查历史项目；
- 对来源交叉验证；
- 形成 evidence-backed recommendation。

### Long-term Context

理解：

- 我过去做过什么；
- 当前有哪些 Goal；
- 我有什么机器；
- 我常用什么工具；
- 哪些方法以前失败；
- 哪些经验可以迁移；
- 我的时间与风险偏好。

### Planning

将 Goal 拆成：

```text
Goal
↓
Subgoals
↓
Monitors
↓
Workers
↓
Actions
```

### Scheduling

自动选择：

- Machine；
- Harness；
- Model；
- Concurrency；
- Priority；
- Timing。

### Supervision

Control / Monitor 持续检查：

- 进度；
- 正确性；
- 方向；
- 资源；
- 重复劳动；
- failure loop；
- hallucinated completion；
- evidence quality。

### Replanning

如果现实变化：

- worker 失败；
- 机器下线；
- API 改变；
- deadline 改变；
- 新证据推翻旧假设；

Cicada 自动调整执行计划。

### Fabric Awareness

Control 还负责维护 Cicada Fabric 的网络视图：

- Endpoint membership；
- Address / alias；
- Machine location；
- Endpoint capability；
- liveness；
- visibility；
- routing；
- request / reply correlation；
- permission boundary。

但 Control 不应把完整网络状态不断塞进每个 Worker 的上下文。它应该通过 Directory 与工具调用提供**按需、实时、最小化**的网络信息。

---

## 4.3 Executor：真正做事的地方

Executor 是可插拔的。

```text
Executor API
├── Native Codex
├── Claude Code
├── OpenCode
├── Happy Agent
├── Shell
├── Browser
└── Future Harness
```

Cicada 的核心不应该绑定任何一家模型或 harness。

但是可以选择一个主线实现，例如优先把 Native Codex 的能力做完整，再实现其他兼容层。

---

# 5. Machine & Resource Scheduler

Cicada 必须真正知道“我有什么生产资料”。

---

## 5.1 Machine Discovery

机器可通过：

- 手动添加；
- SSH pairing；
- daemon registration；
- 局域网发现；
- cloud connector；

进入 Cicada。

---

## 5.2 Capability Profile

每台机器应维护：

```text
CPU
GPU / NPU
Memory
Disk
Network
OS
Drivers
CUDA / ROCm / CANN
Compilers
Containers
Python environments
Current jobs
Health
Cost
```

---

## 5.3 自动选机器

我说：

> “跑一下这个 PyTorch CUDA 项目。”

Cicada 自动排除 NPU server。

我说：

> “优化这个 Ascend 算子。”

Cicada 自动找到合适 910B。

我说：

> “这个任务不急，尽量不要占 H100。”

Scheduler 将偏好视为 constraint，而不是让我自己记机器状态。

---

## 5.4 迁移和恢复

Worker 不应该和 Machine 永久绑定。

理想情况下：

```text
Worker
  ↓ assigned to
Machine A

Machine A fails

Worker
  ↓ recover / migrate
Machine B
```

---

# 6. Monitor / Worker 协作模型

这是 Cicada 的核心产品 primitive 之一。

---

## 6.1 Monitor 不负责机械执行

Monitor 更像：

- tech lead；
- reviewer；
- experiment supervisor；
- project manager。

它关注：

> “结果是否仍然服务 Goal？”

---

## 6.2 Worker 不负责全局决策

Worker 关注：

> “把当前分配给我的事情做好。”

避免每个 worker 都重新理解整个世界。

---

## 6.3 信息共享

Monitor 负责减少重复劳动。

例如：

```text
Worker A:
发现依赖版本 2.3 有 bug

      ↓

Monitor

      ↓

Worker B:
不要再测试 2.3，直接使用 2.4
```

---

## 6.4 动态调整拓扑

Cicada 可以：

- 增加 worker；
- 合并 worker；
- 停止 worker；
- 提升某个 worker 为 monitor；
- 增加更高层 monitor；
- 把任务迁移到其他 machine。

执行图应是动态的，而不是任务开始时一次性固定。

---

# 7. 长期任务

Cicada 必须支持“小时 / 天”尺度，而不仅是一次聊天。

长期任务需要：

- durable state；
- heartbeats；
- checkpoint；
- automatic resume；
- crash recovery；
- session restoration；
- event history；
- periodic evaluation；
- timeout / budget；
- artifact persistence。

即使：

- Client 关闭；
- 手机离线；
- Control 重启；
- worker 重启；

Goal 仍应继续存在。

---

# 8. Idea Lifecycle

Cicada 不只是 Task Manager。

它还应该管理我的“尚未成为任务的可能性”。

完整状态可以是：

```text
CAPTURED
  ↓
RESEARCHING
  ↓
ASSESSED
  ├── PARKED
  │     ↓
  │  RE-EVALUATE
  │
  ├── REJECTED
  │
  └── APPROVED
        ↓
      PLANNED
        ↓
      RUNNING
        ↓
   ┌────┼─────┐
   │    │     │
BLOCKED PAUSED COMPLETED
              ↓
            REVIEW
              ↓
           ARCHIVED
```

Parked Idea 应记录：

- 当时为什么不做；
- 缺什么条件；
- 什么时候重新检查；
- 哪些未来事件会触发重新评估。

---

# 9. Memory

Cicada 需要的不是单纯聊天历史，而是面向行动的记忆。

---

## 9.1 Personal Context

例如：

- 我的目标；
- 工作习惯；
- 偏好；
- 常用机器；
- 常用 repo；
- 常用模型。

---

## 9.2 Project Memory

例如：

- 项目背景；
- 设计决策；
- benchmark 结果；
- 曾经踩过的坑；
- 不应该再次尝试的方法。

---

## 9.3 Execution Memory

例如：

- Worker A 为什么失败；
- 什么修复有效；
- 哪个环境配置正确；
- 某个性能回归从什么时候开始。

---

## 9.4 Idea Memory

保存：

- 未执行的想法；
- 调研结论；
- 搁置原因；
- 恢复条件。

---

# 10. Cicada Fabric：AI ↔ AI 组网与通信

Cicada 内部以及跨用户场景都需要 agent communication，但通信不是简单“让两个 AI 聊天”。

Cicada Fabric 的目标是：

> **让我当前正在使用的 AI 能够知道自己处于一个可发现、可寻址、受权限控制的 Agent 网络中，并在需要时主动访问其他 worker、monitor 或人的 Cicada，而不需要我充当信息中转站。**

---

## 10.1 Session-first：先正常工作，需要时再加入 Fabric

普通用户不应该先手工登记 UUID，才能开始使用 Cicada。

推荐使用周期是：

```text
normal harness session
        ↓
work normally
        ↓
user decides to network it
        ↓
@cicada / @cicada join
        ↓
auto-discover current session
        ↓
create / bind Endpoint
        ↓
join Fabric
```

例如：

```bash
gpu1$ cd ~/AAA/le-wm
gpu1$ codex
```

我先正常工作。直到某一刻说：

> `@cicada`

Cicada Integration 自动发现：

- 当前 harness；
- native thread / session ID；
- hostname / Machine；
- cwd / Workspace；
- 当前用户；
- 可用原生能力。

然后建立 Endpoint。

因此：

```text
Integration installed
≠
Session joined
```

服务器可以提前安装 Cicada integration，但一个 session 只有在用户明确加入或 policy 自动加入后，才成为 Fabric Endpoint。

`cicada thread register ...` 等手工命令只作为调试、恢复和兼容入口存在。

---

## 10.2 跨 Harness 的统一 Endpoint

Cicada Fabric 不能假设所有 AI 都使用 thread 这个概念。

网络层统一处理 Endpoint：

```text
Endpoint
├── Native Codex Thread
├── Claude Code Session
├── OpenCode Session
├── Hermes Session
├── DeepSeek Harness Session
├── Monitor
└── Future Agent Runtime
```

每个 harness 通过自己的 Integration Adapter 实现类似能力：

```text
DetectCurrentSession()
Join()
Capabilities()
Send()
Wake()
Resume()
Leave()
```

技术实现可以不同，但用户心智模型应一致：

> **“让当前 AI 加入 Cicada。”**

---

## 10.3 Endpoint Address：人类可读地址 + 稳定内部身份

Cicada 应同时存在两种身份。

### 稳定内部身份

```text
endpoint_id = ep_01K...
```

用于：

- durable routing；
- migration；
- audit；
- permission；
- correlation；
- rename 后保持连续性。

### 人类可读地址

推荐形式：

```text
endpoint_name@server_name:workspace_dir
```

例如：

```text
planner@gpu1:~/AAA/le-wm
benchmark@gpu2:/data/le-wm
ascend-opt@a2:~/ops-math
monitor@control:/goals/lewm
```

这个形式的好处是：

- 一眼知道目标是谁；
- 一眼知道当前位于哪台 Machine；
- 能看到工作上下文；
- 很像熟悉的 `user@host:/path`；
- 适合在 TUI 中直接引用。

但 Machine 和 Workspace 是**locator / context**，不是永久身份。

例如 Endpoint 从 gpu2 迁移到 gpu3：

```text
benchmark@gpu2:/data/le-wm
            ↓ migrate
benchmark@gpu3:/data/le-wm
```

其 `endpoint_id` 不应变化。

---

## 10.4 地址缩写与解析

我不应该每次都输入完整地址。

Cicada Resolver 应支持：

```text
benchmark@gpu2:/data/le-wm   # 完全限定
benchmark@gpu2               # 在 gpu2 上唯一即可
benchmark                    # 整个可见 Fabric 中唯一即可
```

解析原则：

1. 显式完整地址优先；
2. server-qualified alias 次之；
3. global-visible unique alias 再次；
4. 发生歧义时绝不能静默猜测。

例如：

```text
Ambiguous endpoint "benchmark":

1. benchmark@gpu1:~/foo
2. benchmark@gpu2:~/bar
```

AI 可以先根据 Goal / Project / Workspace 上下文消歧；如果仍无法确定，再询问用户。

---

## 10.5 每个 Endpoint 应该知道多少网络信息

每个 Endpoint **应该知道 Cicada Fabric 存在**，但不应该默认拿到全网所有上下文。

它可以默认知道：

- 自己的 Endpoint ID 和地址；
- 当前 Machine；
- 当前 Workspace；
- 当前 Goal / Project（如果有）；
- 当前角色；
- 可用 Cicada 网络工具；
- 当前 Fabric / Control identity。

它可以通过 Directory 按需查询：

```text
list()
resolve()
inspect()
```

例如：

```text
SERVERS
gpu1    online    H100
gpu2    online    RTX4090
a2      online    Ascend 910B

ENDPOINTS
planner@gpu1:~/AAA/le-wm
benchmark@gpu2:~/AAA/le-wm
ascend-test@a2:~/ops
monitor@control:/goals/lewm
```

默认可见信息可以包括：

- endpoint name；
- role；
- harness；
- machine；
- display workspace；
- status；
- Goal / Project label；
- capabilities；
- tags；
- last seen。

默认**不应该**暴露：

- 完整 thread history；
- system prompt；
- credentials；
- secrets；
- `.env`；
- 私有文件；
- 私有 memory；
- 未授权 workspace 内容。

这些能力必须受 Permission & Trust 控制。

核心原则：

> **A Cicada Endpoint knows that the network exists, but queries the network when it needs to know its current shape.**

---

## 10.6 Cicada Tool / MCP：AI 自己使用网络，而不是人手工执行 CLI

用户不应该告诉 AI：

> “请执行 `cicada thread queue UUID ...`。”

加入 Fabric 后，AI 应直接拥有稳定的 Cicada Tool 接口，例如：

```text
cicada_whoami()
cicada_list(...)
cicada_resolve(...)
cicada_inspect(...)
cicada_send(...)
cicada_ask(...)
```

例如我说：

> “问一下 benchmark 那边现在最优结果是多少。”

当前 AI 可以自动：

```text
cicada_resolve("benchmark")
        ↓
benchmark@gpu2:~/AAA/le-wm

cicada_ask(
  target="benchmark@gpu2:~/AAA/le-wm",
  question="目前 benchmark 的最优结果和配置是什么？"
)
```

这类能力应优先通过 MCP / plugin / skill / harness-native tool 提供，而不是要求模型通过 shell 拼 Cicada CLI。

CLI 仍然有价值，但主要面向：

- 调试；
- 运维；
- 自动化；
- fallback。

---

## 10.7 `send` 与 `ask` 是不同的 primitive

普通消息只需要：

```text
send(target, message)
```

但 Agent 协作更重要的是：

```text
ask(target, question)
```

`ask` 应具有 request / reply 语义：

```text
A
 ↓ ask
request_id = rq_123
 ↓
B
 ↓ work
reply_to = rq_123
 ↓
A resumes
```

例如：

```text
planner@gpu1
  ↓ ask
benchmark@gpu2

“目前最优 benchmark 是多少？”

        ↓

benchmark@gpu2
处理、查询、必要时运行工具

        ↓

reply:
“2.31 ms，配置为 ...”
```

回复到达后，原始 Endpoint 应可以被自动唤醒或恢复，让它继续原来的上下文：

> “gpu2 回复了。结果是 2.31 ms，我接下来会据此修改当前方案。”

这比简单聊天更接近 **Agent RPC**。

---

## 10.8 同一用户内部协作

同一用户的 Fabric 可以包含：

```text
Monitor
   ↕
Worker A
   ↕
Worker B
   ↕
Manual TUI Endpoint
```

Endpoint 可以位于：

- 同一进程；
- 同一服务器；
- 不同服务器；
- 不同 harness；
- 不同 workspace。

同一用户内部可以通过 Control Plane / local daemon / secure transport 通信。

用户不应该成为 worker 之间的 copy-paste 中间人。

---

## 10.9 Monitor 也可以成为 Endpoint

Monitor 是一种逻辑角色，不要求一定是永久运行的 LLM thread。

但它应该可以被寻址，例如：

```text
monitor@control:/goals/lewm
```

我可以从当前 TUI 说：

> “问一下 monitor，为什么 benchmark 还没有结束。”

Control 可以根据：

- Goal state；
- Worker events；
- artifacts；
- evidence；
- monitor state；

直接回答，或者临时启动 reasoning。

因此 Endpoint 不等于 OS process，也不等于必须存在一个永久 thread。

---

## 10.10 不同用户之间

例如我和另一个人一起做项目。

我们双方都安装 Cicada。

我可以告诉自己的 AI：

> “问一下 Bob，他们那边 API v2 的 schema 定下来没有。”

我的 AI 不需要让我复制一段话到 Telegram。

理想流程：

```text
Me
 ↓
My current Endpoint
 ↓
My Cicada
 ↓
resolve Bob / target endpoint
 ↓
E2EE
 ↓
Bob's Cicada
 ↓
Bob's relevant Endpoint
 ↓
reply
 ↓
E2EE
 ↓
My original Endpoint resumes
```

---

## 10.11 Person-level Contact

长期不应该只是：

```text
agent-123 ↔ agent-789
```

而应该建立：

```text
Me ↔ Bob
```

然后由双方 Cicada 决定：

- 这条消息交给哪个 Endpoint；
- 哪个 thread / session；
- 可以访问哪些信息；
- 哪些操作需要人工批准。

因此跨用户地址未来可以进一步扩展，例如：

```text
benchmark@bob/gpu2:/project
```

或其他更合适的 federation namespace。

具体外部 namespace 可以演进，但**内部稳定 Endpoint ID 与用户级 Contact identity 必须分离**。

---

## 10.12 E2EE

跨用户通信应默认端到端加密。

Relay 可以负责：

- forwarding；
- offline queue；
- wake；
- delivery receipt；

但不应该拥有消息明文。

Cicada 不应自行发明密码学，而应基于成熟协议 / library 实现。

---

# 11. Permission & Trust

Agent 能相互通信，并不等于可以无限制相互操作。

每一个外部 Contact / Agent 都应该具有能力边界。

例如：

```text
Bob

Allowed
✓ Chat
✓ Exchange public code snippets
✓ Ask project status

Approval required
△ Send private project files
△ Open PR
△ Execute commands

Never
✗ Read secrets
✗ Read credentials
✗ Spend money
✗ Deploy production
```

---

## 11.1 Permission Scope

权限至少可以针对：

- Contact；
- Goal；
- Workspace；
- Machine；
- Tool；
- File path；
- Repository；
- External service；
- Action type；

进行限制。

---

## 11.2 Human Approval

Approval 必须是 Cicada 的一级对象，而不是某个具体 harness 的弹窗。

这样即使底层从 Codex 换到 Claude，用户体验仍然一致。

---

# 12. 外部信息平台

Cicada 的长期目标不是只管理 coding agents。

它还应该成为我的信息代理。

可对接：

- Email；
- Telegram；
- X；
- 微信；
- QQ；
- Slack；
- Discord；
- Calendar；
- Documents；
- 其他消息 / 工作平台。

---

## 12.1 不是“把所有通知搬到 Cicada”

这会制造另一个信息垃圾场。

正确逻辑应该是：

```text
External messages
      ↓
Cicada
      ↓
understand / classify / merge / act
      ↓
only meaningful information
      ↓
Me
```

---

## 12.2 可以自动处理的事情自动处理

例如一封协作邮件：

> “benchmark 的结果出来了吗？”

如果权限允许，Cicada 可以：

1. 找到对应 Goal；
2. 查询 monitor；
3. 得到当前结果；
4. 起草回复；
5. 根据 policy 自动发送，或者请求我一键批准。

---

## 12.3 “镜像一个我”

长期愿景不是让 AI 假装成我聊天。

而是：

> Cicada 了解我的目标、上下文、权限和做事方式，因此能替我处理大量原本需要我持续在线的协调工作。

它应明确区分：

- 可以自主决定的事情；
- 可以自主执行但需要记录的事情；
- 必须请求我批准的事情；
- 永远不能替我决定的事情。

---

# 13. Browser & External Actions

Control 需要可靠地访问互联网。

能力可能包括：

- search；
- fetch；
- browser；
- authenticated browser session；
- form filling；
- downloads；
- external APIs。

但浏览器是高风险能力。

必须有：

- domain policy；
- credential isolation；
- permission boundary；
- action log；
- confirmation for destructive actions；
- secrets protection。

---

# 14. Notification Philosophy

Cicada 的成功标准之一，是**减少通知，而不是增加通知**。

通知优先级：

### P0 — 必须立即打扰

- 安全风险；
- 高价值不可逆操作；
- 严重资源故障；
- deadline 即将错过。

### P1 — 需要人做决定

- Approval；
- 主观选择；
- 策略冲突。

### P2 — 有结果

- Goal completed；
- 关键 milestone；
- 重大新发现。

### P3 — 普通事件

只进入 Timeline，不 push。

---

# 15. 我一天中的 Cicada

一个理想的日常体验可能是：

### 07:00

我打开手机。

Cicada：

> “早上好。昨晚 3 个长期任务中 2 个完成，1 个仍在运行。没有紧急问题。  
> CUDA benchmark 最优性能提高 23.4%。  
> Paper reproduction 仍在跑最后一组实验。  
> 昨天搁置的一个 idea 没有新变化。”

### 08:30

我想到一个东西：

> “是不是可以让我们的两个 AI 直接通信？帮我研究一下。”

说完手机放下。

### 10:20

Cicada：

> “调研完成。已有相邻项目，但我们仍可能在 autonomous personal orchestration 层存在机会。我已经把结论记录到 Idea。没有执行任何代码。”

### 11:00

我：

> “先做一个最小原型。”

Cicada：

> “建议使用 gpu2，不需要 H100。将创建一个 monitor 和一个 Native Codex worker。预计只修改新 workspace。可以开始吗？”

我：

> “开始。”

之后继续自己的事情。

### 14:10

没有通知。

实际上 worker 在 13:20 遇到依赖问题，monitor 已经自动解决。

### 16:00

通知：

> “原型完成。两个 Codex thread 已经可以互发消息。测试 30 次，30/30 成功。是否继续做跨机器 E2EE？”

我：

> “继续。”

---

# 16. Cicada 不是什么

为了保持产品边界，需要明确以下几点。

---

## 16.1 Cicada 不是更漂亮的 Codex Remote UI

如果最终我仍然需要：

- 手动选择 session；
- 手动盯日志；
- 手动决定每个下一步；

那只是 remote control，不是 Cicada。

---

## 16.2 Cicada 不是 AI Slack

Agent 之间聊天只是能力之一。

真正核心是：

> **自主编排和监督。**

---

## 16.3 Cicada 不是新的 Agent Harness

它不需要重新发明 Codex / Claude Code / OpenCode。

它应该管理这些 harness。

---

## 16.4 Cicada 不是新的加密协议

需要 E2EE，但不应该自己发明密码学。

---

## 16.5 Cicada 不是“无限自治”

自主不是取消人的控制。

Cicada 应该：

> 尽量减少人类介入，但在边界、风险、价值判断和不可逆操作上保留明确的人类主权。

---

## 16.6 Cicada 不是必须依赖某个单一模型

Cicada 的稳定抽象应该高于：

- GPT；
- Claude；
- Gemini；
- GLM；
- DeepSeek；
- 未来模型。

---

# 17. 产品原则

## 17.1 Intent over Instructions

我表达：

> “我要什么。”

而不是：

> “每一步怎么做。”

---

## 17.2 Goals over Chats

聊天只是交互方式。

真正持久的是 Goal。

---

## 17.3 Autonomous by Default, Interrupt by Exception

能自行处理就自行处理。

只有真正需要人时才打扰。

---

## 17.4 Native Capabilities over Lowest Common Denominator

支持多个 harness，但不要因为兼容性而放弃 Codex thread 等原生高级能力。

---

## 17.5 Logical Workers over Physical Processes

Worker / Monitor 是逻辑对象。

进程、机器、模型都可以变化。

---

## 17.6 Durable over Ephemeral

Cicada 要面对几小时、几天甚至更久的 Goal。

重启不应该意味着失忆。

---

## 17.7 Evidence over Confidence

Agent 说“完成了”不等于完成。

Monitor 应尽量验证：

- tests；
- benchmark；
- artifacts；
- logs；
- sources；
- reproducibility。

---

## 17.8 Human Attention Is the Scarce Resource

GPU 很贵，token 很贵，但对 Cicada 来说最需要保护的是：

> **我的注意力。**

---

## 17.9 Join Existing Work, Do Not Force a New Workflow

Cicada 应该加入我已经在进行的工作，而不是要求我为了使用 Cicada 重开一个特殊 session。

理想路径是：

```text
normal Codex / Claude / OpenCode session
        ↓
work
        ↓
@cicada
        ↓
join Fabric
```

而不是：

```text
先登记 UUID
↓
先创建 Cicada session
↓
再开始工作
```

---

## 17.10 Query the Fabric, Do Not Dump the Fabric

每个 Endpoint 应知道自己处于 Fabric 中，但不应该把整个网络拓扑、所有线程和所有状态长期塞入模型上下文。

网络信息应：

- 实时；
- 按需；
- 最小化；
- 权限过滤；
- 可查询；
- 可失效刷新。

**Network state belongs in the Directory, not in the prompt.**

---

# 18. 功能总览

完整 Cicada 可以分成以下模块：

```text
Cicada
│
├── Client
│   ├── Mobile
│   ├── Web
│   ├── Desktop
│   ├── Voice
│   ├── Notifications
│   └── Approvals
│
├── Control
│   ├── Intent
│   ├── Research
│   ├── Planning
│   ├── Memory
│   ├── Goal Manager
│   ├── Idea Manager
│   ├── Scheduler
│   ├── Supervisor
│   ├── Policy
│   └── Event Engine
│
├── Runtime
│   ├── Monitor
│   ├── Worker
│   ├── Endpoint
│   ├── Workspace
│   ├── Machine
│   ├── Recovery
│   └── Artifact
│
├── Fabric
│   ├── Membership / Join
│   ├── Endpoint Directory
│   ├── Address Resolver
│   ├── Presence / Liveness
│   ├── Capability Discovery
│   ├── Harness Integration
│   └── Network Card
│
├── Executors
│   ├── Native Codex
│   ├── Claude Code
│   ├── OpenCode
│   ├── Hermes
│   ├── DeepSeek Harness
│   ├── Happy Agent
│   ├── Shell
│   └── Browser
│
├── Communication
│   ├── Internal Messaging
│   ├── Endpoint-to-Endpoint
│   ├── Agent RPC / Ask
│   ├── Request / Reply Correlation
│   ├── Wake / Resume
│   ├── E2EE Peer Link
│   ├── Contact
│   └── Federation
│
├── Integrations
│   ├── Email
│   ├── Telegram
│   ├── X
│   ├── WeChat
│   ├── QQ
│   ├── Slack / Discord
│   ├── Calendar
│   └── Files / Documents
│
└── Security
    ├── Identity
    ├── E2EE
    ├── Permission
    ├── Approval
    ├── Secrets
    ├── Audit
    └── Isolation
```

---

# 19. MVP：什么东西最先证明 Cicada 成立

完整愿景很大，但 MVP 不应该同时开发全部模块。

第一版只需要证明一句话：

> **我给一个 Manager 一个目标，它能自己选择机器、创建一个真实 Codex worker、持续监督并纠偏，最后只把结果告诉我。**

最小环境：

```text
Control
├── Server A
└── Server B
```

最小能力：

1. 注册两台 Machine；
2. 读取机器状态；
3. 创建 Goal；
4. Control 自动选机器；
5. 创建 workspace；
6. 创建 Native Codex worker；
7. 创建 / 绑定 monitor；
8. 获取 worker events；
9. monitor 可以向 worker 发送纠偏；
10. worker 崩溃后可以恢复；
11. Goal 完成后形成 summary；
12. 只在 Approval 时请求我。

第一阶段甚至：

- 不需要手机 App；
- 不需要语音；
- 不需要微信；
- 不需要跨用户；
- 不需要漂亮 dashboard；
- 不需要自己造 E2EE；
- 不需要支持所有 harness。

只需要证明：

```text
Me
 ↓ one instruction
Cicada Control
 ↓
Monitor
 ↓
Worker
 ↓
work / fail / recover / continue
 ↓
Result
 ↓
Me
```

## 19.1 第二个关键验收：现有 TUI 动态加入 Fabric

在 Autonomous Coding Supervisor 的闭环成立后，下一项最重要的验收不是增加更多外部平台，而是证明：

> **我可以在一个已经工作了一段时间的 AI TUI 中临时加入 Cicada，并让当前 AI 自己访问其他 Endpoint。**

最小验收场景：

```text
gpu1                               gpu2

existing Codex A                   existing Codex B
      │                                  │
      │ @cicada                          │ @cicada
      ↓                                  ↓
 Endpoint A                           Endpoint B
      │                                  │
      └──────── Cicada Fabric ───────────┘
```

然后我只在 A 中说：

> “问一下 gpu2 上的 benchmark thread，目前最优结果是多少。”

系统自动完成：

1. 当前 Codex A 已经通过 `@cicada` 加入 Fabric；
2. 自动解析目标 Endpoint；
3. A 调用 `ask`；
4. 请求通过 Fabric 路由到 B；
5. B 的原生 session 被唤醒 / resume；
6. B 得到问题并处理；
7. 回复与 `request_id` 关联；
8. 回复回到 A；
9. A 的原 session 自动继续；
10. 我没有离开 A 的 TUI，也没有复制任何信息。

第一版只要求：

- Codex ↔ Codex；
- 两台 Machine；
- 一个 Control / Fabric Directory；
- Endpoint join；
- 地址解析；
- `list / resolve / ask / send`；
- exact native-session wake；
- request / reply correlation。

第一版不要求：

- 跨用户；
- 公共 directory；
- native mobile；
- 所有 harness；
- 复杂群聊；
- 社交网络。

---

# 20. 后续演进

## Phase 1 — Autonomous Coding Supervisor

目标：

> “我不再盯 Codex。”

实现：

- Control；
- Machine；
- Goal；
- Monitor；
- Native Codex Worker；
- Scheduler；
- Events；
- Approval；
- Recovery。

---

## Phase 2 — Personal Client

目标：

> “我可以离开电脑。”

增加：

- Mobile；
- Push；
- Voice；
- Goal overview；
- Approval UX；
- remote status。

可以大量复用 / 改造已有开源项目的成熟 Client 与 remote-agent 基础设施，而不是重新实现所有 plumbing。

---

## Phase 3 — Fabric Membership & Agent RPC

目标：

> “我当前正在使用的 AI 可以随时加入 Cicada，并直接访问其他 AI。”

增加：

- Endpoint；
- Fabric Directory；
- `@cicada` / join UX；
- automatic native-session discovery；
- `endpoint_name@server_name:workspace` locator；
- stable Endpoint ID；
- address resolver；
- Network Card；
- `list / resolve / inspect / send / ask`；
- request / reply correlation；
- exact session wake / resume；
- Codex ↔ Codex first-class path。

---

## Phase 4 — Multi-Harness Fabric

目标：

> “加入 Cicada 的不只是 Codex，而是所有 Agent。”

增加：

- Claude Code；
- OpenCode；
- Hermes；
- DeepSeek harness；
- Happy Agent；
- harness-specific session discovery；
- harness-specific wake / resume；
- capability-normalized Endpoint API。

---

## Phase 5 — Secure Cross-User Agent Network

目标：

> “我的 AI 可以和你的 AI 直接合作。”

增加：

- Contact；
- Peer identity；
- E2EE；
- cross-Control Endpoint routing；
- cross-user `ask / reply`；
- cross-user permission；
- federation；
- person-level routing；
- relay / offline delivery。

---

## Phase 6 — Personal Information Proxy

目标：

> “我不再持续盯消息平台。”

增加：

- Email；
- Telegram；
- X；
- 微信；
- QQ；
- Calendar；
- proactive triage；
- authorized replies。

---

## Phase 7 — Cicada

最终状态：

> 我不再围着 AI 转。  
> AI、服务器、消息、项目和长期任务都在后台持续运转。  
> 我只负责提出真正值得做的事情，以及作出只有我才能作出的选择。

---

# 21. 成功标准

Cicada 成功并不意味着：

> “它同时运行了更多 agent。”

而应该意味着：

### 我减少了多少人工监督？

如果我仍然每天频繁：

```text
ssh
tmux
check
copy
paste
resume
retry
```

Cicada 就失败了。

### 它能否保持 Goal 一致性？

worker 工作几个小时以后，是否仍然在解决原问题？

### 它能否自己处理正常失败？

普通编译错误、网络错误、依赖错误、模型中断，不应该频繁升级给我。

### 它是否知道什么时候必须问我？

减少打扰不能以越权为代价。

### 它能否跨机器、跨 harness 保持连续性？

底层对象变化不应该摧毁 Goal。

### 我能否不离开当前 TUI 就调用整个 Fabric？

如果我为了问另一个 worker 仍然需要：

```text
查 UUID
SSH
切 tmux
复制问题
等待
复制答案
切回来
```

那么 Cicada 的组网就失败了。

理想状态是：

> 我只告诉当前 AI“去问那个 Endpoint”，剩下的寻址、权限、唤醒、等待、回复和上下文继续都由 Cicada 完成。

### 它最终有没有让我离开屏幕？

这是最重要的指标。

---

# 22. 一句话产品定义

> **Cicada is an autonomous personal AI manager that manages my agents, machines, goals, ideas, and communication so I don't have to.**

中文：

> **Cicada 是替我管理 AI、机器、目标、想法和通信的自主个人 AI Manager，让我从持续的信息处理和任务监督中“金蝉脱壳”。**

---

# 23. 最终用户故事

我希望有一天，我可以只对手机说：

> “最近有没有什么值得我做的？”

Cicada 可以结合：

- 我的 Idea；
- 我的 Goal；
- 我的项目；
- 我的机器；
- 我的时间；
- 外部世界的新变化；
- 合作者的进展；

回答：

> “有两件。第一件我已经可以自己开始，不需要你参与；第二件需要你先做一个选择。”

我说：

> “第一件你去做。第二件晚上再提醒我。”

然后把手机放回口袋。

**这就是 Cicada。**
