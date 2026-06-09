# Anti-Crack：软件防破解安全审计技能

一套软件安全审计提示词，`SKILL.md` 丢给任何 AI Agent 都能跑。从攻击者视角对客户端软件做 7大通用维度 × 9个平台专项 的全量审计，找出那些"改一行代码就绕过"的漏洞。没有 AI 也能当手动检查清单用。

## 它能查什么

| 维度 | 检查内容 |
|------|---------|
| 🔑 激活码验证 | 有没有 `if (isDev) return true` 这种门控？改一行就过？ |
| 💾 本地存储 | license 信息是不是明文？删掉 config 重新打开能用吗？ |
| 🖥️ 机器指纹 | 一码多机？换个电脑也能用？ |
| 🌐 服务端验证 | 只在启动时验一次？每次核心操作前验不验？ |
| 🐛 DevTools | Electron 生产环境还能 F12？调试端口开着？ |
| 📦 后端脚本 | Python 脚本能脱离 App 直接 `python xxx.py` 跑？ |
| 🔌 离线攻击 | 改 hosts 指向 127.0.0.1 就能绕过？断网无限用？ |

**加上 9 个平台专项**：Electron / iOS / Android / Flutter & RN / Go & Rust & C++ / .NET & C# / CLI 工具 / 游戏 / 联网通信 & 服务端配合

## 使用方式

`SKILL.md` 就是一套完整的审计提示词，和 AI Agent 无关。三种用法：

### 方式一：任何 AI Agent（通用）

直接把 `SKILL.md` 的内容粘贴给 ChatGPT、Claude、OpenClaw、Codex、Cursor 等任意 AI，然后：

> "按照上面的审计流程，检查我项目 `~/my-app/` 的安全漏洞"

AI 会按提示词里定义的 7+9 维度逐文件扫描。

### 方式二：Claude Code（原生技能）

```bash
git clone https://github.com/sundaygod1207/anti-crack-skill.git
mkdir -p ~/.claude/skills/anti-crack
cp anti-crack-skill/SKILL.md ~/.claude/skills/anti-crack/
```

然后在 Claude Code 中直接说"安全审计"即可自动加载。

### 方式三：人工检查清单

没有 AI 时，打开 `SKILL.md`，按里面的检查项逐条对照你的代码审查。

## 核心哲学

**假设攻击者能读到你的全部源码。**

代码混淆、加壳、反调试只是拖时间。AI 攻击者能在 5 分钟内读完你所有代码并找到所有漏洞。唯一真正的防线在**服务端**。

## 最容易被攻击的 10 个点

1. 开发模式放行 — `if (dev) skipAuth()`
2. 本地存储明文 — `config.json` 写 `licenseValid: true`
3. 断网绕过 — hosts 屏蔽验证服务器
4. 源码无保护 — asar/jadx/dnSpy 解包即得源码
5. DevTools 开着 — F12 控制台随便调
6. 无机器绑定 — 一个码全群共享
7. 无限流 — 暴力枚举激活码
8. 前端判断权限 — F12 改个变量就过
9. 时间本地判断 — 改系统时间绕过过期
10. 二进制泄露 — `strings ./binary | grep sk-` 找到 API Key

## 平台死穴速查

| 平台 | 致命弱点 | 一句补救 |
|------|---------|---------|
| Electron | asar 解包 = 源码全暴露 | 不存密钥，核心在服务端 |
| iOS | 越狱 + Frida = 函数全可控 | SSL Pinning + 越狱检测 + 服务端验证 |
| Android | jadx 反编译 + 重签名 | ProGuard + Native .so + Play Integrity |
| Flutter/RN | snapshot/bundle 提取分析 | Native 层放核心逻辑 |
| Go/Rust/C++ | `strings` + Ghidra 定位授权 | 去符号 + 服务端为唯一防线 |
| .NET/C# | dnSpy 反编译回 C# 源码 | NativeAOT 或服务端验证 |
| CLI/npm | `npm install` = 源码到手 | 价值在后端 API |
| Unity | Mono DLL → dnSpy 还原源码 | IL2CPP + 重要逻辑服务端 |

## 联系作者

📱 **微信 / 手机**：17600560007

## 付费咨询服务

我提供 AI Agent 全方面的付费咨询，包括但不限于：

- 🤖 **AI Agent 开发**：Claude Code / OpenClaw / Codex 等平台的智能体定制
- 🔧 **AI 软件开发**：帮你用 AI Agent 自动化业务流程、搭建内部工具
- 🛡️ **软件安全审计**：用本仓库的 anti-crack 方法论对你的产品做深度审计
- 💡 **技术咨询**：AI Agent 选型、架构设计、Claude Code 技能编写
- 🏗️ **定制开发**：根据你的需求，从零构建专属 AI 软件或智能体

有需要直接微信联系，备注来意。

## License

MIT
