---
name: anti-crack
description: Anti-crack audit for client software. 防破解安全审计——保护客户端软件不被盗版、逆向、破解。覆盖 Electron/iOS/Android/Flutter/Go/Rust/C++/.NET(WPF/WinForms)/CLI/游戏等客户端平台，含联网通信和服务端配合防御，7大通用维度 + 10大平台专项。
---

# 软件安全审计 Skill

对客户端软件（Windows/Mac/Linux 桌面、iOS/Android 移动端、跨平台 App、编译型可执行程序、CLI 工具、游戏）做全面的防破解安全审计。目标是保护基于激活码/订阅/内购的客户端商业模式不被破解和盗版。

## 使用方式

用户说"检查安全""安全审计""查漏洞""防破解""加固"等关键词时调用本 Skill。

## 审计流程

⚠️ **审计前必须先做回归验证（见维度〇）**，避免之前修过的漏洞被新代码重新引入。

对每个文件逐行读，以攻击者视角完成以下 **7+9 个维度** 的检查：

1. **通用维度（所有平台）**：激活码验证 → 本地存储 → 机器指纹 → 服务端验证 → DevTools/调试 → 后端脚本保护 → 离线攻击
2. **平台专项**：根据软件类型对应检查（Electron / iOS / Android / Flutter / Go-Rust-C++ / CLI / Games / 联网通信 / 服务端配合）

---

## 〇、修复后回归验证（每次审计前必做）

修完漏洞后重新审计时，**先验证**上次报告中的 🔴 和 🟡 项是否仍然修复到位。常见回归模式：

| 回归类型 | 例子 | 检查方式 |
|----------|------|----------|
| 函数名写错 | 上次创建了 `verifyLicense`，新代码调用了 `verifyLicenseOnline`（未定义） | grep 所有新增函数调用，确认被调用方存在 |
| 属性名写错 | config 存为 `licenseCode`，代码访问 `config.license.code` | 对比 save 和 load 的 key 名是否一致 |
| 路径残留 | 上次改了 `<script src="app.js">`，新 HTML 又写回 `js/app.js` | 提取构建产物，grep 确认旧路径不存在 |
| 令牌绕过复活 | 上次删了 `--test-key` 的 `if not args.test_key`，新代码又加回去 | grep 搜索所有跳过验证的条件分支 |
| 环境变量 vs CLI | 上次把 `--license-token` 改为 `MY_APP_TOKEN` 环境变量，Python 端还在读 `args.license_token` | 对比 JS 传递方式和 Python 接收方式 |

**关键原则**：修复后不光看改了的那几行——要从构建产物中验证最终效果。

---

## 一、激活码验证链路

### 检查清单

| # | 检查项 | 看什么 |
|---|--------|--------|
| 1.1 | 开发模式放行 | 有没有 `if (!electronAPI)` / `isDev` / `DEBUG` 等无条件放行逻辑？必须删除 |
| 1.2 | 本地优先验证 | 是否先读本地缓存就放行，再后台验证？必须先调服务端 |
| 1.3 | Boolean 门控 | 有没有 `licenseValid = true` 这种单点判断？攻击者改一行就过 |
| 1.4 | 关键操作验证 | 每次执行核心功能（生成/导出/计算）前是否重新验证？不是只在启动时验一次 |

### 标准做法

```
激活流程：
1. 用户输码 → 调服务端 /verify（携带机器指纹）
2. 服务端返回 {valid, remaining_days} → 客户端加密存储
3. 每次启动 → 静默调服务端重验证 → 失败则锁定
4. 每次核心操作 → 再次调服务端验证（即使 UI 已显示"已激活"）
```

---

## 二、本地存储安全

### 检查清单

| # | 检查项 | 看什么 |
|---|--------|--------|
| 2.1 | 存储加密 | config.json、license 信息是否明文？必须 AES-256 加密，密钥来自机器指纹 |
| 2.2 | 计数器保护 | 使用次数/额度是否明文？攻击者改 0 就无限用 |
| 2.3 | 旧版兼容回退 | 有没有 "如果解密失败就用明文读" 的逻辑？升级后必须删除 |
| 2.4 | 存储位置 | iOS: Keychain; Android: EncryptedSharedPreferences; 桌面: 加密文件 |
| 2.5 | 删除重建 | 删掉 config 文件重新打开 → 能否绕过？必须服务端记录激活状态 |

### 标准做法

```javascript
// 加密：密钥 = SHA256(机器指纹)
function encryptConfig(obj) {
  const key = sha256(getMachineId());
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  return base64(iv + cipher.update(JSON.stringify(obj)) + cipher.final());
}

// 解密失败 = 配置作废，不读明文
function decryptConfig(str) {
  try { /* AES decrypt */ return JSON.parse(...); }
  catch { return null; } // 不 fallback 到明文
}
```

---

## 三、机器指纹绑定

### 检查清单

| # | 检查项 | 看什么 |
|---|--------|--------|
| 3.1 | 指纹因子 | 是否包含硬件信息？最少需要：hostname + MAC + 硬盘序列号 + 用户名 |
| 3.2 | 指纹传递 | 服务端验证时是否发送机器指纹？header: `x-machine-id` |
| 3.3 | 绑定数量 | 一码几机？建议一码一机。多机需服务端限制上限 |
| 3.4 | 指纹稳定性 | MAC 是否取第一个非虚拟网卡？硬盘 ID 是否用 `fs.statSync`？ |
| 3.5 | 跨平台一致性 | Windows/Mac/Linux 是否用相同的因子采集逻辑？ |

### 标准做法

```javascript
function getMachineId() {
  const mac = getFirstPhysicalMac();
  const diskId = fs.statSync(homeDir).dev;
  const seed = `${hostname}|${mac}|${username}|${platform}|${diskId}`;
  return sha256(seed);
}
```

**注意**：
- 排除虚拟网卡（Docker、VPN、VMware）
- MAC 地址为空时用硬盘序列号兜底
- Windows 上可用 `wmic diskdrive get serialnumber`

### ⚠️ 3.6 跨语言一致性（JS ↔ Python）

**这是最容易遗漏的漏洞**。当同一逻辑在 JS 和 Python 中分别实现时，必须逐行对比：

| 对比项 | 常见不一致 |
|--------|-----------|
| 平台标识 | `process.platform` → `'darwin'`（小写），`platform.system()` → `'Darwin'`（首字母大写）→ SHA-256 完全不同 |
| MAC 格式 | JS `os.networkInterfaces()` 返回 `'ac:de:48:...'`（冒号），Python `uuid.getnode()` 返回 `0xacde48...`（无冒号 hex） |
| 用户名 | JS `os.userInfo().username` vs Python `os.environ.get('USER','')` — 通常一致但非 100% |
| 因子顺序 | `hostname|mac|user|platform|disk` 必须完全一致，连分隔符都不能差 |

**修复原则**：**不要让 Python 自行计算机器指纹**。让 JS 计算好，通过环境变量传给 Python。Python 只做验证，不做计算。

---

## 四、服务端验证

### 检查清单

| # | 检查项 | 看什么 |
|---|--------|--------|
| 4.1 | HTTPS | 是否强制 HTTPS？有没有 `rejectUnauthorized: false`？ |
| 4.2 | 限流 | /verify 端点是否有频率限制？建议每 IP 每分钟 ≤10 次 |
| 4.3 | 绑定逻辑 | 首次激活绑定机器，换机需人工解绑。不要在客户端做绑定判断 |
| 4.4 | 状态管理 | 服务端能否吊销/停用激活码？后台是否有 is_active 字段？ |
| 4.5 | 过期处理 | 过期后返回明确状态码，客户端清除本地配置 |
| 4.6 | 错误信息 | 错误消息不泄露内部信息。对攻击者和合法用户返回同样的消息 |

### 标准做法

```javascript
// 服务端 /verify 端点
router.get('/verify', async (req, res) => {
  // 1. 限流检查
  if (!checkRateLimit(req.ip)) return res.status(429).json({...});

  // 2. 验证激活码
  const record = await ApiKey.findOne({ key: req.headers['x-api-key'] });
  if (!record || !record.is_active) {
    return res.json({ valid: false, message: '激活码无效' });
  }

  // 3. 机器绑定（一码一机）
  const machineId = req.headers['x-machine-id'];
  if (!record.device_id) {
    record.device_id = machineId; // 首次绑定
  } else if (record.device_id !== machineId) {
    return res.json({ valid: false, message: '激活码已在其他设备使用' });
  }

  // 4. 过期检查
  const days = calcRemainingDays(record.expires_at);
  return res.json({ valid: true, remaining_days: days });
});
```

---

## 五、DevTools 与调试防护

### 检查清单

| # | 检查项 | 看什么 |
|---|--------|--------|
| 5.1 | 生产环境 DevTools | `webPreferences.devTools: false` 或 `app.isPackaged` 时禁用 |
| 5.2 | WebView 调试 | Android: `WebView.setWebContentsDebuggingEnabled(true)` 必须在生产关闭 |
| 5.3 | 控制台注入 | `contextIsolation: true` + `nodeIntegration: false` 是否设置？ |
| 5.4 | preload 暴露面 | preload.js 是否只暴露必要 API？不暴露 `require` 或 `process` |
| 5.5 | 错误信息 | console.log 是否泄露密钥/机器码/激活码？生产环境禁用 console |

### 标准做法

```javascript
// Electron
if (app.isPackaged) {
  mainWindow.webContents.on('devtools-opened', () => {
    mainWindow.webContents.closeDevTools();
  });
}

// Android
// 删掉或条件编译：
// WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG);
```

---

## 六、后端脚本与资产保护

### 检查清单

| # | 检查项 | 看什么 |
|---|--------|--------|
| 6.1 | 直接调用 | Python/Node 脚本能否脱离 App 直接 `python3 xxx.py` 运行？ |
| 6.2 | 参数注入 | 脚本是否接受命令行参数？能否被传恶意参数？ |
| 6.3 | 会话令牌 | Electron 启动 Python 时是否传一次性令牌？Python 是否验证？ |
| 6.4 | 令牌有效期 | 令牌是否有时效（建议 5 分钟）？是否绑定机器指纹？ |
| 6.5 | 提示词/模型 | 核心 IP（Prompt、模型配置）是否明文存储？base64 不算加密 |
| 6.6 | 密钥管理 | 签名密钥是否在两个文件中各存不同片段？单个文件泄露不能推完整密钥 |
| 6.7 | 包体提取 | APK/DMG 解包后能否直接复制走核心文件？ |
| 6.8 | 代码正确性 | 🔑 所有被调用的函数是否真实存在？属性名是否与存储时一致？ |

### 6.8 代码正确性验证（新增）

安全功能代码写错了 = 安全功能不存在。必须检查：

```
1. 函数存在性：grep 每个函数调用，确认被调用方已定义
   反面案例：调用了 verifyLicenseOnline(code) 但函数从未定义 → ReferenceError
   
2. 属性名一致性：对比 save 和 load 的 key 名
   反面案例：save 时存 config.licenseCode = 'xxx'，load 时读 config.license.code → undefined

3. 环境变量 vs 命令行参数：对比 JS 传递方式和 Python 接收方式
   反面案例：JS 用 env.MY_APP_TOKEN 传，Python 读 args.license_token → 永远为空
```

### 标准做法

```
Electron 端生成令牌 → 传 --license-token → Python 端验证

令牌 = HMAC-SHA256(machineId + timestamp, SECRET_KEY)
- SECRET_KEY 拆成 A+B 两半，JS 存 A+B 拼接，Python 存 B+A 拼接
- Python 验证：超时(5分钟)拒绝、签名不匹配拒绝
- 测试模式(--test-key)可以跳过令牌，但只允许测试 API Key 连接
```

---

## 七、离线与网络攻击

### 检查清单

| # | 检查项 | 看什么 |
|---|--------|--------|
| 7.1 | hosts 屏蔽 | 改 /etc/hosts 指向 127.0.0.1 能否绕过验证？ |
| 7.2 | 离线宽限期 | 断网后能用多久？建议最多 7 天，超时强制联网 |
| 7.3 | MITM | HTTPS 证书是否验证？有没有自定义 CA？ |
| 7.4 | 重放攻击 | 验证请求能否被抓包重放？令牌应包含时间戳 |
| 7.5 | 本地时间篡改 | 改系统时间能否延长试用期？令牌验证用绝对时间戳 |

### 标准做法

```javascript
// 离线宽限期最多 7 天
const graceDays = Math.min(saved.remainingDays, 7);
// 令牌带时间戳
const token = { ts: Date.now(), sig: hmac(...) };
// Python 验证时间窗口
if (Math.abs(now - token.ts) > 5 * 60 * 1000) reject('token expired');
```

---

## 平台专项

### 一、Electron 桌面（Mac/Windows/Linux）
- 检查 `package.json` 的 `build` 配置：asar 打包、extraResources 暴露面
- `contextIsolation: true` + `nodeIntegration: false` 必须设置
- `webSecurity: true` 不要关闭
- asar 不是加密，只是打包——`npx asar extract app.asar /tmp/` 即可解出全部源码
- macOS 签名缺失时用户可右键打开绕过，不是防线；Windows NSIS 安装包可 7-Zip 解压

### 二、iOS Native（Swift / Objective-C）
| 检查项 | 看什么 |
|--------|--------|
| 越狱检测 | 是否检测 Cydia/Substrate 等越狱环境？建议多重检测（文件 + dyld + URL scheme） |
| App Store 收据验证 | 是否验证 `appStoreReceiptURL`？本地验证服务端都应做 |
| 调试检测 | 是否检测 `PT_DENY_ATTACH`、`sysctl` 反调试？ |
| 代码签名 | 是否检查 `SecCodeCheckValidity` 防止重签名？ |
| 鱼钩检测 | 是否检测 Frida / Cydia Substrate hook 框架？ |
| 存储 | 敏感数据是否用 Keychain（非 UserDefaults）？Keychain 的 accessibility 是否设为 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`？ |
| 网络 | 是否 SSL Pinning 防止 Charles/Proxyman 抓包？ |

**常见攻击**：越狱手机 + Frida hook 绕过内购验证、重签名 IPA 分发到非越狱设备、ProxyMan 抓 API 接口后写脚本调用。

### 三、Android Native（Kotlin / Java）
| 检查项 | 看什么 |
|--------|--------|
| Root 检测 | 是否检测 su 二进制、Magisk、SuperSU？建议 SafetyNet / Play Integrity |
| 混淆 | ProGuard/R8 是否启用？`minifyEnabled true`？混淆规则是否过度保留？ |
| 加固 | 是否考虑 360 加固/腾讯乐固等？ |
| 模拟器检测 | 是否检测 QEMU/Genymotion 特征？ |
| 反调试 | `android:debuggable="false"` + 是否检测 `Debug.isDebuggerConnected()`？ |
| 签名校验 | 是否用 `PackageManager.GET_SIGNING_CERTIFICATES` 防重签名？ |
| 存储 | 敏感数据是否用 `EncryptedSharedPreferences`？Key 是否硬编码在代码里？ |
| Native 层 | 核心逻辑是否移到 JNI .so 里（ida pro 反编译难度 >> jadx 反编译 Java）？ |
| Frida 检测 | 是否检测 Frida 默认端口 27042 或 frida-server 进程？ |

**常见攻击**：jadx-gui 反编译 APK → 搜 "license" "valid" "key" → 改 smali → 重打包；Magisk + LSPosed 注入模块；Frida hook 关键函数返回值。

### 四、Flutter / React Native（跨平台移动端）
| 检查项 | 看什么 |
|--------|--------|
| Dart 混淆 | Flutter: `--obfuscate --split-debug-info` 是否开启？ |
| JS Bundle | React Native: Hermes 引擎是否开启？bundle 是否加密？ |
| 代码提取 | APK/IPA 解包后 assets 里的 Dart snapshot / JS bundle 是否可直接读取？ |
| 平台通道 | 核心逻辑是否下放到 Native 层（Kotlin/Swift）绕过 Dart/JS 层的可读性？ |
| 热更新 | CodePush/Shorebird 等热更新通道是否可能被劫持下发恶意代码？ |
| 本地存储 | 是否使用对应平台的加密存储而非 AsyncStorage/SharedPreferences 明文？ |

**常见攻击**：解包提取 Dart kernel blob → 用 darter/kernel_snapshot 工具分析；React Native bundle 直接读 JS 源码；平台通道 hook 截获 Dart↔Native 通信。

### 五、Go / Rust / C++ 编译型语言
| 检查项 | 看什么 |
|--------|--------|
| 符号表 | 二进制是否 `strip` 过？`go build -ldflags="-s -w"` 去除调试信息？ |
| 字符串 | API Key、密钥等敏感字符串是否在二进制中明文？`strings binary \| grep sk-` |
| 反编译 | Go: `go tool objdump` 可直接反汇编；Rust: debug builds 信息量极大 |
| 调试保护 | Linux: `ptrace(PT_DENY_ATTACH)`；macOS: `PT_DENY_ATTACH`；Windows: `DebugActiveProcessStop`？ |
| 校验和 | 二进制是否自校验 CRC/SHA 防篡改？ |
| 加壳 | 是否考虑 UPX/VMProtect/Themida 等？ |
| 许可证 | License 校验逻辑是否容易在 IDA Pro / Ghidra 中定位（搜 "invalid" "expired" 字符串）？ |

**关键原则**：编译型语言虽然比脚本语言难以逆向，但 `strings` + `objdump` + Ghidra 仍能 30 分钟内找到许可证校验点。核心防线仍在服务端。

### 六、.NET / C# 桌面应用（WPF / WinForms / MAUI）

C# 桌面软件在国内企业应用极广（进销存、ERP、OA），dnSpy 几乎能逐行还原源码，是**最容易被逆向的编译型语言**。

| # | 检查项 | 看什么 |
|---|--------|--------|
| 6.1 | 反编译 | IL → dnSpy/ILSpy/dotPeek 能否还原出完整 C# 源码？几行代码改掉就重编译绕过 |
| 6.2 | 混淆 | 是否用 ConfuserEx/Obfuscar/.NET Reactor/SmartAssembly 混淆？混淆强度是否够？ |
| 6.3 | Native AOT | 是否启用 NativeAOT（.NET 7+）编译为本机代码而非 IL？AOT 后 dnSpy 无效，只能走 IDA/ Ghidra |
| 6.4 | ReadyToRun | 是否用 R2R 预编译？效果不如 AOT 但仍增加逆向难度 |
| 6.5 | 强名称 | 程序集是否有强名称签名？但强名称防篡改有限——可剔除后重编译 |
| 6.6 | 许可逻辑 | 许可证校验函数是否容易被定位？dnSpy 里搜 "License" "Activate" "Trial" 立刻找到 |
| 6.7 | 序列号算法 | 激活码生成算法是否在客户端？dnSpy 反编译出算法 → 写注册机 |
| 6.8 | 配置文件 | `App.config` / `appsettings.json` 是否明文存 license key？ |
| 6.9 | 单文件发布 | .NET 8+ SingleFile 打包是否被提取？`dotnet-sdk` 工具可解压单文件包 |
| 6.10 | 代码完整性 | 是否校验自身 DLL 的 SHA 防替换？攻击者改掉 `LicenseValidator.dll` 直接替换 |
| 6.11 | ClickOnce | 是否用 ClickOnce 部署？`.application` 文件可被篡改指向恶意更新服务器 |
| 6.12 | 调试检测 | 是否检测 `Debugger.IsAttached`？是否检测 dnSpy/ILSpy 进程？ |
| 6.13 | MAUI/Avalonia | 跨平台 .NET 的 Native 层是否单独加固？ |

**常见攻击链**（30 分钟完成）：
```
dnSpy 打开主程序 .exe → 搜 "License" → 找到 ValidateLicense(string key)
→ 右键 "Edit Method" → 改成 return true → 编译 → 保存为新 .exe
→ 破解完成，分发给任何人。
```

**补救措施**：
1. **NativeAOT**（最有效）：把 C# 编译成本机代码，dnSpy 直接失效
2. **.NET Reactor / VMProtect**：核心校验方法用虚拟机保护
3. **服务端验证**：激活码校验逻辑放服务端，客户端只传参数
4. **完整性自检**：启动时对自己和所有 .dll 做 SHA-256 校验，篡改则静默退出

### 七、CLI 工具 / npm 包 / pip 包
| 检查项 | 看什么 |
|--------|--------|
| 源码暴露 | npm/pip 包发布后源码完全透明——所有加密、混淆在最终用户机器上都可被读 |
| License 验证 | npm 包中的 key 验证逻辑是否在用户机器上执行？等于没有 |
| 环境变量 | API Key 是否强制用户设环境变量而非打包在代码里？ |
| 依赖安全 | `npm audit` / `pip audit`：供应链攻击（恶意依赖包）也是盗版入口 |
| 安装时脚本 | `postinstall` 脚本是否可能被利用？ |
| 分发控制 | 是否通过私有 registry（npm private / private pypi）控制分发？ |

**关键认知**：CLI/package 形式的软件，源码 100% 暴露。唯一的防盗手段是：软件本身是客户端，核心价值在服务端 API（如 OpenAI SDK → API Key 在服务端计费）。

### 八、游戏（Unity / Unreal / Godot）
| 检查项 | 看什么 |
|--------|--------|
| IL2CPP | Unity: 是否用 IL2CPP 替代 Mono？Mono 的 C# DLL 可被 dnSpy 直接反编译回源码 |
| 内存修改 | 金币/血量等数值是否在客户端做权威判断？必须服务端校验 |
| 存档保护 | 本地存档是否签名防篡改？PlayerPrefs 明文修改是入门级攻击 |
| 加速器 | 是否检测 SpeedHack / GameGuardian 等工具？ |
| 内购验证 | Google Play / App Store 收据是否服务端二次验证？本地验证不够 |
| Unreal | .pak 文件是否加密？`aes.key` 是否在二进制中明文？ |
| Godot | .pck 文件是否加密？GDScript 是否编译为 Godot 二进制格式？ |
| 多人游戏 | 权威逻辑是否在服务端？客户端只做表现层？ |
| Mod 注入 | 是否检测未签名 DLL/so 注入？ |

**游戏特殊风险**：破解版游戏 = 修改 APK 去除授权 + 解锁内购 + 修改存档。单机游戏几乎无法防破解，唯一出路是重要的玩法逻辑放服务端（即使是"单机"游戏也做 online-only 验证）。

### 九、客户端联网通信安全（客户端 ↔ 服务端）

绝大多数客户端软件都需要连接服务端（激活验证、内购收据、API 调用、数据同步）。攻击者会从客户端与服务器之间的通信链路下手。

| # | 检查项 | 看什么 |
|---|--------|--------|
| 8.1 | HTTPS 强制 | 客户端是否强制 HTTPS？有没有 HTTP 降级回退？`NSAppTransportSecurity`（iOS）是否开了 HTTP 例外？ |
| 8.2 | SSL Pinning | 客户端是否做了证书锁定（Certificate/Public Key Pinning）？没有 pinning = Charles/Proxyman/mitmproxy 直接抓包看明文请求 |
| 8.3 | 证书校验 | 是否 `rejectUnauthorized: false`（Node.js）或自定义 TrustManager 接受所有证书（Android）？必须删掉 |
| 8.4 | 请求签名 | 客户端发出的请求是否有 HMAC 签名？签名密钥是否在客户端代码里明文？签名是否包含时间戳防重放？ |
| 8.5 | Token 传输 | JWT/Token 是否通过 Header 传输？是否存 Keychain（iOS）/ EncryptedSharedPreferences（Android）而非 UserDefaults/SharedPreferences 明文？ |
| 8.6 | API 端点隐藏 | 客户端代码中所有 API URL 是否硬编码明文？攻击者 `strings` / `grep` 就能拿到全部接口列表 |
| 8.7 | 重放攻击 | 令牌/请求是否包含时间戳 + nonce？服务端是否验证时间窗口？抓包重放激活请求能否绕过？ |
| 8.8 | 代理检测 | 客户端是否检测系统代理、VPN、Fiddler/Charles 等抓包工具？代理开启时是否拒绝核心操作或报警？ |
| 8.9 | 响应篡改 | 服务端返回的 `{valid: false}` 能否被改包工具改成 `{valid: true}`？客户端是否用 HMAC 验证服务端响应完整性？ |
| 8.10 | 限流绕过 | 攻击者能否不断换 IP/换 Token 对 /verify 端点暴力枚举激活码？ |

**关键原则**：
- **客户端发出的请求必须签名**（HMAC），服务端验证签名 + 时间窗口
- **服务端返回的响应必须签名**，客户端验证——防止改包工具篡改服务端返回值
- **单一客户端被攻破 ≠ 所有接口暴露**：每个客户端实例用独立设备密钥签名，即使一个被抓包也不影响其他用户
- 攻击工具链：Charles/Proxyman 拦截 → 改请求/响应 → 重放 → 写脚本自动化。每步都要防

### 十、服务器端配合防御（客户端视角出发）

客户端防破解不能只靠客户端——必须联合服务端。以下是从客户端安全出发，服务端需要配合做的事。

| # | 检查项 | 看什么 |
|---|--------|--------|
| 9.1 | 每次核心操作验证 | 客户端执行关键功能（生成/导出/保存）前，是否调服务端重验证？不是只在启动时验一次 |
| 9.2 | 设备指纹上报 | 客户端是否每次请求都上报设备指纹 hash？服务端是否检测同一账号多设备并发？ |
| 9.3 | 激活码绑定 | 服务端是否记录首次激活的设备指纹？换机是否需人工解绑？一码一机还是一码几机？ |
| 9.4 | 离线宽限期 | 断网后客户端能用多久？服务端是否记录上次在线时间？超限是否锁定？ |
| 9.5 | 版本检查 | 客户端启动时是否上报版本号？服务端是否阻止过旧版本（已知破解版本）连接？ |
| 9.6 | 使用行为分析 | 服务端是否分析请求模式？同一用户 24h 不间断使用 + 多 IP 同时在线 = 账号共享/破解迹象 |
| 9.7 | 吊销机制 | 服务端是否有能力立即吊销某个激活码/设备？客户端下次联网验证时是否立即锁定？ |
| 9.8 | 脚本检测 | 请求时序是否有人类操作特征？API 调用间隔是否过短（< 1s）？是否无 GUI 操作直接调核心接口？ |
| 9.9 | 响应签名 | 服务端返回的关键数据（`remainingDays`、`licenseValid`）是否带 HMAC 签名？客户端是否验证？ |

**核心思路**：客户端是"不可信的前哨"，服务端是"唯一的真相来源"。客户端做的所有判断，服务端都要再验证一遍；服务端说的每句话，客户端都要验证签名防篡改。

---

## 八、通用防线技术（跨平台适用）

### 8.1 代码混淆与反逆向

| 技术 | 适用场景 | 效果 |
|------|---------|------|
| 符号混淆 | Go/Rust/C++ | `-s -w` 去除符号，降低 IDA 可读性 |
| 字符串加密 | 所有语言 | 敏感字符串在二进制/字节码中动态解密，而非明文 |
| 控制流混淆 | C/C++/Java | OLLVM/ProGuard 打乱控制流，增加逆向难度 |
| 完整性校验 | 所有平台 | 启动时校验自身/资源文件 CRC，检测篡改 |
| 反调试 | Native | 检测 ptrace/LDR/Debugger，检测到 → 退出或喂假数据 |
| 虚拟化 | 高价值应用 | VMProtect/Themida 把核心代码编译为自定义 VM 字节码 |

**但记住**：混淆只是拖时间，不是防线。决心够强的攻击者总能破解。最终防线永远是服务端。

### 8.2 账号共享对抗

| 技术 | 说明 |
|------|------|
| 设备数限制 | 服务端记录激活的设备指纹数，超出阈值拒绝新设备或要求旧设备下线 |
| 并发检测 | 同一 token 同时从不同 IP/设备发起请求 → 标记可疑 |
| 地理位置异常 | 5 分钟内北京→纽约同时使用 → 不可能，判定共享 |
| 使用模式 | 24 小时不间断使用 vs 正常人作息 → 可能是多人轮流用 |
| 心跳机制 | 客户端定时发心跳，服务端检测同一账号多心跳源 |

### 8.3 时间篡改对抗

| 技术 | 说明 |
|------|------|
| NTP 对时 | 客户端取 NTP 时间而非系统时间做有效期判断 |
| 服务端时间戳 | 所有有效期判断在服务端用绝对时间戳完成 |
| 单调递增记录 | 本地记录服务端每次返回的时间，如果新返回时间 < 上次记录 → 检测到时钟回拨 |
| 过期宽限期 | 7 天宽限 + 超时必联网，限制离线攻击窗口 |

### 8.4 API 滥用防护

| 技术 | 说明 |
|------|------|
| 令牌设计 | HMAC(timestamp + machineId + nonce) 防重放；5 分钟有效期 |
| 客户端指纹 | 请求附带设备指纹 hash，服务端同一指纹异常高频 → 限流 |
| 渐进式限流 | 1/min → 10/hour → 100/day，逐层触发，不要只设一个固定值 |
| 客户端校验 | 服务端可要求客户端对参数做 HMAC 签名，提高脚本门槛 |
| 验证码 | 异常检测时触发 captcha（Cloudflare Turnstile 等无感验证） |

### 8.5 不同分发模式的安全基线

| 分发模式 | 被盗风险 | 核心防线 |
|----------|---------|----------|
| 开源 CLI 工具 | 极高（源码完全透明） | 服务端 API Key 计费 → 本地只是客户端 |
| npm/pip 包 | 极高（`npm install` 即得源码） | 同上，或核心逻辑在私有后端 |
| 免费 App | 高（解包即得代码） | 服务端验证 + 账号体系 |
| 买断制桌面软件 | 中高（激活码可被共享） | 设备绑定 + 换机需审核 + 服务端每次操作验证 |
| 内网/企业部署 | 中（代码在客户服务器上） | 合约约束 + 使用审计日志 + 定期 License 文件续期 |
| 纯在线游戏 | 低（权威逻辑在服务端） | 客户端只是个渲染器 |
| 纯单机游戏 | 极高（离线 = 无防线） | 接受现实，用 Denuvo 等商业方案拖首发窗口 |

---

## 审计报告格式

完成检查后，输出三层报告：

```
## 安全审计报告

### ✅ 已安全（列出通过的检查项）

### 🔴 必须修复（列出严重漏洞，每条包含：漏洞描述、攻击方式、修复建议）

### 🟡 建议加固（列出中等风险项）

### 优先级排序（按严重度×修复成本排序）
```

---

## 经验总结

### 最容易被攻击的点（按频率排序，跨平台通用）

1. **开发模式放行** — 几乎所有项目都留了 `if(dev) skipAuth()`，AI 一眼就找到
2. **本地存储明文** — config.json / SharedPreferences 存 `licenseValid: true`，改一个字就破解
3. **断网绕过** — hosts 文件屏蔽验证服务器，客户端就信本地缓存
4. **源码无保护** — Python .py、Node .js、C# DLL (Mono)、Dart snapshot 解包即得源码
5. **DevTools/调试开着** — Electron控制台、Android WebView调试、iOS Xcode attach 直接调函数
6. **无机器绑定** — 一个激活码全群共享
7. **无限流** — 暴力枚举激活码、API 被脚本无限调用
8. **前端判断权限** — `if(user.vip) { showButton() }` 被浏览器 F12 改个变量就过
9. **时间本地判断** — `if(Date.now() < expireTime)` 被改系统时间绕过
10. **二进制字符串泄露** — `strings ./binary | grep sk-` 找到 API Key

### 不同平台的"死穴"

| 平台 | 致命弱点 | 一句补救 |
|------|---------|---------|
| Electron | asar 解包 = 源码全部暴露 | 不存密钥，核心在服务端 |
| iOS | 越狱 + Frida = 函数全可控 | SSL Pinning + 越狱检测 + 服务端收据验证 |
| Android | jadx 反编译 + 重签名 = 改完重新上架 | ProGuard + Native .so + Play Integrity |
| Flutter/RN | snapshot/bundle 提取 + 分析 | Native 层放核心逻辑，Dart/JS 只做 UI |
| Go/Rust/C++ | `strings` + Ghidra 定位授权逻辑 | 去掉调试符号 + 服务端验证为唯一防线 |
| CLI/npm | `npm install` = 源码到手 | 价值在后端 API，CLI 只是薄客户端 |
| Unity 游戏 | Mono DLL → dnSpy 反编译回 C# 源码 | IL2CPP + 重要逻辑服务端 |
| 联网通信 | Charles/Proxyman 抓包 = API 全暴露 + 改包篡改 | SSL Pinning + 请求和响应双签名 |
| 服务端配合 | 客户端被攻破后服务端无感知 = 破解版本大规模传播 | 设备指纹 + 行为分析 + 吊销机制 |

### 为什么需要多次审计？（修复后回归）

同一项目审计多次不是因为 skill 不完整，而是因为：

1. **修复引入回归** — 改了 A 文件，B 文件里引用的函数名/属性名没同步更新
2. **跨语言不一致** — JS 和 Python 各自实现的 `getMachineId()` 输出永远不同（`darwin` vs `Darwin`），HMAC 验签永远失败但无人发现
3. **代码正确性 ≠ 安全设计** — 安全方案设计对了，但代码写错了（调不存在的函数、读不存在的属性）

**教训**：每次修复后必须回归验证。不光验证修了什么，还要验证没修的部分没被改坏。

### 核心安全哲学

1. **客户端可被完全控制** — 所有客户端代码、存储、内存最终都能被攻击者操控。唯一防线在服务端。
2. **混淆不可靠** — 代码混淆、加壳、反调试只是拖时间，决心够强的攻击者总能突破。
3. **安全纵深防御** — 不要只靠一层防护。激活码验证 + 设备绑定 + 服务端重验证 + 使用行为分析，层层叠加。
4. **攻击成本 > 软件价值** — 不是要做到 100% 防破解，而是让破解成本高于软件售价或攻击者收益。
5. **源码透明假设** — 设计安全方案时就假设攻击者能读到全部源码。如果你的安全依赖"攻击者不知道算法"，那它已经被破解了。

记住：**AI 攻击者能在 5 分钟内读完全部源代码并找到所有上述漏洞。防御必须假设源码完全透明。**

---

## 联系作者

📱 **微信 / 手机**：17600560007

## 付费咨询

提供 AI Agent 全方面付费咨询与定制开发服务：

- **AI Agent 开发**：Claude Code / OpenClaw / Codex 等平台的智能体定制
- **AI 软件开发**：用 AI Agent 自动化业务流程、搭建内部工具
- **软件安全审计**：用本技能的方法论对你的产品做深度安全审计
- **技术咨询**：AI Agent 选型、架构设计、Claude Code 技能编写
- **定制开发**：根据需求从零构建专属 AI 软件或智能体

微信联系，备注来意。
