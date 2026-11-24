# 飞书 im.db 加密逆向分析总结

> 目标二进制：`com.larksuite.suite` 的 `lib/arm64-v8a/liblark.so`（Rust，剥离符号，SQLCipher 静态链接）
> 分析工具：IDA Pro + IDA MCP + Frida
> 最终目标：离线解密 `im.db`

---

## 一、最终结论

`im.db` 是 **SQLCipher** 加密库，密钥在运行时由本地两个标识现算，**不落盘**：

```
device_id = 文件内容  files/npth/RuntimeContext/did            → "7710123185600990993"
user_id   = 文件名     files/mmkv/<19位数字>                    → "7710125579177086504"

key       = md5(device_id + user_id)[:7]   小写 hex            → "9ee22ce"
库目录     = databases/sdk_storage/<md5(user_id)>/             → .../4245e6e0af0e71d614c9e4bc356d5ffd/
```

SQLCipher 加密参数（与旧 CN 版不同）：

```sql
PRAGMA key = '9ee22ce';
PRAGMA cipher_compatibility = 3;
PRAGMA cipher_use_hmac = OFF;
PRAGMA cipher_page_size = 1024;
PRAGMA cipher_memory_security = OFF;
```

### 离线复现（无需 hook，root 或全量备份即可）

```python
import hashlib

did = open("files/npth/RuntimeContext/did").read().strip()      # 设备 id
uid = "7710125579177086504"                                      # 从 files/mmkv/ 下列出的 19 位数字文件名

key  = hashlib.md5((did + uid).encode()).hexdigest()[:7]         # 9ee22ce
path = hashlib.md5(uid.encode()).hexdigest()                     # 4245e6e0af0e71d614c9e4bc356d5ffd
```

### 本地解密验证

```bash
sqlcipher im.db
sqlite> PRAGMA key = '9ee22ce';
sqlite> PRAGMA cipher_compatibility = 3;
sqlite> PRAGMA cipher_use_hmac = OFF;
sqlite> PRAGMA cipher_page_size = 1024;
sqlite> SELECT count(*) FROM sqlite_master;
```

> 注意：若 `im.db-wal` / `im.db-shm` 中有未 checkpoint 的数据，必须连同这两个文件一起拷贝到同目录再打开，否则会看到旧数据或空表。

---

## 二、逆向过程时间线

| 阶段 | 操作 | 结论 |
|---|---|---|
| 1 | 连接 IDA MCP，搜索 `im.db` 字符串 | 确认有数据库操作，定位 `sub_3BA7124` 等引用点 |
| 2 | 搜索 `PRAGMA` / `key` / `cipher_*` 字符串 | 确认是 SQLCipher，`PRAGMA key` 由 `sub_470D098` 执行（旧 CN 版） |
| 3 | 搜索 `lark_share::db::encryption_key` | 定位密钥派生模块 `lark-share/src/db/encryption_key.rs` |
| 4 | 追踪 OnceCell 缓存 | key 缓存在内存 `byte_4D72428`，磁盘仅有 `db-newkey-mark` 标记（旧版） |
| 5 | 追 "app secret" 来源 | `sub_44006D4` 从全局 `Lazy<Env>` 按 `"db-encryption"` 取 32 字节（旧版） |
| 6 | 写 Java hook 打印 `InitSDKRequest` 参数 | 崩溃：`Sdk.<clinit>` 过早触发 native loader |
| 7 | 改 native JNI hook `_initSDK(byte[])` | 抓到请求字节，**不含 secret**；`env` 只是 ONLINE 枚举 |
| 8 | 设备全盘搜索 `db-encryption` | 0 命中 → secret 纯内存，不落盘 |
| 9 | **换 IDA 载入的 .so**（旧 IDB 是 CN 版，设备是 suite 版） | 校验通过：`0x1795CC4` 是真函数，版本对齐 |
| 10 | 新版里 `db-encryption` / `db-newkey-mark` 字符串**全部消失** | 新版密钥链路变为纯 `device_factor` + device_id |
| 11 | hook `0x2CC7C60`（device_factor 读取/派生） | 看到 device_id 传入、输出 32 字节（中间值，每次不同） |
| 12 | 改 hook `sqlite3_key` / `sqlite3_exec` | 直接抓到 `PRAGMA key = '9ee22ce'` |
| 13 | 暴力验证公式 | `md5("7710123185600990993"+"7710125579177086504")[:7]` == `9ee22ce` ✅ |
| 14 | 定位 uid 落盘位置 | `files/mmkv/<uid>`（文件名即 uid，内容是 MMKV 密文） |

---

## 三、关键反编译代码 / 地址

> 地址分两套：**旧 CN 版 IDB**（最初分析的）和 **suite 版 IDB**（设备实际跑的，最终对齐的那套）。旧版地址对当前设备无效。

### suite 版（设备实际版本，最终有效）

| 符号 / 地址 | 含义 |
|---|---|
| `Java_com_bytedance_lark_sdk_Sdk__1initSDK` → `0x1795CC4` | JNI 入口，`SUB SP,SP,#0xC0` 正常序言；运行时偏移与 Frida 报的 `0x1795CC4` 吻合，是**版本对齐的判据** |
| `0x2CC7C60` | `device_factor` 读取 / 派生函数（1592 字节）：入参 `x1/x2 = device_id`（19 字节），`x3` 指向输出缓冲，返回长度 |
| `0x9F4167` / `0x9F4143` | 字符串 `lark_share::db::encryption_key` / `...:: DEVICE_FACTOR` |
| `0x9F41E2` | 字符串 `device_factor`（文件名） |
| `0x9F4000` 字符串块 | 同源日志：`clear cached devie_factor`、`device factor file not exists, use device id`、`retrive device_factor from different user: user_id=` |

### 旧 CN 版（早期分析，对设备无效，但理解架构有用）

| 地址 | 含义 |
|---|---|
| `0x4D72428` | key 的内存 OnceCell 缓存（.data 段初值全 0xFF） |
| `sub_4381DB8` | `encryption_key()` 主体，含 `app secret no init` 日志 |
| `sub_44006D4` | 从 `Lazy<Env>`(0x4D696B0) 按 `"db-encryption"` 取 32 字节；要求状态字节 `+0x78==2`（已初始化） |
| `sub_470D098` | 执行 `PRAGMA key`，同时设 `cipher_compatibility=4`、page_size=0x2000（旧版参数） |
| `sub_461D348` | `open_with_key(path, key)` → `sub_470D044` 组装 options → `sub_470D098` |
| `0x8AF02B` | 字符串 `db-newkey-mark`（新版已无此文件） |

---

## 四、hook 脚本清单

工作目录：`C:\Users\Administrator\Documents\Trae-CN\temp_20261120_03\`

| 文件 | 作用 | 状态 |
|---|---|---|
| `hook_initsdk.js` | hook `Sdk` 类，打印 `_initSDK` 字节流 / `getInitSetting` 入参；最终定位到 `InitSDKRequest` 不含 secret | 有效（最终版 v6 不卡主线程） |
| `hook_device_factor.js` | native hook `liblark.so+0x2CC7C60`，dump `x0/x3` 输出缓冲和 device_id 入参 | 有效 |
| `hook_sqlcipher_key.js` | 跨模块 hook `sqlite3_key` / `sqlite3_exec`，**直接抓 `PRAGMA key`**（最终拿到 `9ee22ce` 的脚本） | ✅ 最终有效 |
| `derive_test.ps1` | 本地用 `device_factor` / device_id 暴力试 md5/sha/hmac/截断，验证公式 | 有效 |
| `scan_df.js` | 内存扫描 device_factor 32 字节特征 + key 命中点 | 辅助（未用于最终结论） |

### 各脚本核心思路

#### 1. hook_initsdk.js

经历了多次迭代：

- **v1（崩溃）**：`Java.use('com.bytedance.lark.sdk.Sdk')` 在 spawn 阶段就解析类，触发 `Sdk.<clinit>` → `Thoth.<clinit>` → `com.bytedance.b.b.<clinit>`，而 native loader 尚未 `init`，抛 `com.bytedance.b.d: you should call init first`，进程崩溃。
- **v2（误报）**：改 native JNI 导出 hook，绕开 `<clinit>`。但 `InitSDKRequest$a` 没声明自己的 `toString`，`K.toString.overloads` 命中的是 `java.lang.Object.toString` 的同一 jmethodID，导致**全进程的 Object.toString 都被替换**，打出一堆无关对象（`androidx.core.content.res.e$a$2` 等）。
- **v3（卡死）**：hook `_initSDK(byte[])` 时，在 `implementation` 里同步做整段字节复制 + O(n²) 字符串拼接 + 递归 protobuf 解析 + 逐条 `console.log`，阻塞了主线程，App 停在初始化界面。
- **v6（最终）**：hook 体只记录参数，解析放 `setTimeout(0)`；字节解析默认关闭、限长 64KB；只打印前 256 字节。不再卡主线程。

最终确认：`InitSDKRequest` 全部字段已 dump，**没有任何 secret / app_secret 字段**，`env` 只是 ONLINE 枚举，`env_v2` 只有 type/unit/brand。

#### 2. hook_device_factor.js

native hook `liblark.so` 基址 + `0x2CC7C60`：

```javascript
var base = Module.findBaseAddress("liblark.so");
Interceptor.attach(base.add(0x2CC7C60), {
    onEnter: function(args) {
        this.x0 = args[0]; this.x1 = args[1]; this.x2 = args[2];
        this.x3 = args[3]; this.x8 = this.context.x8;
    },
    onLeave: function(retval) {
        // dump this.x3 指向的输出缓冲（前 48 字节）
        // x1/x2 是 device_id（19 字节 ASCII）
    }
});
```

关键发现：`x1/x2` 传入的是 19 字节的 device_id（`"7710125579177086504"`），`x3` 指向输出缓冲，函数返回 32 字节。但同一个 device_id 每次输出的 32 字节不同（因为还吃另一个"用途"输入），是中间值而非最终 key。

#### 3. hook_sqlcipher_key.js（最关键）

不再依赖 `liblark.so` 里易变的内部偏移，改为**按导出符号** hook SQLCipher 本身：

```javascript
function hookAll() {
    Process.enumerateModules().forEach(function(m) {
        ["sqlite3_key", "sqlite3_key_v2", "sqlite3_exec"].forEach(function(sym) {
            var p = Module.findExportByName(m.name, sym);
            if (p) {
                Interceptor.attach(p, {
                    onEnter: function(args) {
                        // sqlite3_exec: args[1] 是 SQL 字符串
                        // Rust 字符串无 \0 终止，必须用 readByteArray 而非 readCString
                        var buf = args[1].readByteArray(256);
                        // 取可打印前缀，遇 0x00 停
                    }
                });
            }
        });
    });
}
// 每 500ms 轮询，持续 90s，覆盖新加载的库
```

抓到的输出：

```
[sqlite3_exec #2] ptr=0x... 
  ascii: PRAGMA key = '9ee22ce'
  hex  : 505241474d41206b6579203d20273965653232636527
```

同时抓到完整加密参数：`cipher_compatibility=3`、`cipher_use_hmac=OFF`、`cipher_page_size=1024`、`cipher_memory_security=OFF`。

> 还发现同进程内有 `suite_drive_cypher.db` 等多个加密库，说明不止 im.db 一个。

---

## 五、踩过的坑（避免重走）

### 1. IDB 版本不对齐 ⚠️ 最关键

- 最初分析的是 `com.ss.android.lark`（CN 版），设备跑的是 `com.larksuite.suite`。
- 症状：`0x1795CC4` 在旧 IDB 里是 `DCB 0`、`Java_..._1initSDK` 是数据表条目而非代码。
- **判据**：`Java_com_bytedance_lark_sdk_Sdk__1initSDK` 必须是代码函数、运行时偏移必须落在函数序言（`STP`/`SUB SP`）上。
- 换对 .so 后，旧版的 `db-encryption` / `db-newkey-mark` / `app secret no init` 字符串**全部消失**，说明架构其实变了——之前在旧版上推出的"app secret + db-newkey-mark"结论对这台设备不成立。

### 2. `Java.use('Sdk')` 过早触发 `<clinit>`

- spawn 阶段就 `Java.use` 解析类 → 触发类初始化 → native loader 未 init → 崩溃。
- 解决：只在 App 自己加载完 Sdk 类后再延迟挂（`Java.enumerateLoadedClasses` 检测到后 `setTimeout` 6 秒），或直接走 native JNI 导出 hook（不碰 Java 类）。

### 3. `Object.toString` 被全局替换

- `InitSDKRequest$a` 没声明 `toString`，`K.toString.overloads` 命中 `java.lang.Object.toString` 的 jmethodID → 全进程 toString 被 hook。
- 解决：只 hook 类**自己声明**的方法（用 `K.class.getDeclaredMethods()` 过滤），或直接读 `toByteArray()`。

### 4. Rust 字符串无 `\0` 终止

- `readCString` 一直读到相邻堆内存，把 `/client/invite/...`、device_id 等无关数据一起读进来，污染 key 显示。
- 解决：`readByteArray(256)` + 逐字节取可打印前缀（遇 `0x00` 停），同时打印 ascii + hex。

### 5. Frida `implementation` 阻塞主线程

- 在 hook 体里同步做重活（大段内存复制 + 字符串拼接 + 递归解析 + 逐条 log）→ 初始化界面卡死。
- 解决：hook 体只记录，解析放 `setTimeout(0)` 交给脚本线程；字节处理默认关闭、限长。

### 6. uid 搜不到的原因

- 逐字节搜 555 个文件**内容**，`7710125579177086504` 零命中。
- 实际它不落盘文件内容，只出现在**文件名**（`files/mmkv/<uid>`）。
- 教训：搜索标识时，文件名和目录名也要一并考虑。

### 7. `device_factor` 是误导

- 35 字节文件（32 字节数据 + 3 字节尾），与 key 无直接哈希关系，是另一用途材料。
- 早期花了不少时间在它上面（hook `0x2CC7C60` 看到的 32 字节其实是中间派生值）。
- 真正的 key 只依赖 `did` + `uid` 的 md5 前 7 位。

---

## 六、架构理解

### 密钥派生链路（suite 版 5.2.33）

```
device_id (files/npth/RuntimeContext/did, 明文)
        +
user_id   (files/mmkv/<uid> 文件名, 运行时从 InitSDKRequest.user_id 注入)
        │
        ▼
md5(device_id + user_id)  [小写 hex, 无分隔符, 无盐]
        │
        ├── [:7]   → im.db 的 passphrase "9ee22ce"
        └── [0:32] → (不直接用，但 user_id 的 md5 用作存储目录名)

md5(user_id) → databases/sdk_storage/<32位hex>/  (按用户隔离)
```

### 与微信方案的对比

| 项 | 微信 | 飞书 suite 版 |
|---|---|---|
| 公式 | `md5(IMEI + uin)[:7]` | `md5(device_id + user_id)[:7]` |
| 前项来源 | IMEI（设备标识） | `files/npth/RuntimeContext/did`（设备标识） |
| 后项来源 | uin（账号） | `files/mmkv/<uid>` 文件名（账号） |
| 拼接方式 | 直接拼接，无分隔 | 直接拼接，无分隔 |
| 截断 | 前 7 位小写 hex | 前 7 位小写 hex |

### 存储隔离

- `databases/sdk_storage/<md5(user_id)>/`：按**用户**隔离（切换账号 → 目录变 + key 变）。
- `device_factor` 按 `device_id` 缓存，跨账号共享（源码有 `retrive device_factor from different user: user_id=` 日志）。
- `files/mmkv/<uid>`：按账号的 MMKV 加密 KV 存储，文件名即 uid，内容加密（除文件名外读不到明文）。

---

## 七、换设备 / 换账号后的复现步骤

1. 取 `device_id`：
   ```bash
   adb shell su -c 'cat /data/user/0/com.larksuite.suite/files/npth/RuntimeContext/did'
   ```
2. 取 `user_id`（列出 19 位数字文件名）：
   ```bash
   adb shell su -c 'ls /data/user/0/com.larksuite.suite/files/mmkv/ | grep -E "^[0-9]{19}$"'
   ```
3. 计算 key 和库路径（Python）：
   ```python
   import hashlib
   did = "<步骤1结果>".strip()
   uid = "<步骤2结果>"
   key  = hashlib.md5((did + uid).encode()).hexdigest()[:7]
   path = hashlib.md5(uid.encode()).hexdigest()
   print("key:", key)
   print("db dir:", f"/data/user/0/com.larksuite.suite/databases/sdk_storage/{path}/")
   ```
4. 拉取 `im.db` + `im.db-wal` + `im.db-shm`，用上述 SQLCipher 参数本地解密。

---

## 八、一句话概括

> 飞书 im.db 的加密方案复刻了微信：`key = md5(设备id + 用户id)[:7]`，设备 id 明文存在 `files/npth/RuntimeContext/did`，用户 id 以 `files/mmkv/<uid>` 的文件名存在，二者都能离线读取，因此无需 hook 即可复现密钥并解密任意用户的数据库。
