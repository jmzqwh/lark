/*
 * 追踪 app secret（32 字节）的生成源头
 * ------------------------------------------------------------------
 * 依据反编译结论（base.apk, 8.5.0）：
 *   com.ss.android.lark.framework.assembly.rust.a0
 *       a()  -> 单例
 *       d()  -> 从 SharedPreferences / keva 读取 "rust" 键；无效则 UUID.randomUUID() 生成
 *       b()  -> d().substring(0,32).getBytes(UTF-8)  → byte[32]
 *       c()  -> 校验：长度>=32 且前32字符全 ASCII
 *   iv7.a -> getSpName() / getSpNameSuffix()   （全局 SP 的名字）
 *   com.ss.android.lark.sp.AbstractSharedPreferences -> getString("rust")
 *
 * 用法：
 *   frida -U -f com.ss.android.lark -l hook_java_secret_origin2.js -o origin3.log
 *   跑 20 秒后 Ctrl+C
 *
 * 安全设计：
 *   - 不在脚本加载时直接 Java.use 目标类，而是等它被应用自然加载后再挂，
 *     避免触发 <clinit> 抢跑（上次 com.bytedance.lark.sdk.e 就是这样崩溃的）。
 *   - 每个类 / 每个重载独立 try/catch，失败只打印 [WARN]。
 *   - 除 a0.d() 外，UUID 钩子不打印（避免无关 UUID 刷屏）。
 */

'use strict';

var SECRET_PREFIX = 'f3234c2b';   // 已知 secret 前缀，用于命中判断
var PREFIX = '[secret] ';

function ts() {
    var d = new Date();
    function p(n, w) { n = '' + n; while (n.length < w) n = '0' + n; return n; }
    return p(d.getHours(), 2) + ':' + p(d.getMinutes(), 2) + ':' + p(d.getSeconds(), 2) + '.' + p(d.getMilliseconds(), 3);
}

function log(msg) {
    console.log('[' + ts() + ']' + PREFIX + msg);
}

/* ---------------- 基础工具 ---------------- */

function javaStack(limit) {
    try {
        var Log = Java.use('android.util.Log');
        var Throwable = Java.use('java.lang.Throwable');
        var s = Log.getStackTraceString(Throwable.$new());
        var lines = s.split('\n');
        var out = [];
        for (var i = 0; i < lines.length && out.length < (limit || 10); i++) {
            var ln = lines[i];
            if (ln.indexOf('at ') === 0) out.push('    ' + ln);
        }
        return out.join('\n');
    } catch (e) {
        return '    <stack unavailable: ' + e + '>';
    }
}

function bytesInfo(arr) {
    try {
        var n = arr.length;
        var ascii = '';
        var hex = '';
        for (var i = 0; i < n; i++) {
            var v = arr[i] & 0xff;
            ascii += (v >= 32 && v < 127) ? String.fromCharCode(v) : '.';
            hex += ('0' + v.toString(16)).slice(-2);
        }
        return 'byte[' + n + '] ascii="' + ascii + '" hex=' + hex;
    } catch (e) {
        return '<byte[] read err: ' + e + '>';
    }
}

/* ---------------- 状态与统计 ---------------- */

var stats = {
    d: 0, b: 0, c: 0, a: 0,
    spName: 0, spSuffix: 0,
    getString: 0, getStringHit: 0,
    uuidInD: 0, hooked: 0
};
var inD = false;

/* ---------------- 具体 hook 实现 ---------------- */

function attachA0() {
    var NAME = 'com.ss.android.lark.framework.assembly.rust.a0';
    var C = Java.use(NAME);
    log('[HOOK] ' + NAME);

    // d(): String  —— 真正决定 secret 的地方
    if (C.d) {
        C.d.overloads.forEach(function (ov) {
            ov.implementation = function () {
                stats.d++;
                var ret;
                inD = true;
                try {
                    ret = ov.call(this);
                } finally {
                    inD = false;
                }
                var hit = (ret && ret.indexOf(SECRET_PREFIX) >= 0) ? '  <<< HIT' : '';
                log('[CALL] a0.d() #' + stats.d + ' -> "' + ret + '" len=' + (ret ? ret.length : -1) + hit);
                if (stats.d <= 3) log(javaStack(8));
                return ret;
            };
        });
    }

    // b(): byte[]  —— secret 的 32 字节
    if (C.b) {
        C.b.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.call(this);
                stats.b++;
                var info = bytesInfo(ret);
                var hit = (info.indexOf(SECRET_PREFIX) >= 0) ? '  <<< HIT' : '';
                log('[CALL] a0.b() #' + stats.b + ' -> ' + info + hit);
                return ret;
            };
        });
    }

    // c(String): boolean  —— 校验（true = 无效，false = 有效）
    if (C.c) {
        C.c.overloads.forEach(function (ov) {
            ov.implementation = function (s) {
                stats.c++;
                var ret = ov.call(this, s);
                if (stats.c <= 6 || (s && s.toString().indexOf(SECRET_PREFIX) === 0)) {
                    log('[CALL] a0.c("' + s + '") -> ' + ret + (ret === false ? ' (有效)' : ' (无效)'));
                }
                return ret;
            };
        });
    }

    // a(): 单例，只计数
    if (C.a) {
        C.a.overloads.forEach(function (ov) {
            ov.implementation = function () {
                stats.a++;
                return ov.call(this);
            };
        });
    }
    stats.hooked++;
}

function attachSpName() {
    var NAME = 'iv7.a';
    var C = Java.use(NAME);
    log('[HOOK] ' + NAME + ' (SP 名称)');

    ['getSpName', 'getSpNameSuffix'].forEach(function (mn) {
        if (!C[mn]) { log('[WARN] ' + NAME + '.' + mn + ' 不存在'); return; }
        C[mn].overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.call(this);
                if (mn === 'getSpName') {
                    stats.spName++;
                    if (stats.spName <= 3) log('[CALL] ' + NAME + '.getSpName() -> "' + ret + '"');
                } else {
                    stats.spSuffix++;
                    if (stats.spSuffix <= 3) log('[CALL] ' + NAME + '.getSpNameSuffix() -> "' + ret + '"');
                }
                return ret;
            };
        });
    });
    stats.hooked++;
}

function attachGetString() {
    var NAME = 'com.ss.android.lark.sp.AbstractSharedPreferences';
    var C = Java.use(NAME);
    log('[HOOK] ' + NAME + '.getString');

    if (!C.getString) { log('[WARN] ' + NAME + '.getString 不存在'); return; }

    C.getString.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 && args[0] !== null ? args[0].toString() : null;
            var ret = ov.apply(this, args);
            stats.getString++;
            var retStr = ret !== null && ret !== undefined ? ret.toString() : 'null';
            var isHit = (key === 'rust') || (retStr.indexOf(SECRET_PREFIX) >= 0);
            if (isHit) {
                stats.getStringHit++;
                log('[HIT] getString(key="' + key + '") -> "' + retStr + '"');
                log(javaStack(10));
            }
            return ret;
        };
    });
    stats.hooked++;
}

function attachUuid() {
    try {
        var U = Java.use('java.util.UUID');
        U.randomUUID.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.call(this);
                if (inD) {
                    stats.uuidInD++;
                    log('[UUID] a0.d() 执行期间调用 randomUUID -> ' + ret);
                    log(javaStack(6));
                }
                return ret;
            };
        });
        log('[HOOK] java.util.UUID.randomUUID()（仅 a0.d() 内打印）');
    } catch (e) {
        log('[WARN] UUID hook 失败: ' + e);
    }
}

/* ---------------- 等待类被应用加载后再挂载 ---------------- */

var TASKS = [
    { name: 'com.ss.android.lark.framework.assembly.rust.a0', fn: attachA0 },
    { name: 'iv7.a', fn: attachSpName },
    { name: 'com.ss.android.lark.sp.AbstractSharedPreferences', fn: attachGetString }
];

function pendingTasks() {
    var p = [];
    for (var i = 0; i < TASKS.length; i++) if (!TASKS[i].done) p.push(TASKS[i]);
    return p;
}

var polling = false;
function poll() {
    if (polling) return;
    var pend = pendingTasks();
    if (pend.length === 0) return;
    polling = true;
    try {
        var loaded = Java.enumerateLoadedClassesSync();
        var set = {};
        for (var i = 0; i < loaded.length; i++) set[loaded[i]] = true;
        for (var j = 0; j < pend.length; j++) {
            var t = pend[j];
            if (set[t.name]) {
                try {
                    t.fn();
                    t.done = true;
                } catch (e) {
                    log('[ERR] 挂载 ' + t.name + ' 失败: ' + e);
                    t.done = true;
                }
            }
        }
    } catch (e) {
        // enumerateLoadedClassesSync 在极早期可能抛错，忽略并重试
    } finally {
        polling = false;
    }
}

var startedAt = Date.now();
function heartbeat() {
    var left = pendingTasks().length;
    log('[STATUS] t=' + ((Date.now() - startedAt) / 1000).toFixed(1) + 's hooked=' + stats.hooked +
        ' pending=' + left +
        ' | d=' + stats.d + ' b=' + stats.b + ' c=' + stats.c +
        ' spName=' + stats.spName + ' getString=' + stats.getString + '/hit=' + stats.getStringHit +
        ' uuidInD=' + stats.uuidInD);
    if (left > 0 && (Date.now() - startedAt) > 60000) {
        log('[WARN] 60 秒仍未加载完：' + pendingTasks().map(function (x) { return x.name; }).join(', '));
    }
}

/* ---------------- 入口 ---------------- */

function main() {
    log('[INIT] 脚本开始布防 (Java.available=' + Java.available + ')');
    attachUuid();                 // UUID 类一定已加载，直接挂
    poll();
    setInterval(poll, 300);
    setInterval(heartbeat, 5000);
    log('[GATE] 已启动轮询，等待目标类被应用加载…');
}

try {
    Java.perform(function () {
        main();
    });
} catch (e) {
    // 极早期 ART 未就绪时重试
    log('[WARN] Java.perform 失败，1 秒后重试: ' + e);
    setTimeout(function () {
        Java.perform(function () { main(); });
    }, 1000);
}
