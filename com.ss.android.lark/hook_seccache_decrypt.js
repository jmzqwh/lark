/*
 * 验证 seccache / 偏好明文（含 rust 的值） —— v4
 * ------------------------------------------------------------------
 * 结论回顾：
 *   v2：d.a(byte[]) 解出 lkSuitPreference 的 GCM 明文 =
 *       "8qLdCLLbcgxm1DYrrpd2Lg==:nxC7W7DkBsHTJSs2CqDImrKIA2RYAuaKpfbFCO5q41I="
 *       （即 iv_b64:AES256Key_b64，“钥匙的钥匙”）
 *   v3：d.d / d.h 全程 0 次 —— 因为主路径不走它。
 *
 * 静态确认的真实链路（iv7.a.a()）：
 *   key = gi7.a.h(ctx, "kPreference")        // 解出上面的 key blob
 *   gb7.d(ctx, key, spName)                  // 偏好值加解密器
 *   gb7.d.b(String) = 解密（密文 -> 明文）    ← 本脚本重点
 *   gb7.d.a(String) = 加密（明文 -> 密文）
 *   gb7.d.c(String) = 解密降级分支（会走 d.d / seccache）
 *
 * 预期命中：gb7.d.b() 的 OUT 出现
 *   f3234c2b-6ab4-4fc4-8b50-7a0cb6ae4949
 *
 * 用法：
 *   frida -U -f com.ss.android.lark -l hook_seccache_decrypt.js -o seccache.log
 *   跑到 t=60s 左右再 Ctrl+C。
 */

'use strict';

var PREFIX = '[seccache] ';
var LIMIT_SP = 40;     // 偏好 getString 前 N 次
var LIMIT_GB = 40;     // gb7.d.b 前 N 次
var LIMIT_ENC = 15;    // gb7.d.a 前 N 次
var LIMIT_FB = 15;     // gb7.d.c 前 N 次
var LIMIT_FA = 2;      // seccache d.a 前 N 次
var stat = { sp: 0, gb: 0, enc: 0, fb: 0, a: 0, hits: 0 };
var started = Date.now();

function ts() {
    var d = new Date();
    function p(n, w) { n = '' + n; while (n.length < w) n = '0' + n; return n; }
    return p(d.getHours(), 2) + ':' + p(d.getMinutes(), 2) + ':' + p(d.getSeconds(), 2) + '.' + p(d.getMilliseconds(), 3);
}
function log(m) { console.log('[' + ts() + ']' + PREFIX + m); }

function clip(s, limit) {
    if (s === null || s === undefined) return '<null>';
    s = '' + s;
    if (s.length <= limit) return 'len=' + s.length + ' "' + s + '"';
    return 'len=' + s.length + ' "' + s.substring(0, limit) + '" …(截断)';
}

function isHit(s) {
    if (s === null || s === undefined) return false;
    s = '' + s;
    return s.indexOf('rust') >= 0 || s.indexOf('f3234c2b') >= 0;
}

function bytesInfo(arr, limit) {
    try {
        var n = arr.length;
        var max = Math.min(n, limit || 96);
        var ascii = '', hex = '';
        for (var i = 0; i < max; i++) {
            var v = arr[i] & 0xff;
            ascii += (v >= 32 && v < 127) ? String.fromCharCode(v) : '.';
            hex += ('0' + v.toString(16)).slice(-2);
            if (i % 32 === 31) hex += '\n        ';
        }
        return 'len=' + n + ' ascii="' + ascii + '"' + (n > max ? ' …' : '') + '\n        hex=' + hex;
    } catch (e) { return '<byte[] err: ' + e + '>'; }
}

function javaStack(limit) {
    try {
        var Log = Java.use('android.util.Log');
        var Throwable = Java.use('java.lang.Throwable');
        var s = Log.getStackTraceString(Throwable.$new()).split('\n');
        var out = [];
        for (var i = 0; i < s.length && out.length < (limit || 8); i++) {
            if (s[i].indexOf('at ') === 0) out.push('    ' + s[i]);
        }
        return out.join('\n');
    } catch (e) { return '    <stack unavailable>'; }
}

function attachAll() {
    /* ---------- 1) gb7.d：偏好值加解密 ---------- */
    try {
        var GB = Java.use('gb7.d');
        log('[HOOK] gb7.d (SecurePolicy)');

        try {
            var ovB = GB.b.overload('java.lang.String');
            ovB.implementation = function (val) {
                stat.gb++;
                var out = ovB.call(this, val);
                var hit = isHit(out) || isHit(val);
                if (hit) stat.hits++;
                if (stat.gb <= LIMIT_GB || hit) {
                    log('[gb7.d.b #' + stat.gb + '] 解密' + (hit ? '  <<< 命中 rust/secret' : ''));
                    log('   IN  ' + clip(val, 120));
                    log('   OUT ' + clip(out, hit ? 500 : 120));
                    if (hit) log(javaStack(10));
                }
                return out;
            };
            log('[HOOK] gb7.d.b(String)  ← 偏好值解密【重点】');
        } catch (e) { log('[ERR] gb7.d.b 挂载失败: ' + e); }

        try {
            var ovA = GB.a.overload('java.lang.String');
            ovA.implementation = function (val) {
                stat.enc++;
                var out = ovA.call(this, val);
                if (stat.enc <= LIMIT_ENC || isHit(val)) {
                    log('[gb7.d.a #' + stat.enc + '] 加密');
                    log('   IN  ' + clip(val, 200));
                    log('   OUT ' + clip(out, 120));
                }
                return out;
            };
            log('[HOOK] gb7.d.a(String)  ← 偏好值加密');
        } catch (e) { log('[ERR] gb7.d.a 挂载失败: ' + e); }

        try {
            var ovC = GB.c.overload('java.lang.String');
            ovC.implementation = function (val) {
                stat.fb++;
                var out = ovC.call(this, val);
                var hit = isHit(out);
                if (hit) stat.hits++;
                if (stat.fb <= LIMIT_FB || hit) {
                    log('[gb7.d.c #' + stat.fb + '] 解密(降级分支)' + (hit ? '  <<< 命中' : ''));
                    log('   IN  ' + clip(val, 120));
                    log('   OUT ' + clip(out, hit ? 500 : 120));
                    if (hit) log(javaStack(10));
                }
                return out;
            };
            log('[HOOK] gb7.d.c(String)  ← 降级解密');
        } catch (e) { log('[ERR] gb7.d.c 挂载失败: ' + e); }
    } catch (e) {
        log('[ERR] gb7.d 挂载失败: ' + e);
    }

    /* ---------- 2) SP 层：键名 -> 明文（直接看 key="rust"） ---------- */
    try {
        var SP = Java.use('com.ss.android.lark.sp.AbstractSharedPreferences');
        SP.getString.overloads.forEach(function (ov) {
            var argc = ov.argumentTypes.length;
            if (argc < 1 || argc > 2) return;
            ov.implementation = function (key, def) {
                var ret;
                if (argc === 1) ret = ov.call(this, key);
                else ret = ov.call(this, key, def);
                stat.sp++;
                var hk = isHit(key);
                var hv = isHit(ret);
                if (hk || hv) stat.hits++;
                if (stat.sp <= LIMIT_SP || hk || hv) {
                    log('[sp #' + stat.sp + '] getString key="' + key + '"' + ((hk || hv) ? '  <<< 命中' : ''));
                    log('   VALUE ' + clip(ret, (hk || hv) ? 500 : 80));
                    if (hk || hv) log(javaStack(8));
                }
                return ret;
            };
        });
        log('[HOOK] AbstractSharedPreferences.getString');
    } catch (e) {
        log('[WARN] AbstractSharedPreferences 挂载失败（不影响 gb7.d）: ' + e);
    }

    /* ---------- 3) 参照：seccache 文件级 GCM（已证明） ---------- */
    try {
        var D = Java.use('com.ss.android.lark.seccache.impl.d');
        D.a.overloads.forEach(function (ov) {
            if (ov.argumentTypes.length !== 1 || ov.argumentTypes[0].className !== '[B') return;
            ov.implementation = function (data) {
                stat.a++;
                var ret = ov.call(this, data);
                if (stat.a <= LIMIT_FA) {
                    log('[d.a #' + stat.a + '] 文件级 GCM');
                    log('   IN  ' + bytesInfo(data, 64));
                    log('   OUT ' + bytesInfo(ret, 96));
                }
                return ret;
            };
        });
        log('[HOOK] seccache.impl.d.a(byte[])');
    } catch (e) {
        log('[WARN] seccache.impl.d 挂载失败: ' + e);
    }

    log('[READY] 挂载完成，等待调用…');
}

function main() {
    log('[INIT] 布防 (Java.available=' + Java.available + ')');
    attachAll();
    setInterval(function () {
        log('[STATUS] t=' + ((Date.now() - started) / 1000).toFixed(1) + 's sp=' + stat.sp +
            ' gb=' + stat.gb + ' enc=' + stat.enc + ' fb=' + stat.fb + ' a=' + stat.a + ' 命中=' + stat.hits);
    }, 5000);
    log('[GATE] 已进入等待（无类枚举，不会拖慢启动）');
}

try {
    Java.perform(function () { main(); });
} catch (e) {
    log('[WARN] Java.perform 失败，1 秒后重试: ' + e);
    setTimeout(function () { Java.perform(function () { main(); }); }, 1000);
}
