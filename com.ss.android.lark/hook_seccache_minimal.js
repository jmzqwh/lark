/*
 * hook_seccache_minimal.js  v3 — 零卡顿版
 * ------------------------------------------------------------------
 * 目标：只抓 3 类信息，不做任何多余操作
 *   1) Cipher.init DECRYPT 的 SecretKeySpec 原始字节（session key）
 *   2) Cipher.doFinal 解出的可读内容（只打印 JSON/域名/数字等短串）
 *   3) getIV 的正确调用方式（这次用 $className + Java.cast）
 *
 * 为什么 v2 会卡：
 *   - stack(18) 每 15 次 DECRYPT 就打印 ~20 行 Java 栈
 *   - getIV TypeError 刷屏 400+ 条
 *   - v3 全部修掉
 *
 * 用法：
 *   frida -U -f com.ss.android.lark -l hook_seccache_minimal.js -o sk3.log
 *   跑 30s Ctrl+C
 */
'use strict';

var P = '[min] ';
var started = Date.now();
function ts() { return ((Date.now() - started)/1000).toFixed(2) + 's'; }
function log(m) { console.log('[' + ts() + ']' + P + m); }

function toClass(obj) {
    try { return obj.$className; } catch (e) { return '<?>'; }
}
function getRawBytes(obj) {
    var cn = toClass(obj);
    try {
        if (cn === 'javax.crypto.spec.SecretKeySpec') {
            return Java.cast(obj, Java.use('javax.crypto.spec.SecretKeySpec')).getEncoded();
        }
        if (cn === 'javax.crypto.spec.IvParameterSpec') {
            return Java.cast(obj, Java.use('javax.crypto.spec.IvParameterSpec')).getIV();
        }
        if (cn === 'javax.crypto.spec.GCMParameterSpec') {
            return Java.cast(obj, Java.use('javax.crypto.spec.GCMParameterSpec')).getIV();
        }
        // 数组类型
        if (cn.indexOf('[B') >= 0) return obj;
    } catch (e) { }
    return null;
}
function hexOf(b) {
    if (!b) return '';
    var out = '';
    for (var i = 0; i < b.length; i++) out += ('0' + (b[i] & 0xff).toString(16)).slice(-2);
    return out;
}
function asciiOf(b, limit) {
    if (!b) return '';
    var out = '', max = limit || 120;
    for (var i = 0; i < Math.min(b.length, max); i++) {
        var c = b[i] & 0xff;
        out += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
    }
    return out;
}

/* ---------------- 状态 ---------------- */
var KEYS = {};       // keyhex -> count
var IVS = {};        // ivhex  -> count
var PLAINS = {};     // 明文 -> count（去重短串）
var CNT = { ci: 0, cd: 0, cf: 0 };

/* ---------------- hook ---------------- */
try {
    var C = Java.use('javax.crypto.Cipher');

    C.getInstance.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var algo = arguments[0] || '';
            CNT.ci++;
            if (CNT.ci <= 3 || /GCM|CBC|seccache|AES/i.test(String(algo))) {
                log('[Cipher.getInstance #' + CNT.ci + '] ' + String(algo));
            }
            return ov.apply(this, arguments);
        };
    });

    C.init.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var mode = args[0];
            var mi = mode && mode.toInt32 ? mode.toInt32() : (mode & 0xffffffff);

            if (mi === 2) {  // DECRYPT
                CNT.cd++;
                var algo = '';
                try { algo = this.getAlgorithm(); } catch (e) {}

                var keyHex = null, ivHex = null;
                for (var i = 1; i < args.length; i++) {
                    var a = args[i];
                    var cn = toClass(a);
                    var raw = getRawBytes(a);
                    if (cn === 'javax.crypto.spec.SecretKeySpec' && raw) {
                        keyHex = hexOf(raw);
                        KEYS[keyHex] = (KEYS[keyHex] || 0) + 1;
                    } else if ((cn === 'javax.crypto.spec.IvParameterSpec' ||
                                cn === 'javax.crypto.spec.GCMParameterSpec') && raw) {
                        ivHex = hexOf(raw);
                        IVS[ivHex] = (IVS[ivHex] || 0) + 1;
                    }
                }

                if (CNT.cd <= 5 || CNT.cd % 20 === 0 || (keyHex && KEYS[keyHex] === 1)) {
                    log('[init DECRYPT #' + CNT.cd + '] algo=' + algo +
                        (keyHex ? '  key=' + keyHex : '') +
                        (ivHex ? '  iv=' + ivHex : ''));
                }
            } else if (mi === 1) {
                CNT.cd++;  // 复用计数器
            }
            return ov.apply(this, arguments);
        };
    });

    C.doFinal.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var ret;
            try { ret = ov.apply(this, arguments); } catch (e) { throw e; }
            CNT.cf++;
            if (ret && ret.length > 0 && ret.length <= 160) {
                var algo = '';
                try { algo = this.getAlgorithm(); } catch (e) {}
                var plain = asciiOf(ret, 140);
                var key = ret.length + 'B:' + hexOf(ret.slice(0, 8)) + '...:' + plain;
                PLAINS[key] = (PLAINS[key] || 0) + 1;
                if (PLAINS[key] === 1) {
                    log('[doFinal #' + CNT.cf + '] algo=' + algo + ' out=' + ret.length + 'B: ' + plain);
                }
            }
            return ret;
        };
    });
    log('[HOOK] Cipher OK');
} catch (e) { log('[ERR] Cipher: ' + e); }

/* ---------------- 汇总 ---------------- */
function dumpStats() {
    log('');
    log('========== KEYS (DEC) ==========');
    Object.keys(KEYS).forEach(function (k) {
        log('  ' + KEYS[k] + 'x  ' + k);
    });
    log('========== IVS ================');
    Object.keys(IVS).forEach(function (k) {
        log('  ' + IVS[k] + 'x  ' + k);
    });
    log('========== UNIQUE PLAINS ======');
    Object.keys(PLAINS).forEach(function (k) {
        if (PLAINS[k] <= 5) log('  [' + PLAINS[k] + 'x] ' + k);
    });
    log('===============================');
}
setInterval(dumpStats, 15000);

/* ---------------- 启动 ---------------- */
log('[INIT] v3 只读极简版');
Java.perform(function () {
    log('[READY] 已挂');
});
