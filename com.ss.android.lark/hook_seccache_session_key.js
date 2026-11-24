/*
 * hook_seccache_session_key.js  v2
 * ------------------------------------------------------------------
 * v1 问题：
 *   - a.getClass().getName() / a.getEncoded() 在 Frida 代理里 TypeError
 *   - seccache.impl.* 类名可能混淆，没挂到
 *   - Crypto 实际在走 AES/CBC/PKCS5Padding（session key 已缓存，降级 CBC）
 *
 * v2 改进：
 *   - 正确读取 Java 代理的类名 (arg.$className / Java.cast)
 *   - 正确读取 SecretKeySpec.getEncoded() / IvParameterSpec.getIV()
 *   - Cipher.init DECRYPT 打印 stack 和所有参数类型+值
 *   - Cipher.doFinal 也挂（解密结果也可能是证据）
 *   - 加 java.util.Base64.decode / encode 辅助
 *   - 降低 d.a/b/a/b 等类的枚举（只挑有意义的）
 *
 * 用法：
 *   frida -U -f com.ss.android.lark -l hook_seccache_session_key.js -o sk2.log
 *   跑 40s Ctrl+C
 */
'use strict';

var P = '[seccache] ';
var LIMIT_DECRYPT = 30;
var LIMIT_ENCRYPT = 10;
var LIMIT_DOFINAL = 40;
var started = Date.now();
function ts() { return ((Date.now() - started)/1000).toFixed(2) + 's'; }
function log(m) { console.log('[' + ts() + ']' + P + m); }

/* ---------------- Java 辅助 ---------------- */
function className(o) {
    if (!o) return '<null>';
    try { return o.$className; } catch (e) { }
    try { return Java.cast(o, Java.use('java.lang.Object')).getClass().getName(); } catch (e) { }
    return '<?>' + (typeof o);
}
function bytesOf(b) {
    if (!b) return '';
    try { return '[' + b.length + 'B]'; } catch (e) { return ''; }
}
function hexOfJavaBytes(b, limit) {
    if (!b) return '<null>';
    var arr;
    try { arr = Java.array('byte', b); } catch (e) {
        try {
            arr = [];
            for (var i = 0; i < b.length; i++) arr.push(b[i]);
        } catch (e2) { return '<hex err>'; }
    }
    var out = '';
    var n = b.length;
    var max = limit || 64;
    for (var i = 0; i < Math.min(n, max); i++) {
        var v = (arr[i] & 0xff);
        out += ('0' + v.toString(16)).slice(-2);
    }
    if (n > max) out += '...(' + n + 'B)';
    return out;
}
function asciiOfJavaBytes(b, limit) {
    if (!b) return '';
    var out = '';
    var max = limit || 80;
    for (var i = 0; i < Math.min(b.length, max); i++) {
        var c = (b[i] & 0xff);
        out += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
    }
    if (b.length > max) out += '...';
    return out;
}
function stack(depth) {
    try {
        var Log = Java.use('android.util.Log');
        var TB = Java.use('java.lang.Throwable');
        var lines = Log.getStackTraceString(TB.$new()).split('\n');
        var out = [];
        for (var i = 0; i < lines.length && out.length < (depth || 15); i++) {
            if (lines[i].indexOf('at ') === 0) out.push('  ' + lines[i]);
        }
        return out.join('\n');
    } catch (e) { return '<stack err: ' + e + '>'; }
}

/* ---------------- 状态 ---------------- */
var STAT = {
    cipher_getInstance: 0, cipher_init_dec: 0, cipher_init_enc: 0,
    cipher_dofinal: 0, keyStore_getInstance: 0, keyStore_getKey: 0,
    ks_callbacks: 0, keyGenerator: 0,
    hooked: 0, pending: 0
};
var KEYS_FOUND = [];

/* ---------------- Cipher hook ---------------- */
function hookCipher() {
    log('[HOOK] javax.crypto.Cipher.getInstance/init/doFinal');
    var C = Java.use('javax.crypto.Cipher');

    // getInstance
    try {
        C.getInstance.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                var first = args[0] || '';
                STAT.cipher_getInstance++;
                // 打印所有 AES / GCM / CBC 相关
                var s = first.toString();
                if (/AES|GCM|CBC|DES|RSA|seccache/i.test(s)) {
                    log('[Cipher.getInstance #' + STAT.cipher_getInstance + '] ' + s);
                }
                return ov.apply(this, arguments);
            };
        });
    } catch (e) { log('[ERR] Cipher.getInstance ' + e); }

    // init
    try {
        C.init.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                var mode = args[0];
                var modeInt = mode && mode.toInt32 ? mode.toInt32() : (mode & 0xffffffff);
                var modeName = ({1:'ENCRYPT',2:'DECRYPT',3:'WRAP',4:'UNWRAP'})[modeInt] || String(modeInt);

                if (modeInt === 2) {  // DECRYPT
                    STAT.cipher_init_dec++;
                    var algo = '';
                    try { algo = this.getAlgorithm(); } catch (e) {}

                    log('[Cipher.init DECRYPT #' + STAT.cipher_init_dec + '] algo=' + algo);

                    for (var i = 1; i < args.length; i++) {
                        var a = args[i];
                        var cn = className(a);
                        log('  arg[' + i + '] class=' + cn);

                        // SecretKeySpec
                        if (cn === 'javax.crypto.spec.SecretKeySpec') {
                            try {
                                var enc = a.getEncoded();
                                var hexs = hexOfJavaBytes(enc);
                                var ascii = asciiOfJavaBytes(enc);
                                var key32 = (enc.length === 32);
                                log('    → RAW KEY ' + enc.length + 'B  hex=' + hexs +
                                    (key32 ? '  <<<< session key!' : '') +
                                    '  ascii=' + JSON.stringify(ascii));
                                if (key32) KEYS_FOUND.push({idx: STAT.cipher_init_dec, hex: hexs, ascii: ascii, algo: algo});
                            } catch (e) { log('    [err getEncoded] ' + e); }
                        }
                        // IvParameterSpec
                        if (cn === 'javax.crypto.spec.IvParameterSpec') {
                            try {
                                var iv = a.getIV();
                                log('    → IV ' + iv.length + 'B  hex=' + hexOfJavaBytes(iv));
                            } catch (e) { log('    [err getIV] ' + e); }
                        }
                        // GCMParameterSpec
                        if (cn === 'javax.crypto.spec.GCMParameterSpec') {
                            try {
                                var iv2 = a.getIV();
                                log('    → GCM IV=' + hexOfJavaBytes(iv2) + '  tagLen=' + a.getTLen());
                            } catch (e) { log('    [err GCM] ' + e); }
                        }
                        // SecKeyRef / 其它可能的 Keystore Key —— 打印摘要
                        if (cn.indexOf('KeyStore') >= 0 || cn.indexOf('Secure') >= 0 || cn.indexOf('Keystore') >= 0) {
                            log('    → (Keystore-backed key, material not extractable)');
                        }
                    }

                    if (STAT.cipher_init_dec <= 15 || KEYS_FOUND.length > 0) {
                        log(stack(18));
                    }
                    log('');  // 空行分隔
                } else if (modeInt === 1) {  // ENCRYPT
                    STAT.cipher_init_enc++;
                    if (STAT.cipher_init_enc <= LIMIT_ENCRYPT) {
                        var algo2 = '';
                        try { algo2 = this.getAlgorithm(); } catch (e) {}
                        log('[Cipher.init ENCRYPT #' + STAT.cipher_init_enc + '] algo=' + algo2);
                    }
                }

                return ov.apply(this, arguments);
            };
        });
    } catch (e) { log('[ERR] Cipher.init ' + e); }

    // doFinal(byte[])
    try {
        C.doFinal.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                STAT.cipher_dofinal++;
                var ret;
                try { ret = ov.apply(this, arguments); } catch (e) { throw e; }
                if (STAT.cipher_dofinal <= LIMIT_DOFINAL && ret && ret.length > 0) {
                    // 只对短输出（< 128B）打 —— 可能就是 session key / IV
                    if (ret.length <= 128) {
                        var algo = '';
                        try { algo = this.getAlgorithm(); } catch (e) {}
                        log('[doFinal #' + STAT.cipher_dofinal + '] algo=' + algo + ' out=' + ret.length + 'B hex=' + hexOfJavaBytes(ret));
                    }
                }
                return ret;
            };
        });
    } catch (e) { }

    STAT.hooked++;
}

/* ---------------- KeyStore hook ---------------- */
function hookKeyStore() {
    log('[HOOK] java.security.KeyStore.getInstance/getKey');
    var KS = Java.use('java.security.KeyStore');
    try {
        KS.getInstance.overloads.forEach(function (ov) {
            ov.implementation = function () {
                STAT.keyStore_getInstance++;
                var args = Array.prototype.slice.call(arguments);
                log('[KeyStore.getInstance #' + STAT.keyStore_getInstance + '] type=' + args.join('|'));
                return ov.apply(this, arguments);
            };
        });
    } catch (e) { }

    try {
        KS.getKey.overloads.forEach(function (ov) {
            ov.implementation = function (alias, password) {
                STAT.keyStore_getKey++;
                log('[KeyStore.getKey #' + STAT.keyStore_getKey + '] alias=' + alias);
                var ret = ov.call(this, alias, password);
                if (ret) {
                    var cn = className(ret);
                    log('  ret class=' + cn);
                    try {
                        var enc = ret.getEncoded();
                        log('  material len=' + enc.length + 'B hex=' + hexOfJavaBytes(enc));
                    } catch (e) {
                        log('  (not extractable: hardware-backed)');
                    }
                }
                return ret;
            };
        });
    } catch (e) { }

    STAT.hooked++;
}

/* ---------------- 等待类加载 ---------------- */
var TASKS = [
    { name: 'javax.crypto.Cipher', fn: hookCipher, done: false },
    { name: 'java.security.KeyStore', fn: hookKeyStore, done: false },
];
// 额外尝试：seccache.impl.*（可能被混淆，逐个尝试）
['com.ss.android.lark.seccache.impl.d',
 'com.ss.android.lark.seccache.impl.b',
 'com.ss.android.lark.seccache.impl.c',
 'com.ss.android.lark.seccache.impl.a',
 'com.ss.android.lark.seccache.impl.AesCbcUtils'].forEach(function (n) {
    TASKS.push({ name: n, fn: hookSeccacheGen(n), done: false });
});

function hookSeccacheGen(name) {
    return function () {
        try {
            var C = Java.use(name);
            log('[HOOK] ' + name + ' —— 方法:');
            try {
                C.class.getDeclaredMethods().forEach(function (m) {
                    var mn = m.getName();
                    var ov = C[mn];
                    if (!ov || !ov.overloads) return;
                    ov.overloads.forEach(function (o) {
                        o.implementation = function () {
                            var args = Array.prototype.slice.call(arguments);
                            var ret;
                            try { ret = o.apply(this, args); } catch (e) {
                                log('[ERR] ' + name + '.' + mn + ': ' + e);
                                throw e;
                            }
                            if (mn.length <= 3) {
                                // short method names like a/b/c/d
                                var summary = '[%s.%s] %d args -> %s';
                                var as = args.map(function (a) {
                                    var cn = className(a);
                                    try {
                                        if (a && cn.indexOf('[B') >= 0) return cn + ':' + hexOfJavaBytes(a, 32);
                                        if (a && cn.indexOf('String') >= 0) return JSON.stringify(a.toString()).slice(0, 80);
                                    } catch (e) {}
                                    return cn;
                                });
                                var rcn = className(ret);
                                var rs = '';
                                try {
                                    if (ret && rcn.indexOf('[B') >= 0) rs = hexOfJavaBytes(ret, 64);
                                    else rs = JSON.stringify((ret && ret.toString) ? ret.toString() : ret).slice(0, 80);
                                } catch (e) {}
                                log('  [' + name + '.' + mn + '] args=' + JSON.stringify(as) + ' -> ' + rcn + ' ' + rs);
                            }
                            return ret;
                        };
                    });
                });
            } catch (e) { log('  listMethods err: ' + e); }
            STAT.hooked++;
        } catch (e) { log('[SKIP] ' + name + ': ' + e); }
    };
}

function poll() {
    var pend = TASKS.filter(function (t) { return !t.done; });
    if (pend.length === 0) return;
    try {
        var loaded = Java.enumerateLoadedClassesSync();
        var set = {};
        for (var i = 0; i < loaded.length; i++) set[loaded[i]] = true;
        for (var j = 0; j < pend.length; j++) {
            var t = pend[j];
            if (set[t.name]) {
                try { t.fn(); t.done = true; }
                catch (e) { t.done = true; }
            }
        }
    } catch (e) { }
}

function main() {
    log('[INIT] v2 布防');
    poll();
    setInterval(poll, 300);
    setInterval(function () {
        var left = TASKS.filter(function (t) { return !t.done; }).length;
        STAT.pending = left;
        log('[STATUS] t=' + ((Date.now() - started)/1000).toFixed(1) + 's  hooked=' + STAT.hooked +
            ' pending=' + left +
            ' | ci=' + STAT.cipher_getInstance + ' d=' + STAT.cipher_init_dec + '/e=' + STAT.cipher_init_enc +
            ' doFinal=' + STAT.cipher_dofinal +
            ' KSi=' + STAT.keyStore_getInstance + ' KSg=' + STAT.keyStore_getKey +
            ' keysFound=' + KEYS_FOUND.length);
        if (KEYS_FOUND.length > 0) {
            log('  ====== 已抓到 32B session keys ======');
            for (var i = 0; i < KEYS_FOUND.length; i++) {
                var k = KEYS_FOUND[i];
                log('  [' + k.idx + '] algo=' + k.algo + ' hex=' + k.hex);
            }
            log('  ====================================');
        }
    }, 8000);
    log('[GATE] 等待…');
}

try { Java.perform(main); } catch (e) { setTimeout(main, 1000); }
