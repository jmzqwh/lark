// hook_rust_a0_origin.js  (v2)
// v1 问题：C['b']/C['d']/C['e']/C['g'] 直接取是 undefined（混淆类的方法名可能不同/需按签名取），
//          且失败被静默 return，导致 hooked 里只有类级别键、一个方法都没挂上。
// v2 改为：反射 getDeclaredMethods() 枚举真实签名 -> 按 名字+参数类型 精确取 overload 再挂。
//
// 执行：frida -U -f com.ss.android.lark -l hook_rust_a0_origin.js -o origin2.log

'use strict';

var SECRET = 'f3234c2b-6ab4-4fc4-8b50-7a0cb6ae';

var TARGETS = {
    'com.ss.android.lark.framework.assembly.rust.a0': ['b'],
    'com.ss.android.lark.framework.assembly.rust.g': ['d', 'e'],
    'com.ss.android.lark.framework.assembly.rust.InitImSdkTask': ['g']
};

var S = { t0: Date.now(), done: {}, dumps: 0, calls: 0 };

function ts() { return new Date().toISOString().substr(11, 12); }
function el() { return ((Date.now() - S.t0) / 1000).toFixed(2) + 's'; }
function log(t, m) { console.log('[' + ts() + '][' + t + '] ' + m); }

function stack(max) {
    var out = [];
    try {
        var arr = Java.use('java.lang.Throwable').$new().getStackTrace();
        for (var i = 1; i < Math.min(arr.length, max || 12); i++) out.push('      ' + arr[i].toString());
    } catch (e) { out.push('      <bt failed>'); }
    return out.join('\n');
}

function asStr(v) {
    try { return (v === null || v === undefined) ? 'null' : String(v); }
    catch (e) { return '<toString failed>'; }
}

function bytesAsStr(a) {
    try {
        var s = '';
        for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i] & 0xff);
        return s;
    } catch (e) { return '<bytes?>'; }
}

function dumpFields(obj, max) {
    var out = [];
    try {
        var cls = obj.getClass();
        var guard = 0;
        while (cls !== null && guard++ < 4) {
            var fs = cls.getDeclaredFields();
            for (var i = 0; i < fs.length && out.length < (max || 30); i++) {
                var v;
                try { fs[i].setAccessible(true); v = fs[i].get(obj); } catch (e) { continue; }
                var sv = asStr(v);
                if (sv.length > 160) sv = sv.substring(0, 160) + '…';
                out.push(fs[i].getName() + '=' + sv);
            }
            cls = cls.getSuperclass();
        }
    } catch (e) { out.push('<dumpFields: ' + e + '>'); }
    return out.join('; ');
}

function describeArgs(args) {
    var lines = [];
    for (var i = 0; i < args.length; i++) {
        var v = args[i];
        var s = asStr(v);
        var short = s.length > 180 ? s.substring(0, 180) + '…' : s;
        var isArr = (s.charAt(0) === '[');
        var line = 'arg' + i + ': ' + short;
        try {
            if (v && !isArr && s.charAt(0) !== '"' && s.indexOf('=') === -1) {
                var d = dumpFields(v, 25);
                if (d) line += '\n        fields: ' + d;
            }
        } catch (e) { }
        lines.push(line);
    }
    return lines.join('\n    ');
}

function containsSecret(s) { return typeof s === 'string' && s.indexOf(SECRET) !== -1; }

function maybeLog(key, args, ret) {
    var info = describeArgs(args);
    var rs = asStr(ret);
    var blob = info + '\n    ret: ' + (rs.length > 180 ? rs.substring(0, 180) + '…' : rs);
    var hot = containsSecret(info) || containsSecret(rs);
    if (!hot && ret && ret.length !== undefined) hot = containsSecret(bytesAsStr(ret));
    if (hot) {
        S.dumps++;
        log('HIT', key + ' thread=' + Java.use('java.lang.Thread').currentThread().getName() +
            '\n    ' + blob + '\n  stack:\n' + stack(14));
    } else if (S.dumps < 6 && key.indexOf('InitImSdkTask') !== -1) {
        S.dumps++;
        log('DUMP', key + '\n    ' + blob + '\n  stack:\n' + stack(8));
    }
}

function hookClass(className, wanted) {
    var C;
    try { C = Java.use(className); } catch (e) { log('ERR', 'Java.use ' + className + ': ' + e); return; }

    var ms;
    try { ms = C.class.getDeclaredMethods(); } catch (e) { log('ERR', 'declaredMethods ' + className + ': ' + e); return; }

    var names = [], matched = 0;
    for (var i = 0; i < ms.length; i++) {
        var nm = ms[i].getName();
        if (names.length < 60 && names.indexOf(nm) === -1) names.push(nm);
        if (wanted.indexOf(nm) === -1) continue;

        var ps = ms[i].getParameterTypes();
        var pn = [];
        for (var j = 0; j < ps.length; j++) pn.push(ps[j].getName());
        var key = className + '.' + nm + '(' + pn.join(',') + ')';
        if (S.done[key]) continue;

        try {
            var holder = C[nm];
            if (!holder || !holder.overload) { log('MISS', key + ' (C[nm] 不可用)'); continue; }
            var ov = holder.overload.apply(holder, pn);
            ov.implementation = function () {
                var r;
                try { r = ov.apply(this, arguments); } catch (e) { log('ERR', 'call ' + key + ': ' + e); throw e; }
                S.calls++;
                try { maybeLog(key, arguments, r); } catch (e) { log('ERR', 'log ' + key + ': ' + e); }
                return r;
            };
            S.done[key] = true;
            matched++;
            log('HOOK', key);
        } catch (e) { log('ERR', 'hook ' + key + ': ' + e); }
    }

    if (matched === 0) {
        log('MISS', className + ' 未找到 ' + JSON.stringify(wanted) + '；类内方法名: ' + names.join(','));
    }
    return matched;
}

// ---- 主循环：等类加载后再挂（不抢 <clinit>）----
var timer = setInterval(function () {
    var loaded = {};
    try {
        var all = Java.enumerateLoadedClassesSync();
        for (var i = 0; i < all.length; i++) loaded[all[i]] = true;
    } catch (e) { return; }

    var pending = 0;
    for (var cls in TARGETS) {
        if (S.done['#cls#' + cls]) continue;
        if (!loaded[cls]) { pending++; continue; }
        S.done['#cls#' + cls] = true;
        log('INFO', cls + ' 已加载，开始挂载 (' + el() + ')');
        hookClass(cls, TARGETS[cls]);
    }
    if (pending === 0) { clearInterval(timer); log('READY', '全部目标类处理完毕 (' + el() + ')'); }
}, 120);

setTimeout(function () {
    log('WARN', '12s 状态: ' + JSON.stringify(Object.keys(S.done)));
}, 12000);

setInterval(function () {
    log('SUMMARY', 't=' + el() + ' calls=' + S.calls + ' dumps=' + S.dumps);
}, 5000);
