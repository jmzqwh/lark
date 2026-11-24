/*
 * hook_initsdk.js  (v6 - 轻量版，避免初始化卡死)
 *
 * 卡死原因（v5）：
 *   - hook 实现体是在"调用者线程"（通常是主线程）里同步执行的：
 *     _initSDK(byte[]) 里做了 byteArrayToU8 + 逐字节拼字符串 + protobuf 递归解析，
 *     几百 KB 的数组在 JS 里跑，主线程直接被拖住，表现就是停在初始化界面。
 *   - 另外 dumpSdkClass() 在 App 正在初始化 Sdk 时 Java.use()，可能撞上类初始化锁。
 *
 * v6 原则：
 *   1. hook 实现体里只做"取参数 + 记录"，所有解析/打印都 setTimeout 到脚本线程再做；
 *   2. 不在 hook 里做反射、不 dump 全字段、不逐字节拼长字符串；
 *   3. 关闭 Sdk 类 dump 和 builder 全量 dump（已经拿到过，不必重复）。
 *
 * 用法：
 *   frida -U -f com.larksuite.suite -l hook_initsdk.js --no-pause
 */

'use strict';

const TARGET_MODULE = 'liblark.so';
const EXPORT_RE = /Sdk__1(pre)?initSDK/i;

const HOOK_NATIVE_REGS = true;      // 只打印 x0~x7，成本极低
const HOOK_INIT_SETTING = true;     // 重点：getInitSetting / _getInitSettings 的 4 个入参
const HOOK_INIT_SDK_BYTES = false;  // _initSDK 的 byte[] 内容（需要时再打开）

const SDK_WAIT_TIMEOUT_MS = 60000;

/* ================= 小工具（都不做重活） ================= */

function hexPrefix(u8, n) {
    n = Math.min(n || 64, u8.length);
    let out = [];
    for (let i = 0; i < n; i++) {
        let b = u8[i];
        out.push((b < 16 ? '0' : '') + b.toString(16));
    }
    return out.join('') + (u8.length > n ? '...' : '');
}

function toU8Quiet(arr) {
    try {
        let len = arr.length;
        if (len > 65536) return null;          // 太大就不碰，避免拖死
        let u8 = new Uint8Array(len);
        for (let i = 0; i < len; i++) u8[i] = arr[i] & 0xff;
        return u8;
    } catch (e) {
        return null;
    }
}

function asString(v) {
    if (v === null || v === undefined) return 'null';
    try { return String(v); } catch (e) { return '<?>'; }
}

/* ================= 1. native 寄存器（廉价） ================= */

let attached = {};

function attachNative() {
    let m = Process.findModuleByName(TARGET_MODULE);
    if (!m) { setTimeout(attachNative, 200); return; }
    console.log('[+] ' + TARGET_MODULE + ' @ ' + m.base);

    let exports = [];
    try { exports = m.enumerateExports(); } catch (e) { return; }
    for (let i = 0; i < exports.length; i++) {
        let e = exports[i];
        if (!HOOK_NATIVE_REGS) break;
        if (e.type !== 'function' || !EXPORT_RE.test(e.name) || attached[e.name]) continue;
        attached[e.name] = true;
        (function (name, addr) {
            console.log('[+] attach ' + name + ' @ ' + addr);
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this.t0 = Date.now();
                    try {
                        let raw = [];
                        for (let k = 0; k < 8; k++) raw.push('x' + k + '=' + args[k]);
                        console.log('\n[native] ' + name + ' ' + raw.join('  '));
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    try { console.log('[native] ' + name + ' cost=' + (Date.now() - this.t0) + 'ms\n'); } catch (e) {}
                }
            });
        })(e.name, e.address);
    }
}

/* ================= 2. Sdk 的 Java 方法 hook（实现体只记录，不解析） ================= */

function whenSdkLoaded(cb) {
    let start = Date.now();
    function tick() {
        let loaded = false;
        try {
            let names = Java.enumerateLoadedClassesSync();
            for (let i = 0; i < names.length; i++) {
                if (names[i] === 'com.bytedance.lark.sdk.Sdk') { loaded = true; break; }
            }
        } catch (e) {}
        if (loaded) { cb(); return; }
        if (Date.now() - start > SDK_WAIT_TIMEOUT_MS) { console.log('[-] 等待 Sdk 超时'); return; }
        setTimeout(tick, 200);
    }
    tick();
}

let loggedInitSDK = 0;

function installSdkHooks() {
    if (!HOOK_INIT_SETTING && !HOOK_INIT_SDK_BYTES) return;
    if (typeof Java === 'undefined' || !Java.available) return;

    whenSdkLoaded(function () {
        Java.perform(function () {
            let Sdk = null;
            try { Sdk = Java.use('com.bytedance.lark.sdk.Sdk'); }
            catch (e) { console.log('[-] Sdk 未就绪: ' + e); return; }

            // getInitSetting(String, String, int, String)
            if (HOOK_INIT_SETTING) {
                ['getInitSetting', '_getInitSettings'].forEach(function (nm) {
                    try {
                        if (!Sdk[nm]) { console.log('[.] ' + nm + ' 不存在'); return; }
                        Sdk[nm].overloads.forEach(function (ov) {
                            let sig = '';
                            try { sig = ov.argumentTypes.map(function (t) { return t.className; }).join(', '); } catch (e) {}
                            ov.implementation = function () {
                                // 只记录，立刻返回，解析交给脚本线程
                                let snap = { tag: nm + '(' + sig + ')', args: [], retLen: -1 };
                                for (let k = 0; k < arguments.length; k++) {
                                    snap.args.push(asString(arguments[k]));
                                }
                                let r = ov.apply(this, arguments);
                                try { snap.retLen = r === null ? -1 : r.length; } catch (e) {}
                                setTimeout(function () { printInitSetting(snap); }, 0);
                                return r;
                            };
                        });
                        console.log('[+] hook Sdk.' + nm);
                    } catch (e) { console.log('[.] ' + nm + ' hook 失败: ' + e); }
                });
            }

            // _initSDK(byte[]) —— 只处理小 payload，且延迟打印
            if (HOOK_INIT_SDK_BYTES) {
                try {
                    Sdk._initSDK.overloads.forEach(function (ov) {
                        ov.implementation = function (arr) {
                            let u8 = toU8Quiet(arr);
                            if (u8 && loggedInitSDK++ < 3) {
                                let hx = hexPrefix(u8, 256);
                                let size = u8.length;
                                setTimeout(function () {
                                    console.log('\n===== Sdk._initSDK(byte[]) size=' + size + ' =====');
                                    console.log('  hex: ' + hx);
                                }, 0);
                            }
                            return ov.apply(this, arguments);
                        };
                    });
                    console.log('[+] hook Sdk._initSDK');
                } catch (e) { console.log('[.] _initSDK hook 失败: ' + e); }
            }
        });
    });
}

function printInitSetting(snap) {
    console.log('\n===== Sdk.' + snap.tag + ' =====');
    for (let k = 0; k < snap.args.length; k++) {
        console.log('  arg[' + k + '] = ' + snap.args[k]);
    }
    if (snap.retLen >= 0) console.log('  => ret byte[' + snap.retLen + ']');
}

/* ================= 启动 ================= */

setTimeout(attachNative, 0);
setTimeout(installSdkHooks, 0);
