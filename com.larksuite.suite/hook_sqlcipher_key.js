/*
 * hook_sqlcipher_key.js
 * 重新抓取 im.db 的 passphrase：
 *   1) 在所有已加载模块里找 sqlite3_key / sqlite3_key_v2 / sqlite3_exec 导出；
 *   2) sqlite3_key(db, pKey, nKey)  → 直接打印密钥（hex + ascii）；
 *   3) sqlite3_exec(db, sql, ...)   → 只打印含 PRAGMA / cipher 的 SQL；
 *   4) 找不到 sqlite3_key 时，仅靠 sqlite3_exec 里的 "PRAGMA key" 也能拿到。
 *
 * 用法：
 *   frida -U -f com.larksuite.suite -l hook_sqlcipher_key.js --no-pause
 *   或已启动：frida -U com.larksuite.suite -l hook_sqlcipher_key.js
 *
 * 纯 native hook，不触碰 Java 类，不会引起 <clinit> 崩溃。
 */

'use strict';

const MAX_PRINT = 40;
const WAIT_MS = 90000;

let keyPrinted = 0;
let sqlPrinted = 0;
let attachedKeys = {};
let attachedExecs = {};

function hexOf(p, n) {
    try {
        let b = new Uint8Array(p.readByteArray(Math.min(n, 128)));
        let out = [];
        for (let i = 0; i < b.length; i++) out.push((b[i] < 16 ? '0' : '') + b[i].toString(16));
        return out.join('');
    } catch (e) { return null; }
}

function asciiOf(p, n) {
    try {
        let b = new Uint8Array(p.readByteArray(Math.min(n, 128)));
        let s = '';
        for (let i = 0; i < b.length; i++) s += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : '.';
        return s;
    } catch (e) { return null; }
}

function printKey(api, pKey, nKey, extra) {
    if (keyPrinted >= MAX_PRINT) return;
    keyPrinted++;
    let hx = hexOf(pKey, nKey);
    let asc = asciiOf(pKey, nKey);
    console.log('\n===== ' + api + ' #' + keyPrinted + (extra ? ' ' + extra : '') + ' =====');
    console.log('  ptr=' + pKey + '  len=' + nKey);
    console.log('  hex  : ' + hx);
    console.log('  ascii: ' + asc);
}

function attachModule(m) {
    let exps;
    try { exps = m.enumerateExports(); } catch (e) { return; }

    for (let i = 0; i < exps.length; i++) {
        let e = exps[i];
        if (e.type !== 'function') continue;

        // sqlite3_key / sqlite3_key_v2
        if ((e.name === 'sqlite3_key' || e.name === 'sqlite3_key_v2') && !attachedKeys[m.name + e.name]) {
            attachedKeys[m.name + e.name] = true;
            let isV2 = (e.name === 'sqlite3_key_v2');
            console.log('[+] ' + m.name + '!' + e.name + ' @ ' + e.address);
            Interceptor.attach(e.address, {
                onEnter: function (args) {
                    try {
                        if (isV2) {
                            // (db, zDbName, pKey, nKey)
                            printKey(e.name, args[2], args[3].toInt32(), 'db=' + (args[1].isNull() ? 'main' : args[1].readCString()));
                        } else {
                            // (db, pKey, nKey)
                            printKey(e.name, args[1], args[2].toInt32(), '');
                        }
                    } catch (err) { console.log('  [key dump error] ' + err); }
                }
            });
        }

        // sqlite3_exec(db, sql, cb, arg, errmsg)
        if (e.name === 'sqlite3_exec' && !attachedExecs[m.name]) {
            attachedExecs[m.name] = true;
            console.log('[+] ' + m.name + '!sqlite3_exec @ ' + e.address);
            Interceptor.attach(e.address, {
                onEnter: function (args) {
                    if (sqlPrinted >= MAX_PRINT) return;
                    try {
                        // 不用 readCString：Rust 侧字符串可能不以 \0 结尾，会读进相邻内存
                        let raw = new Uint8Array(args[1].readByteArray(256));
                        if (!raw || raw.length === 0) return;

                        // 取可打印前缀
                        let asc = '';
                        let n = 0;
                        for (let i = 0; i < raw.length; i++) {
                            let b = raw[i];
                            if (b === 0) break;
                            asc += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
                            n++;
                        }
                        if (asc.indexOf('PRAGMA') < 0 && asc.indexOf('PRAGMA'.toLowerCase()) < 0) return;
                        if (asc.indexOf('key') < 0 && asc.indexOf('cipher') < 0) return;

                        sqlPrinted++;
                        let hx = '';
                        for (let i = 0; i < n; i++) hx += (raw[i] < 16 ? '0' : '') + raw[i].toString(16);

                        console.log('\n[sqlite3_exec #' + sqlPrinted + '] ptr=' + args[1] + ' len~' + n);
                        console.log('  ascii: ' + asc);
                        console.log('  hex  : ' + hx);
                    } catch (err) {}
                }
            });
        }
    }
}

let start = Date.now();
function tick() {
    let mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) attachModule(mods[i]);
    if (Date.now() - start < WAIT_MS) setTimeout(tick, 500);
    else console.log('[.] 轮询结束（已挂到 ' + (Object.keys(attachedKeys).length + Object.keys(attachedExecs).length) + ' 个符号）');
}
tick();
console.log('[+] 开始扫描 sqlite3_key / sqlite3_exec ...');
