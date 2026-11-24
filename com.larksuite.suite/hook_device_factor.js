/*
 * hook_device_factor.js
 * 在 liblark.so 的 0x2CC7C60（读 device_factor 的主逻辑）下 hook，
 * 打印入参/返回值寄存器，并尝试把返回值当 Rust 的 (ptr / len) 结构解读出来。
 *
 * 用法：
 *   frida -U -f com.larksuite.suite -l hook_device_factor.js --no-pause
 *   或已启动时：frida -U com.larksuite.suite -l hook_device_factor.js
 *
 * 说明：
 *   - 纯 native hook，不碰 Java 类，不会触发 <clinit> 崩溃；
 *   - 每次只在 onLeave 读取几个寄存器 + 最多 64 字节，成本极低，不会卡初始化界面；
 *   - 默认打印前 12 次调用，之后的调用静默（只计数）。
 */

'use strict';

const MODULE = 'liblark.so';
const OFF = 0x2CC7C60;
const MAX_PRINT = 6;
const WAIT_MS = 60000;

let printed = 0;
let total = 0;

function u64(p, off) {
    try { return p.add(off).readU64(); } catch (e) { return null; }
}

function readable(p) {
    if (!p || p.isNull()) return false;
    try { return Process.findRangeByAddress(p) !== null; } catch (e) { return false; }
}

function hexdumpSafe(p, n) {
    if (!readable(p)) return null;
    try {
        let size = p.readU64 ? n : n;   // 占位，保持可读
        return hexdump(p, { length: n, ansi: false });
    } catch (e) { return null; }
}

// 尝试把 p 当成 Rust 的 Vec<u8>/&[u8] 头部：{ptr, cap, len} 或 {ptr, len}
function trySlice(p, label) {
    let out = [];
    for (let layout of [[0, 8, 16], [0, 8]]) {
        let ptr = u64(p, layout[0]);
        let len = u64(p, layout[layout.length - 1]);
        if (ptr === null || len === null) continue;
        if (!Number.isSafeInteger(len)) continue;
        if (len > 4096 || len === 0) continue;
        let q = ptrToNative(ptr);
        if (!readable(q)) continue;
        let d = hexdumpSafe(q, Math.min(len, 128));
        if (d) out.push('    [' + label + ' layout' + JSON.stringify(layout) + '] len=' + len + '\n' + d);
    }
    return out;
}

function ptrToNative(v) {
    try { return ptr('0x' + v.toString(16)); } catch (e) { return null; }
}

function dumpCtx(tag, ctx) {
    let regs = ['x0', 'x1', 'x2', 'x3', 'x8'];
    let vals = {};
    for (let i = 0; i < regs.length; i++) {
        try { vals[regs[i]] = ctx[regs[i]]; } catch (e) { vals[regs[i]] = null; }
    }

    // 直接看 x0/x1/x8 指向的内存
    let regsToDump = [['x0', vals.x0], ['x1', vals.x1], ['x8', vals.x8], ['x2', vals.x2]];
    for (let i = 0; i < regsToDump.length; i++) {
        let name = regsToDump[i][0];
        let v = regsToDump[i][1];
        if (!v || v.isNull()) continue;
        if (!readable(v)) continue;
        let d = hexdumpSafe(v, 64);
        if (d) {
            console.log('  --- [' + name + '] 64 bytes ---');
            console.log(d);
            let sl = trySlice(v, name);
            if (sl && sl.length) sl.forEach(function (s) { console.log(s); });
        }
    }
}

function attachNow(m) {
    let target = m.base.add(OFF);
    console.log('[+] ' + MODULE + ' @ ' + m.base + '  hook ' + target + ' (off 0x' + OFF.toString(16) + ')');
    Interceptor.attach(target, {
        onEnter: function (args) {
            total++;
            this.silent = printed >= MAX_PRINT;
            this.sret = null;
            try { this.sret = this.context.x8; } catch (e) {}
            this.inRegs = [];
            for (let i = 0; i < 4; i++) { try { this.inRegs.push(this.context['x' + i]); } catch (e) { this.inRegs.push(null); } }
            // 入参 x0/x3 是输出缓冲区指针，入参 x1/x2 是 device_id
            this.devId = null;
            try {
                let p = this.inRegs[1], n = this.inRegs[2] ? this.inRegs[2].toInt32() : 0;
                if (p && !p.isNull() && readable(p) && n > 0 && n < 128) {
                    this.devId = p.readUtf8String(n);
                }
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (this.silent) return;
            printed++;
            try {
                console.log('\n[leave] call#' + total + '  retval(x0)=' + retval + '  (0x20=32 字节输出)');
                if (this.devId !== null) console.log('  device_id = "' + this.devId + '"');
                // 输出缓冲区：x0（入口保存）和 x3
                let outs = [['entry x0', this.inRegs[0]], ['entry x3', this.inRegs[3]]];
                for (let i = 0; i < outs.length; i++) {
                    let name = outs[i][0], p = outs[i][1];
                    if (!p || p.isNull() || !readable(p)) continue;
                    let d = hexdumpSafe(p, 48);
                    if (d) {
                        console.log('  --- [' + name + ' 指向的 48 字节] ---');
                        console.log(d);
                    }
                }
            } catch (e) {
                console.log('  [dump error] ' + e);
            }
        }
    });
    console.log('[+] 已挂上，等待 device_factor 逻辑被调用 ...');
}

let start = Date.now();
function waitModule() {
    let m = Process.findModuleByName(MODULE);
    if (m) { attachNow(m); return; }
    if (Date.now() - start > WAIT_MS) { console.log('[-] 等待 ' + MODULE + ' 超时'); return; }
    setTimeout(waitModule, 200);
}
waitModule();
