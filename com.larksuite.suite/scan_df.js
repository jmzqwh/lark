/*
 * scan_df.js
 * 在 Lark 进程内存里定位 device_factor 的 32 字节特征，并 dump 其前后各 192 字节。
 * 目的：看 device_factor 附近是否就躺着派生的 key / app secret（Rust 结构体常把它们放一起）。
 *
 * 可选：把 hook 到的 key（64 hex）填到 KEY_HEX，脚本会同时定位 key 所在内存，
 *       如果它紧邻 device_factor，就能直接判断派生关系。
 *
 * 用法（宿主进程已启动时）：
 *   frida -U com.larksuite.suite -l scan_df.js
 * 或在 spawn 后 8~10 秒再跑（等 SDK 完成初始化，key 已算好）。
 */

'use strict';

// device_factor 前 32 字节（来自 /data/user/0/com.larksuite.suite/databases/sdk_storage/<hash>/device_factor）
const DF_HEX = '794a7fcf5b2c05f2bb9ec7cf958c16c0b73f7b6611a582133e3e1ef39767b549';
// 可选：hook 到的 passphrase 的 32 字节 hex（64 个字符）
const KEY_HEX = '';

const MAX_HITS = 6;
const CTX = 192;

function hexPattern(h) {
    return h.match(/../g).map(function (x) { return x; }).join(' ');
}

function toHex(p, n) {
    try { return hexdump(p, { length: n, ansi: false }); } catch (e) { return '<hexdump failed>'; }
}

function toAscii(p, n) {
    let out = '';
    try {
        let b = new Uint8Array(p.readByteArray(n));
        for (let i = 0; i < b.length; i++) {
            let c = b[i];
            out += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
        }
    } catch (e) { out = '<read failed>'; }
    return out;
}

function dumpAround(addr, label) {
    let start = addr.sub(CTX);
    if (start.compare(ptr('0')) < 0) start = addr;
    let len = CTX * 2;
    console.log('\n--- ' + label + ' @ ' + addr + ' ---');
    let mod = Process.findModuleByAddress(addr);
    console.log('  module: ' + (mod ? mod.name + '+0x' + addr.sub(mod.base).toString(16) : 'unknown'));
    console.log('  ascii: ' + toAscii(start, len));
    console.log(toHex(start, len));
}

function scanAll(patternHex, label) {
    let pat = hexPattern(patternHex);
    let ranges = Process.enumerateRanges('r--');
    let hits = 0;
    for (let i = 0; i < ranges.length && hits < MAX_HITS; i++) {
        let r = ranges[i];
        if (r.size < 32) continue;
        let matches;
        try {
            matches = Memory.scanSync(r.base, r.size, pat);
        } catch (e) { continue; }
        for (let j = 0; j < matches.length && hits < MAX_HITS; j++) {
            hits++;
            dumpAround(matches[j].address, label + ' #' + hits);
        }
    }
    if (hits === 0) console.log('[-] 未找到 ' + label);
}

console.log('[+] 扫描 device_factor 特征 ...');
scanAll(DF_HEX, 'device_factor');

if (KEY_HEX && KEY_HEX.replace(/\s/g, '').length === 64) {
    console.log('\n[+] 扫描 hooked key 特征 ...');
    scanAll(KEY_HEX.replace(/\s/g, ''), 'hooked-key');
}

console.log('\n[+] 完成。若 key 命中点周围的 ascii/hex 里能看到 device_factor，说明两者同结构；把输出贴回来即可判断算法。');
