# derive_test.ps1
# 用途：拿你 hook 到的 key（32 字节 / 64 hex）去撞一批常见派生方式，
#       只用本地 device_factor 文件，不需要 app secret。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File .\derive_test.ps1 -KeyHex "<你hook到的64位hex>"
#   可选：-DfFile "path\to\device_factor"

param(
    [Parameter(Mandatory = $true)][string]$KeyHex,
    [string]$DfFile = "$env:TEMP\larkdump\data\data\com.larksuite.suite\databases\sdk_storage\4245e6e0af0e71d614c9e4bc356d5ffd\device_factor"
)

function To-Hex([byte[]]$b) { ($b | ForEach-Object { $_.ToString('x2') }) -join '' }
function To-HexUpper([byte[]]$b) { ($b | ForEach-Object { $_.ToString('x2') }).ToUpper() -join '' }
function Sha256([byte[]]$b) { [System.Security.Cryptography.SHA256]::Create().ComputeHash($b) }
function Md5([byte[]]$b) { [System.Security.Cryptography.MD5]::Create().ComputeHash($b) }
function HmacSha256([byte[]]$key, [byte[]]$data) { (New-Object System.Security.Cryptography.HMACSHA256(,$key)).ComputeHash($data) }

$target = $KeyHex.Trim().Trim('"').ToLower()
if ($target.StartsWith('x"')) { $target = $target.Substring(2) }
$target = $target.TrimEnd('"').ToLower()
Write-Host "目标 key(hex): $target  (len=$($target.Length))"

if (-not (Test-Path $DfFile)) { Write-Host "找不到 device_factor: $DfFile" -ForegroundColor Red; exit 1 }
$df = [System.IO.File]::ReadAllBytes($DfFile)
$df32 = $df[0..31]
$dfTail = if ($df.Length -gt 32) { $df[32..($df.Length - 1)] } else { @() }
Write-Host ("device_factor len={0} hex={1}" -f $df.Length, (To-Hex $df))
Write-Host ""

$cands = [ordered]@{}
# 先试"不哈希、直接切字节"的情况（文件 35 字节 = 3 字节头 + 32 字节 key 的可能性）
if ($df.Length -ge 32) { $cands['raw df[0:32]'] = $df[0..31] }
if ($df.Length -eq 35) { $cands['raw df[3:35]'] = $df[3..34] }
if ($df.Length -gt 32) { $cands['raw df[末尾32]'] = $df[($df.Length-32)..($df.Length-1)] }
$cands['sha256(df32)'] = Sha256 $df32
$cands['sha256(df全部)'] = Sha256 $df
$cands['md5(df32)'] = Md5 $df32
$cands['sha256(sha256(df32))'] = Sha256 (Sha256 $df32)
$cands['sha256(hexlower(df32))'] = Sha256 ([Text.Encoding]::ASCII.GetBytes((To-Hex $df32)))
$cands['sha256(hexupper(df32))'] = Sha256 ([Text.Encoding]::ASCII.GetBytes((To-HexUpper $df32)))
$rev = $df32.Clone(); [Array]::Reverse($rev)
$cands['sha256(reverse(df32))'] = Sha256 $rev
$cands['hmac(df32, df32)'] = HmacSha256 $df32 $df32

# 用 app_id=1664 / package_id=LARK 之类的弱组合再试几个
foreach ($salt in @('1664', 'LARK', 'com.larksuite.suite', 'lark', '5.2.5')) {
    $sb = [Text.Encoding]::ASCII.GetBytes($salt)
    $cands["sha256(df32 + $salt)"] = Sha256 ([byte[]]($df32 + $sb))
    $cands["sha256($salt + df32)"] = Sha256 ([byte[]]($sb + $df32))
}

$hit = $false
foreach ($k in $cands.Keys) {
    $h = To-Hex $cands[$k]
    $mark = if ($h -eq $target) { '  <== 命中'; $script:hit = $true } else { '' }
    $color = if ($h -eq $target) { 'Green' } else { 'Gray' }
    Write-Host ("{0,-28} {1}{2}" -f $k, $h, $mark) -ForegroundColor $color
}

if (-not $hit) {
    Write-Host ""
    Write-Host "全部不匹配 => key 的确叠加了 app secret（或用了 HKDF/加盐更复杂的方案）。" -ForegroundColor Yellow
    Write-Host "下一步：用 scan_df.js 在进程内存里找 device_factor 附近的结构，或对齐版本后跟 Rust 的 encryption_key。" -ForegroundColor Yellow
}
