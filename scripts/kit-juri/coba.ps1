# Memverifikasi semua contoh bundle di Windows.
# Cara termudah: klik dua kali coba.cmd. Atau dari PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\coba.ps1
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot

$arch = 'amd64'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
$bin = Join-Path $PSScriptRoot "bin\sigap-windows-$arch.exe"
# Hapus tanda "diunduh dari internet" supaya Windows tidak memblokir biner.
Get-ChildItem -Path (Join-Path $PSScriptRoot 'bin') -Filter '*.exe' | Unblock-File -ErrorAction SilentlyContinue

Write-Host ("SIGAP verifier offline (" + (& $bin version) + "), trust store: trust_store.json")
Write-Host ''
Write-Host ('{0,-26} {1,-18} {2,-18}' -f 'BUNDLE', 'HASIL', 'HARAPAN')
$pass = 0
$fail = 0
foreach ($line in Get-Content 'bundle\harapan.txt') {
    $parts = $line.Trim() -split '\s+'
    if ($parts.Count -lt 2) { continue }
    $file = $parts[0]
    $want = $parts[1]
    $out = & $bin verify --trust trust_store.json "bundle\$file" 2>$null
    $got = 'galat'
    if ($out) { $got = ((@($out)[0]) -split '\s+')[0] }
    if ($got -eq $want) { $mark = 'cocok'; $pass++ } else { $mark = 'BEDA'; $fail++ }
    Write-Host ('{0,-26} {1,-18} {2,-18} {3}' -f $file, $got, $want, $mark)
}

Write-Host ''
Write-Host "$pass cocok, $fail beda."
Write-Host 'Lihat alasan lengkap satu bundle, misalnya:'
Write-Host "  .\bin\sigap-windows-$arch.exe verify --trust trust_store.json bundle\01_flip_byte.zip"
Write-Host ''
Read-Host 'Tekan Enter untuk menutup'
if ($fail -gt 0) { exit 1 }
