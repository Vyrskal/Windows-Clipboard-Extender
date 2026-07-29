#Requires -RunAsAdministrator
#Requires -Version 5
<#
.SYNOPSIS
    Self-adapting in-memory patch for cbdhsvc. Parses PE from disk, patches memory by exact RVA.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int] $NewItemLimit = 255,

    # Per-item size cap in MB. Default lifts the built-in 4 MB limit to 64 MB.
    # Capped at 1900 so the sign-extended imm32 store stays a positive 64-bit value.
    [ValidateRange(1, 1900)]
    [int] $NewSizeLimitMB = 64
)

$ErrorActionPreference = 'Stop'

# ==========================================
# PART 1: PE PARSER (finds exact RVAs from disk)
# ==========================================
function Get-CbdhPatchInfo {
    param([string]$Path)
    
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $b = [System.IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 0x200 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { return $null }
    
    $peOff = [BitConverter]::ToInt32($b, 0x3C)
    if ($b[$peOff] -ne 0x50 -or $b[$peOff+1] -ne 0x45) { return $null }
    $numSec = [BitConverter]::ToUInt16($b, $peOff + 6)
    $optSize = [BitConverter]::ToUInt16($b, $peOff + 20)
    $opt = $peOff + 24
    if ([BitConverter]::ToUInt16($b, $opt) -ne 0x20B) { return $null }
    
    $imageBase = [BitConverter]::ToUInt64($b, $opt + 24)
    $secTable = $opt + $optSize
    
    $textVA = 0; $textPtr = 0; $textRaw = 0
    for ($s = 0; $s -lt $numSec; $s++) {
        $h = $secTable + $s * 40
        $name = [System.Text.Encoding]::ASCII.GetString($b, $h, 8).TrimEnd([char]0)
        if ($name -eq '.text') {
            $textVA = [BitConverter]::ToUInt32($b, $h + 12)
            $textRaw = [BitConverter]::ToUInt32($b, $h + 16)
            $textPtr = [BitConverter]::ToUInt32($b, $h + 20)
            break
        }
    }
    if ($textPtr -eq 0) { return $null }
    
    $scanEnd = [Math]::Min($textPtr + $textRaw, $b.Length) - 11
    $candidates = @()

    for ($i = $textPtr; $i -le $scanEnd; $i++) {
        if ($b[$i] -eq 0xB8 -and $b[$i+1] -eq 0x19 -and $b[$i+2] -eq 0 -and $b[$i+3] -eq 0 -and $b[$i+4] -eq 0) {
            $fields = @(); $baseNib = $null; $q = $i + 5; $valid = $true
            for ($k = 0; $k -lt 2; $k++) {
                if (($q+2) -lt $b.Length -and $b[$q] -eq 0x89 -and ($b[$q+1] -ge 0x40 -and $b[$q+1] -le 0x47 -and $b[$q+1] -ne 0x44)) {
                    $nib = $b[$q+1] -band 0x0F
                    if ($null -eq $baseNib) { $baseNib = $nib }
                    if ($nib -ne $baseNib) { $valid = $false; break }
                    $fields += [int]$b[$q+2]
                    $q += 3
                } else { break }
            }
            if ($fields.Count -ge 1 -and $valid) {
                # In the same constructor, the 4MB/5MB size caps are stored just before the
                # count via `mov [reg+disp], imm32` (0xC7 stores). Capture the exact imm32
                # locations so we can lift them the same way we lift the count. Requiring the
                # 0xC7 opcode 3 bytes before the constant rejects coincidental 0x00400000 data.
                $winStart = [Math]::Max($textPtr, $i - 0x60)
                $size4 = $null; $size5 = $null; $off4 = $null; $off5 = $null
                for ($w = $winStart; $w -lt $i; $w++) {
                    if ($b[$w] -eq 0x00 -and $b[$w+1] -eq 0x00 -and $b[$w+2] -eq 0x40 -and $b[$w+3] -eq 0x00 -and ($w - 3) -ge $textPtr -and $b[$w-3] -eq 0xC7) {
                        $size4 = [uint32]($textVA + ($w - $textPtr)); $off4 = [int]$b[$w-1]   # disp8 = struct field offset
                    }
                    if ($b[$w] -eq 0x00 -and $b[$w+1] -eq 0x00 -and $b[$w+2] -eq 0x50 -and $b[$w+3] -eq 0x00 -and ($w - 3) -ge $textPtr -and $b[$w-3] -eq 0xC7) {
                        $size5 = [uint32]($textVA + ($w - $textPtr)); $off5 = [int]$b[$w-1]
                    }
                }
                if ($null -ne $size4 -and $null -ne $size5) {
                    $candidates += [PSCustomObject]@{
                        Rva      = [uint32]($textVA + ($i - $textPtr))
                        Fields   = @($fields | Sort-Object -Unique)
                        Size4Rva = $size4
                        Size5Rva = $size5
                        Size4Off = $off4
                        Size5Off = $off5
                    }
                }
            }
        }
    }

    # Refuse-on-ambiguous: only trust a single, unique constructor site.
    # 0 matches -> build not supported; >1 -> ambiguous, never guess which to write.
    $countRva = $null
    $fieldOffsets = @()
    $size4Rva = $null
    $size5Rva = $null
    $size4Off = $null
    $size5Off = $null
    if ($candidates.Count -eq 1) {
        $countRva     = $candidates[0].Rva
        $fieldOffsets = $candidates[0].Fields
        $size4Rva     = $candidates[0].Size4Rva
        $size5Rva     = $candidates[0].Size5Rva
        $size4Off     = $candidates[0].Size4Off
        $size5Off     = $candidates[0].Size5Off
    }

    # SHA256 of the .text section — the build fingerprint we ask users to report.
    $textLen  = [Math]::Min([int]$textRaw, $b.Length - [int]$textPtr)
    $sha      = [System.Security.Cryptography.SHA256]::Create()
    $textHash = ($sha.ComputeHash($b, [int]$textPtr, $textLen) | ForEach-Object { $_.ToString('x2') }) -join ''
    $sha.Dispose()

    return [PSCustomObject]@{
        ImageBase       = $imageBase
        CountRva        = $countRva
        CountCandidates = $candidates.Count
        FieldOffsets    = $fieldOffsets
        Size4Rva        = $size4Rva
        Size5Rva        = $size5Rva
        Size4Off        = $size4Off
        Size5Off        = $size5Off
        TextHash        = $textHash
    }
}

# ==========================================
# PART 2: C# MEMORY PATCHER
# ==========================================
$csharpCode = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class MemPatcher {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int a, bool b, int c);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, int c, out int d);
    [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, int c, out int d);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr a, out MEMORY_BASIC_INFORMATION b, uint c);
    
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_READWRITE = 0x04;
    
    public static bool PatchAt(IntPtr hProcess, long address, byte[] data) {
        int wr;
        return WriteProcessMemory(hProcess, new IntPtr(address), data, data.Length, out wr) && wr == data.Length;
    }
    
    public static int PatchLiveStructs(IntPtr hProcess, uint newVal, uint newSize4, uint newSize5,
                                       int o4, int o5, int oc1, int oc2, int maxRegionMB) {
        int patched = 0;
        IntPtr addr = IntPtr.Zero;
        int mbiSz = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
        MEMORY_BASIC_INFORMATION mbi;
        byte[] valBytes   = BitConverter.GetBytes(newVal);
        byte[] size4Bytes = BitConverter.GetBytes(newSize4);
        byte[] size5Bytes = BitConverter.GetBytes(newSize5);
        int maxOff = Math.Max(Math.Max(o4, o5), Math.Max(oc1, oc2));
        long maxRegionBytes = (long)maxRegionMB * 1024 * 1024;
        
        while (VirtualQueryEx(hProcess, addr, out mbi, (uint)mbiSz) == new IntPtr(mbiSz)) {
            long regionSize = mbi.RegionSize.ToInt64();
            bool isWritable = (mbi.State == MEM_COMMIT) && (mbi.Protect == PAGE_READWRITE);
            if (isWritable && regionSize <= maxRegionBytes) {
                const int chunkSize = 4 * 1024 * 1024;
                byte[] buf = new byte[chunkSize];   // reused across chunks (avoids per-chunk GC churn)
                for (long pos = 0; pos < regionSize; pos += chunkSize) {
                    int toRead = (int)Math.Min((long)chunkSize, regionSize - pos);
                    int rd;
                    IntPtr chunkBase = new IntPtr(mbi.BaseAddress.ToInt64() + pos);
                    if (ReadProcessMemory(hProcess, chunkBase, buf, toRead, out rd)) {
                        int limit = rd - (maxOff + 4);
                        for (int i = 0; i <= limit; i += 8) {
                            if (BitConverter.ToUInt32(buf, i + o4)  == 0x00400000 &&
                                BitConverter.ToUInt32(buf, i + o5)  == 0x00500000 &&
                                BitConverter.ToUInt32(buf, i + oc1) == 0x19 &&
                                BitConverter.ToUInt32(buf, i + oc2) == 0x19) {
                                long b0 = chunkBase.ToInt64() + i;
                                int w4, w5, w1, w2;
                                WriteProcessMemory(hProcess, new IntPtr(b0 + o4),  size4Bytes, 4, out w4);
                                WriteProcessMemory(hProcess, new IntPtr(b0 + o5),  size5Bytes, 4, out w5);
                                WriteProcessMemory(hProcess, new IntPtr(b0 + oc1), valBytes,   4, out w1);
                                WriteProcessMemory(hProcess, new IntPtr(b0 + oc2), valBytes,   4, out w2);
                                if (w4 == 4 && w5 == 4 && w1 == 4 && w2 == 4) patched++;
                            }
                        }
                    }
                }
            }
            addr = new IntPtr(mbi.BaseAddress.ToInt64() + regionSize);
        }
        return patched;
    }
}
'@

if (-not ('MemPatcher' -as [type])) {
    Add-Type -TypeDefinition $csharpCode -Language CSharp
}

# ==========================================
# PART 3: ANALYZE DISK DLL
# ==========================================
$dllPath = Join-Path $env:SystemRoot 'System32\cbdhsvc.dll'
Write-Host "Analyzing $dllPath..."
$info    = Get-CbdhPatchInfo -Path $dllPath
$fileVer = (Get-Item -LiteralPath $dllPath).VersionInfo.FileVersion

if (-not $info) {
    throw "Could not read $dllPath as a valid 64-bit PE image."
}

if ($info.CountCandidates -eq 0) {
    throw @"

Could not locate the clipboard item-count constructor in $dllPath.
This Windows build is not supported yet. Please open an issue with the fingerprint below:
  https://github.com/Vyrskal/Windows-Clipboard-Extender/issues
  File version : $fileVer
  .text SHA256 : $($info.TextHash)
"@
}

if ($info.CountCandidates -gt 1) {
    throw @"

Ambiguous match: found $($info.CountCandidates) candidate constructor sites in $dllPath.
Refusing to patch -- writing to the wrong site could corrupt the clipboard service.
Please open an issue so an exact recipe can be added for this build:
  https://github.com/Vyrskal/Windows-Clipboard-Extender/issues
  File version : $fileVer
  .text SHA256 : $($info.TextHash)
"@
}

Write-Host ("Build: $fileVer  (.text {0}...)" -f $info.TextHash.Substring(0, 16))
Write-Host ("Constructor RVA 0x{0:X}; count fields +{1}; size fields +0x{2:X}/+0x{3:X}" -f `
    $info.CountRva, (($info.FieldOffsets | ForEach-Object { '0x{0:X}' -f $_ }) -join ',+'), $info.Size4Off, $info.Size5Off)
Write-Host ("Size-cap immediates at RVA 0x{0:X} (4MB) and 0x{1:X} (5MB)" -f $info.Size4Rva, $info.Size5Rva)

# ==========================================
# PART 4: FIND SERVICE & PATCH
# ==========================================
function Get-CbdPid($name) {
    $w = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
    if ($w) { return $w.ProcessId }
    return 0
}

function Invoke-ProcessPatch {
    param([int]$TargetPid, [object]$Info, [int]$Limit, [uint32]$Size4, [uint32]$Size5)
    
    $proc = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
    if (-not $proc) { return 0 }
    
    $mod = $proc.Modules | Where-Object { $_.ModuleName -eq 'CBDHSvc.dll' } | Select-Object -First 1
    if (-not $mod) { return 0 }
    
    # Least privilege: VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION (not PROCESS_ALL_ACCESS).
    $h = [MemPatcher]::OpenProcess(0x0438, $false, $TargetPid)
    if ($h -eq [IntPtr]::Zero) { return 0 }
    
    $base = $mod.BaseAddress.ToInt64()
    $patched = 0
    
    # Patch count constructor at base+RVA
    $countAddr = $base + $Info.CountRva
    $pb = [byte[]](0xB8, ($Limit -band 0xFF), (($Limit -shr 8) -band 0xFF), (($Limit -shr 16) -band 0xFF), (($Limit -shr 24) -band 0xFF))
    if ([MemPatcher]::PatchAt($h, $countAddr, $pb)) {
        Write-Host ("Patched count constructor at 0x{0:X}" -f $countAddr) -ForegroundColor Green
        $patched++
    }
    
    # Patch the 4MB/5MB size-cap immediates in the constructor (mov [reg+disp], imm32).
    $s4 = [BitConverter]::GetBytes([uint32]$Size4)
    $s5 = [BitConverter]::GetBytes([uint32]$Size5)
    if ($Info.Size4Rva -and [MemPatcher]::PatchAt($h, $base + $Info.Size4Rva, $s4)) {
        Write-Host ("Patched 4MB size cap at 0x{0:X}" -f ($base + $Info.Size4Rva)) -ForegroundColor Green
        $patched++
    }
    if ($Info.Size5Rva -and [MemPatcher]::PatchAt($h, $base + $Info.Size5Rva, $s5)) {
        Write-Host ("Patched 5MB size cap at 0x{0:X}" -f ($base + $Info.Size5Rva)) -ForegroundColor Green
        $patched++
    }

    # Patch live structs for immediate effect (count + size fields), using the offsets the
    # PE parser detected for this build -- the struct layout shifts between Windows versions.
    $co = @($Info.FieldOffsets)
    $oc1 = [int]$co[0]
    $oc2 = if ($co.Count -ge 2) { [int]$co[1] } else { [int]$co[0] }
    $live = [MemPatcher]::PatchLiveStructs($h, [uint32]$Limit, [uint32]$Size4, [uint32]$Size5,
                                           [int]$Info.Size4Off, [int]$Info.Size5Off, $oc1, $oc2, 100)
    if ($live -gt 0) {
        Write-Host "Patched $live live struct(s)" -ForegroundColor Green
        $patched += $live
    }
    
    [MemPatcher]::CloseHandle($h) | Out-Null
    return $patched
}

$svc = Get-Service | Where-Object { $_.Name -like "cbdhsvc_*" } | Select-Object -First 1
if (-not $svc) { throw "cbdhsvc service not found" }

# Convert the requested MB cap to the byte values stored in the +0x58 / +0x60 fields.
# The originals are 4 MB and 5 MB (a +1 MB headroom), so preserve that gap.
$size4Val = [uint32]([long]$NewSizeLimitMB * 1MB)
$size5Val = [uint32]([long]($NewSizeLimitMB + 1) * 1MB)
Write-Host ("Lifting: item count -> {0}, item size -> {1} MB" -f $NewItemLimit, $NewSizeLimitMB)

# --- Patch current instance ---
$pid1 = Get-CbdPid $svc.Name
Write-Host "Current PID: $pid1"
$total = 0
if ($pid1 -gt 0) {
    $total += Invoke-ProcessPatch -TargetPid $pid1 -Info $info -Limit $NewItemLimit -Size4 $size4Val -Size5 $size5Val
}

# --- Restart so the patched constructor re-runs. Prefer Start-Service; only fall back to a
#     Win+V nudge (which briefly flashes the flyout) if the service won't start on its own. ---
Write-Host "Restarting cbdhsvc..."
Stop-Service $svc.Name -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
try {
    Start-Service $svc.Name -ErrorAction Stop
} catch {
    try {
        $shell = New-Object -ComObject wscript.shell
        $shell.SendKeys('#v'); Start-Sleep -Seconds 2; $shell.SendKeys('{ESC}'); Start-Sleep -Seconds 1
    } catch { }
}
Start-Sleep -Seconds 1

$svc = Get-Service | Where-Object { $_.Name -like "cbdhsvc_*" } | Select-Object -First 1
if ($svc.Status -ne 'Running') {
    Start-Service $svc.Name -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# --- Patch new instance ---
$pid2 = Get-CbdPid $svc.Name
Write-Host "New PID: $pid2"
if ($pid2 -gt 0 -and $pid2 -ne $pid1) {
    $total += Invoke-ProcessPatch -TargetPid $pid2 -Info $info -Limit $NewItemLimit -Size4 $size4Val -Size5 $size5Val
}

if ($total -gt 0) {
    Write-Host "`nSUCCESS! Patched $total location(s)." -ForegroundColor Black -BackgroundColor Green
    Write-Host "Press Win+V and copy 26+ items to verify." -ForegroundColor Green
} else {
    Write-Warning "No patches applied."
}
