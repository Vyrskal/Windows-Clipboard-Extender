<#
.SYNOPSIS
    Clipboard Unlocker - removes the hardcoded 25-item / 4 MB limits from Windows
    clipboard history (Win+V). A GUI wrapper over the in-memory cbdhsvc patcher.

.DESCRIPTION
    Run modes:
      (no args)  -> shows the GUI window
      -Silent    -> applies the patch headless (used by the logon scheduled task)

    Engine (PE parser + memory patcher) is based on Patch-ClipboardHistory.ps1.

.PARAMETER Silent
    Apply the patch without the GUI and exit. Used by the scheduled task at logon.

.PARAMETER Limit
    New maximum number of history items (1..65535). Default 255.

.PARAMETER SizeLimitMB
    New maximum size of a single item, in MB. Default 64.

.NOTES
    Requires administrator rights (the exe is built with a requireAdmin manifest).
#>
[CmdletBinding()]
param(
    [switch] $Silent,
    [ValidateRange(1, 65535)]
    [int]    $Limit = 255,
    [ValidateRange(1, 512)]
    [int]    $SizeLimitMB = 64,
    [switch] $Elevated   # internal guard against relaunch loops
)

$ErrorActionPreference = 'Stop'
$script:AppName  = 'Clipboard Unlocker'
$script:TaskName = 'ClipboardUnlocker'
$script:LogDir   = Join-Path $env:LOCALAPPDATA 'ClipboardUnlocker'
$script:LogFile  = Join-Path $script:LogDir 'log.txt'
$script:GuiLog   = $null   # set to a RichTextBox when the GUI is up

# ============================================================
#  Self-location + elevation
# ============================================================
function Get-SelfInfo {
    $mainModule = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $isExe = ($mainModule -notmatch 'powershell(_ise)?\.exe$') -and ($mainModule -notmatch 'pwsh\.exe$')
    if ($isExe) {
        [PSCustomObject]@{ IsExe = $true;  Path = $mainModule }
    } else {
        [PSCustomObject]@{ IsExe = $false; Path = $PSCommandPath }
    }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Invoke-SelfElevation {
    # Relaunch elevated, preserving mode/args. The compiled exe normally auto-prompts via
    # its manifest, so this mainly matters when running the raw .ps1.
    if ($Elevated) { return }   # already tried once
    $self = Get-SelfInfo
    $argList = @('-Elevated')
    if ($Silent) { $argList += '-Silent' }
    $argList += @('-Limit', $Limit, '-SizeLimitMB', $SizeLimitMB)

    try {
        if ($self.IsExe) {
            Start-Process -FilePath $self.Path -ArgumentList $argList -Verb RunAs
        } else {
            $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $self.Path) + $argList
            Start-Process -FilePath 'powershell.exe' -ArgumentList $psArgs -Verb RunAs
        }
    } catch {
        # user declined UAC
    }
    exit
}

# ============================================================
#  Logging
# ============================================================
function Write-Log {
    param([string]$Message, [ValidateSet('info','ok','warn','err')][string]$Level = 'info')
    $stamp = (Get-Date).ToString('HH:mm:ss')
    $line  = "[$stamp] $Message"
    try {
        if (-not (Test-Path $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }
        Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
    } catch { }

    if ($script:GuiLog) {
        $color = switch ($Level) {
            'ok'   { [System.Drawing.Color]::FromArgb(34,197,94) }
            'warn' { [System.Drawing.Color]::FromArgb(234,179,8) }
            'err'  { [System.Drawing.Color]::FromArgb(239,68,68) }
            default{ [System.Drawing.Color]::FromArgb(203,213,225) }
        }
        $script:GuiLog.SelectionStart  = $script:GuiLog.TextLength
        $script:GuiLog.SelectionLength = 0
        $script:GuiLog.SelectionColor  = $color
        $script:GuiLog.AppendText("$line`r`n")
        $script:GuiLog.SelectionColor  = $script:GuiLog.ForeColor
        $script:GuiLog.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
}

# ============================================================
#  PART 1: PE PARSER  (finds exact RVAs from cbdhsvc.dll on disk)
# ============================================================
function Get-CbdhPatchInfo {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $b = [System.IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 0x200 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { return $null }
    $peOff = [BitConverter]::ToInt32($b, 0x3C)
    if ($b[$peOff] -ne 0x50 -or $b[$peOff+1] -ne 0x45) { return $null }
    $numSec  = [BitConverter]::ToUInt16($b, $peOff + 6)
    $optSize = [BitConverter]::ToUInt16($b, $peOff + 20)
    $opt     = $peOff + 24
    if ([BitConverter]::ToUInt16($b, $opt) -ne 0x20B) { return $null }   # PE32+ (x64) only
    $imageBase = [BitConverter]::ToUInt64($b, $opt + 24)
    $secTable  = $opt + $optSize

    $textVA = 0; $textPtr = 0; $textRaw = 0
    for ($s = 0; $s -lt $numSec; $s++) {
        $h = $secTable + $s * 40
        $name = [System.Text.Encoding]::ASCII.GetString($b, $h, 8).TrimEnd([char]0)
        if ($name -eq '.text') {
            $textVA  = [BitConverter]::ToUInt32($b, $h + 12)
            $textRaw = [BitConverter]::ToUInt32($b, $h + 16)
            $textPtr = [BitConverter]::ToUInt32($b, $h + 20)
            break
        }
    }
    if ($textPtr -eq 0) { return $null }

    $scanEnd = [Math]::Min($textPtr + $textRaw, $b.Length) - 11
    $candidates = @()

    for ($i = $textPtr; $i -le $scanEnd; $i++) {
        # mov eax, 25  ==  B8 19 00 00 00
        if ($b[$i] -eq 0xB8 -and $b[$i+1] -eq 0x19 -and $b[$i+2] -eq 0 -and $b[$i+3] -eq 0 -and $b[$i+4] -eq 0) {
            $fields = @(); $baseNib = $null; $q = $i + 5; $valid = $true
            for ($k = 0; $k -lt 2; $k++) {
                # mov [reg+disp8], eax  ==  89 4X dd  (excl. 0x44 / SIB)
                if (($q+2) -lt $b.Length -and $b[$q] -eq 0x89 -and ($b[$q+1] -ge 0x40 -and $b[$q+1] -le 0x47 -and $b[$q+1] -ne 0x44)) {
                    $nib = $b[$q+1] -band 0x0F
                    if ($null -eq $baseNib) { $baseNib = $nib }
                    if ($nib -ne $baseNib) { $valid = $false; break }
                    $fields += [int]$b[$q+2]
                    $q += 3
                } else { break }
            }
            if ($fields.Count -ge 1 -and $valid) {
                # The 4MB/5MB size caps are stored just before the count via
                # `mov [reg+disp], imm32` (0xC7 stores). Capture the exact imm32 offsets so
                # we can lift them like the count. Requiring 0xC7 3 bytes before the constant
                # rejects coincidental 0x00400000 data.
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
    $countRva = $null; $fieldOffsets = @(); $size4Rva = $null; $size5Rva = $null; $size4Off = $null; $size5Off = $null
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

# ============================================================
#  PART 2: C# MEMORY PATCHER
# ============================================================
$script:CSharp = @'
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
function Initialize-MemPatcher {
    if (-not ('MemPatcher' -as [type])) {
        Add-Type -TypeDefinition $script:CSharp -Language CSharp
    }
}

# ============================================================
#  PART 3: PATCH ONE PROCESS
# ============================================================
function Invoke-PatchProcess {
    param([int]$TargetPid, [object]$Info, [int]$ItemLimit, [uint32]$Size4, [uint32]$Size5)
    $proc = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
    if (-not $proc) { return 0 }
    $mod = $proc.Modules | Where-Object { $_.ModuleName -eq 'CBDHSvc.dll' } | Select-Object -First 1
    if (-not $mod) { return 0 }
    # Least privilege: VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION (not PROCESS_ALL_ACCESS).
    $h = [MemPatcher]::OpenProcess(0x0438, $false, $TargetPid)
    if ($h -eq [IntPtr]::Zero) { return 0 }

    $base = $mod.BaseAddress.ToInt64()
    $patched = 0

    # (1) count constructor: mov eax, <ItemLimit>
    $countAddr = $base + $Info.CountRva
    $pb = [byte[]](0xB8, ($ItemLimit -band 0xFF), (($ItemLimit -shr 8) -band 0xFF), (($ItemLimit -shr 16) -band 0xFF), (($ItemLimit -shr 24) -band 0xFF))
    if ([MemPatcher]::PatchAt($h, $countAddr, $pb)) {
        Write-Log ("Patched count constructor @ 0x{0:X}" -f $countAddr) 'ok'
        $patched++
    }

    # (2) size caps: overwrite the 4MB/5MB immediates in the constructor (mov [reg+disp], imm32)
    $s4 = [BitConverter]::GetBytes([uint32]$Size4)
    $s5 = [BitConverter]::GetBytes([uint32]$Size5)
    if ($Info.Size4Rva -and [MemPatcher]::PatchAt($h, $base + $Info.Size4Rva, $s4)) {
        Write-Log ("Patched 4MB size cap @ 0x{0:X}" -f ($base + $Info.Size4Rva)) 'ok'
        $patched++
    }
    if ($Info.Size5Rva -and [MemPatcher]::PatchAt($h, $base + $Info.Size5Rva, $s5)) {
        Write-Log ("Patched 5MB size cap @ 0x{0:X}" -f ($base + $Info.Size5Rva)) 'ok'
        $patched++
    }

    # (3) live structs (immediate effect): count + size fields, using the offsets the PE
    #     parser detected for this build -- the struct layout shifts between Windows versions.
    $co = @($Info.FieldOffsets)
    $oc1 = [int]$co[0]
    $oc2 = if ($co.Count -ge 2) { [int]$co[1] } else { [int]$co[0] }
    $live = [MemPatcher]::PatchLiveStructs($h, [uint32]$ItemLimit, [uint32]$Size4, [uint32]$Size5,
                                           [int]$Info.Size4Off, [int]$Info.Size5Off, $oc1, $oc2, 100)
    if ($live -gt 0) {
        Write-Log "Patched $live live struct(s)" 'ok'
        $patched += $live
    }

    [MemPatcher]::CloseHandle($h) | Out-Null
    return $patched
}

function Get-CbdPid { param([string]$Name)
    $w = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if ($w) { return [int]$w.ProcessId }
    return 0
}

# ============================================================
#  MAIN PATCH ORCHESTRATION
# ============================================================
function Invoke-ClipboardPatch {
    param([int]$ItemLimit = 255, [int]$SizeMB = 64)

    Write-Log "=== Starting patch: limit=$ItemLimit, size=$SizeMB MB ===" 'info'
    Initialize-MemPatcher

    $dll = Join-Path $env:SystemRoot 'System32\cbdhsvc.dll'
    Write-Log "Analyzing $dll ..." 'info'
    $fileVer = try { (Get-Item -LiteralPath $dll).VersionInfo.FileVersion } catch { '?' }
    $info = Get-CbdhPatchInfo -Path $dll
    if (-not $info) {
        Write-Log "Could not read cbdhsvc.dll as a valid 64-bit PE image." 'err'
        return $false
    }
    if ($info.CountCandidates -eq 0) {
        Write-Log "Build not supported yet. Please open an issue with this fingerprint:" 'err'
        Write-Log ("  version=$fileVer  .text=$($info.TextHash)") 'err'
        return $false
    }
    if ($info.CountCandidates -gt 1) {
        Write-Log "Ambiguous match ($($info.CountCandidates) sites) - refusing to patch to avoid corruption." 'err'
        Write-Log ("  version=$fileVer  .text=$($info.TextHash)") 'err'
        return $false
    }
    Write-Log ("Build $fileVer; constructor @ 0x{0:X}; count +{1}; size fields +0x{2:X}/+0x{3:X}" -f `
        $info.CountRva, (($info.FieldOffsets | ForEach-Object { '0x{0:X}' -f $_ }) -join ',+'), $info.Size4Off, $info.Size5Off) 'info'

    # Convert the requested MB cap to the +0x58 / +0x60 field values (preserve the +1 MB gap).
    $size4Val = [uint32]([long]$SizeMB * 1MB)
    $size5Val = [uint32]([long]($SizeMB + 1) * 1MB)

    $svc = Get-Service | Where-Object { $_.Name -like 'cbdhsvc_*' } | Select-Object -First 1
    if (-not $svc) {
        Write-Log "cbdhsvc service not found. Press Win+V once and try again." 'err'
        return $false
    }

    $total = 0
    $pid1 = Get-CbdPid $svc.Name
    Write-Log "Current PID: $pid1" 'info'
    if ($pid1 -gt 0) {
        $total += Invoke-PatchProcess -TargetPid $pid1 -Info $info -ItemLimit $ItemLimit -Size4 $size4Val -Size5 $size5Val
    }

    # Restart so the patched constructor re-runs. Prefer Start-Service; fall back to a Win+V nudge.
    Write-Log "Restarting service..." 'info'
    Stop-Service $svc.Name -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    try { Start-Service $svc.Name -ErrorAction Stop } catch {
        try {
            $shell = New-Object -ComObject wscript.shell
            $shell.SendKeys('#v'); Start-Sleep -Seconds 2; $shell.SendKeys('{ESC}'); Start-Sleep -Seconds 1
        } catch { }
    }
    Start-Sleep -Seconds 1

    $svc = Get-Service | Where-Object { $_.Name -like 'cbdhsvc_*' } | Select-Object -First 1
    if ($svc.Status -ne 'Running') { Start-Service $svc.Name -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }

    $pid2 = Get-CbdPid $svc.Name
    Write-Log "New PID: $pid2" 'info'
    if ($pid2 -gt 0 -and $pid2 -ne $pid1) {
        $total += Invoke-PatchProcess -TargetPid $pid2 -Info $info -ItemLimit $ItemLimit -Size4 $size4Val -Size5 $size5Val
    }

    if ($total -gt 0) {
        Write-Log "DONE! Patched $total location(s). Press Win+V and copy 26+ items to verify." 'ok'
        return $true
    } else {
        Write-Log "No patches were applied." 'warn'
        return $false
    }
}

# ============================================================
#  PERSISTENCE  (scheduled task at logon, runs -Silent, elevated, no UAC)
# ============================================================
function Install-Persistence {
    $self = Get-SelfInfo
    if ($self.IsExe) {
        $action = New-ScheduledTaskAction -Execute $self.Path -Argument '-Silent'
    } else {
        $psArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($self.Path)`" -Silent"
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArgs
    }
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5))
    Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Log "Auto-start enabled (task '$($script:TaskName)' runs at logon)." 'ok'
}

function Uninstall-Persistence {
    if (Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false
        Write-Log "Auto-start disabled." 'ok'
    } else {
        Write-Log "Auto-start was not enabled." 'info'
    }
}

function Test-PersistenceEnabled {
    [bool](Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue)
}

# ============================================================
#  SILENT MODE (no GUI) - used by the scheduled task
# ============================================================
if ($Silent) {
    if (-not (Test-IsAdmin)) { Invoke-SelfElevation }
    try { Invoke-ClipboardPatch -ItemLimit $Limit -SizeMB $SizeLimitMB | Out-Null }
    catch { Write-Log "Error: $($_.Exception.Message)" 'err' }
    return
}

# ============================================================
#  GUI MODE
# ============================================================
if (-not (Test-IsAdmin)) { Invoke-SelfElevation }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# palette
$cBg     = [System.Drawing.Color]::FromArgb(24, 28, 38)
$cPanel  = [System.Drawing.Color]::FromArgb(31, 37, 51)
$cText   = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cMuted  = [System.Drawing.Color]::FromArgb(148, 163, 184)
$cAccent = [System.Drawing.Color]::FromArgb(58, 134, 255)
$cAccentH= [System.Drawing.Color]::FromArgb(80, 150, 255)
$cGreen  = [System.Drawing.Color]::FromArgb(34, 197, 94)
$cGrey   = [System.Drawing.Color]::FromArgb(55, 65, 81)

$fontH   = New-Object System.Drawing.Font('Segoe UI Semibold', 15, [System.Drawing.FontStyle]::Bold)
$fontN   = New-Object System.Drawing.Font('Segoe UI', 9.5)
$fontS   = New-Object System.Drawing.Font('Segoe UI', 8.5)
$fontMono= New-Object System.Drawing.Font('Consolas', 8.5)

$form = New-Object System.Windows.Forms.Form
$form.Text = $script:AppName
$form.ClientSize = New-Object System.Drawing.Size(460, 510)
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false
$form.StartPosition = 'CenterScreen'
$form.BackColor = $cBg
$form.ForeColor = $cText
$form.Font = $fontN
try {
    $icoPath = (Get-SelfInfo).Path
    if ($icoPath -and (Test-Path $icoPath)) {
        $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($icoPath)
    }
} catch { }

# --- header ---
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'Clipboard Unlocker'
$lblTitle.Font = $fontH
$lblTitle.ForeColor = $cText
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(20, 18)
$form.Controls.Add($lblTitle)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = 'Removes the 25-item and 4 MB limits from clipboard history (Win+V)'
$lblSub.Font = $fontS
$lblSub.ForeColor = $cMuted
$lblSub.AutoSize = $true
$lblSub.Location = New-Object System.Drawing.Point(22, 48)
$form.Controls.Add($lblSub)

# --- limit control ---
$lblLimit = New-Object System.Windows.Forms.Label
$lblLimit.Text = 'Max items:'
$lblLimit.ForeColor = $cText
$lblLimit.AutoSize = $true
$lblLimit.Location = New-Object System.Drawing.Point(22, 84)
$form.Controls.Add($lblLimit)

$numLimit = New-Object System.Windows.Forms.NumericUpDown
$numLimit.Minimum = 1
$numLimit.Maximum = 65535
$numLimit.Value = 255
$numLimit.Increment = 25
$numLimit.Font = $fontN
$numLimit.Width = 90
$numLimit.Location = New-Object System.Drawing.Point(130, 82)
$numLimit.BackColor = $cPanel
$numLimit.ForeColor = $cText
$numLimit.BorderStyle = 'FixedSingle'
$form.Controls.Add($numLimit)

# preset buttons
function New-Preset([string]$text, [int]$val, [int]$x) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text; $b.Tag = $val
    $b.Size = New-Object System.Drawing.Size(48, 26)
    $b.Location = New-Object System.Drawing.Point($x, 82)
    $b.FlatStyle = 'Flat'; $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $cGrey; $b.ForeColor = $cText; $b.Font = $fontS
    $b.Cursor = 'Hand'
    $b.Add_Click({ $numLimit.Value = [int]$this.Tag })
    return $b
}
$form.Controls.Add((New-Preset '100'  100  238))
$form.Controls.Add((New-Preset '255'  255  290))
$form.Controls.Add((New-Preset '1000' 1000 342))

# --- size control ---
$lblSize = New-Object System.Windows.Forms.Label
$lblSize.Text = 'Max size (MB):'
$lblSize.ForeColor = $cText
$lblSize.AutoSize = $true
$lblSize.Location = New-Object System.Drawing.Point(22, 120)
$form.Controls.Add($lblSize)

$numSize = New-Object System.Windows.Forms.NumericUpDown
$numSize.Minimum = 1
$numSize.Maximum = 512
$numSize.Value = 64
$numSize.Increment = 16
$numSize.Font = $fontN
$numSize.Width = 90
$numSize.Location = New-Object System.Drawing.Point(130, 118)
$numSize.BackColor = $cPanel
$numSize.ForeColor = $cText
$numSize.BorderStyle = 'FixedSingle'
$form.Controls.Add($numSize)

function New-SizePreset([string]$text, [int]$val, [int]$x) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text; $b.Tag = $val
    $b.Size = New-Object System.Drawing.Size(48, 26)
    $b.Location = New-Object System.Drawing.Point($x, 118)
    $b.FlatStyle = 'Flat'; $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $cGrey; $b.ForeColor = $cText; $b.Font = $fontS
    $b.Cursor = 'Hand'
    $b.Add_Click({ $numSize.Value = [int]$this.Tag })
    return $b
}
$form.Controls.Add((New-SizePreset '16'  16  238))
$form.Controls.Add((New-SizePreset '64'  64  290))
$form.Controls.Add((New-SizePreset '256' 256 342))

# --- primary button ---
$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Text = 'APPLY'
$btnApply.Size = New-Object System.Drawing.Size(418, 44)
$btnApply.Location = New-Object System.Drawing.Point(22, 162)
$btnApply.FlatStyle = 'Flat'; $btnApply.FlatAppearance.BorderSize = 0
$btnApply.BackColor = $cAccent; $btnApply.ForeColor = [System.Drawing.Color]::White
$btnApply.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11, [System.Drawing.FontStyle]::Bold)
$btnApply.Cursor = 'Hand'
$btnApply.FlatAppearance.MouseOverBackColor = $cAccentH
$form.Controls.Add($btnApply)

# --- autostart checkbox ---
$chkAuto = New-Object System.Windows.Forms.CheckBox
$chkAuto.Text = 'Re-apply automatically after every restart'
$chkAuto.ForeColor = $cText
$chkAuto.Font = $fontN
$chkAuto.AutoSize = $true
$chkAuto.Location = New-Object System.Drawing.Point(22, 218)
$form.Controls.Add($chkAuto)
try { $chkAuto.Checked = Test-PersistenceEnabled } catch { }

# --- log box ---
$log = New-Object System.Windows.Forms.RichTextBox
$log.Location = New-Object System.Drawing.Point(22, 250)
$log.Size = New-Object System.Drawing.Size(418, 200)
$log.ReadOnly = $true
$log.BackColor = [System.Drawing.Color]::FromArgb(15, 18, 26)
$log.ForeColor = $cMuted
$log.Font = $fontMono
$log.BorderStyle = 'None'
$form.Controls.Add($log)
$script:GuiLog = $log

# --- footer note + remove-autostart link ---
$lblNote = New-Object System.Windows.Forms.Label
$lblNote.Text = 'Patch lasts until reboot. Antivirus may flag WriteProcessMemory.'
$lblNote.Font = $fontS
$lblNote.ForeColor = $cMuted
$lblNote.AutoSize = $false
$lblNote.Size = New-Object System.Drawing.Size(300, 34)
$lblNote.Location = New-Object System.Drawing.Point(22, 460)
$form.Controls.Add($lblNote)

$lnkRemove = New-Object System.Windows.Forms.LinkLabel
$lnkRemove.Text = 'Remove auto-start'
$lnkRemove.Font = $fontS
$lnkRemove.LinkColor = $cMuted
$lnkRemove.ActiveLinkColor = $cAccent
$lnkRemove.AutoSize = $true
$lnkRemove.Location = New-Object System.Drawing.Point(330, 472)
$form.Controls.Add($lnkRemove)

# --- behaviour ---
$doApply = {
    $btnApply.Enabled = $false; $btnApply.Text = 'Working...'
    $numLimit.Enabled = $false; $numSize.Enabled = $false
    try {
        $lim = [int]$numLimit.Value
        $sz = [int]$numSize.Value
        $ok = Invoke-ClipboardPatch -ItemLimit $lim -SizeMB $sz
        if ($ok) {
            if ($chkAuto.Checked) { try { Install-Persistence } catch { Write-Log "Auto-start: $($_.Exception.Message)" 'err' } }
            else { if (Test-PersistenceEnabled) { try { Uninstall-Persistence } catch { } } }
            $btnApply.BackColor = $cGreen; $btnApply.Text = 'DONE'
        } else {
            $btnApply.Text = 'APPLY'
        }
    } catch {
        Write-Log "Error: $($_.Exception.Message)" 'err'
        $btnApply.Text = 'APPLY'
    } finally {
        $btnApply.Enabled = $true
        $numLimit.Enabled = $true; $numSize.Enabled = $true
        $t = New-Object System.Windows.Forms.Timer
        $t.Interval = 1800
        $t.Add_Tick({ $btnApply.BackColor = $cAccent; $btnApply.Text = 'APPLY'; $this.Stop(); $this.Dispose() })
        $t.Start()
    }
}
$btnApply.Add_Click($doApply)
$lnkRemove.Add_LinkClicked({ try { Uninstall-Persistence; $chkAuto.Checked = $false } catch { Write-Log $_.Exception.Message 'err' } })

Write-Log "Ready. Pick a limit and click APPLY." 'info'
[void]$form.ShowDialog()
