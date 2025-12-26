# ===============================================
# PC Hardware Report v2
# Tag: 746f617374
# Self-contained, no dependencies (PowerShell / Windows built-ins only)
# Modes:
#   - Basic    : Core hardware + OS + security + network + power
#   - Detailed : Basic + Installed Apps (Classic + Store) + PnP Summary
# ===============================================

# ---------- Paths ----------
$Desktop   = [Environment]::GetFolderPath('Desktop')
$Timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$CrashLog  = Join-Path $Desktop ("PC-Hardware-Report_CRASH_{0}.log" -f $Timestamp)
$TranscriptLog = Join-Path $Desktop ("PC-Hardware-Report_TRANSCRIPT_{0}.log" -f $Timestamp)

# Start transcript ASAP (captures even early failures)
try { Start-Transcript -Path $TranscriptLog -Force | Out-Null } catch {}

# ---------- Globals ----------
$script:ScriptPath = $PSCommandPath
if (-not $script:ScriptPath) { try { $script:ScriptPath = $MyInvocation.PSCommandPath } catch {} }
if (-not $script:ScriptPath) { $script:ScriptPath = '(unknown)' }

$global:ScriptVersion = 'v5.5'
$global:Tag           = '746f617374'

# Track last step for debugging
$script:LastStep = 'Startup'
$script:CollectionErrors = New-Object System.Collections.Generic.List[object]

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Write-CrashLog {
    param([object]$Err)

    $psv       = $PSVersionTable.PSVersion.ToString()
    $isAdmin   = Test-IsAdmin
    
    $scriptPath = $null
    try { $scriptPath = $script:ScriptPath } catch {}
    if (-not $scriptPath) { try { $scriptPath = $PSCommandPath } catch {} }
    if (-not $scriptPath) { try { $scriptPath = $MyInvocation.PSCommandPath } catch {} }
    if (-not $scriptPath) { $scriptPath = '(unknown)' }


    $msg = ''
    $etype = ''
    $lineNo = ''
    $line = ''
    $stack = ''

    if ($Err -is [System.Management.Automation.ErrorRecord]) {
        $msg    = $Err.Exception.Message
        $etype  = $Err.Exception.GetType().FullName
        $lineNo = $Err.InvocationInfo.ScriptLineNumber
        $line   = $Err.InvocationInfo.Line
        $stack  = $Err.ScriptStackTrace
    } elseif ($Err -is [System.Exception]) {
        $msg   = $Err.Message
        $etype = $Err.GetType().FullName
        $stack = $Err.StackTrace
    } else {
        $msg = ($Err | Out-String)
    }

    $payload = @"
PC Hardware Report CRASH
Version: $($global:ScriptVersion)
Tag: $($global:Tag)
Time: $(Get-Date)
PowerShell: $psv
IsAdmin: $isAdmin
ScriptPath: $scriptPath
LastStep: $script:LastStep

Message:
$msg

Type:
$etype

Line:
$lineNo

Command:
$line

StackTrace:
$stack

Transcript:
$TranscriptLog
"@

    # Try Desktop first
    try {
        $payload | Out-File -FilePath $CrashLog -Encoding UTF8 -Force
        if (Test-Path $CrashLog) { return }
    } catch {}

    # Fallback to TEMP if Desktop write fails
    try {
        $fallback = Join-Path $env:TEMP ("PC-Hardware-Report_CRASH_FALLBACK_{0}.log" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
        $payload | Out-File -FilePath $fallback -Encoding UTF8 -Force
        # Also print fallback path so you can find it
        Write-Host ("Crash log fallback written to: {0}" -f $fallback)
    } catch {
        # Absolute last resort: print payload to screen
        Write-Host "Crash log write failed entirely. Dumping crash payload:"
        Write-Host $payload
    }
}


# TRAP catches terminating errors even if they occur outside try/catch blocks.
trap {
    # Always attempt to log
    Write-CrashLog $_

    Write-Host ""
    Write-Host "A fatal error occurred." -ForegroundColor Red
    Write-Host ("LastStep: {0}" -f $script:LastStep) -ForegroundColor Yellow
    Write-Host ""

    Write-Host "Full error record:" -ForegroundColor Yellow
    try {
        ($_ | Format-List * -Force | Out-String) | Write-Host
    } catch {
        Write-Host ($_ | Out-String)
    }

    Write-Host ""
    Write-Host "Expected crash log path (Desktop):"
    Write-Host $CrashLog
    Write-Host "Transcript:"
    Write-Host $TranscriptLog
    Write-Host ""

    try { Stop-Transcript | Out-Null } catch {}
    Read-Host "Press Enter to exit"
    exit 1
}



Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Add-CollectionError {
    param(
        [string]$Section,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $script:CollectionErrors.Add([pscustomobject]@{
        Section = $Section
        Message = $ErrorRecord.Exception.Message
        Type    = $ErrorRecord.Exception.GetType().FullName
    }) | Out-Null
}

function Bytes-ToGB {
    param([nullable[double]]$Bytes)
    if ($null -eq $Bytes) { return '' }
    return [math]::Round(($Bytes / 1GB), 2)
}

function CimDate-ToLocal {
    param($CimDate)
    try {
        if (-not $CimDate) { return '' }
        return ([Management.ManagementDateTimeConverter]::ToDateTime($CimDate)).ToLocalTime()
    } catch { return '' }
}

function Html-Enc {
    param([string]$s)
    if ($null -eq $s) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($s)
}

function Get-ActivePowerPlan {
    $script:LastStep = 'Get-ActivePowerPlan'
    try {
        $out = & powercfg /getactivescheme 2>$null
        if (-not $out) { return $null }
        $m = [regex]::Match(($out -join ' '), 'GUID:\s*([0-9a-fA-F-]+)\s*\((.+)\)')
        if ($m.Success) {
            return [pscustomobject]@{ GUID = $m.Groups[1].Value; Description = $m.Groups[2].Value }
        }
        return [pscustomobject]@{ GUID = ''; Description = ($out -join ' ') }
    } catch { return $null }
}

function Get-SecureBoot {
    $script:LastStep = 'Get-SecureBoot'
    try {
        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
        return [pscustomobject]@{ Enabled = [bool]$enabled }
    } catch {
        return [pscustomobject]@{ Enabled = $null }
    }
}

function Get-MonitorEdidSummary {
    $script:LastStep = 'Get-MonitorEdidSummary'
    try {
        $ids = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction Stop
        $basic = @()
        foreach ($m in $ids) {
            $man = if ($m.ManufacturerName) { ([char[]]$m.ManufacturerName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join '' } else { '' }
            $name = if ($m.UserFriendlyName) { ([char[]]$m.UserFriendlyName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join '' } else { '' }
            $serial = if ($m.SerialNumberID) { ([char[]]$m.SerialNumberID | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join '' } else { '' }
            $prod = if ($m.ProductCodeID) { ([char[]]$m.ProductCodeID | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join '' } else { '' }
            $basic += [pscustomobject]@{
                Manufacturer = $man
                ModelName    = $name
                ProductCode  = $prod
                Serial       = $serial
                Instance     = $m.InstanceName
            }
        }
        return $basic
    } catch { return @() }
}

function Get-PhysicalDisksBestEffort {
    $script:LastStep = 'Get-PhysicalDisksBestEffort'
    try {
        $pd = Get-PhysicalDisk -ErrorAction Stop
        return $pd | Select-Object FriendlyName, SerialNumber, MediaType, BusType, Size, HealthStatus, FirmwareVersion, CanPool
    } catch { return @() }
}

function Get-LogicalDisksBestEffort {
    $script:LastStep = 'Get-LogicalDisksBestEffort'
    try {
        $vol = Get-Volume -ErrorAction Stop
        return $vol | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining
    } catch {
        try {
            $ld = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop
            return $ld | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace
        } catch { return @() }
    }
}

function Get-StorageSmartBestEffort {
    $script:LastStep = 'Get-StorageSmartBestEffort'
    try {
        $s = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop
        return $s | Select-Object InstanceName, PredictFailure, Reason
    } catch { return @() }
}

function Get-WifiDriversBestEffort {
    $script:LastStep = 'Get-WifiDriversBestEffort'
    try {
        $out = & netsh wlan show drivers 2>$null
        if (-not $out) { return @() }

        $pairs = @()
        foreach ($line in $out) {
            if ($line -match '^\s*([^:]+)\s*:\s*(.*)\s*$') {
                $k = $matches[1].Trim()
                $v = $matches[2].Trim()
                if ($k -and $v) { $pairs += [pscustomobject]@{ Key = $k; Value = $v } }
            }
        }
        return $pairs
    } catch { return @() }
}

function Get-PnpSummaryBestEffort {
    $script:LastStep = 'Get-PnpSummaryBestEffort'
    try {
        $all = Get-PnpDevice -ErrorAction Stop
        $g = $all | Group-Object -Property Class | Sort-Object Count -Descending
        return $g | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count } }
    } catch { return @() }
}

function Get-UsbDevicesBestEffort {
    $script:LastStep = 'Get-UsbDevicesBestEffort'
    try {
        $usb = Get-PnpDevice -Class USB -ErrorAction Stop
        return $usb | Select-Object FriendlyName, Manufacturer, Status, InstanceId
    } catch { return @() }
}

function Get-AudioDevicesBestEffort {
    $script:LastStep = 'Get-AudioDevicesBestEffort'
    try {
        $a = @()
        try { $a += Get-PnpDevice -Class Media -ErrorAction Stop } catch {}
        try { $a += Get-PnpDevice -Class AudioEndpoint -ErrorAction Stop } catch {}
        if (-not $a) { return @() }
        return ($a | Select-Object FriendlyName, Manufacturer, Status, InstanceId | Sort-Object FriendlyName -Unique)
    } catch { return @() }
}

function Get-InstalledAppsClassic {
    $script:LastStep = 'Get-InstalledAppsClassic'
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $apps = @()
    foreach ($p in $paths) {
        try {
            $apps += Get-ItemProperty $p -ErrorAction Stop |
                Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        } catch {}
    }
    return ($apps | Sort-Object Publisher, DisplayName -Unique)
}

function Get-InstalledAppsStore {
    $script:LastStep = 'Get-InstalledAppsStore'
    try {
        try { $pkgs = Get-AppxPackage -AllUsers -ErrorAction Stop }
        catch { $pkgs = Get-AppxPackage -ErrorAction Stop }

        return ($pkgs | Select-Object Name, Version, Publisher, InstallLocation | Sort-Object Publisher, Name -Unique)
    } catch { return @() }
}

function Show-ModeMenu {
    param([string]$Version, [string]$Tag)

    $mode = 'Basic'
    while ($true) {
        Clear-Host
        Write-Host ("PC Hardware Report {0} - {1}" -f $Version, $Tag)
        Write-Host ""
        Write-Host ("Mode: {0}" -f $mode)
        Write-Host ""
        Write-Host "1. Basic"
        Write-Host "2. Detailed"
        Write-Host "G. Generate Report"
        Write-Host "Q. Quit"
        Write-Host ""
        Write-Host "Select Mode, Then press [G] To Generate"

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'D1'      { $mode = 'Basic' }
            'NumPad1' { $mode = 'Basic' }
            'D2'      { $mode = 'Detailed' }
            'NumPad2' { $mode = 'Detailed' }
            'G'       { return $mode }
            'Q'       { return $null }
            default   { }
        }
    }
}

function Show-Preflight {
    param([string]$Mode, [string]$DefaultOutDir)

    $script:LastStep = 'Preflight:Show'
    $isAdmin = Test-IsAdmin
    $psv = $PSVersionTable.PSVersion.ToString()

    Clear-Host
    Write-Host ("PC Hardware Report {0} - {1}" -f $global:ScriptVersion, $global:Tag)
    Write-Host ""
    Write-Host "Preflight"
    Write-Host "--------"
    Write-Host ("Mode      : {0}" -f $Mode)
    Write-Host ("PS Version : {0}" -f $psv)
    Write-Host ("Admin      : {0}" -f $isAdmin)
    Write-Host ""
    Write-Host ("Default output folder: {0}" -f $DefaultOutDir)
    Write-Host "Enter a different folder path or press Enter to accept default."
    $outDir = Read-Host "Output folder"
    if (-not $outDir -or $outDir.Trim() -eq '') { $outDir = $DefaultOutDir }

    if (-not (Test-Path $outDir)) {
        Write-Host ""
        Write-Host "Folder does not exist. Creating..."
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    Write-Host ""
    Write-Host ("Output folder set to: {0}" -f $outDir)
    Write-Host "Proceed? (Y/N)"

    while ($true) {
        $k = [Console]::ReadKey($true).Key
        if ($k -eq 'Y') { return $outDir }
        if ($k -eq 'N') { return $null }
    }
}

function To-TableHtml {
    param(
        [string]$Id,
        [string]$Title,
        [object[]]$Rows,
        [string[]]$Properties,
        [hashtable]$PropertyLabels = $null
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        return "<div class='section' id='$Id'><h2>$(Html-Enc $Title)</h2><div class='small'>No data.</div></div>"
    }

    $ths = foreach ($p in $Properties) {
        $label = if ($PropertyLabels -and $PropertyLabels.ContainsKey($p)) { $PropertyLabels[$p] } else { $p }
        "<th>$(Html-Enc $label)</th>"
    }

    $tb = New-Object System.Text.StringBuilder
    foreach ($r in $Rows) {
        [void]$tb.Append("<tr>")
        foreach ($p in $Properties) {
            $v = $null
            try { $v = $r.$p } catch { $v = $null }
            if ($v -is [System.Array]) { $v = ($v -join ', ') }

            if ($p -in @('TotalPhysicalMemory','Capacity','Size','FreeSpace','SizeRemaining','AdapterRAM')) {
                if ($v -as [double]) {
                    $gb = Bytes-ToGB ([double]$v)
                    if ($gb -ne '') { $v = "$gb GB" }
                }
            }

            [void]$tb.Append("<td>$(Html-Enc ([string]$v))</td>")
        }
        [void]$tb.Append("</tr>")
    }

@"
<div class='section' id='$Id'>
  <h2>$(Html-Enc $Title)</h2>
  <table id='$Id-table'>
    <thead><tr>$($ths -join '')</tr></thead>
    <tbody>$($tb.ToString())</tbody>
  </table>
  <div class='action'><button onclick="downloadCSV('$Id-table','$(Html-Enc $Title).csv')">Download CSV</button></div>
</div>
"@
}

function Build-Toc {
    param([object[]]$Items)
    $li = $Items | ForEach-Object { "<li><a href='#$(Html-Enc $_.Id)'>$(Html-Enc $_.Title)</a></li>" }
@"
<div class='toc'>
  <div class='toc-title'>Sections</div>
  <ul>$($li -join '')</ul>
</div>
"@
}

# ---------------- MAIN ----------------
try {
    $script:LastStep = 'ModeMenu'
    $mode = Show-ModeMenu -Version $global:ScriptVersion -Tag $global:Tag
    if ($null -eq $mode) { return }

    $script:LastStep = 'Preflight'
    $outDir = Show-Preflight -Mode $mode -DefaultOutDir $Desktop
    if ($null -eq $outDir) { return }

    $data = [ordered]@{
        GeneratedAt = Get-Date
        Mode        = $mode
        Machine     = $env:COMPUTERNAME
        User        = $env:USERNAME
        IsAdmin     = Test-IsAdmin
        PSVersion   = $PSVersionTable.PSVersion.ToString()
    }

    $script:LastStep = 'BuildStepList'
    $steps = New-Object 'System.Collections.Generic.List[string]'

    $baseSteps = @(
        'ComputerSystem','OperatingSystem','BaseBoard','BIOS','Processors','MemoryDIMMs','MemorySummary',
        'GPU','DiskDrives','PhysicalDisks','LogicalDisks','SMART','Monitors',
        'NetAdapters','NetIP','WifiDrivers','Audio','USB','PowerPlan','SecureBoot','TPM'
    )

    foreach ($s in $baseSteps) { [void]$steps.Add([string]$s) }

    if ($mode -eq 'Detailed') {
        foreach ($s in @('InstalledAppsClassic','InstalledAppsStore','PnPSummary')) { [void]$steps.Add([string]$s) }
    }

# Progress phase 1
    $activity1 = 'Collecting data'
    for ($i = 0; $i -lt $steps.Count; $i++) {
        $step = $steps[$i]
        $script:LastStep = "Collect:$step"
        $pct = [int](($i + 1) / $steps.Count * 100)
        Write-Progress -Activity $activity1 -Status $step -PercentComplete $pct

        try {
            switch ($step) {
                'ComputerSystem' {
                    $cs = Get-CimInstance Win32_ComputerSystem
                    $data.ComputerSystem = @($cs | Select-Object Name, Manufacturer, Model, SystemType, NumberOfLogicalProcessors, NumberOfProcessors, TotalPhysicalMemory)
                }
                'OperatingSystem' {
                    $os = Get-CimInstance Win32_OperatingSystem
                    $lastBoot = CimDate-ToLocal $os.LastBootUpTime
                    $uptime = $null
                    if ($lastBoot) { $uptime = New-TimeSpan -Start $lastBoot -End (Get-Date) }
                    $data.OperatingSystem = @([pscustomobject]@{
                        Caption        = $os.Caption
                        Version        = $os.Version
                        OSArchitecture = $os.OSArchitecture
                        BuildNumber    = $os.BuildNumber
                        InstallDate    = (CimDate-ToLocal $os.InstallDate)
                        LastBootUpTime = $lastBoot
                        Uptime         = if ($uptime) { ("{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes) } else { '' }
                        SerialNumber   = $os.SerialNumber
                    })
                }
                'BaseBoard' {
                    $bb = Get-CimInstance Win32_BaseBoard
                    $data.BaseBoard = @($bb | Select-Object Manufacturer, Product, SerialNumber, Version)
                }
                'BIOS' {
                    $b = Get-CimInstance Win32_BIOS
                    $data.BIOS = @([pscustomobject]@{
                        Manufacturer      = $b.Manufacturer
                        SMBIOSBIOSVersion = $b.SMBIOSBIOSVersion
                        ReleaseDate       = (CimDate-ToLocal $b.ReleaseDate)
                        SerialNumber      = $b.SerialNumber
                    })
                }
                'Processors' {
                    $p = Get-CimInstance Win32_Processor
                    $data.Processors = @($p | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, SocketDesignation, ProcessorId)
                }
                'MemoryDIMMs' {
                    $m = Get-CimInstance Win32_PhysicalMemory
                    $data.MemoryDIMMs = @($m | Select-Object BankLabel, DeviceLocator, Manufacturer, PartNumber, SerialNumber, ConfiguredClockSpeed, Speed, Capacity)
                }
                'MemorySummary' {
                    $pm = $data.MemoryDIMMs
                    $totalGB = 0
                    if ($pm) { foreach ($d in $pm) { if ($d.Capacity -as [double]) { $totalGB += (Bytes-ToGB ([double]$d.Capacity)) } } }

                    $arr = $null
                    try { $arr = Get-CimInstance Win32_PhysicalMemoryArray -ErrorAction Stop } catch { $arr = $null }

                    $maxGB = ''
                    $slots = ''
                    if ($arr) {
                        try {
                            $mc = $arr | Select-Object -First 1 -ExpandProperty MaxCapacity
                            if ($mc -as [double]) { $maxGB = [math]::Round((([double]$mc) * 1KB / 1GB), 2) }
                        } catch {}
                        try { $slots = ($arr | Select-Object -First 1 -ExpandProperty MemoryDevices) } catch {}
                    }

                    $usedSlots = if ($pm) { $pm.Count } else { 0 }
                    $data.MemorySummary = @([pscustomobject]@{
                        ModulesInstalled = $usedSlots
                        SlotsTotal       = $slots
                        TotalCapacityGB  = $totalGB
                        MaxArrayGB       = $maxGB
                    })
                }
                'GPU' {
                    $g = Get-CimInstance Win32_VideoController
                    $data.GPU = @($g | Select-Object Name, VideoProcessor, DriverVersion, AdapterRAM, PNPDeviceID)
                }
                'DiskDrives' {
                    $dd = Get-CimInstance Win32_DiskDrive
                    $data.DiskDrives = @($dd | Select-Object Index, Model, SerialNumber, FirmwareRevision, InterfaceType, MediaType, Size, Partitions)
                }
                'PhysicalDisks' { $data.PhysicalDisks = @(Get-PhysicalDisksBestEffort) }
                'LogicalDisks' {
                    $ld = Get-LogicalDisksBestEffort
                    if ($ld -and ($ld[0].PSObject.Properties.Name -contains 'DriveLetter')) {
                        $data.LogicalDisks = @($ld | ForEach-Object {
                            [pscustomobject]@{
                                DeviceID   = if ($_.DriveLetter) { "$($_.DriveLetter):" } else { '' }
                                VolumeName = $_.FileSystemLabel
                                FileSystem = $_.FileSystem
                                Size       = $_.Size
                                FreeSpace  = $_.SizeRemaining
                            }
                        })
                    } else {
                        $data.LogicalDisks = @($ld)
                    }
                }
                'SMART'     { $data.SMART = @(Get-StorageSmartBestEffort) }
                'Monitors'  { $data.Monitors = @(Get-MonitorEdidSummary) }
                'NetAdapters' {
                    $na = Get-CimInstance Win32_NetworkAdapter
                    $phys = $na | Where-Object { $_.PhysicalAdapter -eq $true -and $_.Name }
                    $data.NetAdapters = @($phys | Select-Object Name, Manufacturer, MACAddress, Speed, NetEnabled, PNPDeviceID)
                }
                'NetIP' {
                    $ip = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
                    $data.NetIP = @($ip | Select-Object Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled)
                }
                'WifiDrivers' { $data.WifiDrivers = @(Get-WifiDriversBestEffort) }
                'Audio'       { $data.Audio = @(Get-AudioDevicesBestEffort) }
                'USB'         { $data.USB = @(Get-UsbDevicesBestEffort) }
                'PowerPlan'   { $data.ActivePowerPlan = @((Get-ActivePowerPlan)) }
                'SecureBoot'  { $data.SecureBoot = @((Get-SecureBoot)) }
                'TPM' {
                    try {
                        $t = Get-Tpm -ErrorAction Stop
                        $data.TPM = @($t | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManagedAuthLevel, OwnerAuth)
                    } catch { $data.TPM = @() }
                }
                'InstalledAppsClassic' { $data.InstalledAppsClassic = @(Get-InstalledAppsClassic) }
                'InstalledAppsStore'   { $data.InstalledAppsStore   = @(Get-InstalledAppsStore) }
                'PnPSummary'           { $data.PnPSummary           = @(Get-PnpSummaryBestEffort) }
            }
        } catch {
            Add-CollectionError -Section $step -ErrorRecord $_
        }
    }
    Write-Progress -Activity $activity1 -Completed
    $data.CollectionErrors = $script:CollectionErrors.ToArray()

    # Progress phase 2
    $script:LastStep = 'BuildReport'
    Write-Progress -Activity "Building report" -Status "Preparing sections" -PercentComplete 20

    # TOC items
    $toc = New-Object System.Collections.Generic.List[object]
    $toc.Add([pscustomobject]@{ Id='computer-system'; Title='Computer System' })
    $toc.Add([pscustomobject]@{ Id='operating-system'; Title='Operating System' })
    $toc.Add([pscustomobject]@{ Id='baseboard'; Title='Motherboard (BaseBoard)' })
    $toc.Add([pscustomobject]@{ Id='bios'; Title='BIOS' })
    $toc.Add([pscustomobject]@{ Id='processors'; Title='Processor(s)' })
    $toc.Add([pscustomobject]@{ Id='memory'; Title='Physical Memory (DIMMs)' })
    $toc.Add([pscustomobject]@{ Id='memory-summary'; Title='Memory Summary' })
    $toc.Add([pscustomobject]@{ Id='gpu'; Title='GPU / Video Controller' })
    $toc.Add([pscustomobject]@{ Id='diskdrives'; Title='Disk Drives (Hardware)' })
    $toc.Add([pscustomobject]@{ Id='physicaldisks'; Title='Physical Disks' })
    $toc.Add([pscustomobject]@{ Id='logicaldisks'; Title='Logical Disks (Volumes)' })
    $toc.Add([pscustomobject]@{ Id='smart'; Title='SMART / Failure Prediction' })
    $toc.Add([pscustomobject]@{ Id='monitors'; Title='Monitors / EDID' })
    $toc.Add([pscustomobject]@{ Id='netadapters'; Title='Network Adapters (Physical)' })
    $toc.Add([pscustomobject]@{ Id='netip'; Title='Network IP Configuration (Enabled)' })
    $toc.Add([pscustomobject]@{ Id='wifi'; Title='Wi-Fi Driver Details' })
    $toc.Add([pscustomobject]@{ Id='audio'; Title='Audio Devices' })
    $toc.Add([pscustomobject]@{ Id='usb'; Title='USB Devices' })
    $toc.Add([pscustomobject]@{ Id='powerplan'; Title='Active Power Plan' })
    $toc.Add([pscustomobject]@{ Id='secureboot'; Title='Secure Boot' })
    $toc.Add([pscustomobject]@{ Id='tpm'; Title='TPM' })

    if ($mode -eq 'Detailed') {
        $toc.Add([pscustomobject]@{ Id='apps-classic'; Title='Installed Apps (Classic)' })
        $toc.Add([pscustomobject]@{ Id='apps-store'; Title='Installed Apps (Store)' })
        $toc.Add([pscustomobject]@{ Id='pnp-summary'; Title='PnP Device Classes (Summary)' })
    }

    $toc.Add([pscustomobject]@{ Id='errors'; Title='Collection Errors' })
    $toc.Add([pscustomobject]@{ Id='json'; Title='Raw JSON Snapshot' })

    $tocHtml = Build-Toc -Items $toc

    Write-Progress -Activity "Building report" -Status "Rendering HTML tables" -PercentComplete 50

    $sections = New-Object System.Text.StringBuilder
    [void]$sections.Append((To-TableHtml -Id 'computer-system' -Title 'Computer System' -Rows $data.ComputerSystem -Properties @('Name','Manufacturer','Model','SystemType','NumberOfLogicalProcessors','NumberOfProcessors','TotalPhysicalMemory')))
    [void]$sections.Append((To-TableHtml -Id 'operating-system' -Title 'Operating System' -Rows $data.OperatingSystem -Properties @('Caption','Version','OSArchitecture','BuildNumber','InstallDate','LastBootUpTime','Uptime','SerialNumber')))
    [void]$sections.Append((To-TableHtml -Id 'baseboard' -Title 'Motherboard (BaseBoard)' -Rows $data.BaseBoard -Properties @('Manufacturer','Product','SerialNumber','Version')))
    [void]$sections.Append((To-TableHtml -Id 'bios' -Title 'BIOS' -Rows $data.BIOS -Properties @('Manufacturer','SMBIOSBIOSVersion','ReleaseDate','SerialNumber')))
    [void]$sections.Append((To-TableHtml -Id 'processors' -Title 'Processor(s)' -Rows $data.Processors -Properties @('Name','Manufacturer','NumberOfCores','NumberOfLogicalProcessors','MaxClockSpeed','SocketDesignation','ProcessorId')))
    [void]$sections.Append((To-TableHtml -Id 'memory' -Title 'Physical Memory (DIMMs)' -Rows $data.MemoryDIMMs -Properties @('BankLabel','DeviceLocator','Manufacturer','PartNumber','SerialNumber','ConfiguredClockSpeed','Speed','Capacity')))
    [void]$sections.Append((To-TableHtml -Id 'memory-summary' -Title 'Memory Summary' -Rows $data.MemorySummary -Properties @('ModulesInstalled','SlotsTotal','TotalCapacityGB','MaxArrayGB')))
    [void]$sections.Append((To-TableHtml -Id 'gpu' -Title 'GPU / Video Controller' -Rows $data.GPU -Properties @('Name','VideoProcessor','DriverVersion','AdapterRAM','PNPDeviceID')))
    [void]$sections.Append((To-TableHtml -Id 'diskdrives' -Title 'Disk Drives (Hardware)' -Rows $data.DiskDrives -Properties @('Index','Model','SerialNumber','FirmwareRevision','InterfaceType','MediaType','Size','Partitions')))
    [void]$sections.Append((To-TableHtml -Id 'physicaldisks' -Title 'Physical Disks' -Rows $data.PhysicalDisks -Properties @('FriendlyName','SerialNumber','MediaType','BusType','Size','HealthStatus','FirmwareVersion','CanPool')))
    [void]$sections.Append((To-TableHtml -Id 'logicaldisks' -Title 'Logical Disks (Volumes)' -Rows $data.LogicalDisks -Properties @('DeviceID','VolumeName','FileSystem','Size','FreeSpace')))
    [void]$sections.Append((To-TableHtml -Id 'smart' -Title 'SMART / Failure Prediction' -Rows $data.SMART -Properties @('InstanceName','PredictFailure','Reason')))
    [void]$sections.Append((To-TableHtml -Id 'monitors' -Title 'Monitors / EDID' -Rows $data.Monitors -Properties @('Manufacturer','ModelName','ProductCode','Serial','Instance')))
    [void]$sections.Append((To-TableHtml -Id 'netadapters' -Title 'Network Adapters (Physical)' -Rows $data.NetAdapters -Properties @('Name','Manufacturer','MACAddress','Speed','NetEnabled','PNPDeviceID')))
    [void]$sections.Append((To-TableHtml -Id 'netip' -Title 'Network IP Configuration (Enabled)' -Rows $data.NetIP -Properties @('Description','MACAddress','IPAddress','IPSubnet','DefaultIPGateway','DNSServerSearchOrder','DHCPEnabled')))
    [void]$sections.Append((To-TableHtml -Id 'wifi' -Title 'Wi-Fi Driver Details' -Rows $data.WifiDrivers -Properties @('Key','Value')))
    [void]$sections.Append((To-TableHtml -Id 'audio' -Title 'Audio Devices' -Rows $data.Audio -Properties @('FriendlyName','Manufacturer','Status','InstanceId') -PropertyLabels @{ InstanceId='PNPDeviceID' }))
    [void]$sections.Append((To-TableHtml -Id 'usb' -Title 'USB Devices' -Rows $data.USB -Properties @('FriendlyName','Manufacturer','Status','InstanceId') -PropertyLabels @{ InstanceId='PNPDeviceID' }))
    [void]$sections.Append((To-TableHtml -Id 'powerplan' -Title 'Active Power Plan' -Rows $data.ActivePowerPlan -Properties @('GUID','Description')))
    [void]$sections.Append((To-TableHtml -Id 'secureboot' -Title 'Secure Boot' -Rows $data.SecureBoot -Properties @('Enabled')))
    [void]$sections.Append((To-TableHtml -Id 'tpm' -Title 'TPM' -Rows $data.TPM -Properties @('TpmPresent','TpmReady','TpmEnabled','TpmActivated','ManagedAuthLevel','OwnerAuth')))

    if ($mode -eq 'Detailed') {
        [void]$sections.Append((To-TableHtml -Id 'apps-classic' -Title 'Installed Apps (Classic)' -Rows $data.InstalledAppsClassic -Properties @('DisplayName','DisplayVersion','Publisher','InstallDate')))
        [void]$sections.Append((To-TableHtml -Id 'apps-store' -Title 'Installed Apps (Store)' -Rows $data.InstalledAppsStore -Properties @('Name','Version','Publisher','InstallLocation')))
        [void]$sections.Append((To-TableHtml -Id 'pnp-summary' -Title 'PnP Device Classes (Summary)' -Rows $data.PnPSummary -Properties @('Name','Count')))
    }

    if ($data.CollectionErrors -and $data.CollectionErrors.Count -gt 0) {
        [void]$sections.Append((To-TableHtml -Id 'errors' -Title 'Collection Errors' -Rows $data.CollectionErrors -Properties @('Section','Message','Type')))
    } else {
        [void]$sections.Append("<div class='section' id='errors'><h2>Collection Errors</h2><div class='small'>None.</div></div>")
    }

    Write-Progress -Activity "Building report" -Status "Embedding JSON snapshot" -PercentComplete 80
    $json = $data | ConvertTo-Json -Depth 6
    $jsonEsc = [System.Net.WebUtility]::HtmlEncode($json)

    $rawJsonSection = @"
<div class='section' id='json'>
  <h2>Raw JSON Snapshot</h2>
  <details>
    <summary>Expand / collapse</summary>
    <pre>$jsonEsc</pre>
  </details>
</div>
"@

    $outfile = Join-Path $outDir ("PC_Hardware_Report_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmm'))

    Write-Progress -Activity "Building report" -Status "Writing HTML file" -PercentComplete 95

    $generatedStamp = (Get-Date).ToString()
    $machineStamp   = Html-Enc $env:COMPUTERNAME
    $modeStamp      = Html-Enc $mode
    $psStamp        = Html-Enc $data.PSVersion
    $adminStamp     = Html-Enc ([string]$data.IsAdmin

)

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PC Hardware Report</title>
<style>
  :root {
    --bg: #ffffff; --fg: #111111; --muted: #666666; --card: #ffffff; --border: #dddddd; --th: #f2f2f2;
    --btnbg: #f8f8f8; --btnbd: #bbbbbb; --prebg: #f7f7f7; --shadow: rgba(0,0,0,0.06); --link: #0b57d0;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #121212; --fg: #e0e0e0; --muted: #aaaaaa; --card: #151515; --border: #343434; --th: #1e1e1e;
      --btnbg: #1a1a1a; --btnbd: #3a3a3a; --prebg: #171717; --shadow: rgba(0,0,0,0.35); --link: #9ec1ff;
    }
  }
  body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: var(--bg); color: var(--fg); }
  h1 { font-size: 28px; margin: 0 0 6px 0; }
  h2 { margin-top: 28px; }
  a { color: var(--link); }
  .topbar { display:flex; justify-content:space-between; gap: 20px; padding: 14px; border: 1px solid var(--border);
            border-radius: 10px; background: var(--card); box-shadow: 0 6px 20px var(--shadow); }
  .small { color: var(--muted); font-size: 12px; }
  hr { border: 0; border-top: 1px solid var(--border); margin: 18px 0; }
  .layout { display:flex; gap: 18px; align-items:flex-start; }
  .toc { position: sticky; top: 12px; width: 270px; max-height: calc(100vh - 60px); overflow:auto; border: 1px solid var(--border);
         border-radius: 10px; padding: 12px; background: var(--card); box-shadow: 0 6px 20px var(--shadow); }
  .toc-title { font-weight: 600; margin-bottom: 8px; }
  .toc ul { list-style: none; padding-left: 0; margin: 0; }
  .toc li { margin: 6px 0; }
  .toc a { text-decoration: none; }
  .toc a:hover { text-decoration: underline; }
  .content { flex: 1; min-width: 420px; }
  .section { margin-bottom: 24px; border: 1px solid var(--border); border-radius: 10px; padding: 12px; background: var(--card);
             box-shadow: 0 6px 20px var(--shadow); }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid var(--border); padding: 6px 8px; }
  th { background: var(--th); text-align: left; }
  .action { margin-top: 8px; }
  button { padding: 6px 10px; border: 1px solid var(--btnbd); background: var(--btnbg); cursor: pointer; border-radius: 8px; color: var(--fg); }
  button:hover { filter: brightness(1.06); }
  pre { background: var(--prebg); padding: 10px; overflow: auto; border: 1px solid var(--border); border-radius: 8px; }
  footer { margin-top: 28px; font-size: 12px; text-align: center; opacity: 0.65; }
  @media (max-width: 980px) { .layout { flex-direction: column; } .toc { width: auto; position: relative; } }
</style>
<script>
function downloadCSV(tableId, filename) {
  const table = document.getElementById(tableId);
  if (!table) return;
  let rows = Array.from(table.querySelectorAll('tr'));
  let csv = rows.map(row => {
    let cols = Array.from(row.querySelectorAll('th,td'));
    return cols.map(col => {
      let text = col.innerText.replace(/\\r?\\n/g, ' ').trim();
      text = '"' + text.replace(/"/g,'""') + '"';
      return text;
    }).join(',');
  }).join('\\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
}
</script>
</head>
<body>

<div class="topbar">
  <div>
    <h1>PC Hardware Report</h1>
    <div class="small">Generated: $generatedStamp | Machine: $machineStamp | Mode: $modeStamp</div>
  </div>
  <div class="small" style="text-align:right;">
    <div>PowerShell: $psStamp</div>
    <div>Admin: $adminStamp</div>
  </div>
</div>

<hr/>

<div class="layout">
  $tocHtml
  <div class="content">
    $($sections.ToString())
    $rawJsonSection
    <footer>$($global:Tag)</footer>
  </div>
</div>

</body>
</html>
"@

    $script:LastStep = 'WriteHTML'
    $html | Out-File -FilePath $outfile -Encoding UTF8 -Force
    Write-Progress -Activity "Building report" -Completed

    Write-Host ""
    Write-Host "Report generated:"
    Write-Host $outfile
    Write-Host "Transcript: $TranscriptLog"
    Write-Host ""
    try { Stop-Transcript | Out-Null } catch {}
    Read-Host "Press Enter to exit"
}
catch {
    Write-CrashLog $_
    Write-Host ""
    Write-Host "A fatal error occurred."
    Write-Host "Crash log: $CrashLog"
    Write-Host "Transcript: $TranscriptLog"
    Write-Host ""
    try { Stop-Transcript | Out-Null } catch {}
    Read-Host "Press Enter to exit"
    exit 1
}
