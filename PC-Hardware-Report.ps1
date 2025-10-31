# ==========================================================
# Single-File PC Hardware Report (Self-Contained HTML only)
# Works on Windows 10/11. No admin required.
# ==========================================================

$ErrorActionPreference = 'SilentlyContinue'

# ---------- Helpers ----------
function New-TableHtml {
    param([Parameter(Mandatory)]$Data,[string]$Title="")
    if (-not $Data) { return "<h2>$Title</h2><p>No data.</p>" }
    $frag = $Data | ConvertTo-Html -Fragment
    if ($Title) { return "<h2>$Title</h2>`n$frag" } else { return $frag }
}

# ---------- Core collections ----------
$ComputerSystem = Get-CimInstance Win32_ComputerSystem
$OperatingSystem = Get-CimInstance Win32_OperatingSystem
$Processor       = Get-CimInstance Win32_Processor
$BaseBoard       = Get-CimInstance Win32_BaseBoard
$BIOS            = Get-CimInstance Win32_BIOS
$VideoController = Get-CimInstance Win32_VideoController
$PhysicalMemory  = Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel,DeviceLocator,Manufacturer,PartNumber,SerialNumber,ConfiguredClockSpeed,Speed,Capacity
$DiskDrives      = Get-CimInstance Win32_DiskDrive | Select-Object Index,Model,SerialNumber,FirmwareRevision,InterfaceType,MediaType,Size,Partitions
$LogicalDisks    = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace
$NetworkAdapters = Get-CimInstance Win32_NetworkAdapter | Where-Object {$_.PhysicalAdapter -eq $true} | Select-Object Name,Manufacturer,MACAddress,Speed,NetEnabled,PNPDeviceID
$NetIPConfigs    = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | Select-Object Description,MACAddress,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder,DHCPEnabled
$SoundDevices    = Get-CimInstance Win32_SoundDevice | Select-Object Name,Manufacturer,Status,PNPDeviceID
$USBDevices      = @(Get-CimInstance Win32_USBControllerDevice | ForEach-Object { ([wmi]$_.Dependent) } | Select-Object Name,Manufacturer,PNPDeviceID) | Sort-Object Name -Unique
$Batteries       = Get-CimInstance Win32_Battery | Select-Object Name,EstimatedChargeRemaining,BatteryStatus,DesignVoltage,EstimatedRunTime
$PnPAll          = Get-CimInstance Win32_PnPEntity | Select-Object Name,PNPClass,Manufacturer,PNPDeviceID,Status

# Storage via newer cmdlet if available (NVMe/BusType view)
$PhysicalDisks   = $null
try { $PhysicalDisks = Get-PhysicalDisk | Select-Object FriendlyName,SerialNumber,MediaType,BusType,Size,HealthStatus,FirmwareVersion,CanPool } catch {}

# Monitors / EDID (root\wmi)
$Monitors = @()
try {
    $ids = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue
    $basic = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue
    foreach ($id in $ids) {
        $serial = ($id.SerialNumberID | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join ''
        $mfg    = ($id.ManufacturerName | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join ''
        $prod   = ($id.ProductCodeID | ForEach-Object { $_.ToString("X2") }) -join ''
        $name   = ($id.UserFriendlyName | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join ''
        $match  = $basic | Where-Object { $_.InstanceName -eq $id.InstanceName }
        $hsize  = if ($match) { $match.MaxHorizontalImageSize } else { $null }
        $vsize  = if ($match) { $match.MaxVerticalImageSize } else { $null }
        $Monitors += [pscustomobject]@{
            Manufacturer = $mfg
            ModelName    = $name
            ProductCode  = $prod
            Serial       = $serial
            MaxSize_cm   = if ($hsize -and $vsize) { "$hsize x $vsize" } else { $null }
            Instance     = $id.InstanceName
        }
    }
} catch {}

# Firmware/Secure Boot/TPM (best-effort)
$SecureBoot = $null
try { $SecureBoot = Confirm-SecureBootUEFI } catch {}
$TPM = $null
try { $TPM = Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,ManagedAuthLevel,OwnerAuth } catch {}

# Active power plan
$ActivePowerPlan = $null
try {
    $line = (powercfg /GETACTIVESCHEME) 2>$null
    if ($line) {
        $guid = ($line -split '\s+')[3]
        $desc = ($line -split '\(')[1].TrimEnd(')')
        $ActivePowerPlan = [pscustomobject]@{ GUID = $guid; Description = $desc }
    }
} catch {}

# ---------- Summary JSON (embedded) ----------
$Summary = [pscustomobject]@{
    GeneratedAt     = (Get-Date)
    ComputerSystem  = $ComputerSystem
    OperatingSystem = $OperatingSystem
    Processor       = $Processor
    BaseBoard       = $BaseBoard
    BIOS            = $BIOS
    VideoController = $VideoController
    PhysicalMemory  = $PhysicalMemory
    DiskDrives      = $DiskDrives
    LogicalDisks    = $LogicalDisks
    PhysicalDisks   = $PhysicalDisks
    NetworkAdapters = $NetworkAdapters
    NetIPConfigs    = $NetIPConfigs
    SoundDevices    = $SoundDevices
    USBDevices      = $USBDevices
    Monitors        = $Monitors
    Batteries       = $Batteries
    ActivePowerPlan = $ActivePowerPlan
    SecureBoot      = if ($SecureBoot -ne $null) { [pscustomobject]@{Enabled=$SecureBoot} } else { $null }
    TPM             = $TPM
    PnPAll          = $PnPAll
}
$SummaryJson = $Summary | ConvertTo-Json -Depth 10

# ---------- Build HTML ----------
$css = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; }
h1 { font-size: 28px; margin-bottom: 0; }
h2 { margin-top: 28px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 6px 8px; }
th { background: #f2f2f2; text-align: left; }
.small { color: #666; font-size: 12px; }
.section { margin-bottom: 24px; }
.action { margin: 6px 0 14px 0; }
details { margin-top: 10px; }
button { padding: 6px 10px; border: 1px solid #bbb; background: #f8f8f8; cursor: pointer; border-radius: 6px; }
button:hover { background: #eee; }
pre { background: #f7f7f7; padding: 10px; overflow: auto; border: 1px solid #ddd; border-radius: 6px; }
hr { border: 0; border-top: 1px solid #ddd; margin: 20px 0; }
</style>
"@

# JavaScript to export each table to CSV (client-side)
$js = @"
<script>
function tableToCSV(table) {
  var rows = table.querySelectorAll('tr');
  var csv = [];
  for (var i=0; i<rows.length; i++) {
    var cols = rows[i].querySelectorAll('th, td');
    var row = [];
    for (var j=0; j<cols.length; j++) {
      var text = cols[j].innerText.replaceAll('""','""""').replace(/\r?\n|\r/g,' ').trim();
      if (text.indexOf(',') >= 0 || text.indexOf('"') >= 0) text = '\"' + text + '\"';
      row.push(text);
    }
    csv.push(row.join(','));
  }
  return csv.join('\n');
}
function downloadCSV(id, name) {
  var section = document.getElementById(id);
  if (!section) return;
  var table = section.querySelector('table');
  if (!table) return;
  var csv = tableToCSV(table);
  var blob = new Blob([csv], {type: 'text/csv;charset=utf-8;'});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = name || (id + '.csv');
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
function copyJSON() {
  const el = document.getElementById('raw-json');
  navigator.clipboard.writeText(el.innerText);
  const btn = document.getElementById('copy-json-btn');
  btn.innerText = 'Copied!';
  setTimeout(()=>btn.innerText='Copy JSON', 1200);
}
</script>
"@

$header = "<h1>PC Hardware Report</h1><div class='small'>Generated: $(Get-Date) | Machine: $($ComputerSystem.Name)</div><hr/>"

function Section {
    param([string]$Id,[string]$Title,$Data)
    $block = "<div class='section' id='$Id'>$(New-TableHtml -Title $Title -Data $Data)<div class='action'><button onclick=`"downloadCSV('$Id','$Title.csv')`">Download CSV</button></div></div>"
    return $block
}

$html = @()
$html += $header

$html += Section -Id 'computer-system' -Title 'Computer System' -Data ($ComputerSystem | Select-Object Name,Manufacturer,Model,SystemType,NumberOfLogicalProcessors,NumberOfProcessors,TotalPhysicalMemory)
$html += Section -Id 'operating-system' -Title 'Operating System' -Data ($OperatingSystem | Select-Object Caption,Version,OSArchitecture,BuildNumber,InstallDate,LastBootUpTime,SerialNumber)
$html += Section -Id 'baseboard' -Title 'Motherboard (BaseBoard)' -Data ($BaseBoard | Select-Object Manufacturer,Product,SerialNumber,Version)
$html += Section -Id 'bios' -Title 'BIOS' -Data ($BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber)
$html += Section -Id 'processors' -Title 'Processor(s)' -Data ($Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,SocketDesignation,ProcessorId)
$html += Section -Id 'memory' -Title 'Physical Memory (DIMMs)' -Data $PhysicalMemory
$html += Section -Id 'gpu' -Title 'GPU / Video Controller' -Data ($VideoController | Select-Object Name,VideoProcessor,DriverVersion,AdapterRAM,PNPDeviceID)
$html += Section -Id 'diskdrives' -Title 'Disk Drives (Hardware)' -Data $DiskDrives
if ($PhysicalDisks) { $html += Section -Id 'physicaldisks' -Title 'Physical Disks (Storage Spaces / NVMe view)' -Data $PhysicalDisks }
$html += Section -Id 'logicaldisks' -Title 'Logical Disks (Volumes)' -Data $LogicalDisks
$html += Section -Id 'monitors' -Title 'Monitors / EDID' -Data $Monitors
$html += Section -Id 'netadapters' -Title 'Network Adapters (Physical)' -Data $NetworkAdapters
$html += Section -Id 'netip' -Title 'Network IP Configuration (Enabled)' -Data $NetIPConfigs
$html += Section -Id 'audio' -Title 'Audio Devices' -Data $SoundDevices
$html += Section -Id 'usb' -Title 'USB Devices' -Data $USBDevices
if ($Batteries) { $html += Section -Id 'battery' -Title 'Battery' -Data $Batteries }
if ($ActivePowerPlan) { $html += Section -Id 'powerplan' -Title 'Active Power Plan' -Data $ActivePowerPlan }
if ($SecureBoot -ne $null) { $html += Section -Id 'secureboot' -Title 'Secure Boot' -Data ([pscustomobject]@{Enabled=$SecureBoot}) }
if ($TPM) { $html += Section -Id 'tpm' -Title 'TPM' -Data $TPM }

# PnP summary (top classes) + Full count
$pnGroups = $PnPAll | Group-Object PNPClass | Sort-Object Count -Descending | Select-Object Name,Count
$html += Section -Id 'pnp-summary' -Title 'PnP Device Classes (Summary)' -Data $pnGroups
$html += "<div class='small'>Full device listing is included below in JSON (open 'Raw JSON Snapshot').</div>"

# PSU Sizing Checklist (inline)
$cpuName   = ($Processor | Select-Object -ExpandProperty Name) -join " | "
$gpuNames  = ($VideoController | Select-Object -ExpandProperty Name) -join " | "
$driveCnt  = @($DiskDrives).Count
$ramCnt    = @($PhysicalMemory).Count
$psuHtml = @"
<h2>PSU Sizing Checklist</h2>
<p>This section summarizes the key info you need for a safe PSU choice.</p>
<table>
<tr><th>CPU</th><td>$cpuName</td></tr>
<tr><th>GPU(s)</th><td>$gpuNames</td></tr>
<tr><th>Motherboard</th><td>$($BaseBoard.Manufacturer) $($BaseBoard.Product)</td></tr>
<tr><th>RAM modules</th><td>$ramCnt</td></tr>
<tr><th>Drive count</th><td>$driveCnt</td></tr>
</table>
<ul>
  <li>Size for worst-case GPU + CPU load, then add <strong>25–30%</strong> headroom.</li>
  <li>Check connectors: <strong>12VHPWR</strong> (new GPUs) or 2–3x 8-pin PCIe for older cards.</li>
  <li>Ensure enough SATA/Molex for drives and accessories.</li>
  <li>Prefer reputable brands with <strong>80 PLUS Gold</strong> (or better).</li>
  <li>If planning a future GPU upgrade, size for that target now.</li>
</ul>
"@
$html += "<div class='section' id='psu'>$psuHtml<div class='action'><button onclick=`"downloadCSV('diskdrives','DiskDrives.csv')`">Export Drive List (CSV)</button></div></div>"

# Raw JSON (embedded, collapsible)
$encodedJson = [System.Web.HttpUtility]::HtmlEncode($SummaryJson)
$jsonBlock = @"
<h2>Raw JSON Snapshot</h2>
<details>
  <summary>Expand / collapse</summary>
  <div class='action' style='margin-top:10px;'>
    <button id='copy-json-btn' onclick='copyJSON()'>Copy JSON</button>
  </div>
  <pre id="raw-json">$encodedJson</pre>
</details>
"@
$html += "<div class='section' id='json'>$jsonBlock</div>"

$final = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>PC Hardware Report</title>$css</head><body>$($header)$($html -join "`n")$js</body></html>"

# ---------- Write single HTML to Desktop ----------
$reportPath = Join-Path $env:USERPROFILE "Desktop\PC_Hardware_Report.html"
$final | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "`nSingle-file report created:"
Write-Host $reportPath
