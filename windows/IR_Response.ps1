# =============================================================================
# INCIDENT RESPONSE - LIVE DATA COLLECTION SCRIPT
# Windows Live Response | Volatile + Non-Volatile Data
# =============================================================================
# USAGE: Run in PowerShell as Administrator
#        .\IR_Collect.ps1
# =============================================================================

#Requires -RunAsAdministrator

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------
$OutputRoot     = $PSScriptRoot
$VolatileDir    = "$OutputRoot\volatile"
$NonVolatileDir = "$OutputRoot\non_volatile"
$PrefetchDir    = "$NonVolatileDir\Prefetch"
$BrowserDir     = "$NonVolatileDir\BrowserCache"
$LogFile        = "$OutputRoot\collection_log.txt"

# -----------------------------------------------------------------------------
# SETUP
# -----------------------------------------------------------------------------

Write-Host "`n============================================================"
Write-Host "  INCIDENT RESPONSE DATA COLLECTION"
Write-Host "============================================================`n"

foreach ($dir in @($OutputRoot, $VolatileDir, $NonVolatileDir, $PrefetchDir, $BrowserDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Write-Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    Add-Content -Path $LogFile -Value $entry
}

Write-Host "Enter investigator details:"
$InvestigatorName  = Read-Host "  Your Name"
$InvestigationName = Read-Host "  Investigation Name / Case ID"
$PhoneTime         = Read-Host "  Current time from your phone/watch (skew reference)"

@"
============================================================
CHAIN OF CUSTODY - COLLECTION RECORD
============================================================
Investigator  : $InvestigatorName
Investigation : $InvestigationName
Phone/Watch   : $PhoneTime
Script Start  : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Hostname      : $env:COMPUTERNAME
Username      : $env:USERNAME
============================================================
"@ | Out-File -FilePath "$OutputRoot\chain_of_custody.txt" -Encoding UTF8

Write-Log "Collection started by $InvestigatorName - Case: $InvestigationName"

# =============================================================================
# PART 3 - VOLATILE DATA
# =============================================================================

Write-Host "`n--- VOLATILE DATA COLLECTION ---`n"

# Step 1: System Time - TXT
Write-Log "Collecting: System Time"
"System Time  - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File "$VolatileDir\systemtime.txt" -Encoding UTF8
"UTC Time     - $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File "$VolatileDir\systemtime.txt" -Encoding UTF8 -Append
Get-Date | Select-Object DateTime, DayOfWeek, Kind | Format-List | Out-File "$VolatileDir\systemtime.txt" -Encoding UTF8 -Append
Write-Log "  SUCCESS -> $VolatileDir\systemtime.txt"

# Step 2: Running Processes - CSV
Write-Log "Collecting: Running Processes"
Get-Process | Select-Object * | Sort-Object Id |
    Export-Csv -Path "$VolatileDir\processes.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $VolatileDir\processes.csv"

# Step 3: Running Services - CSV
Write-Log "Collecting: Running Services"
Get-Service | Select-Object * | Sort-Object Status, Name |
    Export-Csv -Path "$VolatileDir\services.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $VolatileDir\services.csv"

# Step 4: NetBIOS - TXT: raw external command output
Write-Log "Collecting: NetBIOS"
"--- NetBIOS Names ---" | Out-File "$VolatileDir\netbios.txt" -Encoding UTF8
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration |
    Where-Object { $_.WINSPrimaryServer -or $_.MACAddress } |
    Select-Object Description, MACAddress, WINSPrimaryServer, WINSSecondaryServer |
    Format-Table -AutoSize | Out-File "$VolatileDir\netbios.txt" -Encoding UTF8 -Append

"--- NetBIOS Sessions (Active TCP Connections with Process) ---" | Out-File "$VolatileDir\netbios.txt" -Encoding UTF8 -Append
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Format-Table -AutoSize | Out-File "$VolatileDir\netbios.txt" -Encoding UTF8 -Append
Write-Log "  SUCCESS -> $VolatileDir\netbios.txt"

# Step 5: Open Files - CSV
# NOTE: Full handle enumeration requires Sysinternals Handle.exe (third-party).
Write-Log "Collecting: Open Files"
Get-Process | ForEach-Object {
    $proc = $_
    try {
        $proc.Modules | Select-Object -ErrorAction SilentlyContinue |
            ForEach-Object {
                [PSCustomObject]@{
                    PID         = $proc.Id
                    ProcessName = $proc.ProcessName
                    ModuleName  = $_.ModuleName
                    FileName    = $_.FileName
                    BaseAddress = '0x{0:X}' -f $_.BaseAddress.ToInt64()
                    ModuleSize  = $_.ModuleMemorySize
                    FileVersion = $_.FileVersionInfo.FileVersion
                    Description = $_.FileVersionInfo.FileDescription
                    Company     = $_.FileVersionInfo.CompanyName
                }
            }
    } catch { }
} | Export-Csv -Path "$VolatileDir\open_handles.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $VolatileDir\open_handles.csv"
Write-Log "  NOTE: For full handle enumeration run Handle.exe -a (Sysinternals) separately."

# Step 6: Open Network Connections - CSV
Write-Log "Collecting: Network Connections"
Get-NetTCPConnection | Select-Object CreationTime, State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    Export-Csv -Path "$VolatileDir\tcp_connections.csv" -NoTypeInformation -Encoding UTF8
Get-NetUDPEndpoint | Select-Object CreationTime, LocalAddress, LocalPort, OwningProcess |
    Export-Csv -Path "$VolatileDir\udp_connections.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $VolatileDir\tcp_connections.csv"
Write-Log "  SUCCESS -> $VolatileDir\udp_connections.csv"

# Step 7: Routing Table - CSV
Write-Log "Collecting: Routing Table"
Get-NetRoute | Select-Object AddressFamily, State, Protocol, DestinationPrefix, NextHop, RouteMetric, ifIndex, InterfaceAlias, InterfaceMetric |
    Sort-Object DestinationPrefix |
    Export-Csv -Path "$VolatileDir\routing_table.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $VolatileDir\routing_table.csv"

# Step 8: ARP Cache - CSV
Write-Log "Collecting: ARP Cache"
Get-NetNeighbor | Select-Object State, AddressFamily, ifIndex, InterfaceAlias, IPAddress, LinkLayerAddress |
    Export-Csv -Path "$VolatileDir\arp_cache.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $VolatileDir\arp_cache.csv"

# Step 9: DNS Cache - CSV
Write-Log "Collecting: DNS Cache"
Get-DnsClientCache | Select-Object Entry, Name, Type, Status, Section, TimeToLive, DataLength, Data |
    Export-Csv -Path "$VolatileDir\dns_cache.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $VolatileDir\dns_cache.csv"

# Step 10: PowerShell Command History - TXT
Write-Log "Collecting: PowerShell History"
"--- Current Session History ---" | Out-File "$VolatileDir\history.txt" -Encoding UTF8
Get-History | Select-Object Id, CommandLine, StartExecutionTime, ExecutionStatus |
    Format-Table -AutoSize | Out-File "$VolatileDir\history.txt" -Encoding UTF8 -Append
"" | Out-File "$VolatileDir\history.txt" -Encoding UTF8 -Append
"--- Saved PSReadLine History ---" | Out-File "$VolatileDir\history.txt" -Encoding UTF8 -Append
$histPath = (Get-PSReadLineOption).HistorySavePath
if ($histPath -and (Test-Path $histPath)) {
    Get-Content $histPath | Select-Object -Last 200 | Out-File "$VolatileDir\history.txt" -Encoding UTF8 -Append
} else {
    "PSReadLine history file not found." | Out-File "$VolatileDir\history.txt" -Encoding UTF8 -Append
}
Write-Log "  SUCCESS -> $VolatileDir\history.txt"

# LAST VOLATILE STEP: Logged-On Users - TXT
Write-Log "Collecting: Logged-On Users"
"--- Active Logon Sessions ---" | Out-File "$VolatileDir\loggedon_users.txt" -Encoding UTF8
Get-CimInstance -ClassName Win32_LogonSession | Select-Object LogonId, LogonType, StartTime |
    Format-Table -AutoSize | Out-File "$VolatileDir\loggedon_users.txt" -Encoding UTF8 -Append
"" | Out-File "$VolatileDir\loggedon_users.txt" -Encoding UTF8 -Append
"--- Current Interactive User ---" | Out-File "$VolatileDir\loggedon_users.txt" -Encoding UTF8 -Append
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName, Name |
    Format-List | Out-File "$VolatileDir\loggedon_users.txt" -Encoding UTF8 -Append
Write-Log "  SUCCESS -> $VolatileDir\loggedon_users.txt"

# =============================================================================
# PART 4 - NON-VOLATILE DATA
# =============================================================================

Write-Host "`n--- NON-VOLATILE DATA COLLECTION ---`n"

# Step 1: System Information - TXT
Write-Log "Collecting: System Information"
"--- Operating System ---" | Out-File "$NonVolatileDir\sysinfo.txt" -Encoding UTF8
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, CurrentTimeZone, LastBootUpTime, RegisteredUser, SerialNumber, SystemDirectory | 
    Format-List | Out-File "$NonVolatileDir\sysinfo.txt" -Encoding UTF8 -Append
"--- Computer System ---" | Out-File "$NonVolatileDir\sysinfo.txt" -Encoding UTF8 -Append
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Name, Domain, Manufacturer, Model, @{N="TotalRAM(GB)"; E={[math]::Round($_.TotalPhysicalMemory/1GB,2)}} |
    Format-List | Out-File "$NonVolatileDir\sysinfo.txt" -Encoding UTF8 -Append
"--- BIOS ---" | Out-File "$NonVolatileDir\sysinfo.txt" -Encoding UTF8 -Append
Get-CimInstance -ClassName Win32_BIOS |
    Select-Object Manufacturer, Name, Version, BIOSVersion, SerialNumber, ReleaseDate |
    Format-List | Out-File "$NonVolatileDir\sysinfo.txt" -Encoding UTF8 -Append
Write-Log "  SUCCESS -> $NonVolatileDir\sysinfo.txt"

# Step 2: Event Logs - CSV
Write-Log "Collecting: Event Logs (Can take roughly 5 to 20 minutes)"

$path = "$NonVolatileDir\event_logs.csv"
$enc  = [System.Text.UTF8Encoding]::new($false)

# --- Discover non-empty logs ---
$logNames = Get-WinEvent -ListLog '*' -ErrorAction SilentlyContinue |
    Where-Object { $_.RecordCount -gt 0 } |
    Select-Object -ExpandProperty LogName

# --- Shared thread-safe queue ---
$queue    = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$header   = '"LogName","TimeCreated","Id","LevelDisplayName","ProviderName","Message"'
$queue.Enqueue($header)

# --- Runspace pool: one runspace per logical processor ---
$maxThreads = [Environment]::ProcessorCount
$pool       = [RunspaceFactory]::CreateRunspacePool(1, $maxThreads)
$pool.Open()

# Scriptblock executed by each runspace - processes one log at a time
$sb = {
    param([string]$LogName, [System.Collections.Concurrent.ConcurrentQueue[string]]$Queue)
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $LogName } -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $msg  = $e.Message.Replace("`r`n", ' ').Replace("`n", ' ').Replace('"', '""')
            $line = '"{0}","{1}",{2},"{3}","{4}","{5}"' -f `
                $e.LogName, $e.TimeCreated, $e.Id, $e.LevelDisplayName, $e.ProviderName, $msg
            $Queue.Enqueue($line)
        }
    } catch { }
}

# --- Spawn one runspace job per log ---
$jobs = foreach ($log in $logNames) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($sb).AddArgument($log).AddArgument($queue)
    [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
}

# --- Progress monitor: wait for all jobs to complete ---
$total     = $jobs.Count
$lastCount = 0
do {
    Start-Sleep -Milliseconds 500
    $done = ($jobs | Where-Object { $_.Handle.IsCompleted }).Count
    if ($done -ne $lastCount) {
        $lastCount = $done
    }
} while ($done -lt $total)

# --- Cleanup runspaces ---
foreach ($job in $jobs) {
    try { $job.PS.EndInvoke($job.Handle) } catch { }
    $job.PS.Dispose()
}
$pool.Close()
$pool.Dispose()

# --- Drain queue to file via StreamWriter ---
$fs     = [System.IO.File]::Open($path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
$writer = [System.IO.StreamWriter]::new($fs, $enc, 16777216)
$writer.AutoFlush = $false

$line = $null
while ($queue.TryDequeue([ref]$line)) {
    $writer.WriteLine($line)
}
$writer.Flush()
$writer.Close()
$fs.Dispose()
Write-Log "  SUCCESS -> $NonVolatileDir\event_logs.csv"

# Step 3: Prefetch Files - CSV
Write-Log "Collecting: Prefetch File Listing"
if (Test-Path "C:\Windows\Prefetch") {
    # Copy all files including subdirectories, log anything that fails
    Get-ChildItem -Path "C:\Windows\Prefetch" -Recurse -File | ForEach-Object {
        $dest = Join-Path $PrefetchDir $_.FullName.Substring("C:\Windows\Prefetch\".Length)
        $destDir = Split-Path $dest -Parent
        if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        try {
            Copy-Item -Path $_.FullName -Destination $dest -Force
        } catch {
            Write-Log "  FAILED to copy: $($_.FullName) - $($_.Exception.Message)"
        }
    }
    Write-Log "  Prefetch files copied -> $PrefetchDir"

} else {
    "Prefetch directory not found or access denied." | Out-File "$NonVolatileDir\prefetch_list.txt" -Encoding UTF8
    Write-Log "  Prefetch directory not accessible."
}

# Step 4: Scheduled Tasks - CSV
Write-Log "Collecting: Scheduled Tasks"
Get-ScheduledTask | Select-Object * | Sort-Object TaskPath, TaskName |
    Export-Csv -Path "$NonVolatileDir\sched_tasks.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $NonVolatileDir\sched_tasks.csv"

# Step 5: Installed Drivers - CSV
Write-Log "Collecting: Installed Drivers"
Get-CimInstance -ClassName Win32_SystemDriver | Select-Object * |
    Export-Csv -Path "$NonVolatileDir\drivers.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $NonVolatileDir\drivers.csv"

# Step 6: Disk Space - CSV
Write-Log "Collecting: Disk Space"
Get-CimInstance -ClassName Win32_LogicalDisk |
    Select-Object DeviceID, VolumeName,
        @{N="Size(GB)"; E={[math]::Round($_.Size/1GB,2)}},
        @{N="Free(GB)"; E={[math]::Round($_.FreeSpace/1GB,2)}},
        @{N="Used(GB)"; E={[math]::Round(($_.Size-$_.FreeSpace)/1GB,2)}},
        @{N="Free%";    E={if($_.Size){[math]::Round($_.FreeSpace/$_.Size*100,1)}}},
        * -ExcludeProperty DeviceID, VolumeName, Size, FreeSpace, CimInstanceProperties, CimSystemProperties | Sort-Object Name |
    Export-Csv -Path "$NonVolatileDir\logical_disks.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $NonVolatileDir\logical_disks.csv"

# Step 7: Network Adapter Configuration - TXT
Write-Log "Collecting: Network Adapter Configuration"
"--- IP Addresses ---" | Out-File "$NonVolatileDir\ipconfig.txt" -Encoding UTF8
Get-NetIPAddress | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, AddressState, IPAddress, SubnetMask, PrefixLength, PrefixOrigin, SuffixOrigin, Type, PreferredLifetime, ValidLifetime |
    Format-Table -AutoSize | Out-File "$NonVolatileDir\ipconfig.txt" -Encoding UTF8 -Append
"--- Adapters ---" | Out-File "$NonVolatileDir\ipconfig.txt" -Encoding UTF8 -Append
Get-NetAdapter | Select-Object * | Sort-Object Name |
    Format-Table -Wrap | Out-File "$NonVolatileDir\ipconfig.txt" -Encoding UTF8 -Append
"--- DNS Servers ---" | Out-File "$NonVolatileDir\ipconfig.txt" -Encoding UTF8 -Append
Get-DnsClientServerAddress | Select-Object InterfaceAlias, AddressFamily, ServerAddresses |
    Format-Table -AutoSize | Out-File "$NonVolatileDir\ipconfig.txt" -Encoding UTF8 -Append
"--- Default Gateways ---" | Out-File "$NonVolatileDir\ipconfig.txt" -Encoding UTF8 -Append
Get-NetIPConfiguration | Select-Object InterfaceAlias,
    @{N="Gateway";     E={$_.IPv4DefaultGateway.NextHop}},
    @{N="IPv6Gateway"; E={$_.IPv6DefaultGateway.NextHop}} |
    Format-Table -AutoSize | Out-File "$NonVolatileDir\ipconfig.txt" -Encoding UTF8 -Append
Write-Log "  SUCCESS -> $NonVolatileDir\ipconfig.txt"

# Step 8: Local Users & Groups - CSV
Write-Log "Collecting: Local Users"
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, UserMayChangePassword, Description |
    Export-Csv -Path "$NonVolatileDir\users.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $NonVolatileDir\users.csv"

Write-Log "Collecting: Local Group Members"
Get-LocalGroup | ForEach-Object {
    $grp = $_.Name
    try {
        Get-LocalGroupMember -Group $grp -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Group = $grp; Member = $_.Name; PrincipalSource = $_.PrincipalSource; ObjectClass = $_.ObjectClass }
        }
    } catch { }
} | Export-Csv -Path "$NonVolatileDir\group_members.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $NonVolatileDir\group_members.csv"

# Step 9: Pagefile & Hibernation - TXT
Write-Log "Collecting: Pagefile and Hibernation Info"
"--- Pagefile Configuration ---" | Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8
Get-CimInstance -ClassName Win32_PageFileUsage   | Select-Object Name, CurrentUsage, PeakUsage, AllocatedBaseSize |
    Format-Table -AutoSize | Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
Get-CimInstance -ClassName Win32_PageFileSetting | Select-Object Name, InitialSize, MaximumSize |
    Format-Table -AutoSize | Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
"" | Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
"--- Hibernation File ---" | Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
if (Test-Path "C:\hiberfil.sys" -ErrorAction SilentlyContinue) {
    Get-Item "C:\hiberfil.sys" -Force | Select-Object FullName, Length, CreationTime, LastWriteTime |
        Format-List | Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
        Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
} else {
    "hiberfil.sys not found - hibernation may be disabled." |
        Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
}
"" | Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
"--- Virtual Memory ---" | Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
Get-CimInstance -ClassName Win32_OperatingSystem |
    Select-Object TotalVirtualMemorySize, FreeVirtualMemory, TotalVisibleMemorySize, FreePhysicalMemory |
    Format-List | Out-File "$NonVolatileDir\pagefile_hibernation.txt" -Encoding UTF8 -Append
Write-Log "  SUCCESS -> $NonVolatileDir\pagefile_hibernation.txt"

# Step 10: Mounted Devices - CSV
Write-Log "Collecting: Mounted Devices"
Get-CimInstance -ClassName Win32_DiskDrive | Select-Object * |
    Export-Csv -Path "$NonVolatileDir\disk_drive.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $NonVolatileDir\disk_drive.csv"
Get-CimInstance -ClassName Win32_Volume | Select-Object * |
    Export-Csv -Path "$NonVolatileDir\volume.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $NonVolatileDir\volume.csv"

# Step 11: Browser Cache - TXT
Write-Log "Collecting: Browser Cache"

# -------- CHROME & EDGE --------
$chromiumBrowsers = @(
    @{ Name = "Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
    @{ Name = "Edge";   Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
)

foreach ($browser in $chromiumBrowsers) {
    $outFile = "$NonVolatileDir\browser_$($browser.Name).txt"
    "=== $($browser.Name) ===" | Out-File $outFile -Encoding UTF8
    $profiles = Get-ChildItem $browser.Path -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "Default|Profile" }
    foreach ($profile in $profiles) {
        $historyPath = Join-Path $profile.FullName "History"
        $cachePath   = Join-Path $profile.FullName "Cache"
        "" | Out-File $outFile -Encoding UTF8 -Append
        "--- Profile: $($profile.Name) ---" | Out-File $outFile -Encoding UTF8 -Append
        "History: $historyPath" | Out-File $outFile -Encoding UTF8 -Append
        if (Test-Path $historyPath) {
            $item = Get-Item $historyPath -Force
            "  Found | Size: $($item.Length) bytes | Modified: $($item.LastWriteTime)" | Out-File $outFile -Encoding UTF8 -Append
            "  NOTE: SQLite database - copied to BrowserCache folder for offline analysis." | Out-File $outFile -Encoding UTF8 -Append
            Copy-Item $historyPath "$BrowserDir\$($browser.Name)_$($profile.Name)_History" -Force -ErrorAction SilentlyContinue
        } else {
            "  Not found." | Out-File $outFile -Encoding UTF8 -Append
        }
        "Cache: $cachePath" | Out-File $outFile -Encoding UTF8 -Append
        if (Test-Path $cachePath) {
            Get-ChildItem $cachePath -Recurse -File -ErrorAction SilentlyContinue |
                Select-Object FullName, @{N="Size(KB)"; E={[math]::Round($_.Length/1KB,1)}}, LastWriteTime |
                Sort-Object LastWriteTime -Descending | Select-Object -First 100 |
                Format-Table -AutoSize | Out-File $outFile -Encoding UTF8 -Append
        } else {
            "  Not found." | Out-File $outFile -Encoding UTF8 -Append
        }
    }
    Write-Log "  Browser processed: $($browser.Name) -> $outFile"
}

# -------- FIREFOX --------
$outFile = "$NonVolatileDir\browser_Firefox.txt"
$ffProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
"=== Firefox ===" | Out-File $outFile -Encoding UTF8
if (Test-Path $ffProfilesPath) {
    $profiles = Get-ChildItem $ffProfilesPath -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $profiles) {
        $historyPath = Join-Path $profile.FullName "places.sqlite"
        $cachePath   = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\$($profile.Name)\cache2"
        "" | Out-File $outFile -Encoding UTF8 -Append
        "--- Profile: $($profile.Name) ---" | Out-File $outFile -Encoding UTF8 -Append
        "History: $historyPath" | Out-File $outFile -Encoding UTF8 -Append
        if (Test-Path $historyPath) {
            $item = Get-Item $historyPath -Force
            "  Found | Size: $($item.Length) bytes | Modified: $($item.LastWriteTime)" | Out-File $outFile -Encoding UTF8 -Append
            "  NOTE: SQLite database - copied to BrowserCache folder for offline analysis." | Out-File $outFile -Encoding UTF8 -Append
            Copy-Item $historyPath "$BrowserDir\Firefox_$($profile.Name)_History.sqlite" -Force -ErrorAction SilentlyContinue
        } else {
            "  Not found." | Out-File $outFile -Encoding UTF8 -Append
        }
        "Cache: $cachePath" | Out-File $outFile -Encoding UTF8 -Append
        if (Test-Path $cachePath) {
            Get-ChildItem $cachePath -Recurse -File -ErrorAction SilentlyContinue |
                Select-Object FullName, @{N="Size(KB)"; E={[math]::Round($_.Length/1KB,1)}}, LastWriteTime |
                Sort-Object LastWriteTime -Descending | Select-Object -First 100 |
                Format-Table -AutoSize | Out-File $outFile -Encoding UTF8 -Append
        } else {
            "  Not found." | Out-File $outFile -Encoding UTF8 -Append
        }
    }
} else {
    "Firefox profiles folder not found." | Out-File $outFile -Encoding UTF8 -Append
}
Write-Log "  Browser processed: Firefox -> $outFile"

# LAST NON-VOLATILE STEP: Directory Listings - CSV
Write-Log "Collecting: Directory Listings (this may take several minutes)..."
$drives = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -and (Test-Path $_.Root) }).Root

$dirPool = [RunspaceFactory]::CreateRunspacePool(1, ([Environment]::ProcessorCount))
$dirPool.Open()

$dirSb = {
    param([string]$Drive, [string]$Out)
    $enc    = [System.Text.UTF8Encoding]::new($false)
    $fs     = [System.IO.File]::Open($Out, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $writer = [System.IO.StreamWriter]::new($fs, $enc, 16777216)
    $writer.AutoFlush = $false
    $writer.WriteLine('"FullName","Attributes","Size","CreationTime","LastWriteTime","LastAccessTime"')

    Get-ChildItem -Path $Drive -Recurse -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            $size  = if ($_.PSIsContainer) { '' } else { $_.Length }
            $ctime = try { $_.CreationTime   } catch { 'INVALID' }
            $wtime = try { $_.LastWriteTime  } catch { 'INVALID' }
            $atime = try { $_.LastAccessTime } catch { 'INVALID' }
            $line  = '"{0}","{1}","{2}","{3}","{4}","{5}"' -f $_.FullName, $_.Attributes, $size, $ctime, $wtime, $atime
            $writer.WriteLine($line)
        }

    $writer.Flush()
    $writer.Close()
    $fs.Dispose()
}

$dirJobs = foreach ($drive in $drives) {
    $driveLetter = ($drive -replace '[:\\/]', '')
    $out = "$NonVolatileDir\dirlisting_${driveLetter}.csv"
    Write-Log "  Directory listing of $drive starting..."
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $dirPool
    [void]$ps.AddScript($dirSb).AddArgument($drive).AddArgument($out)
    [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Drive = $drive; Out = $out }
}

foreach ($job in $dirJobs) {
    $job.Handle.AsyncWaitHandle.WaitOne() | Out-Null
    try { $job.PS.EndInvoke($job.Handle) } catch { Write-Log "  ERROR on $($job.Drive) - $_" }
    $job.PS.Dispose()
    Write-Log "    SUCCESS -> $($job.Out)"
}

$dirPool.Close()
$dirPool.Dispose()

# =============================================================================
# PART 5 - FINALIZE: Hash all collected files
# =============================================================================

Write-Host "`n--- FINALIZING: HASHING COLLECTED FILES ---`n"
Write-Log "Hashing volatile files..."
Get-ChildItem -Path "$VolatileDir\*" -Recurse -File |
    Get-FileHash -Algorithm SHA1 |
    Select-Object Hash, Algorithm, Path |
    Export-Csv -Path "$OutputRoot\volatile_hashes.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $OutputRoot\volatile_hashes.csv"

Write-Log "Hashing non-volatile files..."
Get-ChildItem -Path "$NonVolatileDir\*" -Recurse -File |
    Get-FileHash -Algorithm SHA1 |
    Select-Object Hash, Algorithm, Path |
    Export-Csv -Path "$OutputRoot\non_volatile_hashes.csv" -NoTypeInformation -Encoding UTF8
Write-Log "  SUCCESS -> $OutputRoot\non_volatile_hashes.csv"

Add-Content -Path "$OutputRoot\chain_of_custody.txt" -Value "Script End    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Content -Path "$OutputRoot\chain_of_custody.txt" -Value "Collection Log: $LogFile"

Write-Host "`n============================================================"
Write-Host "  COLLECTION COMPLETE"
Write-Host "  Output root : $OutputRoot"
Write-Host "  Log file    : $LogFile"
Write-Host "============================================================`n"
Write-Log "Collection complete."