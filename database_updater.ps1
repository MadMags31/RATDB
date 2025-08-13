#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RAT Problem Database Updater - Comprehensive CRUD operations for RMM/RAT database management

.DESCRIPTION
    This script provides comprehensive database management capabilities for the RAT Problem security system.
    It supports adding, updating, removing, and bulk importing RAT/RMM tool signatures with full validation,
    backup, and audit trail functionality.

.PARAMETER Action
    The action to perform: Add, Remove, UpdateRisk, BulkImport, List, Search

.PARAMETER InputType
    For Add action: Interactive or Template

.PARAMETER TemplatePath
    Path to JSON template file for Add action

.PARAMETER InputPath
    Path to CSV file for BulkImport action

.PARAMETER RMMName
    Name of the RMM tool to update or remove

.PARAMETER NewRiskLevel
    New risk level for UpdateRisk action (authorized, medium, high)

.PARAMETER Reason
    Reason for the change (for audit logging)

.PARAMETER DatabasePath
    Path to the database file (defaults to ./rmm_database.json)

.PARAMETER NoBackup
    Skip automatic backup creation

.PARAMETER Force
    Force operation without confirmation prompts

.EXAMPLE
    .\database_updater.ps1 -Action Add -InputType Interactive
    Interactively add a new RAT/RMM entry

.EXAMPLE
    .\database_updater.ps1 -Action BulkImport -InputPath "threat_intel.csv"
    Import multiple entries from CSV file

.EXAMPLE
    .\database_updater.ps1 -Action UpdateRisk -RMMName "TeamViewer" -NewRiskLevel "authorized" -Reason "Approved for business use"
    Update risk level of existing entry

.EXAMPLE
    .\database_updater.ps1 -Action Remove -RMMName "ObsoleteRAT" -Reason "No longer in use"
    Remove entry from database

.NOTES
    Author: RAT Problem Security Team
    Version: 1.0
    Requires: PowerShell 5.1, Administrative privileges
    Database: JSON-based signature database with full validation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Add", "Remove", "UpdateRisk", "BulkImport", "List", "Search")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Interactive", "Template")]
    [string]$InputType = "Interactive",

    [Parameter(Mandatory = $false)]
    [string]$TemplatePath,

    [Parameter(Mandatory = $false)]
    [string]$InputPath,

    [Parameter(Mandatory = $false)]
    [string]$RMMName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("authorized", "suspicious", "unauthorized")]
    [string]$NewRiskLevel,

    [Parameter(Mandatory = $false)]
    [string]$Reason,

    [Parameter(Mandatory = $false)]
    [string]$DatabasePath = ".\rmm_database.json",

    [Parameter(Mandatory = $false)]
    [switch]$NoBackup,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Global variables
$script:LogFile = ".\database_updater.log"
$script:BackupDir = ".\Backups"
$script:ValidRiskLevels = @("authorized", "suspicious", "unauthorized")
$script:RequiredFields = @("name", "vendor", "risk_level", "detection_signatures", "uninstaller_info")
$script:RequiredSignatureFields = @("processes", "services", "registry_keys", "installation_paths", "files")
$script:RequiredUninstallerFields = @("display_name", "uninstall_string", "quiet_uninstall")

#region Logging Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with appropriate color
    switch ($Level) {
        "INFO"  { Write-Host $logMessage -ForegroundColor Green }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
}

#endregion

#region Database Functions

function Test-DatabasePath {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Log "Database file not found: $Path" "ERROR"
        return $false
    }
    
    try {
        $content = Get-Content $Path -Raw | ConvertFrom-Json
        return $true
    }
    catch {
        Write-Log "Invalid JSON in database file: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-Database {
    param([string]$Path)
    
    if (-not (Test-DatabasePath $Path)) {
        return $null
    }
    
    try {
        $content = Get-Content $Path -Raw
        return $content | ConvertFrom-Json
    }
    catch {
        Write-Log "Failed to read database: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Save-Database {
    param(
        [object]$Database,
        [string]$Path
    )
    
    try {
        # Update database info
        $Database.database_info.last_updated = Get-Date -Format "yyyy-MM-dd"
        $Database.database_info.total_entries = $Database.rmm_tools.Count
        
        # Convert to JSON with proper formatting
        $jsonOutput = $Database | ConvertTo-Json -Depth 10 -Compress:$false
        
        # Save to file
        $jsonOutput | Out-File -FilePath $Path -Encoding UTF8 -Force
        
        Write-Log "Database saved successfully to: $Path"
        return $true
    }
    catch {
        Write-Log "Failed to save database: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Backup-Database {
    param([string]$DatabasePath)
    
    if ($NoBackup) {
        Write-Log "Backup skipped due to -NoBackup parameter"
        return $true
    }
    
    try {
        # Create backup directory if it doesn't exist
        if (-not (Test-Path $script:BackupDir)) {
            New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null
        }
        
        # Create timestamped backup
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupPath = Join-Path $script:BackupDir "rmm_database_backup_$timestamp.json"
        
        Copy-Item $DatabasePath $backupPath -Force
        Write-Log "Database backed up to: $backupPath"
        
        # Clean old backups (keep last 10)
        $backups = Get-ChildItem $script:BackupDir -Filter "rmm_database_backup_*.json" | Sort-Object CreationTime -Descending
        if ($backups.Count -gt 10) {
            $backups[10..($backups.Count-1)] | Remove-Item -Force
            Write-Log "Cleaned up old backup files"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to create backup: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

#endregion

#region Validation Functions

function Test-RMMEntry {
    param([object]$Entry)
    
    $isValid = $true
    $errors = @()
    
    # Check required top-level fields
    foreach ($field in $script:RequiredFields) {
        if (-not $Entry.PSObject.Properties.Name.Contains($field)) {
            $errors += "Missing required field: $field"
            $isValid = $false
        }
    }
    
    # Validate risk level
    if ($Entry.risk_level -and $Entry.risk_level -notin $script:ValidRiskLevels) {
        $errors += "Invalid risk level: $($Entry.risk_level). Must be one of: $($script:ValidRiskLevels -join ', ')"
        $isValid = $false
    }
    
    # Validate detection signatures
    if ($Entry.detection_signatures) {
        foreach ($sigField in $script:RequiredSignatureFields) {
            if (-not $Entry.detection_signatures.PSObject.Properties.Name.Contains($sigField)) {
                $errors += "Missing detection signature field: $sigField"
                $isValid = $false
            }
        }
    }
    
    # Validate uninstaller info
    if ($Entry.uninstaller_info) {
        foreach ($uninstallField in $script:RequiredUninstallerFields) {
            if (-not $Entry.uninstaller_info.PSObject.Properties.Name.Contains($uninstallField)) {
                $errors += "Missing uninstaller field: $uninstallField"
                $isValid = $false
            }
        }
    }
    
    # Check for empty name or vendor
    if ([string]::IsNullOrWhiteSpace($Entry.name)) {
        $errors += "Name cannot be empty"
        $isValid = $false
    }
    
    if ([string]::IsNullOrWhiteSpace($Entry.vendor)) {
        $errors += "Vendor cannot be empty"
        $isValid = $false
    }
    
    if ($errors.Count -gt 0) {
        Write-Log "Validation errors for entry '$($Entry.name)': $($errors -join '; ')" "ERROR"
    }
    
    return $isValid
}

function Test-DuplicateEntry {
    param(
        [object]$Database,
        [string]$Name,
        [string]$Vendor
    )
    
    $existing = $Database.rmm_tools | Where-Object { 
        $_.name -eq $Name -and $_.vendor -eq $Vendor 
    }
    
    return $existing -ne $null
}

#endregion

#region CRUD Operations

function Add-RMMEntry {
    param(
        [object]$Database,
        [object]$NewEntry
    )
    
    # Validate entry
    if (-not (Test-RMMEntry $NewEntry)) {
        Write-Log "Entry validation failed" "ERROR"
        return $false
    }
    
    # Check for duplicates
    if (Test-DuplicateEntry $Database $NewEntry.name $NewEntry.vendor) {
        Write-Log "Duplicate entry detected: $($NewEntry.name) by $($NewEntry.vendor)" "ERROR"
        return $false
    }
    
    # Add entry to database
    $Database.rmm_tools += $NewEntry
    
    Write-Log "Added new entry: $($NewEntry.name) by $($NewEntry.vendor) (Risk: $($NewEntry.risk_level))"
    return $true
}

function Remove-RMMEntry {
    param(
        [object]$Database,
        [string]$Name
    )
    
    $originalCount = $Database.rmm_tools.Count
    $Database.rmm_tools = @($Database.rmm_tools | Where-Object { $_.name -ne $Name })
    
    if ($Database.rmm_tools.Count -lt $originalCount) {
        Write-Log "Removed entry: ${Name}"
        return $true
    } else {
        Write-Log "Entry not found: ${Name}" "WARN"
        return $false
    }
}

function Update-RMMRiskLevel {
    param(
        [object]$Database,
        [string]$Name,
        [string]$NewRiskLevel
    )
    
    $entry = $Database.rmm_tools | Where-Object { $_.name -eq $Name }
    
    if (-not $entry) {
        Write-Log "Entry not found: ${Name}" "ERROR"
        return $false
    }
    
    $oldRiskLevel = $entry.risk_level
    $entry.risk_level = $NewRiskLevel
    
    Write-Log "Updated risk level for ${Name}: $oldRiskLevel -> $NewRiskLevel"
    return $true
}

#endregion

#region Interactive Functions

function Get-InteractiveRMMEntry {
    Write-Host "`n=== Interactive RAT/RMM Entry Creation ===" -ForegroundColor Cyan
    
    # Basic information
    $name = Read-Host "Enter RAT/RMM name"
    $vendor = Read-Host "Enter vendor name"
    
    # Risk level with validation
    do {
        $riskLevel = Read-Host "Enter risk level (authorized/medium/high)"
    } while ($riskLevel -notin $script:ValidRiskLevels)
    
    # Detection signatures
    Write-Host "`n--- Detection Signatures ---" -ForegroundColor Yellow
    
    $processes = @()
    Write-Host "Enter process names (press Enter with empty input to finish):"
    do {
        $process = Read-Host "Process"
        if (![string]::IsNullOrWhiteSpace($process)) {
            $processes += $process
        }
    } while (![string]::IsNullOrWhiteSpace($process))
    
    $services = @()
    Write-Host "Enter service names (press Enter with empty input to finish):"
    do {
        $service = Read-Host "Service"
        if (![string]::IsNullOrWhiteSpace($service)) {
            $services += $service
        }
    } while (![string]::IsNullOrWhiteSpace($service))
    
    $registryKeys = @()
    Write-Host "Enter registry keys (press Enter with empty input to finish):"
    do {
        $regKey = Read-Host "Registry Key"
        if (![string]::IsNullOrWhiteSpace($regKey)) {
            $registryKeys += $regKey
        }
    } while (![string]::IsNullOrWhiteSpace($regKey))
    
    $installPaths = @()
    Write-Host "Enter installation paths (press Enter with empty input to finish):"
    do {
        $path = Read-Host "Installation Path"
        if (![string]::IsNullOrWhiteSpace($path)) {
            $installPaths += $path
        }
    } while (![string]::IsNullOrWhiteSpace($path))
    
    $files = @()
    Write-Host "Enter specific files (press Enter with empty input to finish):"
    do {
        $file = Read-Host "File"
        if (![string]::IsNullOrWhiteSpace($file)) {
            $files += $file
        }
    } while (![string]::IsNullOrWhiteSpace($file))
    
    # Uninstaller information
    Write-Host "`n--- Uninstaller Information ---" -ForegroundColor Yellow
    $displayName = Read-Host "Display name in Add/Remove Programs"
    $uninstallString = Read-Host "Standard uninstall command"
    $quietUninstall = Read-Host "Silent uninstall command"
    
    # Create entry object
    $entry = [PSCustomObject]@{
        name = $name
        vendor = $vendor
        risk_level = $riskLevel
        detection_signatures = [PSCustomObject]@{
            processes = $processes
            services = $services
            registry_keys = $registryKeys
            installation_paths = $installPaths
            files = $files
        }
        uninstaller_info = [PSCustomObject]@{
            display_name = $displayName
            uninstall_string = $uninstallString
            quiet_uninstall = $quietUninstall
        }
    }
    
    return $entry
}

function Show-DatabaseSummary {
    param([object]$Database)
    
    Write-Host "`n=== Database Summary ===" -ForegroundColor Cyan
    Write-Host "Version: $($Database.database_info.version)"
    Write-Host "Last Updated: $($Database.database_info.last_updated)"
    Write-Host "Total Entries: $($Database.database_info.total_entries)"
    
    # Risk level breakdown
    $authorized = ($Database.rmm_tools | Where-Object { $_.risk_level -eq "authorized" }).Count
    $medium = ($Database.rmm_tools | Where-Object { $_.risk_level -eq "medium" }).Count
    $high = ($Database.rmm_tools | Where-Object { $_.risk_level -eq "high" }).Count
    
    Write-Host "`nRisk Level Breakdown:" -ForegroundColor Yellow
    Write-Host "  Authorized: $authorized"
    Write-Host "  Medium: $medium" 
    Write-Host "  High: $high"
    
    Write-Host "`nRecent Entries:" -ForegroundColor Yellow
    $Database.rmm_tools | Select-Object name, vendor, risk_level | Sort-Object name | Format-Table -AutoSize
}

#endregion

#region Bulk Import Functions

function Import-BulkCSV {
    param(
        [string]$CSVPath,
        [object]$Database
    )
    
    if (-not (Test-Path $CSVPath)) {
        Write-Log "CSV file not found: $CSVPath" "ERROR"
        return $false
    }
    
    try {
        $csvData = Import-Csv $CSVPath
        $successCount = 0
        $errorCount = 0
        
        foreach ($row in $csvData) {
            try {
                # Convert CSV row to RMM entry object
                $entry = [PSCustomObject]@{
                    name = $row.name
                    vendor = $row.vendor
                    risk_level = $row.risk_level
                    detection_signatures = [PSCustomObject]@{
                        processes = ($row.processes -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                        services = ($row.services -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                        registry_keys = ($row.registry_keys -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                        installation_paths = ($row.installation_paths -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                        files = ($row.files -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    }
                    uninstaller_info = [PSCustomObject]@{
                        display_name = $row.display_name
                        uninstall_string = $row.uninstall_string
                        quiet_uninstall = $row.quiet_uninstall
                    }
                }
                
                if (Add-RMMEntry $Database $entry) {
                    $successCount++
                } else {
                    $errorCount++
                }
            }
            catch {
                Write-Log "Error processing row for $($row.name): $($_.Exception.Message)" "ERROR"
                $errorCount++
            }
        }
        
        Write-Log "Bulk import completed: $successCount successful, $errorCount errors"
        return $successCount -gt 0
    }
    catch {
        Write-Log "Failed to import CSV: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

#endregion

#region Main Logic

# Initialize logging
Write-Log "Database Updater started - Action: $Action"

# Validate parameters
switch ($Action) {
    "Add" {
        if ($InputType -eq "Template" -and [string]::IsNullOrEmpty($TemplatePath)) {
            Write-Log "Template path required when InputType is Template" "ERROR"
            exit 1
        }
        if ($InputType -eq "Template" -and -not (Test-Path $TemplatePath)) {
            Write-Log "Template file not found: $TemplatePath" "ERROR"
            exit 1
        }
    }
    "Remove" {
        if ([string]::IsNullOrEmpty($RMMName)) {
            Write-Log "RMMName parameter required for Remove action" "ERROR"
            exit 1
        }
    }
    "UpdateRisk" {
        if ([string]::IsNullOrEmpty($RMMName) -or [string]::IsNullOrEmpty($NewRiskLevel)) {
            Write-Log "RMMName and NewRiskLevel parameters required for UpdateRisk action" "ERROR"
            exit 1
        }
    }
    "BulkImport" {
        if ([string]::IsNullOrEmpty($InputPath)) {
            Write-Log "InputPath parameter required for BulkImport action" "ERROR"
            exit 1
        }
        if (-not (Test-Path $InputPath)) {
            Write-Log "Input file not found: $InputPath" "ERROR"
            exit 1
        }
    }
}

# Load database
$database = Get-Database $DatabasePath
if (-not $database) {
    Write-Log "Failed to load database from: $DatabasePath" "ERROR"
    exit 1
}

# Create backup
if (-not (Backup-Database $DatabasePath)) {
    if (-not $Force) {
        Write-Log "Backup creation failed. Use -Force to continue without backup." "ERROR"
        exit 1
    }
}

# Perform action
$success = $false
switch ($Action) {
    "Add" {
        if ($InputType -eq "Interactive") {
            $newEntry = Get-InteractiveRMMEntry
            $success = Add-RMMEntry $database $newEntry
        } elseif ($InputType -eq "Template") {
            try {
                $template = Get-Content $TemplatePath -Raw | ConvertFrom-Json
                $success = Add-RMMEntry $database $template
            }
            catch {
                Write-Log "Failed to load template: $($_.Exception.Message)" "ERROR"
            }
        }
    }
    
    "Remove" {
        if (-not $Force) {
            $confirm = Read-Host "Are you sure you want to remove '$RMMName'? (y/N)"
            if ($confirm -ne 'y' -and $confirm -ne 'Y') {
                Write-Log "Remove operation cancelled by user"
                exit 0
            }
        }
        $success = Remove-RMMEntry $database $RMMName
    }
    
    "UpdateRisk" {
        $success = Update-RMMRiskLevel $database $RMMName $NewRiskLevel
    }
    
    "BulkImport" {
        $success = Import-BulkCSV $InputPath $database
    }
    
    "List" {
        Show-DatabaseSummary $database
        $success = $true
    }
    
    "Search" {
        if ([string]::IsNullOrEmpty($RMMName)) {
            Write-Log "RMMName parameter required for Search action" "ERROR"
        } else {
            $results = $database.rmm_tools | Where-Object { $_.name -like "*$RMMName*" -or $_.vendor -like "*$RMMName*" }
            if ($results) {
                Write-Host "`nSearch results for '$RMMName':" -ForegroundColor Cyan
                $results | Select-Object name, vendor, risk_level | Format-Table -AutoSize
            } else {
                Write-Host "No entries found matching '$RMMName'" -ForegroundColor Yellow
            }
            $success = $true
        }
    }
}

# Save database if changes were made
if ($success -and $Action -in @("Add", "Remove", "UpdateRisk", "BulkImport")) {
    if (Save-Database $database $DatabasePath) {
        Write-Log "Database operation completed successfully"
        
        # Log the change for audit purposes
        $auditMessage = "Action: $Action"
        if ($RMMName) { $auditMessage += ", RMM: $RMMName" }
        if ($NewRiskLevel) { $auditMessage += ", New Risk: $NewRiskLevel" }
        if ($Reason) { $auditMessage += ", Reason: $Reason" }
        Write-Log "Audit: $auditMessage"
        
        exit 0
    } else {
        Write-Log "Failed to save database changes" "ERROR"
        exit 1
    }
} elseif ($success) {
    # Read-only operations
    exit 0
} else {
    Write-Log "Database operation failed" "ERROR"
    exit 1
}

#endregion
# SIG # Begin signature block
# MIIb6QYJKoZIhvcNAQcCoIIb2jCCG9YCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyGWqHXTRAJFKEZDBp34skJ/s
# 1qugghZSMIIDFDCCAfygAwIBAgIQflfO7V2mO51FJpe60M0g4zANBgkqhkiG9w0B
# AQUFADAiMSAwHgYDVQQDDBdSQVRQcm9ibGVtIENvZGUgU2lnbmluZzAeFw0yNTA4
# MDgyMDIyMjNaFw0yODA4MDgyMDMyMjNaMCIxIDAeBgNVBAMMF1JBVFByb2JsZW0g
# Q29kZSBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6AU6
# MuUldDrlNkSYASIJyd1AQlxwQEbCqSA5lxq2dZtxOluuC52ohkgwDhZC1XbkMpfe
# DyTT77uLczZKfqOaJuOzZir9mFasUa9NVL9evlFqRVAjiYhrrUx5BqGWkxoCkAdq
# y88um0s6+27MlwP/lCMWNo9Gd6Bymmupcz0xKEo8LpuZC/tjgxywbXALi6VzhNoC
# 9NC9i+VKlp+o93XYfa5qGEWwfPoCDWTJNeZMd1l9LyZ2axTBq85xfpgcl6IbrGb3
# hIOwxr43VHnPlUC/U+wpg0cEp0edfi8wC5RJa3yp6v8naQSCj+qRn0ifSo3+dS6o
# cYBGJGMQevDuNBkAiQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
# CgYIKwYBBQUHAwMwHQYDVR0OBBYEFPjMw6zKQj1upPJgw3RM0NgcyMJzMA0GCSqG
# SIb3DQEBBQUAA4IBAQAYRQbAhmOrsIzICXuoAhuzfjxB4BRG0WsLHTga7FlBJqaT
# 30jbEnwEKCIkYumUTkTOWFp1iN/siHAEtHvpWHFawShvEnIEuT4Dq492HqJKuYln
# k5Y5asnqJKMyjwT7xLaJeArtiIE/Rw9i12XRE2/IeNw8egUvB6nT0y/eLEIn59in
# tRxWtFgooPX7DsHbnDcwvZ+WwJWpc24BpXwi25ZzZQwsjrb5qmnt0KLEzPfHXPOH
# RoEBxO4ea3ImnrU5XUlG4nc9fJvqCqa0BmY7JJYY/+vvW7h3TuvSzBkZRc0C4cOq
# WZ0XqiwYm9nOPxDpkT4k8RjwiU/KeaKacqQGyoh9MIIFjTCCBHWgAwIBAgIQDpsY
# jvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQw
# IgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAw
# MDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhE
# aWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57
# G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9o
# k3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFh
# mzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463J
# T17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFw
# q1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yh
# Tzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU
# 75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LV
# jHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJ
# bOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8Qg
# UWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IB
# OjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6
# mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/
# BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4
# oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJv
# b3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBw
# oL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0
# E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtD
# IeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlU
# sLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFig
# DkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwY
# w02fc7cBqZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjAN
# BgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5
# WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx
# 0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz
# 4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJ
# gMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQ
# bzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6
# bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJ
# RfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU1
# 4lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDD
# jAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cn
# T6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq
# 1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqg
# PrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8G
# A1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjAT
# BgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYD
# VR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9
# bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfF
# iBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4
# /iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/
# DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HR
# trYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2
# o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K
# 9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc
# 3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLi
# Ru7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAv
# jSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3J
# E3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM
# 1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgwDQYJKoZIhvcN
# AQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5MDMyMzU5NTla
# MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UE
# AxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAy
# MDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQRqwtEsae0Oqu
# YFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8AUjni6bz52fG
# Tfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSbf+EIYLkrLKd6
# qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAldytxNM89PZXU
# P/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkTlCDQ0/fKJLKL
# kzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA98Oskkkrvt6l
# PAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmHHjQNC3zbJ6nJ
# 6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvundrAtuvz0D3T
# +dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40h5avMcpi54wm0i2e
# PZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGifgJYi+6I03Uu
# T1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHNm0IaadCKCkUe
# 2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIw
# ADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0jBBgwFoAU729T
# SunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoG
# CCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2
# U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5
# NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG
# /WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhEnmNAciH45PYi
# T9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPBVBajYfrbIYG+
# Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+2DE5qjzvZs7J
# IIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM4kzekd8oEARz
# FAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F/0Kr15zW/mJA
# xZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZagHLhFU9HCrG
# /syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaEt2OdDh4GmO0/
# 5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66Gp3CSBXG6IwXM
# ZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUXf53VJUNOaMWM
# ts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW+yERNpbJCjyC
# YG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3Qrx5bIbY3TVz
# giFI7Gq3zWcxggUBMIIE/QIBATA2MCIxIDAeBgNVBAMMF1JBVFByb2JsZW0gQ29k
# ZSBTaWduaW5nAhB+V87tXaY7nUUml7rQzSDjMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTC4Z7q
# vHMceyg8S2RTuDb5BRTJ6zANBgkqhkiG9w0BAQEFAASCAQCCYkn8EdgbGwptVJyE
# 6z2PCUOxVrnr+jJh8kdnnwT/N8DlPHNGFxkHYChRWdctNLFCKrvz6oZKHTT6BIy6
# 7vbwlMX9QTY/01ZunhAf1XOdf7V6DRGboznzpfHlyn6rD3VRJxDcfi642IeLae1w
# /A/viAgKWkyddvhzNTQhGevrdHMn68O+qLqMx+dCqRb94q28Jg0zlGFKoGFuS3VV
# iDv66GenCBMOaPBwvAnQxWE3BIMiEcPKxYFulG44YiRobZKC2phbLmnFjrGFQo3Q
# d/Nz67jIo3DSdaAzpbk5HzN4H6C8yLdWWcAvJ4cWS0ghlkn6WhgLlyxfIYr97Bre
# Krm/oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBU
# cnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQ
# CoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDgwODIwMzIzM1owLwYJKoZI
# hvcNAQkEMSIEIFZLXJ1OLB06yJlxiucRUh+qKy31SnLqJc+z5rUA+2ipMA0GCSqG
# SIb3DQEBAQUABIICAB4VL8VTwOnkCpN4Qd1504ubTRc3NV0lDvg9iGGcuDIeUkjH
# BFNIxAEs/Z1qDbjrHsUYwJuZD0XJfv+kiPozrUOczmtMgElV4Ien4VhH74dikJFg
# t7QBoNGjrcoZTsAMlt0iyR6Z7DUkSmiI7l2kYnztZuA41jV52Tn6dJZhRGF6bSUo
# vpaQu5Iu1kfwiyTf3dPP24igtZq04/S/30yjmqo7DDqUJONak9PvMo4MolMJH3dp
# gD9oH2zBNwzbCP8T3d/f6Sv1iUd4WDXN9DEwGnLo8psGEiZkwIp+V8nptqdOqsVn
# 7CK5jBLvoMeaRp0OhGSyINvRZ/4ysRfiuTlZJ6cnsJbFy0bvyRLXp9sSO7f8Og8E
# LCm4gfmU1k7Sm68Pc16zHE6X8AmabC0bH6z7AMymxzEGUP1nDUfcvvPAX4slkZge
# XSyHTBoVJvtW4Axtp6jkewnLE951hy80NqLkgeyJgVzKYyj/5TU3rIB0eCWkKjRs
# GM0FhRfa+jgL97y+90uq1K6IqTOAJFwqlPuw9hO/riClF4xImmIxaYYXToBQjc2l
# cocK3K+S1Is4FMx7eEybLPH1K80goZeszStlN2+CzVeISpLZLzNNmB4f3lNvRSqx
# heraHzzGs0OvCSUWkS0Q8k6FPMIjU4EWi0N6Q0l241oCXj7yuPWnriXlvcv8
# SIG # End signature block
