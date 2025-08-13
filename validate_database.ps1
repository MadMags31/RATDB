#Requires -Version 5.1

<#
.SYNOPSIS
    RAT Problem Database Validator - Comprehensive validation and integrity checking

.DESCRIPTION
    This script provides comprehensive validation for the RAT Problem database including
    schema validation, data integrity checks, duplicate detection, and detailed reporting.

.PARAMETER DatabasePath
    Path to the database file to validate (defaults to ./rmm_database.json)

.PARAMETER GenerateReport
    Generate a detailed validation report

.PARAMETER ReportPath
    Path for the validation report (defaults to ./validation_report.txt)

.PARAMETER FixIssues
    Attempt to automatically fix non-critical issues

.PARAMETER Verbose
    Display detailed validation information

.EXAMPLE
    .\validate_database.ps1
    Basic validation of default database

.EXAMPLE
    .\validate_database.ps1 -DatabasePath ".\rmm_database.json" -GenerateReport -DetailedOutput
    Full validation with detailed report

.EXAMPLE
    .\validate_database.ps1 -FixIssues
    Validation with automatic fixes for non-critical issues

.NOTES
    Author: RAT Problem Security Team
    Version: 1.0
    Requires: PowerShell 5.1
    Database: JSON-based signature database validation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DatabasePath = ".\rmm_database.json",

    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\validation_report.txt",

    [Parameter(Mandatory = $false)]
    [switch]$FixIssues,

    [Parameter(Mandatory = $false)]
    [switch]$DetailedOutput
)

# Global validation configuration
$script:ValidRiskLevels = @("authorized", "suspicious", "unauthorized")
$script:RequiredTopLevelFields = @("database_info", "rmm_tools")
$script:RequiredDatabaseInfoFields = @("version", "last_updated", "total_entries")
$script:RequiredRMMFields = @("name", "vendor", "risk_level", "detection_signatures", "uninstaller_info")
$script:RequiredSignatureFields = @("processes", "services", "registry_keys", "installation_paths", "files")
$script:RequiredUninstallerFields = @("display_name", "uninstall_string", "quiet_uninstall")
$script:ValidationResults = @()
$script:IssuesFound = 0
$script:CriticalIssues = 0
$script:WarningsFound = 0
$script:FixesApplied = 0

#region Validation Result Management

function Add-ValidationResult {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("PASS", "WARN", "FAIL", "FIXED")]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Check,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Recommendation = "",

        [Parameter(Mandatory = $false)]
        [string]$EntryName = "",

        [Parameter(Mandatory = $false)]
        [bool]$Critical = $false
    )

    $result = [PSCustomObject]@{
        Status = $Status
        Check = $Check
        Message = $Message
        Recommendation = $Recommendation
        EntryName = $EntryName
        Critical = $Critical
        Timestamp = Get-Date
    }

    $script:ValidationResults += $result

    # Update counters
    switch ($Status) {
        "FAIL" { 
            $script:IssuesFound++
            if ($Critical) { $script:CriticalIssues++ }
        }
        "WARN" { $script:WarningsFound++ }
        "FIXED" { $script:FixesApplied++ }
    }

    # Display result if detailed output requested
    if ($DetailedOutput) {
        $color = switch ($Status) {
            "PASS" { "Green" }
            "WARN" { "Yellow" }
            "FAIL" { "Red" }
            "FIXED" { "Cyan" }
        }
        
        $displayMessage = "[$Status] $Check"
        if ($EntryName) { $displayMessage += " ($EntryName)" }
        $displayMessage += ": $Message"
        
        Write-Host $displayMessage -ForegroundColor $color
    }
}

#endregion

#region Core Validation Functions

function Test-DatabaseStructure {
    param([object]$Database)

    Write-Host "Validating database structure..." -ForegroundColor Cyan

    # Check top-level fields
    foreach ($field in $script:RequiredTopLevelFields) {
        if ($Database.PSObject.Properties.Name -notcontains $field) {
            Add-ValidationResult -Status "FAIL" -Check "Database Structure" -Message "Missing required top-level field: $field" -Critical $true -Recommendation "Add missing field to database structure"
        } else {
            Add-ValidationResult -Status "PASS" -Check "Database Structure" -Message "Required field '$field' present"
        }
    }

    # Validate database_info structure
    if ($Database.database_info) {
        foreach ($field in $script:RequiredDatabaseInfoFields) {
            if ($Database.database_info.PSObject.Properties.Name -notcontains $field) {
                Add-ValidationResult -Status "FAIL" -Check "Database Info" -Message "Missing database_info field: $field" -Critical $true -Recommendation "Add missing database_info field"
            } else {
                Add-ValidationResult -Status "PASS" -Check "Database Info" -Message "Database info field '$field' present"
            }
        }

        # Validate total_entries count
        $actualCount = if ($Database.rmm_tools) { $Database.rmm_tools.Count } else { 0 }
        $reportedCount = $Database.database_info.total_entries

        if ($actualCount -ne $reportedCount) {
            if ($FixIssues) {
                $Database.database_info.total_entries = $actualCount
                Add-ValidationResult -Status "FIXED" -Check "Entry Count" -Message "Fixed total_entries count: $reportedCount -> $actualCount" -Recommendation "Count has been automatically corrected"
            } else {
                Add-ValidationResult -Status "WARN" -Check "Entry Count" -Message "total_entries mismatch: reported $reportedCount, actual $actualCount" -Recommendation "Update total_entries to match actual count"
            }
        } else {
            Add-ValidationResult -Status "PASS" -Check "Entry Count" -Message "total_entries count is accurate: $actualCount"
        }

        # Validate date format
        try {
            [DateTime]::ParseExact($Database.database_info.last_updated, "yyyy-MM-dd", $null)
            Add-ValidationResult -Status "PASS" -Check "Date Format" -Message "last_updated date format is valid"
        } catch {
            if ($FixIssues) {
                $Database.database_info.last_updated = Get-Date -Format "yyyy-MM-dd"
                Add-ValidationResult -Status "FIXED" -Check "Date Format" -Message "Fixed last_updated date format" -Recommendation "Date has been updated to current date"
            } else {
                Add-ValidationResult -Status "WARN" -Check "Date Format" -Message "Invalid last_updated date format: $($Database.database_info.last_updated)" -Recommendation "Use yyyy-MM-dd format"
            }
        }
    }
}

function Test-RMMEntries {
    param([object]$Database)

    Write-Host "Validating RMM entries..." -ForegroundColor Cyan

    if (-not $Database.rmm_tools -or $Database.rmm_tools.Count -eq 0) {
        Add-ValidationResult -Status "WARN" -Check "RMM Entries" -Message "No RMM tools found in database" -Recommendation "Database appears empty"
        return
    }

    foreach ($entry in $Database.rmm_tools) {
        $entryName = if ($entry.name) { $entry.name } else { "Unknown Entry" }
        
        # Validate required fields
        foreach ($field in $script:RequiredRMMFields) {
            if ($entry.PSObject.Properties.Name -notcontains $field) {
                Add-ValidationResult -Status "FAIL" -Check "Required Fields" -Message "Missing required field: $field" -EntryName $entryName -Critical $true -Recommendation "Add missing field to entry"
            }
        }

        # Validate name and vendor
        if ([string]::IsNullOrWhiteSpace($entry.name)) {
            Add-ValidationResult -Status "FAIL" -Check "Entry Name" -Message "Name is empty or whitespace" -EntryName $entryName -Critical $true -Recommendation "Provide a valid name"
        }

        if ([string]::IsNullOrWhiteSpace($entry.vendor)) {
            Add-ValidationResult -Status "FAIL" -Check "Entry Vendor" -Message "Vendor is empty or whitespace" -EntryName $entryName -Critical $true -Recommendation "Provide a valid vendor name"
        }

        # Validate risk level
        if ($entry.risk_level -notin $script:ValidRiskLevels) {
            Add-ValidationResult -Status "FAIL" -Check "Risk Level" -Message "Invalid risk level: $($entry.risk_level)" -EntryName $entryName -Critical $true -Recommendation "Use one of: $($script:ValidRiskLevels -join ', ')"
        } else {
            Add-ValidationResult -Status "PASS" -Check "Risk Level" -Message "Valid risk level: $($entry.risk_level)" -EntryName $entryName
        }

        # Validate detection signatures
        if ($entry.detection_signatures) {
            foreach ($field in $script:RequiredSignatureFields) {
                if ($entry.detection_signatures.PSObject.Properties.Name -notcontains $field) {
                    Add-ValidationResult -Status "FAIL" -Check "Detection Signatures" -Message "Missing signature field: $field" -EntryName $entryName -Recommendation "Add missing signature field"
                } else {
                    # Check if array is empty
                    $fieldValue = $entry.detection_signatures.$field
                    if (-not $fieldValue -or ($fieldValue -is [array] -and $fieldValue.Count -eq 0)) {
                        Add-ValidationResult -Status "WARN" -Check "Detection Signatures" -Message "Empty signature field: $field" -EntryName $entryName -Recommendation "Consider adding detection signatures"
                    } else {
                        Add-ValidationResult -Status "PASS" -Check "Detection Signatures" -Message "Signature field '$field' has data" -EntryName $entryName
                    }
                }
            }

            # Validate registry key format
            if ($entry.detection_signatures.registry_keys) {
                foreach ($regKey in $entry.detection_signatures.registry_keys) {
                    if ($regKey -and -not ($regKey -match '^HK(LM|CU|CR|U|CC)\\')) {
                        Add-ValidationResult -Status "WARN" -Check "Registry Keys" -Message "Registry key may be invalid format: $regKey" -EntryName $entryName -Recommendation "Ensure registry keys start with valid hive (HKLM, HKCU, etc.)"
                    }
                }
            }

            # Validate installation paths format
            if ($entry.detection_signatures.installation_paths) {
                foreach ($path in $entry.detection_signatures.installation_paths) {
                    if ($path -and -not ($path -match '^[A-Za-z]:\\' -or $path -match '^\\\\')) {
                        Add-ValidationResult -Status "WARN" -Check "Installation Paths" -Message "Path may be invalid format: $path" -EntryName $entryName -Recommendation "Ensure paths are valid Windows paths"
                    }
                }
            }
        }

        # Validate uninstaller info
        if ($entry.uninstaller_info) {
            foreach ($field in $script:RequiredUninstallerFields) {
                if ($entry.uninstaller_info.PSObject.Properties.Name -notcontains $field) {
                    Add-ValidationResult -Status "WARN" -Check "Uninstaller Info" -Message "Missing uninstaller field: $field" -EntryName $entryName -Recommendation "Add missing uninstaller field"
                } else {
                    $fieldValue = $entry.uninstaller_info.$field
                    if ([string]::IsNullOrWhiteSpace($fieldValue)) {
                        Add-ValidationResult -Status "WARN" -Check "Uninstaller Info" -Message "Empty uninstaller field: $field" -EntryName $entryName -Recommendation "Provide uninstaller information"
                    }
                }
            }
        }
    }
}

function Test-DuplicateEntries {
    param([object]$Database)

    Write-Host "Checking for duplicate entries..." -ForegroundColor Cyan

    if (-not $Database.rmm_tools -or $Database.rmm_tools.Count -eq 0) {
        return
    }

    $nameVendorPairs = @{}
    $duplicates = @()

    foreach ($entry in $Database.rmm_tools) {
        $key = "$($entry.name)|$($entry.vendor)"
        
        if ($nameVendorPairs.ContainsKey($key)) {
            $duplicates += [PSCustomObject]@{
                Name = $entry.name
                Vendor = $entry.vendor
                Key = $key
            }
            Add-ValidationResult -Status "FAIL" -Check "Duplicate Detection" -Message "Duplicate entry found: $($entry.name) by $($entry.vendor)" -EntryName $entry.name -Recommendation "Remove or merge duplicate entries"
        } else {
            $nameVendorPairs[$key] = $true
        }
    }

    if ($duplicates.Count -eq 0) {
        Add-ValidationResult -Status "PASS" -Check "Duplicate Detection" -Message "No duplicate entries found"
    } else {
        Add-ValidationResult -Status "FAIL" -Check "Duplicate Detection" -Message "Found $($duplicates.Count) duplicate entries" -Critical $true -Recommendation "Review and remove duplicate entries"
    }
}

function Test-DataConsistency {
    param([object]$Database)

    Write-Host "Checking data consistency..." -ForegroundColor Cyan

    if (-not $Database.rmm_tools -or $Database.rmm_tools.Count -eq 0) {
        return
    }

    # Check for entries with same processes but different risk levels
    $processMap = @{}
    foreach ($entry in $Database.rmm_tools) {
        if ($entry.detection_signatures -and $entry.detection_signatures.processes) {
            foreach ($process in $entry.detection_signatures.processes) {
                if (-not $processMap.ContainsKey($process)) {
                    $processMap[$process] = @()
                }
                $processMap[$process] += [PSCustomObject]@{
                    Name = $entry.name
                    RiskLevel = $entry.risk_level
                }
            }
        }
    }

    foreach ($process in $processMap.Keys) {
        $entries = $processMap[$process]
        $riskLevels = $entries | Select-Object -ExpandProperty RiskLevel -Unique
        
        if ($riskLevels.Count -gt 1) {
            $entryNames = $entries | Select-Object -ExpandProperty Name
            Add-ValidationResult -Status "WARN" -Check "Data Consistency" -Message "Process '$process' used by multiple entries with different risk levels: $($entryNames -join ', ')" -Recommendation "Review risk level consistency"
        }
    }

    # Check for authorized entries with high-risk keywords
    $riskKeywords = @("rat", "backdoor", "trojan", "malware", "hack", "crack", "keylog")
    foreach ($entry in $Database.rmm_tools) {
        if ($entry.risk_level -eq "authorized") {
            $entryText = "$($entry.name) $($entry.vendor)".ToLower()
            foreach ($keyword in $riskKeywords) {
                if ($entryText -match $keyword) {
                    Add-ValidationResult -Status "WARN" -Check "Risk Assessment" -Message "Authorized entry contains suspicious keyword '$keyword': $($entry.name)" -EntryName $entry.name -Recommendation "Review risk level assignment"
                    break
                }
            }
        }
    }

    Add-ValidationResult -Status "PASS" -Check "Data Consistency" -Message "Data consistency checks completed"
}

function Test-SecurityValidation {
    param([object]$Database)

    Write-Host "Performing security validation..." -ForegroundColor Cyan

    if (-not $Database.rmm_tools -or $Database.rmm_tools.Count -eq 0) {
        return
    }

    # Check for potentially dangerous uninstall commands
    $dangerousCommands = @("format", "del /s", "rd /s", "rmdir /s", "shutdown", "powershell", "cmd.exe", "net user")
    
    foreach ($entry in $Database.rmm_tools) {
        if ($entry.uninstaller_info) {
            $uninstallCommands = @($entry.uninstaller_info.uninstall_string, $entry.uninstaller_info.quiet_uninstall)
            
            foreach ($command in $uninstallCommands) {
                if ($command) {
                    foreach ($dangerous in $dangerousCommands) {
                        if ($command.ToLower() -match $dangerous) {
                            Add-ValidationResult -Status "WARN" -Check "Security Validation" -Message "Potentially dangerous uninstall command detected: $command" -EntryName $entry.name -Recommendation "Review uninstall command for security"
                        }
                    }
                }
            }
        }

        # Check for overly broad registry keys
        if ($entry.detection_signatures -and $entry.detection_signatures.registry_keys) {
            foreach ($regKey in $entry.detection_signatures.registry_keys) {
                if ($regKey -match '^HKLM\\SOFTWARE$' -or $regKey -match '^HKCU\\SOFTWARE$') {
                    Add-ValidationResult -Status "WARN" -Check "Security Validation" -Message "Overly broad registry key: $regKey" -EntryName $entry.name -Recommendation "Use more specific registry keys"
                }
            }
        }
    }

    Add-ValidationResult -Status "PASS" -Check "Security Validation" -Message "Security validation completed"
}

#endregion

#region Reporting Functions

function Write-ValidationSummary {
    Write-Host "`n=== Validation Summary ===" -ForegroundColor Cyan
    Write-Host "Total Checks: $($script:ValidationResults.Count)"
    Write-Host "Issues Found: $script:IssuesFound" -ForegroundColor $(if ($script:IssuesFound -gt 0) { "Red" } else { "Green" })
    Write-Host "Critical Issues: $script:CriticalIssues" -ForegroundColor $(if ($script:CriticalIssues -gt 0) { "Red" } else { "Green" })
    Write-Host "Warnings: $script:WarningsFound" -ForegroundColor $(if ($script:WarningsFound -gt 0) { "Yellow" } else { "Green" })
    
    if ($FixIssues -and $script:FixesApplied -gt 0) {
        Write-Host "Fixes Applied: $script:FixesApplied" -ForegroundColor Cyan
    }

    # Overall status
    if ($script:CriticalIssues -gt 0) {
        Write-Host "`nDatabase Status: CRITICAL ISSUES FOUND" -ForegroundColor Red
        Write-Host "Action Required: Fix critical issues before using database" -ForegroundColor Red
    } elseif ($script:IssuesFound -gt 0 -or $script:WarningsFound -gt 0) {
        Write-Host "`nDatabase Status: ISSUES FOUND" -ForegroundColor Yellow
        Write-Host "Recommendation: Review and address identified issues" -ForegroundColor Yellow
    } else {
        Write-Host "`nDatabase Status: VALIDATED" -ForegroundColor Green
        Write-Host "Database passed all validation checks" -ForegroundColor Green
    }
}

function Generate-ValidationReport {
    param([string]$ReportPath)

    Write-Host "Generating validation report..." -ForegroundColor Cyan

    $report = @()
    $report += "RAT Problem Database Validation Report"
    $report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $report += "Database: $DatabasePath"
    $report += "=" * 60
    $report += ""

    # Summary
    $report += "VALIDATION SUMMARY"
    $report += "-" * 20
    $report += "Total Checks: $($script:ValidationResults.Count)"
    $report += "Issues Found: $script:IssuesFound"
    $report += "Critical Issues: $script:CriticalIssues"
    $report += "Warnings: $script:WarningsFound"
    
    if ($FixIssues -and $script:FixesApplied -gt 0) {
        $report += "Fixes Applied: $script:FixesApplied"
    }
    $report += ""

    # Group results by status
    $groupedResults = $script:ValidationResults | Group-Object Status

    foreach ($group in $groupedResults) {
        $report += "$($group.Name.ToUpper()) RESULTS ($($group.Count))"
        $report += "-" * 30
        
        foreach ($result in $group.Group) {
            $line = "[$($result.Check)]"
            if ($result.EntryName) { $line += " ($($result.EntryName))" }
            $line += ": $($result.Message)"
            $report += $line
            
            if ($result.Recommendation) {
                $report += "  Recommendation: $($result.Recommendation)"
            }
            $report += ""
        }
    }

    # Detailed recommendations
    $criticalIssues = $script:ValidationResults | Where-Object { $_.Status -eq "FAIL" -and $_.Critical }
    if ($criticalIssues) {
        $report += "CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION"
        $report += "-" * 45
        foreach ($issue in $criticalIssues) {
            $line = "$($issue.Check)"
            if ($issue.EntryName) { $line += " ($($issue.EntryName))" }
            $line += ": $($issue.Message)"
            $report += $line
            if ($issue.Recommendation) {
                $report += "  Action: $($issue.Recommendation)"
            }
            $report += ""
        }
    }

    # Save report
    try {
        $report | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
        Write-Host "Validation report saved to: $ReportPath" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to save report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

#endregion

#region Main Execution

Write-Host "RAT Problem Database Validator" -ForegroundColor Cyan
Write-Host "Database: $DatabasePath" -ForegroundColor Gray

# Check if database file exists
if (-not (Test-Path $DatabasePath)) {
    Write-Host "Database file not found: $DatabasePath" -ForegroundColor Red
    exit 1
}

# Load and parse database
try {
    $databaseContent = Get-Content $DatabasePath -Raw
    $database = $databaseContent | ConvertFrom-Json
    Write-Host "Database loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "Failed to parse database JSON: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Run validation checks
Test-DatabaseStructure $database
Test-RMMEntries $database
Test-DuplicateEntries $database
Test-DataConsistency $database
Test-SecurityValidation $database

# Save database if fixes were applied
if ($FixIssues -and $script:FixesApplied -gt 0) {
    try {
        $database | ConvertTo-Json -Depth 10 | Out-File -FilePath $DatabasePath -Encoding UTF8 -Force
        Write-Host "`nDatabase updated with $script:FixesApplied fixes" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Failed to save database fixes: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Display summary
Write-ValidationSummary

# Generate report if requested
if ($GenerateReport) {
    Generate-ValidationReport $ReportPath
}

# Set exit code based on results
if ($script:CriticalIssues -gt 0) {
    exit 1
} else {
    exit 0
}

#endregion
# SIG # Begin signature block
# MIIb6QYJKoZIhvcNAQcCoIIb2jCCG9YCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUzuN2kkXPEW0FmkjLWjTcMAxT
# tzOgghZSMIIDFDCCAfygAwIBAgIQflfO7V2mO51FJpe60M0g4zANBgkqhkiG9w0B
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS+Mjmw
# g9cDrsG1WgfYh4aNbSM0mDANBgkqhkiG9w0BAQEFAASCAQDNzqOib40Co1zRY849
# RxOcq6VIe5JRE+anNKN/MqAP5WbYVEWNXhFkFqdLlnnEXaFhAV9HHZdpSFldi+jS
# VbT9qi/MOvI6BD9Fww3ivbSqjfWF60BeWLuYwkprLgCUTdIH6u9yvVWlwiZGWOvU
# VUAjneRkIbW831S0HEWMbjz7TzkbxqMhxICUb5dFidCUWVj6cJBfiZF3YXeEpsrm
# Aw3ZgKaRG2gYgT8MH8g4ah4PZ9chQzIw6d5vOBaibTbcxRbvb8o/zVipsuuROBwz
# F9tLWX8CaT5jP8o32b0zuyheDjzbyrRuY2D5UbKWLVhcjk52WZV3ht/ay4g+hR9f
# fQILoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBU
# cnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQ
# CoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDgwODIwMzIzM1owLwYJKoZI
# hvcNAQkEMSIEILZcPKR/wHQQtCGoJdpVR6eG1O+4w1C6CLhT6rsvdcIPMA0GCSqG
# SIb3DQEBAQUABIICABCa2DF1bt6RbmRDn8b918geFXjlXGP+BUGyHBWxxPurc7Ah
# GH+bCmIgSLt4RhE/qt8p4BMcvBf7iWLi8NDIXUJVRy6o5ziP6EcQtg/m0/ERdWSA
# 3hz7LYNisHq68oWDML3l1gqBU0jMjFNhSZzuXKLdpUD2Gb0DRzV26AgVOz2N70qg
# kOd0pHFeHj7J5mZyRpN5ROpQfdKoAMITYSWWD5fRKqwLRqxU6sHn4rvDFBrfsLpV
# bH/WhtdFW3rV7MVPMCvX6uKP4X5cgfCzmHzOu41a0+p/M0l/qTywKl+sN2ogm238
# lZ7LHGc62zkokWDWAORAto3ZrSvIPfkcRYDMdpgRDNz8F1qFn1pfeA+D+wBaDlFi
# yw0NGbIqZcid1snbtivWKRwwIh8mVIPkQ2oZlg5qC87Y+RrwgGMs63WfjT4dkaJI
# EGX8iPY0kpS//wyL5BcU4UINHZ9r0/4RhZUi2TKgblI+g+iKLSG41V+FJve9ku7d
# T8M3rcBx4WyfGP+vPyAxX5TXSy9CDJSa32Nfic058aSQWmkKB5ZuEoz1Wa27AFrL
# ufXdE+rMb4s5JprP67ZSwDHpmjinQEEOS25Le1r7GSo+KS6fwEhn7yeOmEQEuglb
# cf44ZslrazKWsVwaJ+dM9aThl/H3Fz1iex3EJmXYBi0lAqIa3rmPyr6/JsyY
# SIG # End signature block
