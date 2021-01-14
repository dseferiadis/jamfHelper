# PowerShell Script to Import CSV of Student and Teachers 
# and reset their passwords and export results

$inputFile = $PSScriptRoot + "\" + "EMCM_Reset.csv"
$outputFile = $PSScriptRoot + "\" + "EMCM_ResetResults.csv"

# Flag to Manually Validate Change Actions - either 0 (No) or 1 (Yes)
$confirmchanges = 1

# Function to Validate CSV File Columns
function Import-ValidCSV
{
        (
                [parameter(Mandatory=$true)]
                [ValidateScript({test-path $_ -type leaf})]
                [string]$inputFile,
                [string[]]$requiredColumns
        )
        $csvImport = import-csv $inputFile
        $inputTest = $csvImport | gm
        foreach ($requiredColumn in $requiredColumns)
        {
                if (!($inputTest | ? {$_.name -eq $requiredColumn}))
                {
                        write-error "$inputFile is missing the $requiredColumn column"
                        exit 10
                }
        }
        $csvImport
}

function NameToUserPrincipal($fn, $ln, $rl)
{
    #Strip all Non Word Characters and make lowercase from FirstName and LastName so we can create a consistent email format
    $EmailFirstname = $fn
    $EmailFirstname = $EmailFirstname -replace '[\W]', ''
    $EmailFirstname = $EmailFirstname.ToLower()

    $EmailLastname = $ln
    $EmailLastname = $EmailLastname -replace '[\W]', ''
    $EmailLastname = $EmailLastname.ToLower()

    #Get User Role, Remove Non Word Characters and Make Lowercase
    $UserRole = $rl
    $UserRole = $UserRole -replace '[\W]', ''
    $UserRole = $UserRole.ToLower()

    #Format Email Address / UserPrincipalName
    $UserPrincipalName = $EmailFirstname + "." + $EmailLastname + "@" + $UserRole + "." + "ellismarsaliscenter.org"
    $UserPrincipalName = $UserPrincipalName.ToLower()

    return $UserPrincipalName
}

function CheckForDuplicates($inputFile)
{
    $DuplicateQty = 0
    $RowNum = 0
    $Users = Import-Csv -Path $inputFile
    $RefUsers = Import-Csv -Path $inputFile
    foreach($User in $Users){
        $RowNum = $RowNum + 1
        $UserPrincipalName = NameToUserPrincipal $User.FirstName $User.LastName $User.Role
        $UserQty = 0
        foreach($RefUser in $RefUsers){
            $RefUserPrincipalName = NameToUserPrincipal $RefUser.FirstName $RefUser.LastName $RefUser.Role
            if($RefUserPrincipalName -eq $UserPrincipalName){
                $UserQty = $UserQty + 1
            }
        }
        if($UserQty -gt 1){
            Write-Host "Row" $RowNum $UserPrincipalName "is duplicated in import list! Resolve conflict before proceeding"
            $DuplicateQty = $DuplicateQty + 1
        }
    }
    return $DuplicateQty
}

function CheckPhoneSyntax($inputFile)
{
    $InvalidQty = 0
    $RowNum = 0
    $Users = Import-Csv -Path $inputFile
    foreach($User in $Users){
        $UserInvalidPhone = 0
        $RowNum = $RowNum + 1
        $UserPrincipalName = NameToUserPrincipal $User.FirstName $User.LastName $User.Role
        if($User.MoblePhone -match "^\d+$"){
            # Number is numeric
            if($User.MoblePhone.Length -eq 10){
                # Number is numeric and 10 digits - this is valid
            } else {
                # Number is numeric but not 10 digits - this is invalid
                $UserInvalidPhone = $UserInvalidPhone + 1
                $InvalidQty = $InvalidQty + 1
            }
        } else {
            Write-Host "NotNumeric"
            $UserInvalidPhone = $UserInvalidPhone + 1
            $InvalidQty = $InvalidQty + 1
        }

        if($UserInvalidPhone -gt 0){
            Write-Host "Row" $RowNum $UserPrincipalName "has invalid phone number and/or format!" $User.MoblePhone "Resolve before proceeding"
            $DuplicateQty = $DuplicateQty + 1
        }
    }
    return $InvalidQty
}

# Define Required Columns
[string[]]$requiredColumns = "FirstName","LastName","PreferredFirstName","PersonalEmail","MoblePhone","Role"
Write-Host "Importing CSV of Target User List"
$error.clear()
try { 
    $testCsv = Import-ValidCsv $inputFile $requiredColumns
}
catch { 
    "Failed to Import CSV - Malformed File"
    Write-Host $error
}
if (!$error) { 
    "CSV Syntax is Valid" 
}

# Check for Duplicate Users in Import CSV
Write-Host "Checking for Duplicates"
$DuplicateCheck = CheckForDuplicates $inputFile
if($DuplicateCheck -gt 0){
    Write-Host "Duplicate User(s) Detected"
    exit
} else {
    Write-Host "No Duplicate User(s) Detected"
}

# Check Phone Number is in Valid Format
Write-Host "Checking Phone Number Formatting"
$PhoneCheck = CheckPhoneSyntax $inputFile
if($PhoneCheck -gt 0){
    Write-Host "Phone Number Validations Failed"
    exit
} else {
    Write-Host "Phone Number Validations Passed"
}

# If Validation of CSV Passed - Proceed to Load into Target Variable
$Users = Import-Csv -Path $inputFile

#Connect to Azure AD
Write-Host "Connecting to MSOnline and AzureAD"
Connect-MsolService
Connect-AzureAD

#Get all Azure AD Users 
$MsolUsers = Get-MsolUser -All

# Reset Output File and Write Header
Out-File -FilePath $outputFile
Add-Content -Path $outputFile -Value "UserPrincipalName,Password,ResetDate"

foreach($User in $Users){
    $UserPrincipalName = NameToUserPrincipal $User.FirstName $User.LastName $User.Role
    
    #Check to See if Target Account Already Exists
    $UserExists = 0
    
    foreach($Msoluser in $MsolUsers){
    if ($Msoluser.UserPrincipalName -eq $UserPrincipalName){
        $UserExists++
        break
        }
    }

    #Reset Password if Target User is Found
    if ($UserExists -eq 0) {
        Write-Host "$UserPrincipalName not found in Azure AD"
        Add-Content -Path $outputFile -Value "$UserPrincipalName,,$currentDate"
    } else {
        Write-Host "Resetting Password for: " $UserPrincipalName
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        $userpwd = Set-MsolUserPassword -UserPrincipalName $UserPrincipalName
        $currentDate = Get-Date
        Add-Content -Path $outputFile -Value "$UserPrincipalName,$userpwd,$currentDate"
    }
}

Write-Host "Output Complete"