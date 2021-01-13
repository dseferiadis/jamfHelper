# PowerShell Script to Import CSV of Student and Teachers 
# from SalesForce and create accounts that do not already exist
# and update accounts that already exist based on the email address as a
# primary key that does not change

# Flag to Manually Validate Change Actions - either 0 (No) or 1 (Yes)
$confirmchanges = 1

# Define days to wait to process deletion of account after account is not in import CSV
$deletewaitdays = 30

# Function to Validate CSV File Columns
$inputFile = $PSScriptRoot + "\\" + "EMCM_Import.csv"
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
    "Valid CSV File Found!" 
}
# If Validation of CSV Passed - Proceed to Load into Target Variable
$Users = Import-Csv -Path $inputFile

# Target User License AccountSkuId
$TargetLicenseAccountSkuId = "ellismarsaliscenter:STANDARDPACK"

# Prompt User If Running in Validation Mode
if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }

# Ensure MSOnline Module is Instaled (Run from PowerShell prompt started as administrator
Write-Host "Attempting to Install MSOnline for PowerShell"
Install-Module MSOnline

Write-Host "Attempting to Install AzureAD for PowerShell"
Install-Module AzureAD

#Connect to Azure AD
Write-Host "Connecting to MSOnline and AzureAD"
Connect-MsolService
Connect-AzureAD

# Email Naming Conventions 
# firstname.lastname@student|teacher.ellismarsaliscenter.org
# firname and lastname will strip all characters that are not A-Z
# student or teacher will be used based on user role

$Office365StudentTeacherUsers = "C:\Scripts\Office365StudentTeacherUsers.csv"
$Office365AllUsers = "C:\Scripts\Office365AllUsers.csv"

Write-Host "Processing Target User List"
$UserNum = 0
foreach($User in $Users){
    $UserNum++

    $UserPrincipalName = NameToUserPrincipal $User.FirstName $User.LastName $User.Role
    Write-Host "$UserNum - $UserPrincipalName"
    
    #Clean First and Lastnames for Display Names
    $FirstName = $User.FirstName
    $FirstName = $FirstName.Trim()

    $LastName = $User.LastName
    $LastName = $LastName.Trim()

    #Create Display Name with Preferred Firstname if Defined
    $PreferredFirstName = $User.PreferredFirstName
    $PreferredFirstName = $PreferredFirstName.Trim()

    if ($PreferredFirstName.length -eq 0){
        $PreferredFirstName = $FirstName
    }
    $DisplayName = $PreferredFirstName + " " + $LastName

    #Cache Role
    $UserRole = $User.Role
    $UserRole = $UserRole.ToLower()

    #Clean Mobile Phone
    $MobilePhone = $User.MoblePhone
    $MobilePhone = $MobilePhone -replace '[\W]', ''
    $MobilePhone = "+1 " + $MobilePhone

    #Clean Alternate Email Address
    $PersonalEmailAddress = $User.PersonalEmail
    $PersonalEmailAddress = $PersonalEmailAddress.Trim()

    #Check to See if Target Account Already Exists
    $UserExists = 0

    #Get all Azure AD Users 
    $MsolUsers = Get-MsolUser -All

    foreach($Msoluser in $MsolUsers){
        if ($Msoluser.UserPrincipalName -eq $UserPrincipalName){
            $UserExists++
            break
        }
    }

    #Create User if Needed
    if ($UserExists -eq 0) {
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Write-Host "     Creating New User"
        New-MsolUser -DisplayName $DisplayName -FirstName $FirstName -LastName $LastName -UserPrincipalName $UserPrincipalName -UsageLocation US -LicenseAssignment $TargetLicenseAccountSkuId
    } else {
        Write-Host "     User Already Exists - No Need to Create"
    }

    #Update User Attributes
    Write-Host "     Checking User Attributes"
    $aad_DisplayName = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object DisplayName
    if ($aad_DisplayName.DisplayName -cne $DisplayName){
        Write-Host "     Updating DisplayName from: " $aad_DisplayName.DisplayName " to: $DisplayName"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -DisplayName $DisplayName
    }
    $aad_Title = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object Title
    if ($aad_Title.Title -cne $UserRole){
        Write-Host "     Updating Title from: " $aad_Title.Title " to: $UserRole"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -Title $UserRole
    }
    $aad_FirstName = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object FirstName
    if ($aad_FirstName.FirstName -cne $FirstName){
        Write-Host "     Updating FirstName from: " $aad_FirstName.FirstName " to: $FirstName"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -FirstName $FirstName
    }
    $aad_LastName = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object LastName
    if ($aad_LastName.LastName -cne $LastName){
        Write-Host "     Updating LastName from: " $aad_LastName.LastName " to: $LastName"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -LastName $LastName
    }
    $aad_MobilePhone = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object MobilePhone
    if ($aad_MobilePhone.MobilePhone -cne $MobilePhone){
        Write-Host "     Updating MobilePhone from: " $aad_MobilePhone.MobilePhone " to: $MobilePhone"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -MobilePhone $MobilePhone
    }
    $aad_AlternateEmailAddresses = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object AlternateEmailAddresses
    if ($aad_AlternateEmailAddresses.AlternateEmailAddresses -cne $PersonalEmailAddress){
        Write-Host "     Updating AlternateEmailAddresses from: " $aad_AlternateEmailAddresses.AlternateEmailAddresses.value " to: $PersonalEmailAddress" 
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -AlternateEmailAddresses $PersonalEmailAddress
    }
    $aad_UsageLocation = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object UsageLocation
    if ($aad_UsageLocation.UsageLocation -cne "US"){
        Write-Host "     Updating UsageLocation from: " $aad_UsageLocation.UsageLocation " to: US"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -UsageLocation "US"
    }
    $aad_BlockCredential = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object BlockCredential
    if ($aad_BlockCredential.BlockCredential -ne $false){
        Write-Host "     Updating BlockCredential from: " $aad_BlockCredential.BlockCredential " to: $false"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -BlockCredential $false
    }
    # If user is an active user reset the City field to blank, which is used as a soft delete placeholder
    $aad_City = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object City
    if ($aad_City.City -cne $null){
        Write-Host "     Updating City from: " $aad_City.City " to: "
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -City $null
    }

    #Get User License Assignments
    $UserLicenseQty = 0
    $UserLicenses = (Get-MsolUser -UserPrincipalName $UserPrincipalName).licenses
    foreach ($UserLicense in $UserLicenses){
        if ($UserLicense.AccountSkuId -eq $TargetLicenseAccountSkuId){
            $UserLicenseQty++
            break
        }
    }

    #Assign License to User if Needed
    if ($UserLicenseQty -eq 0){
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Write-Host "     Assigning User License"
        Set-MsolUserLicense -UserPrincipalName $UserPrincipalName -AddLicenses "ellismarsaliscenter:STANDARDPACK"
    } else {
        Write-Host "     User License Already Assigned"
    }
    
    #Add to Target Adminisrative Unit
    Write-Host "     Getting Target Administrative Unit Object"
    $administrativeunitObj = Get-AzureADMSAdministrativeUnit -Filter "displayname eq 'Students and Teachers'"

    Write-Host "     Getting Target User Object"
    $UserObj = Get-AzureADUser -Filter "UserPrincipalName eq '$UserPrincipalName'"
    
    #Get Current AdministrativeUnit Members
    Write-Host "     Getting Current AdministrativeUnit Members"
    $administrativeunitObjMembers = Get-AzureADMSAdministrativeUnitMember -Id $administrativeunitObj.Id -All $true

    #Check if User is Already in Target Administrative Unit
    $UserExists = 0 
    foreach ($administrativeunitObjMember in $administrativeunitObjMembers){
        if ($administrativeunitObjMember.Id -eq $UserObj.ObjectId){
                $UserExists++
                break
        }
    }

    #If User is Not Already in Target Administrative Unit then add them
    if ($UserExists -eq 0){
        Write-Host "     Assigning Administrative Unit Member"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Add-AzureADMSAdministrativeUnitMember -Id $administrativeunitObj.Id -RefObjectId $UserObj.ObjectId
    } else {
        Write-Host "     User Already Administrative Unit Member"
    }
}

Write-Host ""
Write-Host ""
Write-Host "Processing Student and Teacher Accounts for Deletion"
$aadusers = Get-MsolUser | Where-Object { $_.isLicensed -eq "True"} | Where-Object {($_.ProxyAddresses -like '*@student.ellismarsaliscenter.org') -or ($_.ProxyAddresses -like '*@teacher.ellismarsaliscenter.org')} | select-object  UserPrincipalName
foreach($aaduser in $aadusers){
    $aaduser_incsv = 0
    $aadupn = $aaduser.UserPrincipalName

    foreach($User in $Users){
        $UserPrincipalName = NameToUserPrincipal $User.FirstName $User.LastName $User.Role
        if($aadupn -eq $UserPrincipalName){
            $aaduser_incsv = $aaduser_incsv + 1
            break
        }
    }

    # If Azure AD User was not found in Import CSV, Block account and flag for deletion
    if($aaduser_incsv -eq 0){
        Write-Host "$aadupn was not found in Import CSV - Processing for Offboard"
        $aad_BlockCredential = Get-MsolUser -UserPrincipalName $aadupn | Select-Object BlockCredential
        if ($aad_BlockCredential.BlockCredential -ne $true){
            Write-Host "   Updating BlockCredential from: " $aad_BlockCredential.BlockCredential " to: $true"
            if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
            Set-MsolUser -UserPrincipalName $UserPrincipalName -BlockCredential $true
        }
        
        $aad_City = Get-MsolUser -UserPrincipalName $aadupn | Select-Object City
        if ($aad_City.City -ne $null){
            $current = Get-Date
            if($current -gt $aad_City.City){
                Write-Host "Processing deletion of $aadupn"
                if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
                Remove-MsolUser -UserPrincipalName $aadupn -Force
            } else {
                Write-Host "   Scheduled for deletion on " $aad_City.City
            }
        } else {
            $deletedate = (Get-Date).adddays(30)
            Write-Host "   Flagging Account for Deletion in $deletedate days (Using City Field)"
            if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
            Set-MsolUser -UserPrincipalName $aadupn -City $deletedate
        }
    }
}

Write-Host ""
Write-Host ""
Write-Host "Exporting Student and Teachers in Office 365"
Get-MsolUser | Where-Object { $_.isLicensed -eq "True"} | Where-Object {($_.ProxyAddresses -like '*@student.ellismarsaliscenter.org') -or ($_.ProxyAddresses -like '*@teacher.ellismarsaliscenter.org')} | select-object  UserPrincipalName, Title, DisplayName, FirstName, LastName, @{Name=“AlternateEmailAddresses”;Expression={$_.AlternateEmailAddresses}}, MobilePhone, @{Name=“Licenses”;Expression={$_.licenses.AccountSku.Skupartnumber}}, WhenCreated | Export-Csv $Office365StudentTeacherUsers

Write-Host ""
Write-Host ""
Write-Host "Exporting All Licensed Users in Office 365"
Get-MsolUser | Where-Object { $_.isLicensed -eq "True"} | select-object  UserPrincipalName, Title, DisplayName, FirstName, LastName, @{Name=“AlternateEmailAddresses”;Expression={$_.AlternateEmailAddresses}}, MobilePhone, @{Name=“Licenses”;Expression={$_.licenses.AccountSku.Skupartnumber}}, WhenCreated | Export-Csv $Office365AllUsers

Write-Host ""
Write-Host ""
Write-Host "Script Complete"