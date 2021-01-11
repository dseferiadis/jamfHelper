# PowerShell Script to Import CSV of Student and Teachers 
# from SalesForce and create accounts that do not already exist
# and update accounts that already exist based on the email address as a
# primary key that does not change

# Function to Validate CSV File Columns
$inputFile = "C:\Scripts\EMCM_Import.csv"
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

    #Strip all Non Word Characters and make lowercase from FirstName and LastName so we can create a consistent email format
    $EmailFirstname = $User.FirstName
    $EmailFirstname = $EmailFirstname -replace '[\W]', ''
    $EmailFirstname = $EmailFirstname.ToLower()

    $EmailLastname = $User.LastName
    $EmailLastname = $EmailLastname -replace '[\W]', ''
    $EmailLastname = $EmailLastname.ToLower()

    #Get User Role, Remove Non Word Characters and Make Lowercase
    $UserRole = $User.Role
    $UserRole = $UserRole -replace '[\W]', ''
    $UserRole = $UserRole.ToLower()

    #Format Email Address / UserPrincipalName
    $UserPrincipalName = $EmailFirstname + "." + $EmailLastname + "@" + $UserRole + "." + "ellismarsaliscenter.org"
    $UserPrincipalName = $UserPrincipalName.ToLower()
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

    #Clean Mobile Phone
    $MobilePhone = $User.Mobile
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
        Write-Host "     Creating New User"
        New-MsolUser -DisplayName $DisplayName -FirstName $FirstName -LastName $LastName -UserPrincipalName $UserPrincipalName -UsageLocation US -LicenseAssignment $TargetLicenseAccountSkuId
    } else {
        Write-Host "     User Already Exists - No Need to Create"
    }

    #Update User Attributes
    Write-Host "     Updating User Attributes"
    Set-MsolUser -UserPrincipalName $UserPrincipalName -DisplayName $DisplayName -Title $UserRole
    Set-MsolUser -UserPrincipalName $UserPrincipalName -FirstName $FirstName
    Set-MsolUser -UserPrincipalName $UserPrincipalName -LastName $LastName
    Set-MsolUser -UserPrincipalName $UserPrincipalName -MobilePhone $MobilePhone
    Set-MsolUser -UserPrincipalName $UserPrincipalName -AlternateEmailAddresses $PersonalEmailAddress
    Set-MsolUser -UserPrincipalName $UserPrincipalName -UsageLocation "US"

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
        Add-AzureADMSAdministrativeUnitMember -Id $administrativeunitObj.Id -RefObjectId $UserObj.ObjectId
    } else {
        Write-Host "     User Already Administrative Unit Member"
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