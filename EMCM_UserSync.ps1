# PowerShell Script to Sync a CSV list of Student and Teachers 
# and create users that don't exist in both Azure AD and Canvas
# or update users whose attributes have changed, and delete users 
# no longer in the import list with a soft delete wait period where
# accounts will be disabled for X days until actual deletion

# Source CSV File
$inputFile = $PSScriptRoot + "\" + "EMCM_Import.csv"
$SettingsFile =  $PSScriptRoot + "\" + "CanvasApiKey.txt"
$Office365StudentTeacherUsers = $PSScriptRoot + "\" + "Office365StudentTeacherUsers.csv"
$Office365AllUsers = $PSScriptRoot + "\" + "Office365AllUsers.csv"

# Flag to Manually Validate Change Actions - either 0 (No) or 1 (Yes)
$confirmchanges = 0

# Define days to wait to process deletion of account after account is not in import CSV
$deletewaitdays = 30

# Load Canvas API Key
Get-Content $SettingsFile | foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $h.Add($k[0], $k[1]) } }
$canvasToken = $h.Get_Item("canvastoken")

function ParseErrorForResponseBody($Error) {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if ($Error.Exception.Response) {  
            Write-Host "HTTP Status: " $Error.Exception
            $Reader = New-Object System.IO.StreamReader($Error.Exception.Response.GetResponseStream())
            $Reader.BaseStream.Position = 0
            $Reader.DiscardBufferedData()
            $ResponseBody = $Reader.ReadToEnd()
            if ($ResponseBody.StartsWith('{')) {
                $ResponseBody = $ResponseBody | ConvertFrom-Json
            }
            return $ResponseBody
        }
    }
    else {
        return $Error.ErrorDetails.Message
    }
}

function ExistsInCanvas($CanvasUsername){
    $canvasDomain = "https://emcm.instructure.com/api/v1"
    $accessToken = $canvasToken
    $headers = @{"Authorization"="Bearer "+$accessToken}  # build access token header
    $canvasUserUrl = "$canvasDomain/accounts/self/users?search_term=$CanvasUsername"
    
    # Write-Host "API Get to:" $canvasUserUrl
    try{
        $response = Invoke-RestMethod -Method Get -uri $canvasUserUrl -header $headers
        if($response.login_id -eq $CanvasUsername){
            # Write-Host "User found!"
            return $true
        } else {
            # Write-Host "User not found!"
            return $false
        }
    } catch {
        Write-Host "Unhandled Web Request Failure!"
        ParseErrorForResponseBody($_)
        return $false
    }
}

function CreateInCanvas($CanvasUsername){
    $canvasDomain = "https://emcm.instructure.com/api/v1"
    $accessToken = $canvasToken
    $headers = @{"Authorization"="Bearer "+$accessToken}  # build access token header
    $canvasUserUrl = "$canvasDomain/accounts/self/users?pseudonym[unique_id]=$CanvasUsername"
    
    # Write-Host "API Post to:" $canvasUserUrl
    try{
        $response = Invoke-RestMethod -Method Post -uri $canvasUserUrl -header $headers -ContentType 'application/json; charset=utf-8'
        if($response.login_id -eq $CanvasUsername){
            # Write-Host "User Creation Succeeded!"
            return $true
        } else {
            Write-Host "User Creation Failed!"
            return $false
        }
    } catch {
        Write-Host "Unhandled Web Request Failure!"
        ParseErrorForResponseBody($_)
        return $false
    }
}

function DeleteInCanvas($CanvasUsername){
    $canvasDomain = "https://emcm.instructure.com/api/v1"
    $accessToken = $canvasToken
    $headers = @{"Authorization"="Bearer "+$accessToken}  # build access token header
    $canvasUserUrl = "$canvasDomain/accounts/self/users?search_term=$CanvasUsername"
    
    # Write-Host "API Delete to:" $canvasUserUrl
    try{
        $response = Invoke-RestMethod -Method Get -uri $canvasUserUrl -header $headers
        if($response.login_id -eq $CanvasUsername){
            # User Exists - Get id to process next delete call
            $canvasuserid = $response.id
            $canvasUserUrl = "$canvasDomain/accounts/self/users/$canvasuserid"
            Write-Host $canvasUserUrl
            $response = Invoke-RestMethod -Method DELETE -uri $canvasUserUrl -header $headers
            if($response.user.name -eq $CanvasUsername){
                # Write-Host "Deletion Successful"
                return $true
            } else {
                Write-Host "Deletion Failed!"
                Write-Host $response.result
                return $false
            }
        } else {
            Write-Host "UserID not Found!"
            return $false
        }
    } catch {
        Write-Host "Unhandled Web Request Failure!"
        ParseErrorForResponseBody($_)
        return $false
    }
}

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
Write-Host "Importing CSV of Target User List:" $inputFile
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
        Write-Host "     Creating New User"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
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
    } else {
        # Write-Host "        Attributes Match AAD: " $aad_DisplayName.DisplayName " CSV: $DisplayName" 
    }
    $aad_Title = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object Title
    if ($aad_Title.Title -cne $UserRole){
        Write-Host "     Updating Title from: " $aad_Title.Title " to: $UserRole"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -Title $UserRole
    } else {
        # Write-Host "        Attributes Match AAD: " $aad_Title.Title " CSV: $UserRole" 
    }
    $aad_FirstName = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object FirstName
    if ($aad_FirstName.FirstName -cne $FirstName){
        Write-Host "     Updating FirstName from: " $aad_FirstName.FirstName " to: $FirstName"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -FirstName $FirstName
    } else {
        # Write-Host "        Attributes Match AAD: " $aad_FirstName.FirstName " CSV: $FirstName" 
    }
    $aad_LastName = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object LastName
    if ($aad_LastName.LastName -cne $LastName){
        Write-Host "     Updating LastName from: " $aad_LastName.LastName " to: $LastName"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -LastName $LastName
    } else {
        # Write-Host "        Attributes Match AAD: " $aad_LastName.LastName " CSV: $LastName" 
    }
    $aad_MobilePhone = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object MobilePhone
    if ($aad_MobilePhone.MobilePhone -cne $MobilePhone){
        Write-Host "     Updating MobilePhone from: " $aad_MobilePhone.MobilePhone " to: $MobilePhone"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -MobilePhone $MobilePhone
    } else {
        # Write-Host "        Attributes Match AAD: " $aad_MobilePhone.MobilePhone " CSV: $MobilePhone" 
    }
    $aad_AlternateEmailAddresses = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object AlternateEmailAddresses
    if ($PersonalEmailAddress.length -ne $aad_AlternateEmailAddresses[0].AlternateEmailAddresses.length -or $aad_AlternateEmailAddresses[0].AlternateEmailAddresses -cne $PersonalEmailAddress){
        Write-Host "     Updating AlternateEmailAddresses from: " $aad_AlternateEmailAddresses[0].AlternateEmailAddresses " to: $PersonalEmailAddress" 
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -AlternateEmailAddresses $PersonalEmailAddress
    } else {
        # Write-Host "        Attributes Match AAD: " $aad_AlternateEmailAddresses[0].AlternateEmailAddresses " CSV: $PersonalEmailAddress" 
    }
    $aad_UsageLocation = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object UsageLocation
    if ($aad_UsageLocation.UsageLocation -cne "US"){
        Write-Host "     Updating UsageLocation from: " $aad_UsageLocation.UsageLocation " to: US"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -UsageLocation "US"
    } else {
        # Write-Host "        Attributes Match AAD: " $aad_UsageLocation.UsageLocation " CSV: US" 
    }
    $aad_BlockCredential = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object BlockCredential
    if ($aad_BlockCredential.BlockCredential -ne $false){
        Write-Host "     Updating BlockCredential from: " $aad_BlockCredential.BlockCredential " to: $false"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -BlockCredential $false
    } else {
        # Write-Host "        Attributes Match AAD: " $aad_BlockCredential.BlockCredential " CSV: false" 
    }
    # If user is an active user reset the City field to blank, which is used as a soft delete placeholder
    $aad_City = Get-MsolUser -UserPrincipalName $UserPrincipalName | Select-Object City
    if ($aad_City.City -cne $null){
        Write-Host "     Updating City from: " $aad_City.City " to: "
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        Set-MsolUser -UserPrincipalName $UserPrincipalName -City $null
    } else {
        # Write-Host "        Attributes Match AAD: " $aad_City.City " CSV: " 
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

    # Check if User Anchor Exists in Canvas
    if(ExistsInCanvas $UserPrincipalName){
        Write-Host "     User Anchor Exists in Canvas"
    } else {
        Write-Host "     Creating User Anchor in Canvas"
        if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
        CreateInCanvas $UserPrincipalName
    }
}

Write-Host ""
Write-Host ""
Write-Host "Processing Student and Teacher Accounts for Deletion"
$aadusers = Get-MsolUser | Where-Object { $_.isLicensed -eq "True"} | Where-Object {($_.ProxyAddresses -like '*@student.ellismarsaliscenter.org') -or ($_.ProxyAddresses -like '*@teacher.ellismarsaliscenter.org')} | select-object  UserPrincipalName
foreach($aaduser in $aadusers){
    $aaduser_incsv = 0
    $aadupn = $aaduser.UserPrincipalName

    foreach($DelUser in $Users){
        $DelUserPrincipalName = NameToUserPrincipal $DelUser.FirstName $DelUser.LastName $DelUser.Role
        if($aadupn -eq $DelUserPrincipalName){
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
            Set-MsolUser -UserPrincipalName $aadupn -BlockCredential $true
        }
        
        $aad_City = Get-MsolUser -UserPrincipalName $aadupn | Select-Object City
        if ($aad_City.City -ne $null){
            $current = Get-Date
            if($current -gt $aad_City.City){
                Write-Host "Processing deletion of $aadupn"
                if($confirmchanges -eq 1){ Read-Host -Prompt "Press any key to continue or CTRL-C to quit" }
                Remove-MsolUser -UserPrincipalName $aadupn -Force
                DeleteInCanvas $aadupn
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