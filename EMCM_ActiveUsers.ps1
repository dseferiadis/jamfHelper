# PowerShell Script to check activity of provisioned accounts
# inactive accounts will be reccomended for cleanup

# Ensure MSOnline Module is Instaled (Run from PowerShell prompt started as administrator
Write-Host "Attempting to Install MSOnline for PowerShell"
Install-Module MSOnline

Write-Host "Attempting to Install AzureAD for PowerShell"
Install-Module AzureAD

#Connect to Azure AD
Write-Host "Connecting to MSOnline and AzureAD"
Connect-MsolService
Connect-AzureAD

Write-Host ""
Write-Host ""
Write-Host "Exporting All Users in Azure AD"

$Users = Get-MsolUser -all
$Headers = "DisplayName`tUserPrincipalName`tLicense`tLastLogon" >>C:\Scripts\Users.txt
ForEach ($User in $Users)
    {
    $UPN = $User.UserPrincipalName
    $LoginTime = Get-AzureAdAuditSigninLogs -top 1 -filter "userprincipalname eq '$UPN'" | select CreatedDateTime
    $NewLine = $User.DisplayName + "`t" + $User.UserPrincipalName + "`t" + $User.Licenses.AccountSkuId + "`t" + $LoginTime.CreatedDateTime
    $NewLine >>C:\Scripts\Users.txt
    }