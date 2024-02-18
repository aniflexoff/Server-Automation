# [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")
$startF = 1
while($startF)
{
    echo ""
    echo "Windows Core Configurator"
    echo ""
    echo "Select a setting"
    echo ""
    echo "(0) Exit: "
    echo ""
    echo "(1) Install AD"
    echo "(2) Install & configuration DHCP"
    echo "(3) Connect client to Domain"
    echo "(4) Create OrganizationalUnit & ADGroup"
    echo "(5) Configuration Quotes & Main folders"
    echo "(6) Create new Users and Home folders"
    echo "(7) Firewall"
    echo "(8) Install Web-Server"
    echo "(9) Configuration GPO"

    echo ""
    Write-Host "Select: "  -NoNewLine
    $sSettings = Read-Host
    cls

    if ($sSettings -eq "0")
    {
        exit
    } 
    elseif ($sSettings -eq "1")
    {
        echo "Install AD"
        echo ""
        echo "Warning!!! Auto-Reboot after installing..."
        echo ""

        Write-Host "Enter a new pass for AD.Administrator (Blank for cancel): " -NoNewLine
        $pass = Read-Host
        

        if ($pass -ne "")
        {
            Write-Host "Enter a domain name (ex. fbi.local): " -NoNewLine
            $dName = Read-Host
            Install-WindowsFeature -Name AD-Domain-Services, RSAT-ADDS, RSAT-ADDS-Tools -IncludeManagementTools
            Install-ADDSForest -DomainName $dName -SafeModeAdministratorPassword (ConvertTo-SecureString $pass -AsPlainText -Force) -Force 
        }
        cls
    }
    elseif ($sSettings -eq "2")
    {
        echo "Install & configuration DHCP"
        echo ""

        Write-Host "Enter Dns-Name {ex. SRV1.fbi.local} (Blank for cancel): " -NoNewLine
        $dName = Read-Host

        if ($dName -ne "")
        {
            Write-Host "Enter IP-address DNS-Server: " -NoNewLine
            $ipSrv = Read-Host
            Write-Host "Enter DHCP-Pool name: " -NoNewLine
            $dPool = Read-Host
            Write-Host "Enter start range for DHCP: " -NoNewLine
            $sDhcp = Read-Host
            Write-Host "Enter end range for DHCP: " -NoNewLine
            $sEnd = Read-Host
            Write-Host "Enter Subnet IP: " -NoNewLine
            $subnet = Read-Host
            Write-Host "Enter SubnetMask: " -NoNewLine
            $subMask = Read-Host

            Install-WindowsFeature DHCP –IncludeManagementTools
            Add-DhcpServerInDC -DnsName $dName -IPAddress $ipSrv
                                                                         
            Add-DhcpServerSecurityGroup 
            Restart-Service -Name DHCPServer -Force 

            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2 # Отключение уведомления о том, что роль требует настройки

            Import-Module DHCPServer
            Add-DhcpServerv4Scope -Name $dPool -StartRange $sDhcp -EndRange $sEnd -SubnetMask $subMask -State InActive

            Set-DhcpServerv4OptionValue -scopeid $subnet -dnsserver $ipSrv -dnsdomain $dName 
            Set-DhcpServerv4Scope -ScopeID $subnet -State Active
            Write-Host "Seccessful: DHCP configuration complete!" -BackGroundColor green
            Write-Host "Press {Enter} to exit: " -NoNewline
            $111 = Read-Host
        }
        cls
    }
    elseif ($sSettings -eq "3")
    {
        echo "Connect client to Domain"
        echo ""
        echo "Warning!!! Running on client..."
        echo ""

        Write-Host "Enter domain name (Blank for cancel): " -NoNewLine
        $dName = Read-Host

        if ($dName -ne "")
        {
            Write-Host "Enter PC name: " -NoNewLine
            $pcName = Read-Host
            Add-Computer -DomainName $dName 
            Rename-Computer -NewName $pcName -Restart
        }
        cls
    }
    elseif ($sSettings -eq "4")
    {
        echo "Create OrganizationalUnit & ADGroup"
        echo ""

        Write-Host "Enter number of (OrganizationalUnit & ADGroup) (Blank for cancel): " -NoNewLine
        $numUnit = Read-Host

        if ($numUnit -ne "")
        {
            Write-Host "Enter domain name (ex. fbi.local): " -NoNewLine
            $domainName = Read-Host

            $addresses = $domainName.split(".")
            $D1 = $addresses[0]
            $D2 = $addresses[1]
            $domain = "DC=$D1,DC=$D2"
            $OU_DU = "OU=Domain.Users,$domain"

            Install-WindowsFeature -Name "FS-Resource-Manager" -IncludeManagementTools
            New-ADOrganizationalUnit -Name "Domain.Users" -Path $domain

            for ([int]$i = 1; $i -le $numUnit; $i++)
            {
                Write-Host "Enter OU[$i] name: " -NoNewline
                $nameUnit = Read-Host
                New-ADOrganizationalUnit -Name $nameUnit -Path $OU_DU
                New-ADGroup -GroupScope Global -Path "OU=$nameUnit,$OU_DU" -Name $nameUnit
                New-Item -Path "c:\Shares\OU.SharedFolders\" -Name $nameUnit -ItemType "directory"
                New-SmbShare -Name "OU.$nameUnit.SharedFolders" -Path C:\Shares\OU.SharedFolders\$nameUnit -FullAccess "$nameUnit", "Administrators"
            }

            Write-Host "Seccessful: OU & Groups configuration complete!" -BackGroundColor green
            Write-Host "Press {Enter} to exit: " -NoNewline
            $111 = Read-Host
        }
        cls
    }
    elseif ($sSettings -eq "5")
    {
        echo "Configuration Quotes & Main folders"
        echo ""

        Write-Host "Enter name of file group (Blank for cancel): " -NoNewLine
        $nFileGroup = Read-Host

        if ($nFileGroup -ne "")
        {
            Write-Host "Enter name for new Shared Users.HomeFolder (ex. Users.HomeFolders): " -NoNewLine
            $nameShareFolder = Read-Host
            New-Item -Path "c:" -Name "Shares" -ItemType "directory"
            New-Item -Path "c:\Shares" -Name $nameShareFolder -ItemType "directory"
            New-SmbShare -Name $nameShareFolder -Path c:\Shares\$nameShareFolder

            $i = 1
            $fExtensionsFlag = $True
            while ($fExtensionsFlag -eq $True)
            {
            Write-Host "Enter file extension[$i] (Blank for end): " -NoNewLine
            $fExtension = Read-Host

                if ($fExtension -ne "")
                {
                    $fExtensions += ",""*.$fExtension"""
                    $i += 1
                }
                elseif ($fExtension -eq "") { $fExtensionsFlag = $False }
            }
            echo $fExtensions.TrimStart(",")
            New-FsrmFileGroup -Name $nFileGroup -IncludePattern @($fExtensions.TrimStart(","))
            $fExtension = ""
            New-FsrmFileScreenTemplate "block" -IncludeGroup $nFileGroup
            Write-Host "Seccessful: OU & Groups configuration complete!" -BackGroundColor green
            Write-Host "Press {Enter} to exit: " -NoNewline
            $111 = Read-Host
        }
        cls
    }
    elseif ($sSettings -eq "6")
    {
        echo "Create new Users and Home folders"
        echo ""

        Write-Host "Enter Server IP-Address (Blank for cancel): " -NoNewLine
        $ipS = Read-Host
        Write-Host "Enter domain name (ex. fbi.local): " -NoNewLine
        $dName = Read-Host 

        if ($ipS -ne "")
        {
            $check = 1
            While ($check) 
            {
                Write-Host "Enter a new username (Blank for cancel): " -NoNewLine
                $userName = Read-Host 

                if ($userName -eq "") 
                { 
                    $check = 0
                }
                else {
                    Write-Host "Enter a Group: " -NoNewLine
                    $group = Read-Host 

                    $addresses = $dName.split(".")
                    $D1 = $addresses[0]
                    $D2 = $addresses[1]
                    $domain = "DC=$D1,DC=$D2"
                    $OU_DU = "OU=Domain.Users,$domain"

                    New-ADUser -Name $userName -UserPrincipalName $userName@$dName -Path "OU=$group,$OU_DU"
                              					
                    Add-ADGroupMember "CN=$group,OU=$group,$OU_DU" -Members $userName
                    New-Item -Path "C:\Shares\Users.HomeFolders\" -Name "$userName" -ItemType "directory"
                    New-SmbShare -Name "$userName.HomeFolder" -Path C:\Shares\Users.HomeFolders\$userName -FullAccess "$userName", "Administrators"
    
                    #-------Очистка всех правил доступа----
    
                    $acl = Get-Acl "C:\Shares\Users.HomeFolders\$userName"
                    $acl.Access | %{$acl.RemoveAccessRule($_)}
                    $acl.SetAccessRuleProtection($True, $False)
                    $acl | Set-Acl C:\Shares\Users.HomeFolders\$userName

                    #------------------------------------------------------------------------

                    $acl = Get-Acl "C:\Shares\Users.HomeFolders\$userName"
                    $acl_rules = New-Object System.Security.AccessControl.FileSystemAccessRule ("$userName", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
                    $acl.SetAccessRule($acl_rules)
                    $acl | Set-Acl C:\Shares\Users.HomeFolders\$userName

                    $acl_rules = New-Object System.Security.AccessControl.FileSystemAccessRule ("Administrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
                    $acl.SetAccessRule($acl_rules)
                    $acl | Set-Acl C:\Shares\Users.HomeFolders\$userName

                    Set-ADUser -Identity $userName -Enabled $true -PasswordNotRequired $true 
                    Set-ADUser -Identity $userName -HomeDirectory "\\$ipS\$userName.HomeFolder" -HomeDrive "U:" 
                    New-FsrmQuota -Path C:\Shares\Users.HomeFolders\$userName -Size 1GB
                    New-FsrmFileScreen -Path C:\Shares\Users.HomeFolders\$userName -Template "block" -Active
                    Get-ADUser $userName 
                }
            }
        }
        cls
    }
    elseif ($sSettings -eq "7")
    {
        $fwFlag = 1
        while ($fwFlag)
        {
            echo "-----{Firewall}-----"
            echo ""

            $content = netsh advfirewall show all state | Select-Object -First 4 | Select-Object -Last 1
            $checkFirewall = $content.Trim("State                               ")

            echo "Select a setting"
            echo ""
            echo "(0) Back to main menu: "
            echo ""
            echo "(1) Firewall enable/disable (State: $checkFirewall)"
            echo "(2) Search Firewall rule"
            echo "(3) Create new Firewall rule"
            echo "(4) Disable/Enable Firewall rule"
            echo "(5) Remove Firewall rule"

            echo ""
            Write-Host "Select: " -NoNewLine
            $sFirewall = Read-Host
        
            if ($sFirewall -eq "1")
            {
                $content = netsh advfirewall show all state | Select-Object -First 4 | Select-Object -Last 1
                $checkFirewall = $content.Trim("State                               ")
                if ($checkFirewall -eq "ON")
                {
                    Set-NetFirewallProfile -All -Enabled False
                    echo "Все профиля Брандмауэра успешно отключёны!"
                    echo ""
                    Write-Host "Press {Enter} to exit: " -NoNewline
                    $111 = Read-Host
                    cls
                } 
                elseif ($checkFirewall -eq "OFF")
                {
                    Set-NetFirewallProfile -All -Enabled True
                    echo "Все профиля Брандмауэра успешно Включены!"
                    echo ""
                    Write-Host "Press {Enter} to exit: " -NoNewline
                    $111 = Read-Host
                    cls
                }
                
            }
            elseif ($sFirewall -eq "2")
            {
                Write-Host "Enter NAME for search Firewall-Rule (Blank for cancel): " -NoNewLine
                $fw_searchRule_dname = Read-Host
                if ($fw_searchRule_dname -eq "")
                {
                    cls
                    continue
                }

                Get-NetFirewallRule -DisplayName *$fw_searchRule_dname*
            }
            elseif ($sFirewall -eq "3")
            {
                Write-Host "Enter the new name FW-Rule (Blank for cancel): " -NoNewLine
                $fw_newRule_dname = Read-Host

                if ($fw_newRule_dname -eq "")
                {
                    cls
                    continue
                }

                Write-Host "Enter the Direction (Outbound/Inbound): " -NoNewLine
                $fw_direction = Read-Host

                Write-Host "Enter the LocalPort: " -NoNewLine
                $fw_port = Read-Host

                Write-Host "Enter the protocol (TCP/UDP): " -NoNewLine
                $fw_protocol = Read-Host

                Write-Host "Enter the Action (Block/Allow): " -NoNewLine
                $fw_action = Read-Host

                New-NetFirewallRule -DisplayName $fw_newRule_dname -Direction $fw_direction -LocalPort 80 -Protocol $fw_protocol -Action $fw_action # для брандмауэра

            }  
            elseif ($sFirewall -eq "4")
            {
                Write-Host "Enter full name for Disable rule (Blank for cancel): " -NoNewLine
                # !!! Доработать Disable/Enable Rule !!!
                $fwDisableRule = Read-Host
                if ($fwDisableRule -eq "")
                {
                    cls
                    continue
                }
                

                Disable-NetFirewallRule –Name *$fwDisableRule*
            }
            elseif ($sFirewall -eq "5")
            {
                Write-Host "Enter full name for Remove rule (Blank for cancel): " -NoNewLine
                $fwRemoveRule = Read-Host
                if ($fwRemoveRule -eq "")
                {
                    cls
                    continue
                }
                Remove-NetFirewallRule -Name *$fwRemoveRule*
            }
            elseif ($sFirewall -eq "0")
            {
                $fwFlag = 0
                cls
            } 
        }
    }
    elseif ($sSettings -eq "8")
    {
        echo "-----{Install Web-Server}-----"
        echo ""

        Write-Host "Enter a Site Name (Blank for cancel): " -NoNewLine
        $siteName = Read-Host
        
        

        if ($siteName -ne "")
        {
            Write-Host "Enter a LocalPort (Two sites cannot exist on the same port): " -NoNewLine
            $sitePort = Read-Host
            Write-Host "Enter a DNS ZoneName (ex. fbi.local): " -NoNewLine
            $domain = Read-Host
            Write-Host "Enter a Web-Server IP-Address (ex. 192.168.1.1): " -NoNewLine
            $ipSrv_Web = Read-Host

            Install-WindowsFeature -name Web-Server -IncludeManagementTools
            Set-Service -name W3SVC -startupType Automatic
            
            # Get-Command -Module IISAdministration - команды модуля управления IIS WebSRV
            
            New-Item -ItemType Directory -Name $siteName -Path C:\MyWebsites\
            New-Item -ItemType File -Name index.html -Path C:\MyWebsites\$siteName\
            Set-content C:\MyWebsites\$siteName\index.html -value " `
            <!DOCTYPE html>
            <html>
                <head>
                     <title>IIS SIte by Havlok & HOW</title>
                </head>
                <body>
                    <h1>IIS SIte by Havlok & HOW</h1>
                    <p>Thank you for reading this site with PowerShell!</p>

                    <p>This page was created using the newer IISAdministration PowerShell module.</p>
                    <h2>First Steps</h2>
                    <p>Keep calm and learn PowerShell.</p>
                </body>
            </html>
            "
            echo "Removing Default Web Site"
            remove-website -name "Default Web Site"

            Add-DnsServerResourceRecordA -Name $siteName -IPv4Address $ipSrv_Web -ZoneName $domain -TimeToLive 01:00:00

            New-IISSite -Name $siteName -PhysicalPath C:\MyWebsites\$siteName\ -BindingInformation "*:$($sitePort):"
            
            New-WebBinding -Name $siteName -IP "*" -Port 443 -Protocol https
            $newCert = New-SelfSignedCertificate -DnsName "$siteName.$domain" -CertStoreLocation cert:\LocalMachine\My
            $binding = Get-WebBinding -Name $siteName -Protocol "https"
            $binding.AddSslCertificate($newCert.GetCertHashString(), "my")

            Write-Host "Your IIS-WebSites: "
            Get-IISSite
            Write-Host "-----{!!!Warning!!!}-----" -BackGroundColor red
            Write-Host "If the status is: stopped, then it is possible that you have two sites on the same port!" -BackGroundColor White -ForegroundColor black
            Write-Host " "
            # Stop-IISSite -Name $siteName - остановка Web-Сайта
            Write-Host "Press {Enter} to exit: " -NoNewline
            $111 = Read-Host
        }
        cls
    }

    elseif ($sSettings -eq "9")
    {
        echo "-----{Configuration GPO}-----"
        echo ""

        Write-Host "The GPO will be configured automatically. Are you sure you want to continue? (Y\N): " -NoNewLine
        $GPO_Confirm = Read-Host
        

        if ($GPO_Confirm.ToLower() -eq "y")
        {
            Write-Host "Enter domain name (ex. fbi.local): " -NoNewLine
            $dName = Read-Host 

            $addresses = $dName.split(".")
            $D1 = $addresses[0]
            $D2 = $addresses[1]
            $domain = "DC=$D1,DC=$D2"
            $OU_DU = "OU=Domain.Users,$domain"
            Install-WindowsFeature GPMC -IncludeManagementTools
            # Get-Command –Module GroupPolicy - команды модуля управления GPO
            New-GPO -Name mmkTestGPO -Comment "Testing GPO PowerShell"
            Get-GPO mmkTestGPO | New-GPLink -Target $OU_DU
            Set-GPRegistryValue -Name mmkTestGPO -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -ValueName "EnableFirstLogonAnimation" -Type DWORD -Value 0
            Set-GPRegistryValue -Name mmkTestGPO -key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -ValueName "DisableRegistryTools" -Type DWORD -Value 1 
            Set-GPRegistryValue -Name mmkTestGPO -key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -ValueName "NoControlPanel" -Type DWORD -Value 1
            Set-GPRegistryValue -Name mmkTestGPO -key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -ValueName "NoDrives" -Type DWORD -Value 4 
            Set-GPRegistryValue -Name mmkTestGPO -key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -ValueName "NoViewOnDrive" -Type DWORD -Value 4 
            Set-GPRegistryValue -Name mmkTestGPO -key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -ValueName "NoControlPanel" -Type DWORD -Value 1
            Set-GPRegistryValue -Name mmkTestGPO -key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop\" -ValueName "NoChangingWallPaper" -Type DWORD -Value 1 
            Set-GPRegistryValue -Name mmkTestGPO -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\" -ValueName "HibernateEnabled" -Type DWORD -Value 0 
            Set-GPRegistryValue -Name mmkTestGPO -key "HKEY_LOCAL_MACHINE\SOFTNARE\PoliciesMicrosoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0edS46ab\" -ValueName "ACSettingIndex" -Type DWORD -Value 0 
            Get-GPO mmkTestGPO | Set-GPPermissions -Replace -PermissionLevel GpoRead -TargetName 'Authenticated Users' -TargetType group | Set-GPPermissions -PermissionLevel gpoapply -TargetName 'Sellers' -TargetType group
            
            Write-Host "Successful configuration GPO!" -BackGroundColor Green
            Write-Host "Press {Enter} to exit: " -NoNewline
            $111 = Read-Host
        }

        elseif ($GPO_Confirm.ToLower() -eq "n") 
        {
            Write-Host "Return to the main menu" -NoNewline
            sleep -Milliseconds 500
            Write-Host "." -NoNewline
            sleep -Milliseconds 500
            Write-Host "." -NoNewline
            sleep -Milliseconds 500
            Write-Host "." -NoNewline
        }
        

        else
        {
            Write-Host "Error: Please enter only Y/N" -BackGroundColor red
            Write-Host "Press {Enter} to exit: " -NoNewline
            $111 = Read-Host
        }
        cls
    }
}
