
#IP options
$IPv6Enabled                = $false
#IP stuff
$publicAdapter              = "Ethernet0"
$privateAdapter             = "Ethernet1"
$thisServerIPv4             = "172.16.19.254"
$thisServerIPv4PrefixLength = "22"
$dnsAddress                 = $thisServerIPv4
$thisServerIPv6             = ""

#Names of stuff
$thisServerName             = "DC1"
$DomainName                 = "eep-sindri.local"
$company                    = 'EEP'
$HomeDriveRoot              = "ServerUsers"
$everyoneGroupName          = "everyEmployee"

#Path related stuff
$CSVpath                    = 'C:\csv.csv'
$HomeDrive                  = 'H:'

#Security
$basePassword               = "" #Leave empty to be prompted for a base password, set a password if you do not wish to be prompted

#CSV options
$isSupervisorCSVEnabled     = $false
#CSV names
$NameCSV                    = "Nafn"
$idCSV                      = "ID"
$DescriptionCSV             = "Starfsheiti"
$StateCSV                   = "Sveitarfelag"
$FirstnameCSV               = "Fornafn"
$LastnameCSV                = "Eftirnafn"
$HomePhoneCSV               = "Heimasimi"
$OfficePhoneCSV             = "Vinnusimi"
$MobilePhoneCSV             = "Farsimi"
$UsernameCSV                = "Notendanafn"
$DepartmentCSV              = "Deild"
$isSupervisorCSV            = "Stada"

#Here comes the script
if(!(Get-ItemProperty -Path HKCU:\Environment -Name CURRENTINCREMENT))
{
    $currentIncrement = "1"
}
else
{
    $currentIncrement = $env:CURRENTINCREMENT
}

if((Get-ItemProperty -Path HKCU:\Environment -Name SCRIPTENABLED))
{
    $ScriptEnabled = $env:SCRIPTENABLED
}
else
{
    Set-ItemProperty -Path HKCU:\Environment -Name SCRIPTENABLED -Value "1"
    $ScriptEnabled = "1"
}

if(($currentIncrement -eq "1") -and ($ScriptEnabled -eq "1"))#Part1
{
    Set-ItemProperty -Path HKCU:\Environment -Name CURRENTINCREMENT -Value "2"
    Rename-NetAdapter -Name $publicAdapter -NewName "Public"
    Rename-NetAdapter -Name $privateAdapter -NewName "Private"
    $privateAdapterIndex = (Get-NetAdapter -Name "Private").ifIndex
    $publicAdapterIndex = (Get-NetAdapter -Name "Public").ifIndex
    Rename-Computer -NewName $thisServerName
    New-NetIPAddress -InterfaceIndex $privateAdapterIndex -IPAddress $thisServerIPv4 -PrefixLength $thisServerIPv4PrefixLength
    if($IPv6Enabled){New-NetIPAddress -InterfaceIndex $privateAdapterIndex -IPAddress $thisServerIPv6}
    Set-DnsClientServerAddress -InterfaceIndex $privateAdapterIndex -ServerAddresses $dnsAddress
    Install-WindowsFeature -Name "AD-Domain-Services" -IncludeManagementTools
    Restart-Computer
}
elseif(($currentIncrement -eq "2") -and ($ScriptEnabled -eq "1"))#Part2
{
    Set-ItemProperty -Path HKCU:\Environment -Name CURRENTINCREMENT -Value "3"
    Install-ADDSForest -DomainName $DomainName -InstallDns
}
elseif(($currentIncrement -eq "3") -and ($ScriptEnabled -eq "1"))#Part3
{
    Set-ItemProperty -Path HKCU:\Environment -Name CURRENTINCREMENT -Value "4"
    if($basePassword){$thepassword = $basePassword}else{$thepassword = Read-Host -Prompt "Type Base Password here"}
    Import-Module activedirectory
    $ADUsers                   = Import-csv $CSVpath -Encoding UTF8
    $domain                    = ((Get-ADDomain).DNSRoot)
    $DC                        = ((Get-ADDomain).DistinguishedName)
    $domain2                   = 'OU='+$company+','+$DC
    $preDC                     = 'OU='
    $domain3                   = ','+$domain2
    $UserRoot                  = '\\DC1\' + $HomeDriveRoot + '\'
    $FolderRoot                = 'C:\' + $HomeDriveRoot + '\'
    $groupArray                = @()
    foreach ($UserGroup in $ADUsers){
        $tempGroup = $UserGroup.$DepartmentCSV
        if(!($groupArray -contains $tempGroup)){
            $groupArray += $tempGroup
        }
    }
    $tempString = ""
    for($i=0;$i -lt $groupArray.Length; $i++){
        if($i -eq ($groupArray.Length - 1)){
            $tempString += $groupArray[$i]
        }
        else
        {
            $tempString += $groupArray[$i] + ';'
        }
    }
    if(!(Get-ItemProperty -Path HKCU:\Environment -Name GROUPS)){
        New-ItemProperty -Path HKCU:\Environment -Name GROUPS -PropertyType ExpandString -Value $tempString
    }
    else{
        Set-ItemProperty -Path HKCU:\Environment -Name GROUPS -Value $tempString
    }


    #OU creation
    if (Get-ADOrganizationalUnit -Filter {Name -eq $company})
    {
        Write-Warning "An OU with the name $company already exist in Active Directory."
    }
    else
    {
        New-ADOrganizationalUnit -Name $company -Path $DC -ProtectedFromAccidentalDeletion $false
    }

    if (Get-ADGroup -Filter {SamAccountName -eq $everyoneGroupName})
    {
        Write-Warning "A group with the name $everyoneGroupName already exist in Active Directory."
    }
    else
    {
        New-ADGroup -Name $everyoneGroupName -SamAccountName $everyoneGroupName -GroupCategory Security -GroupScope Universal -DisplayName $everyoneGroupName -Path $domain2
    }

    foreach ($group in $groupArray)
    {
        $domainGroup = $preDC+$group+$domain3
        $CN1          = 'CN='+$everyoneGroupName+$domain3

        if (Get-ADOrganizationalUnit -Filter {Name -eq $group})
	    {
		     Write-Warning "An OU with the name $group already exist in Active Directory."
	    }
        else
        {
            New-ADOrganizationalUnit -Name $group -Path $domain2 -ProtectedFromAccidentalDeletion $false
        }

        #Group creation
        if (Get-ADGroup -Filter {SamAccountName -eq $group})
	    {
		     Write-Warning "A group with the name $group already exist in Active Directory."
	    }
        else
        {
            New-ADGroup -Name $group -SamAccountName $group -GroupCategory Security -GroupScope Universal -DisplayName $group -Path $domainGroup
            Add-ADGroupMember -Identity $CN1 -Members $group
        }
    }

    $supervisor = ""
    #User creation
    foreach ($User in $ADUsers)
    {
        $fullname      = $User.$NameCSV
        $ID            = $User.$idCSV
        $Description   = $User.$DescriptionCSV
        $State         = $User.$StateCSV
        $Username 	   = $User.$UsernameCSV
        $userprinciple = $Username + "@" + $domain
	    $Firstname     = $User.$FirstnameCSV
	    $Lastname 	   = $User.$LastnameCSV
        $email         = $userprinciple
        $HomePhone     = $User.$HomePhoneCSV
        $OfficePhone   = $User.$OfficePhoneCSV
        $MobilePhone   = $User.$MobilePhoneCSV
        $department    = $User.$DepartmentCSV
        $OU            = $preDC+$department+$domain3
        $Password      = $thepassword
        $CN2           = 'CN='+$department+','+$OU

        if($isSupervisorCSVEnabled){
            $isSupervisor  = $User.$isSupervisorCSV
        }

	    if (Get-ADUser -Filter {SamAccountName -eq $Username})
	    {
		     Write-Warning "A user account with username $Username already exist in Active Directory."
	    }
        elseif ($isSupervisor -and $isSupervisorCSVEnabled)
        {
            New-ADUser -SamAccountName $Username -UserPrincipalName $userprinciple -Name $fullname -GivenName $Firstname -Surname $Lastname -Enabled $True -DisplayName $fullname -Path $OU -EmailAddress $email -Department $department -AccountPassword (convertto-securestring $Password -AsPlainText -Force) -ChangePasswordAtLogon $True -EmployeeID $ID -Description $Description -State $State -HomePhone $HomePhone -OfficePhone $OfficePhone -MobilePhone $MobilePhone
            $supervisor = $Username
        }
	    elseif ($isSupervisorCSVEnabled)
	    {
            New-ADUser -SamAccountName $Username -UserPrincipalName $userprinciple -Name $fullname -GivenName $Firstname -Surname $Lastname -Enabled $True -DisplayName $fullname -Path $OU -EmailAddress $email -Department $department -AccountPassword (convertto-securestring $Password -AsPlainText -Force) -ChangePasswordAtLogon $True -EmployeeID $ID -Description $Description -State $State -HomePhone $HomePhone -OfficePhone $OfficePhone -MobilePhone $MobilePhone -Manager $supervisor
	    }
        else
        {
            New-ADUser -SamAccountName $Username -UserPrincipalName $userprinciple -Name $fullname -GivenName $Firstname -Surname $Lastname -Enabled $True -DisplayName $fullname -Path $OU -EmailAddress $email -Department $department -AccountPassword (convertto-securestring $Password -AsPlainText -Force) -ChangePasswordAtLogon $True -EmployeeID $ID -Description $Description -State $State -HomePhone $HomePhone -OfficePhone $OfficePhone -MobilePhone $MobilePhone
        }
        Add-ADGroupMember -Identity $CN2 -Members $Username

        #adds homefolder to users
        $UserDirectory=$UserRoot+$Username
        $HomeDirectory=$FolderRoot+$Username

        if (Test-Path $HomeDirectory -PathType Container)
        {
            Write-Warning "A directory with the name $HomeDirectory already exist in Active Directory."
        }
        else
        {
            New-Item -path $HomeDirectory -type directory -force
        }
        Set-ADUser -Identity $Username -HomeDrive $HomeDrive -HomeDirectory $UserDirectory

    }
    Restart-Computer
}
elseif(($currentIncrement -eq "4") -and ($ScriptEnabled -eq "1"))#Part4
{
    Set-ItemProperty -Path HKCU:\Environment -Name CURRENTINCREMENT -Value "1"
    Set-ItemProperty -Path HKCU:\Environment -Name SCRIPTENABLED -Value "0"

    

    Restart-Computer
}
elseif($ScriptEnabled -eq "1")
{
    Set-ItemProperty -Path HKCU:\Environment -Name CURRENTINCREMENT -Value "1"
    Restart-Computer
}