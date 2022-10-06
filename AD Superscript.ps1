#Import AD Module
Import-Module ActiveDirectory

while($True){
echo "[0] User Management
[1] Group Management
[2] OU Management
[3] Change Management

Ctrl + C to exit
"

$input = Read-Host -Prompt "Please enter which function you would like to use"
Clear-Host

if($input -eq 0)
{
    $list = "
    [0] Create User (CSV)
    [1] Create User (Prompt)
    [2] Disable Account (CSV)
    [3] Disable Account (Logon Date)
    [4] Disable Account (Prompt)
    [5] Remove User (CSV)
    [6] Remove User (Prompt)
    [7] Enable User (CSV)
    [8] Enable User (Prompt)
    "

    echo $list

    $input = Read-Host -Prompt "Please enter which function you would like to use"

    if($input -eq 0)
    {
        #Notes
        #(thing next to the one) allows you yo continue script on the next line/ NOTE NEEDED AFTER EVERY LINE. WILL NOT WORK IF A SPACE FOLLOWS IT
        #-Name = Full Name (First, Last)
        #-GivenName = First Name
        #-Surname = Last Name
        #-UserPrincipalName = User Name
        #-AccountPassword (ConvertTo-SecureString [string] -AsPlainText -Force) = Password
        #-Path = Path (In AD with view Advanced features on -> right click on the folder -> properties -> attribute editor -> distinguished name)
        #-ChangePasswordAtLogon 1 = Make new user change password at log on. (0 = False, 1 = True)
        #-Enabled 1 = Determines if the account is disabled by default

    

        #prompt user for CSV file path
        $filepath = Read-Host -Prompt "Please enter the path to your CSV file"

        #import the file into a variable
        $users = Import-Csv $filepath

        ForEach ($user in $users)
        {
            #Use the column name after $user
            $firstname = $user."first_name"
            $lastname = $user."last_name"
            $department = $user."Department"
            $jobtitle = $user."jobtitle"
            $username = $user."username"
            $password = $user."password"

            #Create a new department organizational unit if one does not exist
            $departmentCheck = [bool](Get-ADOrganizationalUnit -Filter "Name -eq '$department'")
            if($departmentCheck -eq $false)
            {
               echo "Creating department OU: $department"
               New-ADOrganizationalUnit -Name $department -Path "OU=Test,DC=test,DC=local" 
            }

            #NOTE: If it's continually trying to add a new OU but saying that it already exists, check the spacing on the name.
            #Sometimes a space at the end of the name will cause problems, also an extra space may be added to if the OU is three words long

            #Create a new job title organizational unit if one does not exists
            $titleCheck = [bool](Get-ADOrganizationalUnit -Filter  "DistinguishedName -eq 'OU=$jobtitle,OU=$department,OU=Test,DC=test,DC=local'")
            if($titleCheck -eq $false)
            {
               echo "Creating sub OU: $jobtitle"
               New-ADOrganizationalUnit -Name $jobtitle -Path (Get-ADOrganizationalUnit -Filter "Name -eq '$department'").DistinguishedName 
            }
         
            #Create a new job title organizational unit if one does not exists
            $groupCheck = [bool](Get-ADGroup -Filter  "Name -eq '$jobtitle'")
            if($groupCheck -eq $false)
            {
               #try
               #{
                   New-ADGroup -Name $department -GroupScope Global -GroupCategory Security -ManagedBy (Get-ADGroup "CN=Domain Admins,CN=Users,DC=test,DC=local")
               #}
               #catch
               #{
            
               #}
               echo "Creating sub group: $jobtitle"
               New-ADGroup -Name $jobtitle -GroupScope Global -GroupCategory Security 
            }

            #Gets proper path for New-ADUser
            $path = (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq 'OU=$jobtitle,OU=$department,OU=Test,DC=test,DC=local'").DistinguishedName

            #Create AD user
            New-ADUser `
                -Name "$firstname $lastname" `
                -GivenName $firstname `
                -Surname $lastname `
                -UserPrincipalName $username `
                -Department $department `
                -Title $jobtitle `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                -Path $path `
                -ChangePasswordAtLogon 1 `
                -Enabled 1 

            Add-ADGroupMember -Identity (Get-ADGroup -Filter "Name -eq '$jobtitle'").DistinguishedName -Members (Get-ADUser -Filter "Name -eq '$firstname $lastname'")
            Add-ADGroupMember -Identity (Get-ADGroup -Filter "Name -eq '$department'").DistinguishedName -Members (Get-ADGroup -Filter "Name -eq '$jobtitle'")

            echo "$firstname $lastname created"
        }
    }
    if($input -eq 1)
    {
        #Notes
        #(thing next to the one) allows you yo continue script on the next line/ NOTE NEEDED AFTER EVERY LINE. WILL NOT WORK IF A SPACE FOLLOWS IT
        #-Name = Full Name (First, Last)
        #-GivenName = First Name
        #-Surname = Last Name
        #-UserPrincipalName = User Name
        #-AccountPassword (ConvertTo-SecureString [string] -AsPlainText -Force) = Password
        #-Path = Path (In AD with view Advanced features on -> right click on the folder -> properties -> attribute editor -> distinguished name)
        #-ChangePasswordAtLogon 1 = Make new user change password at log on. (0 = False, 1 = True)
        #-Enabled 1 = Determines if the account is disabled by default

        #Grab Variables from User
        $firstname = Read-Host -Prompt "Please enter your first name"
        $lastname = Read-Host -Prompt "Please enter your last name"
        $password = Read-Host -Prompt "Password"

        #Create AD user
        New-ADUser `
            -Name "$firstname $lastname" `
            -GivenName $firstname `
            -Surname $lastname `
            -UserPrincipalName "$firstname.$lastname" `
            -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
            -Path "OU=Tests,DC=test,DC=local" `
            -ChangePasswordAtLogon 1 `
            -Enabled 1 
    }
    if($input -eq 2)
    {
        #prompt user for CSV file path
        $filepath =Read-Host -Prompt "Please enter the path to your CSV file"

        #import the file into a variable
        $users = Import-Csv $filepath

        ForEach ($user in $users)
        {
            $firstname = $user."first_name" 
            $lastname = $user."last_name"
            $name = "$firstname $lastname"

            #Grabs the Distinguished Name that Disable-ADAccount needs to work 
            $identity = (Get-ADUser -Filter "Name -eq '$name'").DistinguishedName

            #Disables account
            Disable-ADAccount -Identity $identity
        
            #Prints output message
            echo "Accounts disabled" 
        }
    }

    if($input -eq 3)
    {
        $days = Read-Host -Prompt "How many days since last login"
    
        #Gets the previous date
        $lastdate= (Get-Date).AddDays(6) #(Get-Date).AddDays(-$days)

        #Output statement
        echo "Disabling Accounts who haven't logged in since $lastdate"
    
        #Disable the account if the last logon date was over 6 months ago
        $identity = Get-ADUser -Properties LastLogonDate -Filter {LastLogonDate -lt $lastdate } | Disable-ADAccount

        #print results
        $name = $identity.Name
        echo "$name disabled" 
    }
    if($input -eq 4)
    {
        $name = Read-Host -Prompt "Insert Name"
        $identity = (Get-ADUser -Filter "Name -eq '$name'").DistinguishedName | Disable-ADAccount
        echo "$name disabled" 
    }
    if($input -eq 5)
    {
        #prompt user for CSV file path
        $filepath =Read-Host -Prompt "Please enter the path to your CSV file"

        #import the file into a variable
        $users = Import-Csv $filepath

        ForEach ($user in $users)
        {
            $firstname = $user."first_name" 
            $lastname = $user."last_name"
            $name = "$firstname $lastname"

            #Grabs the Distinguished Name that Remove-ADUser needs to work 
            $identity = (Get-ADUser -Filter "Name -eq '$name'").DistinguishedName

            Remove-ADUser -Identity $identity -Confirm:$false
            echo "$name deleted" 
        }
        echo "All Accounts deleted"
    }
    if($input -eq 6)
    {
        #prompt user for user name
        $firstname =Read-Host -Prompt "Please enter the first name of the user"
        $lastname =Read-Host -Prompt "Please enter the last name of the user"

        #Sets the full name
        $name = "$firstname $lastname"

        #Grabs the Distinguished Name that Remove-ADUser needs to work 
        $identity = (Get-ADUser -Filter "Name -eq '$name'").DistinguishedName

        Remove-ADUser -Identity $identity -Confirm:$false
        echo "$name deleted" 
    }
    if($input -eq 7)
    {
        #prompt user for CSV file path
        $filepath =Read-Host -Prompt "Please enter the path to your CSV file"

        #import the file into a variable
        $users = Import-Csv $filepath

        ForEach ($user in $users)
        {
            $firstname = $user."first_name" 
            $lastname = $user."last_name"
            $name = "$firstname $lastname"

            #Grabs the Distinguished Name that Enable-ADAccount needs to work 
            $identity = (Get-ADUser -Filter "Name -eq '$name'").DistinguishedName

            #Enables Account without confirmation method
            Enable-ADAccount -Identity $identity -Confirm:$false
            echo "$name enabled" 
        }
    }
    if($input -eq 8)
    {
        #prompt user for user name
        $firstname =Read-Host -Prompt "Please enter the first name of the user"
        $lastname =Read-Host -Prompt "Please enter the last name of the user"

        #Sets the full name
        $name = "$firstname $lastname"

        #Grabs the Distinguished Name that Enable-ADAccount needs to work 
        $identity = (Get-ADUser -Filter "Name -eq '$name'").DistinguishedName

        #Enable account
        Enable-ADAccount -Identity $identity -Confirm:$false
        echo "$name enabled" 
    }
    #Await input before clearing the screen
    $wait = Read-Host -Prompt "Press enter to continue"
    Clear-Host
 }
 if($input -eq 2)
 {
    echo "
    [0] Create OU
    [1] Remove OU
    "

    $input = Read-Host -Prompt "Please enter which function you would like to use"
    
    if($input -eq 0)
    {
        $input = Read-Host -Prompt "Please input the OU Name"
        $subFolderCheck = Read-Host -Prompt "Is this a sub OU?(y/n)"

        if($subFolderCheck -eq "y")
        {
            #grabs main OU for the path 
            $mainFolder = Read-Host "Please enter the OU that this sub OU is under"
            
            #check to confirm OU's existance
            try
            {
                $path = (Get-ADOrganizationalUnit -Filter "Name -eq '$mainFolder'").DistinguishedName
                
                #create OU
                New-ADOrganizationalUnit -Name $input -Path $path
            }catch
            {
                echo "An error has occurred."
            }
        }
        
        #creates OU under main domain controller
        else
        {
            New-ADOrganizationalUnit -Name $input
        }
        
    }
    
    if($input -eq 1)
    {
        $input = Read-Host -Prompt "Please input the OU Name to delete"
        $identity = (Get-ADOrganizationalUnit -Filter "Name -eq '$input'").DistinguishedName
    
        #prevents Accidental Deletion popup
        Set-ADOrganizationalUnit -Identity $identity -ProtectedFromAccidentalDeletion 0
    
        #removes OU
        Remove-ADOrganizationalUnit -Identity $identity -Recursive -Confirm:$false
        echo "Removed $input"
    }
    #Await input before clearing the screen
    $wait = Read-Host -Prompt "Press enter to continue"
    Clear-Host
}
if($input -eq 3)
{
    echo "[0] Check additions"

    $input = Read-Host -Prompt "Please enter which function you would like to use"

    if($input -eq 0)
    {
        $missingGroupCheck = [bool](Get-ADGroup -Filter "Name -eq 'Unverified Users'")
        if($missingGroupCheck -eq $false)
        {
            echo "Creating department OU: Unverified Users"
            New-ADGroup -Name "Unverified Users" -GroupScope Global -GroupCategory Security
        }
        $CurrentADUsers= Get-ADUser -Filter *
        $LastSaved = Import-Csv "C:\Users\Administrator\Desktop\user_lookup.csv"
        #$PreviousADUsers = Get-AD
        ForEach ($userCheck in $CurrentADUsers)
        {
            if($userCheck.DistinguishedName -inotin $LastSaved.DistinguishedName)
            {
                echo "$userCheck Missing"
                Add-ADGroupMember -Identity (Get-ADGroup -Filter "Name -eq 'Unverified Users'").DistinguishedName -Members $userCheck.name
                $userCheck | Disable-ADAccount
            }
        }
        $date = Get-Date
        $disabledGroup = Get-ADGroupMember -Identity "Unverified Users" | Export-Csv "C:\Users\Administrator\Desktop\Unverified User.csv"
        echo "$disabledGroup"

    }
     #Await input before clearing the screen
    $wait = Read-Host -Prompt "Press enter to continue"
    Clear-Host
    }

}
 

