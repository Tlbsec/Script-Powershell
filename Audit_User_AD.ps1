#***************************************
# Script audit compte Active Directory 
# By Thomas LE BRUN
#***************************************
# Le serveur sur lequel ce script est exécuté doit être membre du domaine 
# Le server  sur lequel ce script est exécuté doit pouvoir contacter les serveurs désirés sur le port DCE-RPC (UDP et TCP 135)
# Le compte utilisé pour exécuter le script doit etre admin des serveurs contactés
#***************************************
# Si votre domaine est en anglais vous devez changer les ligne 70 et 71 du script
#***************************************

# Chargement du module Active directory 

Import-Module ActiveDirectory

# Création de la fonction Get-localadmins qui permet d'obtenir le contenue du groupe local adminsitrator d'un serveur

function get-localadmins {  
    param ($strcomputer)  
  
    $admins = Gwmi win32_groupuser –computer $strcomputer   
    $admins = $admins |? {$_.groupcomponent –like '*"Administrators"' -or $_.groupcomponent –like '*"Administrateurs"'}  
  
    $admins |% {  
        $_.partcomponent –match “.+Domain\=(.+)\,Name\=(.+)$” > $nul  
        $matches[1].trim('"') + “\” + $matches[2].trim('"')  
        }  
    }

# Création de la fonction Get-localrdpusers qui permet d'obtenir le contenue du groupe local Remote Desktop user d'un serveur

    function get-localrdpusers {  
    param ($strcomputer)  
  
    $rdpusers = Gwmi win32_groupuser –computer $strcomputer   
    $rdpusers = $rdpusers |? {$_.groupcomponent –like '*"Remote Desktop Users"' -or $_.groupcomponent –like '*"Utilisateurs du Bureau à distance"'}  
  
    $rdpusers |% {  
        $_.partcomponent –match “.+Domain\=(.+)\,Name\=(.+)$” > $nul  
        $matches[1].trim('"') + “\” + $matches[2].trim('"')  
        }  
    }

# Création de la fonction Get-localusers qui permet d'obtenir le contenue du groupe local Users d'un serveur

    function get-localusers {  
    param ($strcomputer)  
  
    $users = Gwmi win32_groupuser –computer $strcomputer   
    $users = $users |? {$_.groupcomponent –match '"Users"' -or $_.groupcomponent –match '"Power Users"'-or $_.groupcomponent –match '"Utilisateurs"'-or $_.groupcomponent –match '"Utilisateurs avec pouvoir"'}  
  
    $users |% {  
        $_.partcomponent –match “.+Domain\=(.+)\,Name\=(.+)$” > $nul  
        $matches[1].trim('"') + “\” + $matches[2].trim('"')  
        }  
    }

#Demande à l'utilisateur d'enter un nom de groupe ou d'payuer sur entrer pour traitement automatique avec le groupe Domain Computers

"Press enter to use Domain Computers group

Else type the name of the computer group you want to analyse"

$Content = ""
$Content = Read-Host 

# Si $Content est vide alors traitement automatique avec les ordinateurs du domaine

if ($content -eq "") { 
    $listServer = Get-ADGroupMember -Identity "Ordinateurs du domaine" # Ligne à utiliser pour un domaine en français
    #$listServer = Get-ADGroupMember -Identity "Domain Computers" # Ligne à utiliser pour un domaine en Anglais
    }
# Sinon On cherche le nom du groupe entré par l'utilisateur
Else{
    $listServer = Get-ADGroupMember -Identity $Content
    }

# Localise le chemin d'execution du script et s'y déplace

$varCheminRepertoireScript = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Definition)
cd $varCheminRepertoireScript

# Met en forme la date pour la création du repertoire de travail

$date = Get-Date | select Year, Month, Day, Hour, Minute | foreach {$_ -replace ":", "."}
$date = $date -replace "@{Year=",""  -replace "; Month=","-" -replace "; Day=","-" -replace "; Hour=","-" -replace "; Minute=","H" -replace "}",""

# Cherche le nom du domain

$Domain = Get-ADDomain | select name
$Domain = "$Domain" -replace "@{name=","" -replace "}",""

# Créer les repertoires de travail dans le Dossier d'execution du script ainssi que les fichiers Recap et unreacheable

$opath = "$varCheminRepertoireScript\$date"
$DomainDirectory = "$opath\$Domain"
$LocalDirectory = "$opath\Local"
$recap = "$opath\recap.txt"
$unrecheable = "$opath\unreachable.txt"
$DomainUserDirectory = "$opath\$Domain\UserAccess"


new-item $opath –type directory
new-item $DomainDirectory –type directory
new-item $DomainUserDirectory –type directory
new-item $LocalDirectory –type directory
new-item $recap –type file 
new-item $unrecheable –type file 

# Pour chaque serveur dans la liste

foreach($servers in $listServer){

    # On récupère le nom du serveur dans la variable

    $server = $servers.Name

    # On prévient L'utilisateur du serveur sur lequel on tente de se connecter et on inscrit le nom du serveur dans le fichier recap

    "Connect to $server..."

    ADD-content -path $recap -value "**************************************"
    ADD-content -path $recap -value " "
    ADD-content -path $recap -value "**************************************"
    ADD-content -path $recap -value "        $server"
    ADD-content -path $recap -value "********************"

    # On utilise la fonction get-localadmin pour obtenir la liste des utilisateurs 

    $admins = get-localadmins $Server

    # Si le groupe Admin est vide c'est que Le script n'a pas réussi à contacter le serveur.
    # On ajoute donc le serveur comme étant unreacheable dans le fichier recap et dans le fichier unreacheable

    if ($admins -eq $null){
        ADD-content -path $unrecheable -value "$server"
        ADD-content -path $recap -value "UNREACHABLE"
        }
    # Sinon le script a réussi à contacter le serveur
    Else {

        # On ajoute donc la partit admin au fichié recap

        ADD-content -path $recap -value "        ADMINS"
        ADD-content -path $recap -value "********************"

        # Pour chaque utilisateur dans le groupe administrator local

        foreach($user in $admins){
            
            # On ajoute l'utilisateur au fichier recap

            ADD-content -path $recap -value "$user"

            # Si il s'agit d'un utilisateur local on change le nom du serveur par local pour que le nom de l'utilisateur soit de la forme Local\User

            if ("$user" -notlike $Domain){
                $user = $user -replace "$server","local"
                }
            # La variable $user est de la forme Domain\user ou Local\user 

            $file="$opath\$user.txt"

            # On créer le fichier au nom de l'utilisateur dans le repertoir Domain ou Local grace au contenue de la variable $user
            # La gestion de l'erreur est faite pour éviter de faire prompt des erreurs si le fichier a déja été créé lors de la lecture d'un serveur précédent (exemple : groupe admin du domaine)

            $ErrorActionPreference = "SilentlyContinue"
            new-item $file –type file
            $ErrorActionPreference = "Continue"

            # On ajoute le nom du server  dans le fichier créer ci deussous (ou précédement)

            ADD-content -path $file "Admin : $server"

            }

        # On ajoute donc la partit RDP USERS au fichié recap

        ADD-content -path $recap -value "********************"
        ADD-content -path $recap -value "        RDP USERS"
        ADD-content -path $recap -value "********************"

        # Pour chaque utilisateur dans le groupe Remote Dektop Users 
    
        $rdpusers= get-localrdpusers $server

        foreach($user in $rdpusers){

            # On ajoute l'utilisateur au fichier recap

            ADD-content -path $recap -value "$user"

            # Si il s'agit d'un utilisateur local on change le nom du serveur par local pour que le nom de l'utilisateur soit de la forme Local\User

            if ("$user" -notlike $Domain){
                $user = $user -replace "$server","local"
                }
            # La variable $user est de la forme Domain\user ou Local\user 

            $file="$opath\$user.txt"

            # On créer le fichier au nom de l'utilisateur dans le repertoir Domain ou Local grace au contenue de la variable $user
            # La gestion de l'erreur est faite pour éviter de faire prompt des erreurs si le fichier a déja été créé lors de la lecture d'un serveur précédent (exemple : groupe admin du domaine)

            $ErrorActionPreference = "SilentlyContinue"
            new-item $file –type file
            $ErrorActionPreference = "Continue"

            # On ajoute le nom du server  dans le fichier créer ci deussous (ou précédement)

            ADD-content -path $file "RDP Users : $server"

            }

        # On ajoute donc la partit RDP USERS au fichié recap

        ADD-content -path $recap -value "********************"
        ADD-content -path $recap -value "        USERS"
        ADD-content -path $recap -value "********************"
    
        # Pour chaque utilisateur dans le groupe Users 

        $users= get-localusers $server

        foreach($user in $users){

            # On ajoute l'utilisateur au fichier recap

            ADD-content -path $recap -value "$user"

            # Si il s'agit d'un utilisateur local on change le nom du serveur par local pour que le nom de l'utilisateur soit de la forme Local\User

            if ("$user" -notlike $Domain){
                $user = $user -replace "$server","local"
                }
            # La variable $user est de la forme Domain\user ou Local\user 

            $file="$opath\$user.txt"

            # On créer le fichier au nom de l'utilisateur dans le repertoir Domain ou Local grace au contenue de la variable $user
            # La gestion de l'erreur est faite pour éviter de faire prompt des erreurs si le fichier a déja été créé lors de la lecture d'un serveur précédent (exemple : groupe admin du domaine)

            $ErrorActionPreference = "SilentlyContinue"
            new-item $file –type file
            $ErrorActionPreference = "Continue"

            # On ajoute le nom du server  dans le fichier créer ci deussous (ou précédement)

            ADD-content -path $file "Users : $server"

            }
        }
    }

#**********************************************************
#Ajout des membres des groupes du Domaine
#**********************************************************

# On obtient le contenu des groupe fichier créer 

$directory = Get-ChildItem $DomainDirectory| Select-Object Name

# Pour Chaque fichié présent dans le repertoire

foreach ($file IN $directory){

    # On met en forme le nom du fichier
    
    $file = "$file" -replace "@{Name=", "" -replace ".txt}",""

    # On initialise la variable $users avec les membres du groupe dont le nom correspond au nom du fichier
    # L'initialisation et la gestion des erreurs se fait pour éviter les erreur si le fichier correspond à un utilisateur et non un groupe

    $users = ""
    $ErrorActionPreference = "SilentlyContinue"
    $users = get-adgroupmember $file -recursive 
    $ErrorActionPreference = "Continue"

    # Si $users est vide c'est que le fichier étudier correspond à un utilisateur ou a un groupe est vide

    if ($users -eq "") {
        
        $user = Get-ADUser "$file" |select name
        $Enabled = Get-ADUser "$file" |select enabled
        $Enabled = "$Enabled" 
        $user = "$user"
        $User = "$user" -replace "@{name=","" -replace '}',''

        if ( $enabled.contains("@{enabled=False}")) {

             $User = "0-Disable - $user "
             

            }

                                    
        $ErrorActionPreference = "SilentlyContinue"
        new-item "$DomainUserDirectory\$user.txt" –type file
        $ErrorActionPreference = "Continue"

        Add-Content "$DomainUserDirectory\$user.txt" ""
        Add-Content "$DomainUserDirectory\$user.txt" "**************************************"
        Add-Content "$DomainUserDirectory\$user.txt" "        User Direct Acces"
        Add-Content "$DomainUserDirectory\$user.txt" "********************"
        Add-Content "$DomainUserDirectory\$user.txt" ""  
         
        $contents = Get-Content "$DomainDirectory\$file.txt"
        #$contents
        #pause

        foreach ($content IN $contents){
            #$content

            Add-Content "$DomainUserDirectory\$user.txt" "$content"
            #pause
            }
        
        }
    # Sinon c'est que le fichier étudier correspond à un groupe
    else{
        

        foreach ($User IN $users){


            $enabled = Get-ADUser $user | select enabled 
            $Enabled = "$Enabled" 
            $User =  Get-ADUser $user | select name 
            $user = "$user"
            $User = $user -replace "@{name=","" -replace '}',''
            
            if ( $enabled.contains("@{enabled=False}")){

             $User = "0-Disable - $user"
                          

            }

            
            
            $ErrorActionPreference = "SilentlyContinue"
            new-item "$DomainUserDirectory\$User.txt" –type file
            $ErrorActionPreference = "Continue"

            Add-Content "$DomainUserDirectory\$user.txt" ""
            Add-Content "$DomainUserDirectory\$user.txt" "**************************************"
            Add-Content "$DomainUserDirectory\$user.txt" "        Group : $file"
            Add-Content "$DomainUserDirectory\$user.txt" "********************"
            Add-Content "$DomainUserDirectory\$user.txt" "" 
             
            $contents = Get-Content "$DomainDirectory\$file.txt"
            #$contents
            #pause

            foreach ($content IN $contents){

                Add-Content "$DomainUserDirectory\$user.txt" "$content"
            }
            }

        # On ajoute donc les lignes correspondant au membre du groupe

        ADD-content -path "$DomainDirectory\$file.txt" " "
        ADD-content -path "$DomainDirectory\$file.txt" "******************************************"
        ADD-content -path "$DomainDirectory\$file.txt" "              GROUP MEMBER"
        ADD-content -path "$DomainDirectory\$file.txt" "******************************************"
        ADD-content -path "$DomainDirectory\$file.txt" " "
 
        # Pour chaque utilisateur on ajoute son nom dans la liste des membres du groupe
        
        foreach ($User IN $users){
            $enabled = Get-ADUser $user | select enabled
            $Enabled = "$Enabled"  
            $User = Get-ADUser $user | select name 
            $user = "$user"
            if (  $enabled.contains("@{enabled=False}")) {
                $User = "$user | *account disable*"
            }

            $User = "$user" -replace "@{name=","" -replace '}',''
            ADD-content -path "$DomainDirectory\$file.txt" "$user"


            }
        }
    }
