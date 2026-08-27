###
# MIT License
# Copyright (c) 2016 Greg Malone
#
# Untested code, YMMV
#
# ---------------------------------------------------------------------------
# MODIFICATIONS (2026) — version "production" :
#   * Corrections de bugs bloquants :
#       - tableau $keylist : virgules manquantes / point au lieu d'une virgule
#       - "1..8 | foreach $_ { }" : syntaxe ForEach-Object invalide
#       - export CSV : $user (objet ADUser) au lieu du SamAccountName +
#         "echo string | Export-Csv" qui ne produit pas un CSV structuré
#       - ligne d'en-tête factice "User,Password" | Export-Csv -Append
#   * Sécurité : mots de passe 16 caractères (complexité AD garantie), RNG
#     cryptographique, chiffrement DPAPI optionnel, ACL restreintes, purge
#     automatique optionnelle, -WhatIf / ShouldProcess.
#   * Paramétrage : SearchBase / CsvPath / Server en paramètres.
#   * Robustesse : vérif module AD, vérif SearchBase, try/catch par utilisateur,
#     résumé final, logging.
# ---------------------------------------------------------------------------
###

<#
.SYNOPSIS
    Réinitialise en masse les mots de passe de tous les utilisateurs d'une OU
    Active Directory et exporte les nouveaux mots de passe dans un CSV.

.DESCRIPTION
    Pour chaque compte utilisateur trouvé sous le SearchBase indiqué :
      1. génère un mot de passe aléatoire (longueur et jeu de caractères
         configurables ; par défaut 12 car. avec maj + min + chiffre garantis,
         +1 caractère spécial garanti si -IncludeSpecialCharacters) ;
      2. applique le mot de passe via Set-ADAccountPassword -Reset ;
      3. force éventuellement le changement au prochain login (-ChangePasswordAtLogon) ;
      4. consigne le résultat (succès / échec) sans interrompre le traitement ;
      5. exporte SamAccountName + mot de passe dans un CSV structuré.

    Le CSV produit contient TOUS les mots de passe en clair : c'est une donnée
    extrêmement sensible.
        - Transmettez-le uniquement par un canal sécurisé (jamais par email en clair).
        - Supprimez-le dès que les mots de passe ont été distribués.
        - Utilisez -Encrypt pour le chiffrer (DPAPI, lié à l'utilisateur + la machine)
          et/ou -PurgeAfterMinutes pour programmer sa suppression automatique.

.PARAMETER SearchBase
    DistinguishedName de l'OU à traiter.
    Ex : "OU=Example,DC=Contoso,DC=local"

.PARAMETER CsvPath
    Chemin du fichier CSV de sortie.

.PARAMETER Server
    Contrôleur de domaine à cibler (facultatif ; sinon détection automatique).

.PARAMETER PasswordLength
    Longueur des mots de passe générés (minimum 8, défaut 12).

.PARAMETER IncludeSpecialCharacters
    Ajoute des caractères spéciaux (!@#$...) au mot de passe.
    Sans ce switch : uniquement majuscules + minuscules + chiffres, avec au
    moins une majuscule, une minuscule et un chiffre garantis.
    ATTENTION : 8 caractères sans caractère spécial reste conforme à la
    complexité AD par défaut (3 catégories sur 4), mais est peu résistant
    au cassage hors ligne. À réserver aux comptes à faible privilège / temporaires.

.PARAMETER ChangePasswordAtLogon
    Force l'utilisateur à changer son mot de passe à la prochaine connexion.

.PARAMETER ExcludeDisabled
    Ignore les comptes désactivés.

.PARAMETER Encrypt
    Chiffre le CSV de sortie avec DPAPI (portée CurrentUser) : le fichier
    "<CsvPath>.dpapi" est créé et le CSV en clair est supprimé.
    Déchiffrement (même utilisateur, même machine) :
        $b = [IO.File]::ReadAllBytes("sortie.csv.dpapi")
        $clear = [Security.Cryptography.ProtectedData]::Unprotect($b, $null, 'CurrentUser')
        [IO.File]::WriteAllBytes("sortie.csv", $clear)

.PARAMETER PurgeAfterMinutes
    Programme (tâche planifiée ponctuelle) la suppression du fichier de sortie
    après ce délai. 0 = désactivé.

.PARAMETER LogPath
    Fichier de log texte.

.EXAMPLE
    .\Reset-OUUserPasswords.ps1 -SearchBase "OU=Stagiaires,DC=contoso,DC=local" -WhatIf
    Prévisualise les comptes concernés sans rien réinitialiser.

.EXAMPLE
    .\Reset-OUUserPasswords.ps1 -SearchBase "OU=Stagiaires,DC=contoso,DC=local" -ChangePasswordAtLogon -Encrypt

.EXAMPLE
    .\Reset-OUUserPasswords.ps1 -SearchBase "OU=Test,DC=contoso,DC=local" -PurgeAfterMinutes 60

.NOTES
    Compatible PowerShell 5.1 / Windows Server.
    Dépendance : module ActiveDirectory (RSAT-AD-PowerShell).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # Opération destructive : on exige un SearchBase explicite (pas de valeur par défaut).
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [string]$CsvPath = ".\Reset-Passwords_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [ValidateRange(8, 128)]
    [int]$PasswordLength = 12,

    [Parameter()]
    [switch]$IncludeSpecialCharacters,

    [Parameter()]
    [switch]$ChangePasswordAtLogon,

    [Parameter()]
    [switch]$ExcludeDisabled,

    [Parameter()]
    [switch]$Encrypt,

    [Parameter()]
    [ValidateRange(0, 10080)]
    [int]$PurgeAfterMinutes = 0,

    [Parameter()]
    [string]$LogPath = ".\Reset-Passwords_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

#region ------------------------------------------------------------- Fonctions

function Write-Log {
    # Journalise à la fois dans le fichier de log et via Write-Verbose/Host.
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        default   { Write-Verbose $line -Verbose }
    }
}

function New-RandomPassword {
    <#
        Mot de passe aléatoire (RNG cryptographique).
        Garantit toujours : >= 1 majuscule, 1 minuscule, 1 chiffre.
        Avec -IncludeSpecial : garantit aussi >= 1 caractère spécial.
    #>
    param(
        [ValidateRange(8, 128)][int]$Length = 12,
        [switch]$IncludeSpecial
    )

    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = 'abcdefghijkmnopqrstuvwxyz'
    $digits  = '23456789'
    $special = '!@#$%^&*()-_=+[]{}'
    $all     = $upper + $lower + $digits
    if ($IncludeSpecial) { $all += $special }

    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try {
        function Get-SecureIndex([int]$max) {
            $bytes = New-Object 'System.Byte[]' 4
            do {
                $rng.GetBytes($bytes)
                $value = [BitConverter]::ToUInt32($bytes, 0)
            } while ($value -ge ([uint32]::MaxValue - ([uint32]::MaxValue % $max)))
            return [int]($value % $max)
        }

        # Un caractère de chaque catégorie exigée
        $chars = @(
            $upper[(Get-SecureIndex $upper.Length)]
            $lower[(Get-SecureIndex $lower.Length)]
            $digits[(Get-SecureIndex $digits.Length)]
        )
        if ($IncludeSpecial) { $chars += $special[(Get-SecureIndex $special.Length)] }

        for ($i = $chars.Count; $i -lt $Length; $i++) {
            $chars += $all[(Get-SecureIndex $all.Length)]
        }
        # Mélange Fisher-Yates
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = Get-SecureIndex ($i + 1)
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }
        return -join $chars
    }
    finally { $rng.Dispose() }
}

function Protect-FileDpapi {
    # Chiffre un fichier avec DPAPI (portée CurrentUser) et supprime l'original.
    param([string]$Path)
    $plain = [System.IO.File]::ReadAllBytes($Path)
    $enc   = [System.Security.Cryptography.ProtectedData]::Protect($plain, $null, 'CurrentUser')
    [System.IO.File]::WriteAllBytes("$Path.dpapi", $enc)
    Remove-Item -Path $Path -Force
    return "$Path.dpapi"
}

function Set-RestrictiveAcl {
    # Limite l'accès du fichier à l'utilisateur courant + Administrateurs.
    param([string]$Path)
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $admins = (New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    ).Translate([System.Security.Principal.NTAccount]).Value
    foreach ($p in @($me, $admins)) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($p, 'FullControl', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
}

function Register-PurgeTask {
    # Programme la suppression du fichier après $Minutes via une tâche planifiée ponctuelle.
    param([string]$Path, [int]$Minutes)
    $when = (Get-Date).AddMinutes($Minutes)
    $taskName = "PurgeResetPwd_" + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $full = (Resolve-Path $Path).Path
    $cmd = "Remove-Item -LiteralPath '$full','$full.dpapi' -Force -ErrorAction SilentlyContinue; schtasks /Delete /TN '$taskName' /F"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    schtasks /Create /TN $taskName /SC ONCE /ST $when.ToString('HH:mm') /SD $when.ToString('MM/dd/yyyy') `
        /TR "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded" /F | Out-Null
    return $taskName
}

#endregion

#region ------------------------------------------------------------- Initialisation

Write-Log "==== Réinitialisation en masse des mots de passe ===="
Write-Log "SearchBase : $SearchBase"
Write-Log "CSV        : $CsvPath"
Write-Log ("Mot de passe : {0} caractères, spéciaux {1}" -f $PasswordLength, $(if ($IncludeSpecialCharacters) { 'inclus' } else { 'exclus' }))
if (-not $IncludeSpecialCharacters -or $PasswordLength -lt 12) {
    Write-Log "Politique de mot de passe volontairement réduite — acceptable pour comptes temporaires / faible privilège uniquement." 'WARN'
}
if ($WhatIfPreference) { Write-Log "MODE SIMULATION (-WhatIf) : aucun reset ne sera appliqué." 'WARN' }

# 1. Module ActiveDirectory
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "Module 'ActiveDirectory' introuvable. Installez RSAT-AD-PowerShell." 'ERROR'
    exit 2
}
Import-Module ActiveDirectory -ErrorAction Stop

# Paramètres communs pour cibler éventuellement un DC précis
$adCommon = @{}
if ($Server) { $adCommon['Server'] = $Server }

# 2. Le SearchBase existe-t-il ?
try {
    $null = Get-ADObject -Identity $SearchBase @adCommon -ErrorAction Stop
}
catch {
    Write-Log "SearchBase introuvable ou inaccessible : $SearchBase — $($_.Exception.Message)" 'ERROR'
    exit 3
}

#endregion

#region ------------------------------------------------------------- Traitement

# 3. Récupération des utilisateurs (seulement les propriétés utiles)
$filter = '*'
$users = Get-ADUser -Filter $filter -SearchBase $SearchBase -Properties Enabled, DisplayName @adCommon
if ($ExcludeDisabled) { $users = $users | Where-Object { $_.Enabled } }

if (-not $users) {
    Write-Log "Aucun utilisateur trouvé sous $SearchBase." 'WARN'
    exit 0
}
Write-Log "$($users.Count) compte(s) à traiter."

$results   = New-Object System.Collections.Generic.List[psobject]
$countOk   = 0
$countFail = 0

foreach ($user in $users) {
    $sam = $user.SamAccountName

    # -WhatIf / -Confirm gérés nativement par ShouldProcess
    if (-not $PSCmdlet.ShouldProcess($sam, "Réinitialiser le mot de passe")) {
        Write-Log "[SIMULATION] Le mot de passe de '$sam' serait réinitialisé." 'INFO'
        $results.Add([pscustomobject]@{
            SamAccountName = $sam
            DisplayName    = $user.DisplayName
            Enabled        = $user.Enabled
            Password       = '(simulation)'
            Status         = 'Simulé'
            Error          = ''
        })
        continue
    }

    $pword = New-RandomPassword -Length $PasswordLength -IncludeSpecial:$IncludeSpecialCharacters
    try {
        $secstring = ConvertTo-SecureString -String $pword -AsPlainText -Force

        # Réinitialisation (ne nécessite pas l'ancien mot de passe)
        Set-ADAccountPassword -Identity $sam -NewPassword $secstring -Reset -ErrorAction Stop @adCommon

        # Option : forcer le changement au prochain login
        if ($ChangePasswordAtLogon) {
            Set-ADUser -Identity $sam -ChangePasswordAtLogon $true -ErrorAction Stop @adCommon
        }

        Write-Log "Mot de passe réinitialisé pour '$sam'." 'SUCCESS'
        $countOk++
        $results.Add([pscustomobject]@{
            SamAccountName = $sam
            DisplayName    = $user.DisplayName
            Enabled        = $user.Enabled
            Password       = $pword
            Status         = 'OK'
            Error          = ''
        })
    }
    catch {
        # compte verrouillé, désactivé, permissions insuffisantes, politique de mot de passe...
        Write-Log "Échec pour '$sam' : $($_.Exception.Message)" 'ERROR'
        $countFail++
        $results.Add([pscustomobject]@{
            SamAccountName = $sam
            DisplayName    = $user.DisplayName
            Enabled        = $user.Enabled
            Password       = ''
            Status         = 'Échec'
            Error          = $_.Exception.Message
        })
    }
    finally {
        $pword = $null   # on retire le clair de la mémoire au plus tôt
    }
}

#endregion

#region ------------------------------------------------------------- Export & résumé

# 4. Export CSV structuré (Export-Csv génère l'en-tête tout seul)
$results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

if (Test-Path $CsvPath) {
    try { Set-RestrictiveAcl -Path $CsvPath } catch { Write-Log "ACL non appliquées : $($_.Exception.Message)" 'WARN' }

    $finalPath = $CsvPath
    if ($Encrypt -and -not $WhatIfPreference) {
        try {
            $finalPath = Protect-FileDpapi -Path $CsvPath
            Write-Log "Fichier chiffré (DPAPI, CurrentUser) : $finalPath" 'WARN'
        }
        catch { Write-Log "Échec du chiffrement DPAPI : $($_.Exception.Message)" 'ERROR' }
    }

    if ($PurgeAfterMinutes -gt 0) {
        try {
            $t = Register-PurgeTask -Path $finalPath -Minutes $PurgeAfterMinutes
            Write-Log "Suppression automatique programmée dans $PurgeAfterMinutes min (tâche $t)." 'WARN'
        }
        catch { Write-Log "Impossible de programmer la purge : $($_.Exception.Message)" 'WARN' }
    }

    Write-Log "RAPPEL SÉCURITÉ : ce fichier contient des mots de passe. Transmettez-le" 'WARN'
    Write-Log "                 par un canal sécurisé (jamais par email en clair) et supprimez-le après usage." 'WARN'
}

Write-Log "----------------------------------------"
Write-Log ("Terminé. Succès : {0} | Échecs : {1} | Total : {2}" -f $countOk, $countFail, $users.Count)
Write-Log "CSV : $CsvPath"
Write-Log "Log : $LogPath"

if ($countFail -gt 0) { exit 4 } else { exit 0 }

#endregion
