<#
.SYNOPSIS
    Crée en masse des utilisateurs Active Directory à partir d'un fichier CSV,
    en les plaçant dans des OU spécifiques.

.DESCRIPTION
    Version « guichet » du script, pensée pour un lancement simple :

        .\Create-ADUsersFromCSV.ps1

    Sans paramètre :
      - une fenêtre de sélection de fichier s'ouvre pour choisir le CSV ;
      - le script demande UNE FOIS un mot de passe (avec confirmation),
        appliqué à TOUS les utilisateurs créés dans ce lot ;
      - les OU manquantes sont créées automatiquement (confirmation demandée
        pour chacune, sauf -Confirm:$false).

    Déroulé complet :
      1. Sélection du CSV (fenêtre, ou -CsvPath en paramètre)
      2. Saisie du mot de passe commun (invite masquée, ou -Password en paramètre)
      3. Validation de chaque ligne (champs obligatoires, format SamAccountName,
         doublons internes au CSV, collisions UPN/mail)
      4. Vérification de l'OU cible, création automatique si absente
      5. Création du compte (avec retry en cas d'erreur transitoire),
         changement de mot de passe forcé à la première connexion
      6. Ajout optionnel aux groupes AD
      7. Génération d'un log texte + d'un rapport CSV (sans mot de passe)

    Le CSV NE DOIT PAS contenir de colonne "Password" : un seul mot de passe
    commun est saisi au lancement et appliqué à tous les comptes créés.

    ATTENTION SÉCURITÉ : un mot de passe partagé entre plusieurs comptes est
    un compromis de simplicité, pas une bonne pratique. Le script force donc
    -ChangePasswordAtLogon pour que chaque utilisateur le remplace dès sa
    première connexion. Ne réutilisez jamais ce mot de passe pour un lot suivant.

    Colonnes CSV attendues :
        Prenom              (obligatoire)
        Nom                 (obligatoire)
        SamAccountName       (obligatoire, <= 20 car., règles AD)
        OU                  (obligatoire, DistinguishedName de l'OU cible)
        Department          (optionnel)
        Groups              (optionnel, groupes séparés par des points-virgules)
        AccountExpirationDate (optionnel, ex : 2026-09-30 ; sinon param -AccountExpirationDate)

.PARAMETER CsvPath
    Chemin vers le fichier CSV source. Si omis, une fenêtre de sélection de
    fichier s'ouvre (fallback sur une invite texte si aucune interface
    graphique n'est disponible, ex. Server Core).

.PARAMETER Password
    Mot de passe commun à appliquer à tous les comptes créés dans ce lot
    (SecureString). Si omis, le script le demande deux fois au clavier
    (saisie masquée) et vérifie la complexité (8+ caractères, majuscule,
    minuscule, chiffre).

.PARAMETER Delimiter
    Délimiteur du CSV (par défaut : ",").

.PARAMETER LogPath
    Chemin du fichier de log texte.

.PARAMETER ReportPath
    Chemin du rapport CSV récapitulatif (ne contient aucun mot de passe).

.PARAMETER CreateMissingOU
    Crée automatiquement les OU manquantes (activé par défaut ; confirmation
    demandée pour chaque OU, sauf -Confirm:$false). Utilisez
    -CreateMissingOU:$false pour revenir au comportement strict (échec si
    l'OU n'existe pas).

.PARAMETER AccountExpirationDate
    Date d'expiration appliquée à TOUS les comptes créés (sauf si la ligne CSV
    précise sa propre date). Utile pour stagiaires / alternants.

.PARAMETER MaxRetries
    Nombre de tentatives supplémentaires en cas d'erreur transitoire (par défaut : 3).

.PARAMETER RetryDelaySeconds
    Délai initial entre deux tentatives (backoff x2 à chaque essai). Par défaut : 5.

.EXAMPLE
    .\Create-ADUsersFromCSV.ps1
    Lancement guichet : fenêtre de choix du CSV, puis saisie du mot de passe
    commun. Les OU manquantes sont créées automatiquement (avec confirmation).

.EXAMPLE
    .\Create-ADUsersFromCSV.ps1 -CsvPath .\users.csv -WhatIf
    Simule la création sans rien modifier dans l'annuaire.

.EXAMPLE
    .\Create-ADUsersFromCSV.ps1 -CsvPath .\stagiaires.csv -AccountExpirationDate '2026-09-30'
    Crée des comptes qui expirent tous le 30/09/2026 (mot de passe demandé au clavier).

.NOTES
    Compatible PowerShell 5.1 / Windows Server.
    Dépendance unique : module ActiveDirectory (RSAT-AD-PowerShell).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string]$CsvPath,

    [Parameter()]
    [System.Security.SecureString]$Password,

    [Parameter()]
    [string]$Delimiter = ",",

    [Parameter()]
    [string]$LogPath = ".\Create-ADUsers_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",

    [Parameter()]
    [string]$ReportPath = ".\Create-ADUsers_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [Parameter()]
    [switch]$CreateMissingOU = $true,

    [Parameter()]
    [datetime]$AccountExpirationDate,

    [Parameter()]
    [ValidateRange(0, 10)]
    [int]$MaxRetries = 3,

    [Parameter()]
    [ValidateRange(1, 120)]
    [int]$RetryDelaySeconds = 5
)

#region ----------------------------------------------------------------- Fonctions

function Write-Log {
    <#
        Journalise un message à la fois dans le fichier de log et dans la console
        (avec un code couleur selon le niveau).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Level] $Message"

    # Le log ne doit jamais faire échouer le script principal.
    try { Add-Content -Path $script:LogPath -Value $line -Encoding UTF8 -ErrorAction Stop }
    catch { Write-Warning "Impossible d'écrire dans le log : $($_.Exception.Message)" }

    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        default   { Write-Host $line }
    }
}

function Test-ADModuleAvailable {
    <#
        Vérifie que le module ActiveDirectory est présent et l'importe.
        Message d'explication clair sinon (installation RSAT).
    #>
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "Le module 'ActiveDirectory' est introuvable." 'ERROR'
        Write-Log "Installez-le : (Windows Server) Add-WindowsFeature RSAT-AD-PowerShell" 'ERROR'
        Write-Log "               (Windows 10/11) Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" 'ERROR'
        return $false
    }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        return $true
    }
    catch {
        Write-Log "Échec de l'import du module ActiveDirectory : $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Select-CsvFile {
    <#
        Ouvre une fenêtre de sélection de fichier pour choisir le CSV.
        Fallback sur une invite texte si aucune interface graphique n'est
        disponible (ex. Windows Server Core, session distante sans GUI).
    #>
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = "Sélectionner le fichier CSV des utilisateurs à créer"
        $dialog.Filter = "Fichiers CSV (*.csv)|*.csv|Tous les fichiers (*.*)|*.*"
        $dialog.InitialDirectory = (Get-Location).Path
        $result = $dialog.ShowDialog()
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.FileName
        }
        return $null
    }
    catch {
        # Pas d'interface graphique disponible : invite texte classique
        return Read-Host "Chemin du fichier CSV"
    }
}

function ConvertFrom-SecureStringPlain {
    # Extrait temporairement le texte en clair d'une SecureString.
    param([System.Security.SecureString]$Secure)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Read-SharedPassword {
    <#
        Demande deux fois (saisie masquée) un mot de passe commun, vérifie
        qu'il respecte une complexité minimale AD (8+ caractères, majuscule,
        minuscule, chiffre) et que les deux saisies correspondent.
    #>
    while ($true) {
        $secure1 = Read-Host "Mot de passe pour TOUS les nouveaux utilisateurs" -AsSecureString
        $secure2 = Read-Host "Confirmez le mot de passe" -AsSecureString

        $plain1 = ConvertFrom-SecureStringPlain -Secure $secure1
        $plain2 = ConvertFrom-SecureStringPlain -Secure $secure2

        if ($plain1 -ne $plain2) {
            Write-Host "Les deux saisies ne correspondent pas. Réessayez." -ForegroundColor Yellow
            continue
        }
        if ($plain1.Length -lt 8 -or
            $plain1 -notmatch '[A-Z]' -or
            $plain1 -notmatch '[a-z]' -or
            $plain1 -notmatch '\d') {
            Write-Host "Le mot de passe doit faire au moins 8 caractères et contenir une majuscule, une minuscule et un chiffre." -ForegroundColor Yellow
            continue
        }
        $plain1 = $null; $plain2 = $null
        return $secure1
    }
}

function Test-SamAccountName {
    <#
        Valide un SamAccountName selon les règles AD :
        - 1 à 20 caractères
        - pas de caractères interdits : " [ ] : ; | = + * ? < > / \ ,  et pas d'espace
        - ne se termine pas par un point
    #>
    param([string]$Sam)

    if ([string]::IsNullOrWhiteSpace($Sam))      { return "SamAccountName vide" }
    if ($Sam.Length -gt 20)                      { return "SamAccountName > 20 caractères ('$Sam')" }
    if ($Sam -match '[""\[\]:;|=+\*\?<>/\\,\s]') { return "SamAccountName contient un caractère interdit ('$Sam')" }
    if ($Sam.EndsWith('.'))                      { return "SamAccountName se termine par un point ('$Sam')" }
    return $null   # valide
}

function Test-UserRecord {
    <#
        Valide une ligne du CSV. Renvoie la liste des erreurs (vide = OK).
    #>
    param([psobject]$Record)

    $errors = New-Object System.Collections.Generic.List[string]

    foreach ($field in 'Prenom', 'Nom', 'SamAccountName', 'OU') {
        if (-not ($Record.PSObject.Properties.Name -contains $field) -or
            [string]::IsNullOrWhiteSpace($Record.$field)) {
            $errors.Add("Champ obligatoire manquant ou vide : $field")
        }
    }

    if ($Record.PSObject.Properties.Name -contains 'SamAccountName') {
        $samError = Test-SamAccountName -Sam ($Record.SamAccountName | ForEach-Object { "$_".Trim() })
        if ($samError) { $errors.Add($samError) }
    }

    if (($Record.PSObject.Properties.Name -contains 'AccountExpirationDate') -and
        -not [string]::IsNullOrWhiteSpace($Record.AccountExpirationDate)) {
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParse($Record.AccountExpirationDate, [ref]$parsed)) {
            $errors.Add("AccountExpirationDate illisible : '$($Record.AccountExpirationDate)'")
        }
    }

    return $errors
}

function Invoke-WithRetry {
    <#
        Exécute un ScriptBlock avec retry + backoff exponentiel.
        Ne retente que sur les erreurs jugées transitoires (DC injoignable, RPC, etc.).
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [int]$MaxRetries = 3,
        [int]$DelaySeconds = 5,
        [string]$OperationName = 'opération'
    )

    $transientPatterns = @(
        'server is not operational', 'RPC server is unavailable', 'timeout',
        'The specified domain either does not exist', 'A referral was returned',
        'network path was not found', 'temporarily unavailable', 'directory service is busy',
        'unable to contact', 'could not be contacted'
    )

    $attempt = 0
    while ($true) {
        try {
            return & $Action
        }
        catch {
            $attempt++
            $msg = $_.Exception.Message
            $isTransient = $false
            foreach ($p in $transientPatterns) {
                if ($msg -like "*$p*") { $isTransient = $true; break }
            }

            if (-not $isTransient -or $attempt -gt $MaxRetries) {
                throw
            }

            $wait = $DelaySeconds * [math]::Pow(2, $attempt - 1)
            Write-Log "Erreur transitoire sur $OperationName (tentative $attempt/$MaxRetries) : $msg. Nouvel essai dans $wait s." 'WARN'
            Start-Sleep -Seconds $wait
        }
    }
}

function Resolve-OU {
    <#
        Vérifie l'existence de l'OU. Si absente et -CreateMissingOU : la crée
        (via ShouldProcess). Renvoie $true si l'OU est utilisable.
    #>
    param([string]$OUDistinguishedName)

    $existing = Invoke-WithRetry -OperationName "recherche OU" -MaxRetries $script:MaxRetries -DelaySeconds $script:RetryDelaySeconds -Action {
        Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUDistinguishedName'" -ErrorAction SilentlyContinue
    }
    if ($existing) { return $true }

    if (-not $script:CreateMissingOU) {
        Write-Log "OU introuvable : $OUDistinguishedName" 'ERROR'
        return $false
    }

    # Découper le DN : "OU=Stagiaires,OU=Paris,DC=contoso,DC=local"
    if ($OUDistinguishedName -notmatch '^OU=(?<name>[^,]+),(?<parent>.+)$') {
        Write-Log "DN d'OU non conforme, création impossible : $OUDistinguishedName" 'ERROR'
        return $false
    }
    $ouName   = $Matches['name']
    $ouParent = $Matches['parent']

    if ($PSCmdlet.ShouldProcess($OUDistinguishedName, "Créer l'OU manquante")) {
        try {
            Invoke-WithRetry -OperationName "création OU" -MaxRetries $script:MaxRetries -DelaySeconds $script:RetryDelaySeconds -Action {
                New-ADOrganizationalUnit -Name $ouName -Path $ouParent -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            }
            Write-Log "OU créée : $OUDistinguishedName" 'SUCCESS'
            return $true
        }
        catch {
            Write-Log "Échec de création de l'OU '$OUDistinguishedName' : $($_.Exception.Message)" 'ERROR'
            return $false
        }
    }
    return $false   # simulation / refus
}

function Get-UniqueUpn {
    <#
        Construit un UPN unique (prenom.nom@domaine) en évitant les collisions
        dans l'AD et dans le lot en cours.
    #>
    param(
        [string]$Prenom,
        [string]$Nom,
        [string]$DnsRoot,
        [System.Collections.Generic.HashSet[string]]$UsedUpns
    )

    function Convert-ToAscii([string]$s) {
        $normalized = $s.Normalize([System.Text.NormalizationForm]::FormD)
        $sb = New-Object System.Text.StringBuilder
        foreach ($c in $normalized.ToCharArray()) {
            if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -ne 'NonSpacingMark') {
                [void]$sb.Append($c)
            }
        }
        return ($sb.ToString() -replace '[^A-Za-z0-9]', '').ToLower()
    }

    $base = "{0}.{1}" -f (Convert-ToAscii $Prenom), (Convert-ToAscii $Nom)
    if ([string]::IsNullOrWhiteSpace($base.Trim('.'))) { $base = "user" }

    $candidate = "$base@$DnsRoot"
    $i = 1
    while ($UsedUpns.Contains($candidate.ToLower()) -or
           (Get-ADUser -Filter "UserPrincipalName -eq '$candidate'" -ErrorAction SilentlyContinue)) {
        $i++
        $candidate = "$base$i@$DnsRoot"
    }
    [void]$UsedUpns.Add($candidate.ToLower())
    return $candidate
}

#endregion -------------------------------------------------------------- Fonctions


#region ----------------------------------------------------------------- Initialisation

# Variables partagées avec les fonctions (scope script)
$script:LogPath          = $LogPath
$script:MaxRetries       = $MaxRetries
$script:RetryDelaySeconds = $RetryDelaySeconds
$script:CreateMissingOU  = [bool]$CreateMissingOU

Write-Log "==== Démarrage : création d'utilisateurs AD ===="
if ($WhatIfPreference) { Write-Log "MODE SIMULATION (-WhatIf) : aucune modification ne sera appliquée." 'WARN' }

if (-not (Test-ADModuleAvailable)) { exit 2 }

# --- CSV : paramètre, sinon fenêtre de sélection ---
if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    $CsvPath = Select-CsvFile
}
if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    Write-Log "Aucun fichier CSV sélectionné — annulé." 'ERROR'
    exit 1
}
if (-not (Test-Path $CsvPath)) {
    Write-Log "Fichier CSV introuvable : $CsvPath" 'ERROR'
    exit 1
}
Write-Log "CSV     : $CsvPath"
Write-Log "Rapport : $ReportPath"

try {
    $domain  = Invoke-WithRetry -OperationName "Get-ADDomain" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds -Action { Get-ADDomain -ErrorAction Stop }
    $dnsRoot = $domain.DNSRoot
}
catch {
    Write-Log "Impossible de contacter le domaine : $($_.Exception.Message)" 'ERROR'
    exit 3
}

$rawUsers = Import-Csv -Path $CsvPath -Delimiter $Delimiter
if (-not $rawUsers) {
    Write-Log "Le CSV ne contient aucune ligne." 'ERROR'
    exit 1
}
Write-Log "$($rawUsers.Count) ligne(s) lue(s)."

#endregion


#region ----------------------------------------------------------------- 1re passe : validation + doublons CSV

$seenSam   = @{}                                        # SamAccountName déjà vu dans le CSV
$usedUpns  = New-Object System.Collections.Generic.HashSet[string]
$report    = New-Object System.Collections.Generic.List[psobject]
$toProcess = New-Object System.Collections.Generic.List[psobject]

$rowNumber = 1
foreach ($row in $rawUsers) {
    $rowNumber++   # +1 pour l'en-tête

    $validationErrors = Test-UserRecord -Record $row
    if ($validationErrors.Count -gt 0) {
        $detail = $validationErrors -join ' | '
        Write-Log "Ligne $rowNumber ignorée (validation) : $detail" 'ERROR'
        $report.Add([pscustomobject]@{
            SamAccountName = ($row.SamAccountName | ForEach-Object { "$_".Trim() })
            DisplayName    = "$($row.Prenom) $($row.Nom)".Trim()
            OU             = $row.OU
            Status         = 'Invalide'
            Detail         = $detail
            GroupsAdded    = ''
            GroupsFailed   = ''
        })
        continue
    }

    $sam = $row.SamAccountName.Trim()
    $samKey = $sam.ToLower()
    if ($seenSam.ContainsKey($samKey)) {
        Write-Log "Ligne $rowNumber : SamAccountName '$sam' en doublon dans le CSV (déjà vu ligne $($seenSam[$samKey])) — ignorée." 'WARN'
        $report.Add([pscustomobject]@{
            SamAccountName = $sam
            DisplayName    = "$($row.Prenom) $($row.Nom)".Trim()
            OU             = $row.OU
            Status         = 'Doublon-CSV'
            Detail         = "Déjà présent ligne $($seenSam[$samKey])"
            GroupsAdded    = ''
            GroupsFailed   = ''
        })
        continue
    }
    $seenSam[$samKey] = $rowNumber

    $toProcess.Add($row)
}

Write-Log "$($toProcess.Count) ligne(s) valides à traiter, $($report.Count) écartée(s) à ce stade."

# --- Mot de passe commun : paramètre, sinon saisie interactive (sauf simulation) ---
# Demandé seulement si des lignes valides restent à traiter.
if ($toProcess.Count -gt 0) {
    if (-not $PSBoundParameters.ContainsKey('Password') -and -not $WhatIfPreference) {
        $Password = Read-SharedPassword
    }
    if ($Password) {
        $script:SecurePwd = $Password
    }
}

#endregion


#region ----------------------------------------------------------------- 2e passe : création

$countSuccess = 0
$countFailed  = 0
$countSkipped = 0

foreach ($row in $toProcess) {

    $prenom  = $row.Prenom.Trim()
    $nom     = $row.Nom.Trim()
    $sam     = $row.SamAccountName.Trim()
    $ouCible = $row.OU.Trim()
    $service = if ($row.PSObject.Properties.Name -contains 'Department') { $row.Department } else { $null }
    $displayName = "$prenom $nom"

    # Date d'expiration : priorité à la ligne CSV, sinon paramètre global
    $expiration = $null
    if (($row.PSObject.Properties.Name -contains 'AccountExpirationDate') -and
        -not [string]::IsNullOrWhiteSpace($row.AccountExpirationDate)) {
        $expiration = [datetime]::Parse($row.AccountExpirationDate)
    }
    elseif ($PSBoundParameters.ContainsKey('AccountExpirationDate')) {
        $expiration = $AccountExpirationDate
    }

    # Groupes
    $groups = @()
    if (($row.PSObject.Properties.Name -contains 'Groups') -and
        -not [string]::IsNullOrWhiteSpace($row.Groups)) {
        $groups = $row.Groups.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }

    # --- OU ---
    if (-not (Resolve-OU -OUDistinguishedName $ouCible)) {
        Write-Log "Utilisateur '$sam' non créé : OU indisponible ($ouCible)." 'ERROR'
        $countFailed++
        $report.Add([pscustomobject]@{
            SamAccountName = $sam; DisplayName = $displayName; OU = $ouCible
            Status = 'Échec'; Detail = 'OU introuvable / non créée'
            GroupsAdded = ''; GroupsFailed = ''
        })
        continue
    }

    # --- Compte déjà présent ? ---
    $exists = Invoke-WithRetry -OperationName "Get-ADUser" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds -Action {
        Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
    }
    if ($exists) {
        Write-Log "Utilisateur '$sam' déjà présent dans l'AD — ignoré." 'WARN'
        $countSkipped++
        $report.Add([pscustomobject]@{
            SamAccountName = $sam; DisplayName = $displayName; OU = $ouCible
            Status = 'Ignoré-Existant'; Detail = 'SamAccountName déjà dans l''AD'
            GroupsAdded = ''; GroupsFailed = ''
        })
        continue
    }

    # --- UPN unique ---
    $upn = Get-UniqueUpn -Prenom $prenom -Nom $nom -DnsRoot $dnsRoot -UsedUpns $usedUpns

    # --- Création (ShouldProcess => support natif -WhatIf / -Confirm) ---
    if (-not $PSCmdlet.ShouldProcess($sam, "Créer l'utilisateur AD dans $ouCible")) {
        Write-Log "[SIMULATION] Utilisateur '$sam' (UPN $upn) serait créé dans '$ouCible'." 'INFO'
        $report.Add([pscustomobject]@{
            SamAccountName = $sam; DisplayName = $displayName; OU = $ouCible
            Status = 'Simulé'; Detail = "UPN=$upn ; Groupes=$($groups -join ';')"
            GroupsAdded = ''; GroupsFailed = ''
        })
        continue
    }

    try {
        $newUserParams = @{
            Name                  = $displayName
            GivenName             = $prenom
            Surname               = $nom
            SamAccountName        = $sam
            UserPrincipalName     = $upn
            DisplayName           = $displayName
            Path                  = $ouCible
            AccountPassword       = $script:SecurePwd
            Enabled               = $true
            ChangePasswordAtLogon = $true
            ErrorAction           = 'Stop'
        }
        if ($service)    { $newUserParams['Department'] = $service }
        if ($expiration) { $newUserParams['AccountExpirationDate'] = $expiration }

        Invoke-WithRetry -OperationName "New-ADUser '$sam'" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds -Action {
            New-ADUser @newUserParams
        }

        Write-Log "Utilisateur '$sam' créé dans '$ouCible' (UPN $upn)." 'SUCCESS'
        $countSuccess++

        # --- Groupes ---
        $groupsOk = @(); $groupsKo = @()
        foreach ($g in $groups) {
            try {
                Invoke-WithRetry -OperationName "Add-ADGroupMember '$g'" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds -Action {
                    Add-ADGroupMember -Identity $g -Members $sam -ErrorAction Stop
                }
                $groupsOk += $g
                Write-Log "  '$sam' ajouté au groupe '$g'." 'SUCCESS'
            }
            catch {
                $groupsKo += $g
                Write-Log "  Échec ajout de '$sam' au groupe '$g' : $($_.Exception.Message)" 'ERROR'
            }
        }

        $report.Add([pscustomobject]@{
            SamAccountName = $sam; DisplayName = $displayName; OU = $ouCible
            Status = 'Créé'
            Detail = "UPN=$upn" + $(if ($expiration) { " ; Expire=$($expiration.ToString('yyyy-MM-dd'))" } else { '' })
            GroupsAdded  = ($groupsOk -join ';')
            GroupsFailed = ($groupsKo -join ';')
        })
    }
    catch {
        Write-Log "Échec de création de '$sam' : $($_.Exception.Message)" 'ERROR'
        $countFailed++
        $report.Add([pscustomobject]@{
            SamAccountName = $sam; DisplayName = $displayName; OU = $ouCible
            Status = 'Échec'; Detail = $_.Exception.Message
            GroupsAdded = ''; GroupsFailed = ''
        })
    }
}

#endregion


#region ----------------------------------------------------------------- Rapports

# Rapport récapitulatif CSV
try {
    $report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -Delimiter $Delimiter
    Write-Log "Rapport CSV écrit : $ReportPath"
}
catch {
    Write-Log "Impossible d'écrire le rapport CSV : $($_.Exception.Message)" 'ERROR'
}

if ($countSuccess -gt 0) {
    Write-Log "RAPPEL SÉCURITÉ : les $countSuccess compte(s) créé(s) partagent le même mot de passe" 'WARN'
    Write-Log "                 et devront le changer à la première connexion. Ne réutilisez pas" 'WARN'
    Write-Log "                 ce mot de passe pour un autre lot." 'WARN'
}

$countInvalid = ($report | Where-Object { $_.Status -eq 'Invalide' }).Count
$countDupCsv  = ($report | Where-Object { $_.Status -eq 'Doublon-CSV' }).Count

Write-Log "----------------------------------------"
Write-Log ("Terminé. Créés : {0} | Échecs : {1} | Ignorés (existants) : {2} | Invalides : {3} | Doublons CSV : {4}" -f `
    $countSuccess, $countFailed, $countSkipped, $countInvalid, $countDupCsv)
Write-Log "Log     : $script:LogPath"
Write-Log "Rapport : $ReportPath"
Write-Log "==== Fin ===="

# Code de sortie : 0 si aucun échec, 4 sinon (utile pour l'ordonnanceur)
if ($countFailed -gt 0) { exit 4 } else { exit 0 }

#endregion
