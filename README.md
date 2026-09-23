# Scripts d'administration Active Directory

Deux scripts PowerShell de gestion en masse des comptes AD :

- **[Create-ADUsersFromCSV.ps1](Create-ADUsersFromCSV.ps1)** — crée des utilisateurs à partir d'un CSV, dans des OU spécifiques (création automatique des OU manquantes).
- **[Reset-OUUserPasswords.ps1](Reset-OUUserPasswords.ps1)** — réinitialise en masse les mots de passe de tous les utilisateurs d'une OU.

> Le second est basé sur un gist de Greg Malone (2016, MIT), corrigé et durci. Voir l'en-tête de chaque script pour le détail des modifications.

## Prérequis (communs)

- Windows PowerShell 5.1 (Windows Server)
- Module `ActiveDirectory` (RSAT-AD-PowerShell)
- Droits appropriés sur l'OU ciblée (création de comptes / reset de mot de passe)

---

## Create-ADUsersFromCSV.ps1

Lancement « guichet », sans paramètre :

```powershell
.\Create-ADUsersFromCSV.ps1
```

- Une fenêtre s'ouvre pour choisir le CSV (fallback en invite texte sans interface graphique).
- Le script demande **une fois** un mot de passe (saisie masquée + confirmation), appliqué à tous les utilisateurs créés dans ce lot. `-ChangePasswordAtLogon` est forcé.
- Les OU manquantes sont créées automatiquement (confirmation demandée pour chacune).

Colonnes CSV attendues : `Prenom`, `Nom`, `SamAccountName`, `OU` (obligatoires), `Department`, `Groups` (séparés par `;`), `AccountExpirationDate` (optionnels). Voir [users-exemple.csv](users-exemple.csv).

```powershell
# Simulation
.\Create-ADUsersFromCSV.ps1 -CsvPath .\users.csv -WhatIf

# Non interactif, sans créer les OU manquantes
.\Create-ADUsersFromCSV.ps1 -CsvPath .\users.csv -Password (Read-Host -AsSecureString) -CreateMissingOU:$false
```

`Get-Help .\Create-ADUsersFromCSV.ps1 -Full` pour l'aide complète.

### ⚠️ Encodage

Le fichier doit être enregistré en **UTF-8 avec BOM**. Sans BOM, Windows PowerShell 5.1 peut le lire avec l'encodage ANSI du système : les caractères accentués cassent alors le script (`Jeton inattendu « } »` etc.). Si tu copies-colles le script à la main dans un nouveau fichier, ré-encode-le ensuite :

```powershell
$p = "chemin\vers\le\script.ps1"
$c = [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllText($p, $c, (New-Object System.Text.UTF8Encoding($true)))
```

---

## Reset-OUUserPasswords.ps1

```powershell
# Simulation : voir qui serait affecté, sans rien changer
.\Reset-OUUserPasswords.ps1 -SearchBase "OU=Stagiaires,DC=contoso,DC=local" -WhatIf

# Reset réel, mots de passe 8 caractères (maj + min + chiffre)
.\Reset-OUUserPasswords.ps1 -SearchBase "OU=Stagiaires,DC=contoso,DC=local" -PasswordLength 8

# Reset avec mots de passe forts + changement au prochain login + CSV chiffré
.\Reset-OUUserPasswords.ps1 -SearchBase "OU=Admins,DC=contoso,DC=local" `
    -PasswordLength 16 -IncludeSpecialCharacters -ChangePasswordAtLogon -Encrypt
```

`Get-Help .\Reset-OUUserPasswords.ps1 -Full` pour l'aide complète.

### Principaux paramètres

| Paramètre | Rôle |
|---|---|
| `-SearchBase` | **(obligatoire)** DN de l'OU à traiter |
| `-CsvPath` | Fichier CSV de sortie |
| `-PasswordLength` | Longueur (min 8, défaut 12) |
| `-IncludeSpecialCharacters` | Ajoute les caractères spéciaux |
| `-ChangePasswordAtLogon` | Force le changement au prochain login |
| `-ExcludeDisabled` | Ignore les comptes désactivés |
| `-Encrypt` | Chiffre le CSV de sortie (DPAPI) |
| `-PurgeAfterMinutes` | Programme la suppression du fichier de sortie |
| `-WhatIf` / `-Confirm` | Support natif (ShouldProcess) |

### ⚠️ Sécurité

Le CSV de sortie contient **tous les mots de passe en clair**.

- Transmets-le uniquement par un canal sécurisé — **jamais par email en clair**.
- Supprime-le dès que les mots de passe ont été distribués.
- `.gitignore` exclut déjà les fichiers `Reset-Passwords_*` : **ne les commite jamais**.

## Licence

MIT — voir [LICENSE](LICENSE).
