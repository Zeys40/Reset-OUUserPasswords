# Reset-OUUserPasswords

Script PowerShell qui **réinitialise en masse les mots de passe** de tous les
utilisateurs d'une OU Active Directory et exporte les nouveaux mots de passe
dans un CSV.

> Basé sur un gist de Greg Malone (2016, MIT), corrigé et durci pour un usage
> en production (voir l'en-tête du script pour le détail des modifications).

## Prérequis

- Windows PowerShell 5.1 (Windows Server)
- Module `ActiveDirectory` (RSAT-AD-PowerShell)
- Droits de réinitialisation de mot de passe sur l'OU ciblée

## Utilisation

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

## Principaux paramètres

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

## ⚠️ Sécurité

Le CSV de sortie contient **tous les mots de passe en clair**.

- Transmets-le uniquement par un canal sécurisé — **jamais par email en clair**.
- Supprime-le dès que les mots de passe ont été distribués.
- `.gitignore` exclut déjà les fichiers `Reset-Passwords_*` : **ne les commite jamais**.

## Licence

MIT — voir [LICENSE](LICENSE).
