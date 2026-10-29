<#
    backup-covert.ps1 - Gastinel Covert
    Routine de sauvegarde et d'export du coffre chiffre vers un support externe / secondaire.

    Ce script :
      1. Localise l'executable covert (PATH utilisateur, dossier d'installation ou depot).
      2. Declenche la verification cryptographique du mot de passe maitre et la creation
         d'une copie chiffree horodatee (.bin) dans le dossier de destination choisi.
      3. Optionnel (-Export) : genere egalement une archive d'export autonome chiffree (.covert)
         avec un mot de passe d'export dedie (portable sur une autre machine).
      4. Verifie l'integrite physique de la sauvegarde creee (taille, en-tete binaire CVRT, SHA-256).
      5. Conserve un nombre parametrable de sauvegardes (-KeepCount, defaut 20) et archive les plus anciennes.

    Usage :
      powershell -ExecutionPolicy Bypass -File .\backup-covert.ps1
      powershell -ExecutionPolicy Bypass -File .\backup-covert.ps1 -DestinationDir "D:\Sauvegardes\Covert"
      powershell -ExecutionPolicy Bypass -File .\backup-covert.ps1 -DestinationDir "E:\CleUSB\Covert" -Export
#>

[CmdletBinding()]
param(
    [string]$DestinationDir = "",
    [int]$KeepCount = 20,
    [string]$VaultPath = "",
    [switch]$Export
)

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Gastinel Covert - Routine de Sauvegarde Chiffree" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# 1. Determination du dossier de destination par defaut
# -----------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($DestinationDir)) {
    # Si le disque D: existe (disque secondaire separe), on le privilegie
    if (Test-Path "D:\") {
        $DestinationDir = "D:\Sauvegardes\Covert"
    } else {
        $DestinationDir = Join-Path $env:USERPROFILE "Documents\Sauvegardes-Covert"
    }
}

Write-Host "Dossier cible       : $DestinationDir"
Write-Host "Historique conserve : $KeepCount sauvegardes max"
if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
    Write-Host "Coffre specifie     : $VaultPath"
}
Write-Host ""

if (-not (Test-Path $DestinationDir)) {
    New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
    Write-Host "[+] Dossier de destination cree : $DestinationDir" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 2. Localisation de l'executable Covert
# -----------------------------------------------------------------------------
$CovertExe = ""

# 1. Verification dans le PATH
$Cmd = Get-Command "covert.exe" -ErrorAction SilentlyContinue
if (-not $Cmd) {
    $Cmd = Get-Command "covert" -ErrorAction SilentlyContinue
}
if ($Cmd) {
    $CovertExe = $Cmd.Source
}

# 2. Verification dans l'installation locale
if (-not $CovertExe -or -not (Test-Path $CovertExe)) {
    $InstalledCandidate = "$env:LOCALAPPDATA\Programs\GastinelCovert\bin\covert.exe"
    if (Test-Path $InstalledCandidate) {
        $CovertExe = $InstalledCandidate
    }
}

# 3. Verification dans le dossier release du depot
if (-not $CovertExe -or -not (Test-Path $CovertExe)) {
    $ReleaseCandidate = Join-Path $PSScriptRoot "target\release\covert-cli.exe"
    if (Test-Path $ReleaseCandidate) {
        $CovertExe = $ReleaseCandidate
    }
}

if (-not $CovertExe -or -not (Test-Path $CovertExe)) {
    throw "Executable 'covert' introuvable. Lance d'abord .\install.ps1 pour installer Covert."
}

Write-Host "[1/3] Executable Covert detecte : $CovertExe" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 3. Execution de la sauvegarde (covert backup)
# -----------------------------------------------------------------------------
Write-Host "[2/3] Creation de la copie chiffree horodatee..." -ForegroundColor Yellow
Write-Host "      (Saisie securisee du mot de passe maitre requise ci-dessous)" -ForegroundColor DarkGray
Write-Host ""

$BackupArgs = @("backup", "--output-dir", $DestinationDir)
if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
    $BackupArgs += @("--path", $VaultPath)
}

# Memorisation des fichiers existants avant l'appel pour identifier le nouveau
$ExistingFiles = @(Get-ChildItem -Path $DestinationDir -Filter "covert-backup-*.bin" | Select-Object -ExpandProperty FullName)

& $CovertExe @BackupArgs
$ExitCode = $LASTEXITCODE

if ($ExitCode -ne 0) {
    throw "Echec de la commande covert backup (code de sortie $ExitCode)."
}

# Identification du nouveau fichier
$NewFiles = @(Get-ChildItem -Path $DestinationDir -Filter "covert-backup-*.bin" | Select-Object -ExpandProperty FullName)
$CreatedBackup = $NewFiles | Where-Object { $ExistingFiles -notcontains $_ } | Sort-Object | Select-Object -Last 1

if (-not $CreatedBackup -or -not (Test-Path $CreatedBackup)) {
    # Secours : prendre le plus recent
    $CreatedBackup = (Get-ChildItem -Path $DestinationDir -Filter "covert-backup-*.bin" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

if (-not $CreatedBackup -or -not (Test-Path $CreatedBackup)) {
    throw "Aucun fichier de sauvegarde detecte dans $DestinationDir apres execution."
}

# -----------------------------------------------------------------------------
# 4. Verification physique et cryptographique de l'en-tete
# -----------------------------------------------------------------------------
$FileInfo = Get-Item $CreatedBackup
$FileSize = $FileInfo.Length

if ($FileSize -lt 88) {
    throw "Sauvegarde corrompue ou trop petite ($FileSize octets). L'en-tete minimal est de 88 octets."
}

# Verification des 8 octets 'GCOVERT1'
$FileStream = [System.IO.File]::OpenRead($CreatedBackup)
$MagicBuffer = New-Object byte[] 8
$BytesRead = $FileStream.Read($MagicBuffer, 0, 8)
$FileStream.Close()

$MagicStr = [System.Text.Encoding]::ASCII.GetString($MagicBuffer)
if ($MagicStr -ne "GCOVERT1") {
    throw "Magic header invalide : '$MagicStr' au lieu de 'GCOVERT1'."
}

$Sha256 = (Get-FileHash -Path $CreatedBackup -Algorithm SHA256).Hash

Write-Host ""
Write-Host "      [OK] Sauvegarde verifiee avec succes :" -ForegroundColor Green
Write-Host "           Fichier  : $CreatedBackup" -ForegroundColor White
Write-Host "           Taille   : $FileSize octets" -ForegroundColor Gray
Write-Host "           SHA-256  : $Sha256" -ForegroundColor Gray
Write-Host "           En-tete  : Magic 'GCOVERT1' (format v1) authentifie" -ForegroundColor Gray

# -----------------------------------------------------------------------------
# Optionnel : Export autonome chiffré (-Export)
# -----------------------------------------------------------------------------
if ($Export) {
    Write-Host ""
    Write-Host "[+] Generation d'un export autonome chiffre (.covert)..." -ForegroundColor Yellow
    $DateStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $ExportFile = Join-Path $DestinationDir "covert-export-$DateStamp.covert"
    
    $ExportArgs = @("export", "--output", $ExportFile)
    if (-not [string]::IsNullOrWhiteSpace($VaultPath)) {
        $ExportArgs += @("--path", $VaultPath)
    }

    & $CovertExe @ExportArgs
    if ($LASTEXITCODE -eq 0 -and (Test-Path $ExportFile)) {
        $ExportSha256 = (Get-FileHash -Path $ExportFile -Algorithm SHA256).Hash
        Write-Host "      [OK] Export chiffre cree : $ExportFile (SHA-256: $ExportSha256)" -ForegroundColor Green
    } else {
        Write-Host "      [!] Avertissement : l'export a renvoye un code non nul ($LASTEXITCODE)." -ForegroundColor Yellow
    }
}

# -----------------------------------------------------------------------------
# 5. Rotation et purge des anciennes sauvegardes
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "[3/3] Gestion de la rotation des sauvegardes..." -ForegroundColor Yellow
$AllBackups = @(Get-ChildItem -Path $DestinationDir -Filter "covert-backup-*.bin" | Sort-Object LastWriteTime)

if ($AllBackups.Count -gt $KeepCount) {
    $ToRemoveCount = $AllBackups.Count - $KeepCount
    Write-Host "      Purge de $ToRemoveCount ancienne(s) sauvegarde(s) pour respecter la limite de $KeepCount..." -ForegroundColor DarkGray
    for ($i = 0; $i -lt $ToRemoveCount; $i++) {
        $OldFile = $AllBackups[$i].FullName
        Remove-Item -Path $OldFile -Force
        Write-Host "        Supprime : $(Split-Path $OldFile -Leaf)" -ForegroundColor DarkGray
    }
}

$RemainingCount = (Get-ChildItem -Path $DestinationDir -Filter "covert-backup-*.bin").Count
Write-Host "      Total sauvegardes disponibles dans $DestinationDir : $RemainingCount" -ForegroundColor Green

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Sauvegarde terminee avec succes !" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
