<#
    install.ps1 - Gastinel Covert
    Script d'installation et de packaging local pour Windows x64.
    
    Actions realisees (espace utilisateur uniquement, AUCUN droit administrateur requis) :
      1. Verification / compilation release des binaires (covert-cli et covert-gui).
      2. Copie des binaires dans $env:LOCALAPPDATA\Programs\GastinelCovert\bin.
      3. Creation de l'alias direct 'covert.exe' pour appeler la CLI.
      4. Generation du script d'hote Native Messaging (covert-native-host.cmd).
      5. Enregistrement du manifeste JSON Native Messaging dans le registre HKCU
         (Google Chrome, Brave, Microsoft Edge).
      6. Ajout du dossier bin au PATH utilisateur.
      7. Creation d'un raccourci dans le menu Demarrer pour Gastinel Covert GUI.

    Usage :
      powershell -ExecutionPolicy Bypass -File .\install.ps1
      powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoBuild
#>

[CmdletBinding()]
param(
    [switch]$NoBuild,
    [string]$TargetDir = "$env:LOCALAPPDATA\Programs\GastinelCovert",
    [string]$ExtensionId = "gastinelcovertextensionidaaaaaaa"
)

$ErrorActionPreference = 'Stop'

$RepoRoot = $PSScriptRoot
if ([string]::IsNullOrEmpty($RepoRoot)) {
    $RepoRoot = (Get-Location).Path
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Installation locale de Gastinel Covert" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Depot source        : $RepoRoot"
Write-Host "Dossier cible       : $TargetDir"
Write-Host "ID extension autoris: $ExtensionId"
Write-Host ""

# -----------------------------------------------------------------------------
# 1. Verification / Compilation release
# -----------------------------------------------------------------------------
$ReleaseDir = Join-Path $RepoRoot "target\release"
$CliSrcExe  = Join-Path $ReleaseDir "covert-cli.exe"
$GuiSrcExe  = Join-Path $ReleaseDir "covert-gui.exe"

if (-not $NoBuild -or -not (Test-Path $CliSrcExe) -or -not (Test-Path $GuiSrcExe)) {
    Write-Host "[1/6] Compilation de Covert en mode --release..." -ForegroundColor Yellow
    Push-Location $RepoRoot
    try {
        & cargo build --release --workspace
        if ($LASTEXITCODE -ne 0) {
            throw "Echec de la compilation Cargo (code sortie $LASTEXITCODE)."
        }
    }
    finally {
        Pop-Location
    }
} else {
    Write-Host "[1/6] Etape de compilation ignoree (-NoBuild)." -ForegroundColor DarkGray
}

if (-not (Test-Path $CliSrcExe)) {
    throw "Binaire introuvable : $CliSrcExe"
}
if (-not (Test-Path $GuiSrcExe)) {
    throw "Binaire introuvable : $GuiSrcExe"
}
Write-Host "      Binaires sources valides." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 2. Preparation des dossiers cibles
# -----------------------------------------------------------------------------
Write-Host "[2/6] Preparation du dossier d'installation..." -ForegroundColor Yellow
$BinDir = Join-Path $TargetDir "bin"
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

# -----------------------------------------------------------------------------
# 3. Copie des binaires
# -----------------------------------------------------------------------------
Write-Host "[3/6] Copie des executables..." -ForegroundColor Yellow
Copy-Item -Path $CliSrcExe -Destination (Join-Path $BinDir "covert-cli.exe") -Force
Copy-Item -Path $CliSrcExe -Destination (Join-Path $BinDir "covert.exe") -Force
Copy-Item -Path $GuiSrcExe -Destination (Join-Path $BinDir "covert-gui.exe") -Force
Write-Host "      Fichiers installes dans $BinDir :" -ForegroundColor Green
Write-Host "        - covert-cli.exe" -ForegroundColor Green
Write-Host "        - covert.exe" -ForegroundColor Green
Write-Host "        - covert-gui.exe" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 4. Hote et Manifeste Native Messaging
# -----------------------------------------------------------------------------
Write-Host "[4/6] Configuration du Native Messaging Host..." -ForegroundColor Yellow

# Script relais Windows pour le flux stdio Chrome/Brave/Edge
$HostCmdPath = Join-Path $BinDir "covert-native-host.cmd"
$CmdContent = @"
@echo off
setlocal
"%~dp0covert-cli.exe" daemon --native-msg --extension-id $ExtensionId %*
"@
[System.IO.File]::WriteAllText($HostCmdPath, $CmdContent, [System.Text.Encoding]::ASCII)
Write-Host "      Wrapper genere : $HostCmdPath" -ForegroundColor Green

# Manifeste JSON
$ManifestPath = Join-Path $TargetDir "com.gastinel.covert.json"
$NormalizedCmdPath = $HostCmdPath.Replace('\', '\\')
$ManifestJson = @"
{
  "name": "com.gastinel.covert",
  "description": "Gastinel Covert Zero-Trust Password Manager Native Messaging Host",
  "path": "$NormalizedCmdPath",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$ExtensionId/"
  ]
}
"@
[System.IO.File]::WriteAllText($ManifestPath, $ManifestJson, [System.Text.Encoding]::UTF8)
Write-Host "      Manifeste genere : $ManifestPath" -ForegroundColor Green

# Enregistrement dans la base de registre HKCU (CurrentUser = sans droits admin)
$BrowserRegistryBases = @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.gastinel.covert",
    "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.gastinel.covert",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.gastinel.covert"
)

foreach ($regPath in $BrowserRegistryBases) {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $ManifestPath -Force
}
Write-Host "      Enregistrement registre HKCU applique (Chrome, Brave, Edge)." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 5. Ajout au PATH utilisateur
# -----------------------------------------------------------------------------
Write-Host "[5/6] Configuration de la variable d'environnement PATH..." -ForegroundColor Yellow
$CurrentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$PathEntries = ($CurrentUserPath -split ';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

if ($PathEntries -notcontains $BinDir) {
    $NewUserPath = "$CurrentUserPath;$BinDir"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    Write-Host "      Dossier ajoute au PATH utilisateur : $BinDir" -ForegroundColor Green
} else {
    Write-Host "      Le dossier est deja present dans le PATH utilisateur." -ForegroundColor DarkGray
}

# Mise a jour dans la session PowerShell courante
if (($env:Path -split ';') -notcontains $BinDir) {
    $env:Path = "$env:Path;$BinDir"
}

# -----------------------------------------------------------------------------
# 6. Raccourci Menu Demarrer (GUI)
# -----------------------------------------------------------------------------
Write-Host "[6/6] Creation du raccourci Menu Demarrer..." -ForegroundColor Yellow
$StartMenuDir = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs")
if (Test-Path $StartMenuDir) {
    $ShortcutPath = Join-Path $StartMenuDir "Gastinel Covert.lnk"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = Join-Path $BinDir "covert-gui.exe"
    $Shortcut.WorkingDirectory = $BinDir
    $Shortcut.Description = "Gastinel Covert - Gestionnaire de secrets zero-trust"
    $Shortcut.Save()
    Write-Host "      Raccourci cree : $ShortcutPath" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Verification finale
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Installation terminee avec succes !" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan

$InstalledCli = Join-Path $BinDir "covert.exe"
if (Test-Path $InstalledCli) {
    $VersionOutput = (& $InstalledCli --version) 2>$null
    Write-Host "Verification commande 'covert' : $VersionOutput" -ForegroundColor White
}
Write-Host ""
Write-Host "Pour lancer Covert :"
Write-Host "  - CLI : tape 'covert --help' dans n'importe quel terminal." -ForegroundColor Gray
Write-Host "  - GUI : lance 'Gastinel Covert' depuis le menu Demarrer." -ForegroundColor Gray
Write-Host ""
