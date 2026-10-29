<#
    uninstall.ps1 - Gastinel Covert
    Script de desinstallation propre de Gastinel Covert (Windows x64).

    Actions realisees :
      1. Suppression des cles de registre Native Messaging dans HKCU (Chrome, Brave, Edge).
      2. Suppression du raccourci dans le menu Demarrer.
      3. Retrait du dossier bin du PATH utilisateur.
      4. Suppression du dossier d'installation $env:LOCALAPPDATA\Programs\GastinelCovert.

    NOTE IMPORTANTE SUR LE COFFRE :
      Ce script ne touche JAMAIS au coffre de donnees chiffre (%LOCALAPPDATA%\DirectX\ShaderCache).
      Tes mots de passe restent preserves.
#>

[CmdletBinding()]
param(
    [string]$TargetDir = "$env:LOCALAPPDATA\Programs\GastinelCovert"
)

$ErrorActionPreference = 'Continue'

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "  Desinstallation de Gastinel Covert" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Yellow

$BinDir = Join-Path $TargetDir "bin"

# 1. Registre Native Messaging
Write-Host "[1/4] Nettoyage du registre Native Messaging (HKCU)..." -ForegroundColor Yellow
$BrowserRegistryBases = @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.gastinel.covert",
    "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.gastinel.covert",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.gastinel.covert"
)
foreach ($regPath in $BrowserRegistryBases) {
    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "      Cle supprimee : $regPath" -ForegroundColor Green
    }
}

# 2. Raccourci Menu Demarrer
Write-Host "[2/4] Suppression du raccourci Menu Demarrer..." -ForegroundColor Yellow
$StartMenuShortcut = Join-Path ([System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs")) "Gastinel Covert.lnk"
if (Test-Path $StartMenuShortcut) {
    Remove-Item -Path $StartMenuShortcut -Force -ErrorAction SilentlyContinue
    Write-Host "      Raccourci supprime : $StartMenuShortcut" -ForegroundColor Green
}

# 3. Retrait du PATH
Write-Host "[3/4] Retrait du dossier bin du PATH utilisateur..." -ForegroundColor Yellow
$CurrentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentUserPath) {
    $Entries = ($CurrentUserPath -split ';') | Where-Object { 
        -not [string]::IsNullOrWhiteSpace($_) -and $_.TrimEnd('\') -ne $BinDir.TrimEnd('\') 
    }
    $NewPath = $Entries -join ';'
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Host "      PATH utilisateur mis a jour." -ForegroundColor Green
}

# 4. Suppression des binaires
Write-Host "[4/4] Suppression des fichiers programmes..." -ForegroundColor Yellow
if (Test-Path $TargetDir) {
    # Securite absolue : verification du chemin
    if ($TargetDir -like "*Programs\GastinelCovert*") {
        Remove-Item -Path $TargetDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "      Dossier supprime : $TargetDir" -ForegroundColor Green
    } else {
        Write-Host "      ATTENTION : chemin suspect non supprime par precaution : $TargetDir" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  Desinstallation terminee." -ForegroundColor Green
Write-Host "  Note : Tes donnees de coffre chiffré n'ont pas ete touchees." -ForegroundColor DarkGray
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""
