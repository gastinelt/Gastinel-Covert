<#
    verifier-etat.ps1 - Gastinel Covert
    Script de verification EN LECTURE SEULE de l'etat du projet.
    (Texte volontairement sans accents : Windows PowerShell 5.1 lit les .ps1
     en codepage ANSI, les accents UTF-8 casseraient le script.)

    Ce script NE MODIFIE RIEN :
      - il ne modifie aucun fichier source, ne commite pas, ne pousse pas ;
      - il ne touche JAMAIS au vrai coffre
        %LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.* ;
      - il ne lance ni l'interface graphique ni les tests d'auto-type
        (vraies frappes clavier).

    Il affiche : la branche, les commits non pousses, l'etat git, le resultat de
    `cargo build --release`, le resultat de `cargo test` (en excluant les tests
    d'auto-type) et verifie que les options secretes ont disparu de covert-cli.

    Usage :  .\verifier-etat.ps1
#>

$ErrorActionPreference = 'Continue'

$repo = $PSScriptRoot
if ([string]::IsNullOrEmpty($repo)) { $repo = (Get-Location).Path }
Push-Location $repo

function Write-Section($title) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkGray
}

try {
    Write-Host ""
    Write-Host "Gastinel Covert - verification de l'etat (lecture seule)" -ForegroundColor White
    Write-Host "Depot : $repo"

    # -------------------------------------------------------------------
    Write-Section "1. Etat Git"
    # -------------------------------------------------------------------
    $branche = (git rev-parse --abbrev-ref HEAD) 2>$null
    Write-Host "Branche courante : $branche"

    Write-Host ""
    Write-Host "Dernier commit :"
    git log -1 --oneline

    Write-Host ""
    Write-Host "Etat de l'arbre de travail (git status) :"
    $status = git status --short
    if ([string]::IsNullOrWhiteSpace($status)) {
        Write-Host "  (propre - rien a committer)" -ForegroundColor Green
    } else {
        Write-Host $status -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Commits locaux NON POUSSES :"
    $upstream = (git rev-parse --abbrev-ref --symbolic-full-name '@{u}') 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($upstream)) {
        $unpushed = git log --oneline "$upstream..HEAD"
    } else {
        $hasOriginMain = (git rev-parse --verify --quiet origin/main) 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($hasOriginMain)) {
            $unpushed = git log --oneline "origin/main..HEAD"
        } else {
            $unpushed = $null
            Write-Host "  (aucun upstream ni origin/main accessible - calcul impossible)" -ForegroundColor Yellow
        }
    }
    if ($unpushed) {
        Write-Host $unpushed -ForegroundColor Yellow
    } elseif ($LASTEXITCODE -eq 0) {
        Write-Host "  (aucun - a jour avec le distant)" -ForegroundColor Green
    }

    # -------------------------------------------------------------------
    Write-Section "2. Compilation (cargo build --release)"
    # -------------------------------------------------------------------
    cargo build --release
    $buildOk = ($LASTEXITCODE -eq 0)
    if ($buildOk) {
        Write-Host "BUILD : OK" -ForegroundColor Green
    } else {
        Write-Host "BUILD : ECHEC (code $LASTEXITCODE)" -ForegroundColor Red
    }

    # -------------------------------------------------------------------
    Write-Section "3. Tests (cargo test --workspace, SANS les tests d'auto-type)"
    # -------------------------------------------------------------------
    Write-Host "Exclusion du crate covert-autotype (vraies frappes clavier)." -ForegroundColor DarkGray
    Write-Host "Les tests marques #[ignore] ne sont jamais lances ici." -ForegroundColor DarkGray
    Write-Host "Rappel : echec attendu et ACCEPTE = test_git_local_only_no_remotes." -ForegroundColor DarkGray
    Write-Host ""

    $testOutput = cargo test --workspace --exclude covert-autotype 2>&1
    $testExit = $LASTEXITCODE
    $testOutput | ForEach-Object { Write-Host $_ }

    Write-Host ""
    $resultLines = $testOutput | Select-String -Pattern 'test result:'
    if ($resultLines) {
        Write-Host "Resume des binaires de test :" -ForegroundColor White
        $resultLines | ForEach-Object { Write-Host "  $_" }
    }
    $gitRemoteFail = $testOutput | Select-String -Pattern 'test_git_local_only_no_remotes'
    if ($testExit -eq 0) {
        Write-Host "TESTS : tous verts (hors auto-type)." -ForegroundColor Green
    } elseif ($gitRemoteFail) {
        Write-Host "TESTS : seul echec attendu = test_git_local_only_no_remotes (ACCEPTE)." -ForegroundColor Yellow
        Write-Host "        Verifie qu'aucun AUTRE test n'echoue ci-dessus." -ForegroundColor Yellow
    } else {
        Write-Host "TESTS : ECHEC inattendu (code $testExit) - a examiner ci-dessus." -ForegroundColor Red
    }

    # -------------------------------------------------------------------
    Write-Section "4. Verification : plus de secrets en arguments CLI (etape 1)"
    # -------------------------------------------------------------------
    $cliSrc = Join-Path $repo 'crates\covert-cli\src'
    if (Test-Path $cliSrc) {
        $hits = Select-String -Path (Join-Path $cliSrc '*.rs') `
            -Pattern '--password', '--tier2-password', '--totp', '--recovery-code' `
            -SimpleMatch 2>$null
        if ($hits) {
            Write-Host "ATTENTION : options secretes encore presentes dans covert-cli :" -ForegroundColor Red
            $hits | ForEach-Object { Write-Host ("  {0}:{1}: {2}" -f $_.Path, $_.LineNumber, $_.Line.Trim()) -ForegroundColor Red }
        } else {
            Write-Host "OK : aucune option --password/--tier2-password/--totp/--recovery-code dans covert-cli/src." -ForegroundColor Green
        }
    } else {
        Write-Host "Dossier $cliSrc introuvable." -ForegroundColor Yellow
    }

    # -------------------------------------------------------------------
    Write-Section "Fin de la verification"
    # -------------------------------------------------------------------
    Write-Host "Aucune modification effectuee. Le vrai coffre n'a pas ete touche." -ForegroundColor Green
}
finally {
    Pop-Location
}
