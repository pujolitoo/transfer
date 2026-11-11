# Publishes a new version of the client as a GitHub release, which installed
# clients pick up through the updater.
#
#   .\scripts\release.ps1 -Version 0.2.1 -Notes "Qué cambia"
#
# Needs the GitHub CLI logged in, a clean working tree and the signing key
# created with `cargo tauri signer generate` (never commit it).
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [string]$Notes = "",
    [string]$Key = "$env:USERPROFILE\.tauri\transfer-updater.key"
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

function Check([string]$what) {
    if ($LASTEXITCODE -ne 0) { throw "$what falló (código $LASTEXITCODE)" }
}

if (-not (Test-Path $Key)) { throw "No existe la clave de firma $Key" }
if (git status --porcelain) { throw "Hay cambios sin confirmar; haz commit antes de publicar" }
$repo = gh repo view --json nameWithOwner --jq .nameWithOwner; Check "gh repo view"
$tag = "v$Version"
if (git tag --list $tag) { throw "La etiqueta $tag ya existe" }

# The installed app compares this version with latest.json.
$conf = 'crates\app\tauri.conf.json'
$text = [IO.File]::ReadAllText("$root\$conf")
$text = [regex]::new('"version": "[^"]*"').Replace($text, "`"version`": `"$Version`"", 1)
[IO.File]::WriteAllText("$root\$conf", $text)

$env:CARGO_TARGET_DIR = "$root\target\installer"
$env:TAURI_SIGNING_PRIVATE_KEY = $Key
if ($null -eq $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD) { $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = '' }
Push-Location crates\app
try { cargo tauri build; Check "cargo tauri build" } finally { Pop-Location }

$bundle = "$root\target\installer\release\bundle\nsis"
$setup = "$bundle\Transfer_${Version}_x64-setup.exe"
$signature = Get-Content "$setup.sig" -Raw
$manifest = [ordered]@{
    version   = $Version
    notes     = $Notes
    pub_date  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    platforms = @{
        'windows-x86_64' = @{
            signature = $signature.Trim()
            url       = "https://github.com/$repo/releases/download/$tag/Transfer_${Version}_x64-setup.exe"
        }
    }
}
$latest = "$bundle\latest.json"
$manifest | ConvertTo-Json -Depth 4 | Set-Content $latest -Encoding utf8NoBOM

git commit -am "Versión $Version"; Check "git commit"
git tag $tag; Check "git tag"
git push origin HEAD $tag; Check "git push"
gh release create $tag $setup "$setup.sig" $latest --title "Transfer $Version" --notes $Notes; Check "gh release create"
"Publicada $tag en https://github.com/$repo/releases/tag/$tag"
