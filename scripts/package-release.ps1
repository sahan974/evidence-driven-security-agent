param(
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][string]$BinaryName
)

$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repository "target/$Target/release/$BinaryName"
$destination = Join-Path $repository "dist/edsa-$Target"
$archive = "$destination.zip"
$checksum = "$archive.sha256"

if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "release binary does not exist: $source"
}

New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -LiteralPath $source -Destination $destination
Copy-Item -LiteralPath (Join-Path $repository 'README.md') -Destination $destination
Copy-Item -LiteralPath (Join-Path $repository 'LICENSE') -Destination $destination
Copy-Item -LiteralPath (Join-Path $repository 'docs') -Destination $destination -Recurse
Compress-Archive -LiteralPath $destination -DestinationPath $archive -Force
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath $checksum -Value "$hash  $(Split-Path -Leaf $archive)" -Encoding ascii
Write-Output $archive
Write-Output $checksum
