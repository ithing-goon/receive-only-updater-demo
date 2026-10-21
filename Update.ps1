$ErrorActionPreference = 'Stop'
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Node.js 22 or later is required.'
}
& node (Join-Path $PSScriptRoot 'updater.mjs')
if ($LASTEXITCODE -ne 0) { throw 'Update failed. Do not disable security checks.' }
