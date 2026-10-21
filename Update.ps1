$ErrorActionPreference = 'Stop'
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'An approved Node.js version with --use-system-ca support is required.'
}
& node --use-system-ca (Join-Path $PSScriptRoot 'updater.mjs')
if ($LASTEXITCODE -ne 0) { throw 'Update failed. Do not disable security checks.' }

