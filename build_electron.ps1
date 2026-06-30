$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
  throw "npm is required to build Desktop.exe"
}

if (-not (Test-Path node_modules)) {
  npm.cmd install
}

New-Item -ItemType Directory -Force web\vendor | Out-Null
Copy-Item node_modules\react\umd\react.production.min.js web\vendor\react.production.min.js -Force
Copy-Item node_modules\react-dom\umd\react-dom.production.min.js web\vendor\react-dom.production.min.js -Force
Copy-Item node_modules\dayjs\dayjs.min.js web\vendor\dayjs.min.js -Force
Copy-Item node_modules\antd\dist\antd.min.js web\vendor\antd.min.js -Force
Copy-Item node_modules\antd\dist\reset.css web\vendor\antd-reset.min.css -Force
Copy-Item node_modules\@babel\standalone\babel.min.js web\vendor\babel.min.js -Force

$env:CSC_IDENTITY_AUTO_DISCOVERY = "false"
$out = "release-build-$((Get-Date).ToString('yyyyMMddHHmmss'))"
npm.cmd run dist -- --config.directories.output=$out
if (-not (Test-Path "$out\Desktop.exe")) {
  throw "Build finished without $out\Desktop.exe"
}
Copy-Item "$out\Desktop.exe" Desktop.exe -Force
Write-Host "Built: Desktop.exe"
