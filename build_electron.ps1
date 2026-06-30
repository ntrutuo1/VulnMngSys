$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
  throw "npm is required to build VulnMngSys-Setup.exe"
}

if (-not (Test-Path node_modules)) {
  npm.cmd install
}

$pyinstaller = Join-Path $PSScriptRoot ".venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $pyinstaller)) {
  throw "PyInstaller is required at .venv\Scripts\pyinstaller.exe to package the backend"
}

if (Test-Path backend_dist) {
  Remove-Item backend_dist -Recurse -Force
}
New-Item -ItemType Directory -Force backend_dist | Out-Null
& $pyinstaller --noconfirm --clean --onefile --name backend --distpath backend_dist --workpath build\backend_pyinstaller backend.py
if (-not (Test-Path backend_dist\backend.exe)) {
  throw "Backend packaging finished without backend_dist\backend.exe"
}

New-Item -ItemType Directory -Force web\vendor | Out-Null
function Copy-VendorIfMissing($source, $destination) {
  if (-not (Test-Path $destination)) {
    Copy-Item $source $destination -Force
  }
}
Copy-VendorIfMissing node_modules\react\umd\react.production.min.js web\vendor\react.production.min.js
Copy-VendorIfMissing node_modules\react-dom\umd\react-dom.production.min.js web\vendor\react-dom.production.min.js
Copy-VendorIfMissing node_modules\dayjs\dayjs.min.js web\vendor\dayjs.min.js
Copy-VendorIfMissing node_modules\antd\dist\antd.min.js web\vendor\antd.min.js
Copy-VendorIfMissing node_modules\antd\dist\reset.css web\vendor\antd-reset.min.css
Copy-VendorIfMissing node_modules\@babel\standalone\babel.min.js web\vendor\babel.min.js

$env:CSC_IDENTITY_AUTO_DISCOVERY = "false"
$out = "release-build-$((Get-Date).ToString('yyyyMMddHHmmss'))"
npm.cmd run dist -- --config.directories.output=$out
if (-not (Test-Path "$out\VulnMngSys-Setup.exe")) {
  throw "Build finished without $out\VulnMngSys-Setup.exe"
}
Copy-Item "$out\VulnMngSys-Setup.exe" VulnMngSys-Setup.exe -Force
Write-Host "Built: VulnMngSys-Setup.exe"
