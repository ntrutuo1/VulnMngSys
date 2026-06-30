# VulnMngSys - Huong dan cai dat va dong goi ma nguon

Tai lieu nay dung de cai dat du an tu ma nguon va dong goi file `.zip` sach, chi giu lai ma nguon can thiet. Khong dua vao file zip cac thu muc build, cache, dependency da cai san, file bien dich, file report sinh ra trong qua trinh chay.

## 1. Yeu cau moi truong

- Python 3.10 tro len
- Node.js 18 tro len va npm
- Git, neu lay ma nguon tu repository
- Windows PowerShell, neu dong goi tren Windows

Tren Ubuntu/Linux, neu chay giao dien desktop bang webview, cai them cac goi he thong can thiet:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-tk policykit-1
sudo apt install -y python3-gi gir1.2-gtk-3.0 libgtk-3-0 libwebkit2gtk-4.0-37 firefox
```

## 2. Cai dat backend Python

Tai thu muc goc du an:

```bash
python -m venv .venv
```

Kich hoat moi truong ao tren Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Kich hoat moi truong ao tren Linux/macOS:

```bash
source .venv/bin/activate
```

Cai dependencies:

```bash
python -m pip install -U pip
python -m pip install -r requirements.txt
```

## 3. Cai dat frontend React

```bash
cd react-ui
npm install
```

Chay frontend o che do development:

```bash
npm run dev
```

Build frontend khi can dong goi executable:

```bash
npm run build
```

Quay lai thu muc goc:

```bash
cd ..
```

## 4. Chay ung dung

Chay ung dung desktop:

```bash
python main.py
```

Chay che do CLI:

```bash
python main.py --cli --interactive
```

Vi du quet dich vu cu the:

```bash
python main.py --cli --service ssh
python main.py --cli --service apache-http --os-version ubuntu-22.04 --service-version 2.4.50
```

## 5. Build executable

Build tren Windows:

```powershell
.\build_windows.ps1
```

Build tren Linux:

```bash
bash build_linux.sh
```

File build se duoc sinh trong thu muc `dist/`. Cac file nay khong nen dua vao goi zip ma nguon.

## 6. Dong goi zip chi gom ma nguon thuan

Chay lenh sau tai thu muc goc du an tren Windows PowerShell:

```powershell
$SourceRoot = (Get-Location).Path
$ZipPath = Join-Path $SourceRoot "VulnMngSys-source.zip"

if (Test-Path $ZipPath) {
    Remove-Item $ZipPath -Force
}

$ExcludeDirs = @(
    ".git",
    ".agents",
    ".codex",
    ".venv",
    ".vscode",
    "build",
    "dist",
    "reports",
    "__pycache__",
    "react-ui\node_modules",
    "react-ui\dist",
    "react-ui\electron-dist",
    "react-ui\.electron-cache",
    "react-ui\.electron-builder-cache",
    "vulnmngsys_app\frontend\dist",
    "vulnmngsys_app\views\dist"
)

$ExcludeFilePatterns = @(
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.log",
    "*.tmp",
    "*.spec",
    "*.zip",
    "*.exe",
    "*.dll",
    "*.so",
    "*.dylib"
)

$Files = Get-ChildItem -Path $SourceRoot -Recurse -File | Where-Object {
    $relative = $_.FullName.Substring($SourceRoot.Length + 1)
    $inExcludedDir = $false

    foreach ($dir in $ExcludeDirs) {
        if ($relative -eq $dir -or $relative.StartsWith($dir + "\")) {
            $inExcludedDir = $true
            break
        }
    }

    $isExcludedFile = $false
    foreach ($pattern in $ExcludeFilePatterns) {
        if ($_.Name -like $pattern) {
            $isExcludedFile = $true
            break
        }
    }

    -not $inExcludedDir -and -not $isExcludedFile
}

$TempDir = Join-Path $env:TEMP ("VulnMngSys-source-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TempDir | Out-Null

foreach ($file in $Files) {
    $relative = $file.FullName.Substring($SourceRoot.Length + 1)
    $target = Join-Path $TempDir $relative
    $targetDir = Split-Path $target -Parent

    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }

    Copy-Item -LiteralPath $file.FullName -Destination $target
}

Compress-Archive -Path (Join-Path $TempDir "*") -DestinationPath $ZipPath -Force
Remove-Item $TempDir -Recurse -Force

Write-Host "Da tao file zip ma nguon sach: $ZipPath"
```

File tao ra: `VulnMngSys-source.zip`.

## 7. Cac thanh phan bi loai khoi zip

Khi dong goi ma nguon thuan, loai bo cac nhom sau:

- Thu muc dependency: `.venv/`, `react-ui/node_modules/`
- Thu muc build/output: `build/`, `dist/`, `react-ui/dist/`, `react-ui/electron-dist/`, `vulnmngsys_app/frontend/dist/`, `vulnmngsys_app/views/dist/`
- Cache: `__pycache__/`, `.electron-cache/`, `.electron-builder-cache/`
- File binary/bien dich: `*.pyc`, `*.pyd`, `*.exe`, `*.dll`, `*.so`, `*.dylib`
- File log/tam: `*.log`, `*.tmp`
- File dong goi cu: `*.zip`
- File cau hinh workspace ca nhan: `.vscode/`
- Metadata noi bo: `.git/`, `.agents/`, `.codex/`
- Bao cao sinh ra khi chay: `reports/`

## 8. Kiem tra nhanh sau khi giai nen zip

Sau khi giai nen `VulnMngSys-source.zip`, thu muc nguon nen con cac thanh phan chinh:

- `main.py`
- `requirements.txt`
- `build_windows.ps1`
- `build_linux.sh`
- `rules/`
- `scripts/`
- `tests/`
- `vulnmngsys_app/`
- `react-ui/src/`
- `react-ui/package.json`
- `react-ui/package-lock.json`
- `react-ui/index.html`
- `react-ui/vite.config.js`

Neu can chay lai du an tu file zip, thuc hien lai cac buoc cai dat backend va frontend o tren.
