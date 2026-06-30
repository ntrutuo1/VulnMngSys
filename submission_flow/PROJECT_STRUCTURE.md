# Cau truc du an theo vai tro

Tai lieu nay mo ta cac khoi chinh trong bo ma nguon noi bo. Ban zip xem xet khong chua day du cac file nay de tranh viec chay lai ung dung.

## Goc du an

- `main.py`: entrypoint noi bo, da loai khoi goi xem xet.
- `requirements.txt`: dependency backend, da loai khoi goi xem xet.
- `build_windows.ps1`, `build_linux.sh`: script build executable, da loai khoi goi xem xet.
- `rules/`: rule text cho mot so dich vu.
- `scripts/`: cong cu ho tro phat hien/cai dat dich vu.
- `tests/`: test noi bo.

## Backend

- `vulnmngsys_app/domain/`: model va contract thuan.
- `vulnmngsys_app/application/`: factory va composition root.
- `vulnmngsys_app/infrastructure/catalog/`: danh muc module scan.
- `vulnmngsys_app/infrastructure/scan/`: config reader, path selector, scanner, scoring.
- `vulnmngsys_app/infrastructure/intel/`: danh gia CVE theo phien ban.
- `vulnmngsys_app/infrastructure/platform/`: phat hien OS va service version.
- `vulnmngsys_app/infrastructure/reporting/`: ghi bao cao.
- `vulnmngsys_app/infrastructure/security/`: xu ly quyen admin/root.
- `vulnmngsys_app/interfaces/cli/`: delivery layer CLI.
- `vulnmngsys_app/interfaces/gui/`: GUI fallback.
- `vulnmngsys_app/interfaces/desktop/`: host React UI trong desktop window.
- `vulnmngsys_app/modules/`: module rule theo OS/service.

## Frontend

- `react-ui/src/`: giao dien React.
- `react-ui/package.json`: dependency frontend, da loai khoi goi xem xet.
- `react-ui/dist/`: output build, da loai khoi tat ca goi source/xem xet.

## Nhom module scan

- `modules/ssh/`: SSH theo Ubuntu, Windows, macOS.
- `modules/apache/`: Apache HTTP Server va Apache Tomcat theo nen tang.
- `modules/common.py`: thanh phan dung chung khi khai bao module/rule.

## Nhom output bi loai bo

- `build/`
- `dist/`
- `reports/`
- `react-ui/dist/`
- `react-ui/electron-dist/`
- `vulnmngsys_app/frontend/dist/`
- `vulnmngsys_app/views/dist/`
- `__pycache__/`
- `.venv/`
- `node_modules/`
