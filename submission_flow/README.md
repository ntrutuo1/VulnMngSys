# VulnMngSys - Ban xem flow

VulnMngSys la ung dung desktop/CLI ho tro kiem tra cau hinh bao mat cho mot so dich vu pho bien nhu SSH, Apache HTTP Server va Apache Tomcat.

Ban dong goi nay chi dung de xem luong thiet ke. Goi khong chua entrypoint, dependency manifest, build script hoac output co the chay truc tiep.

## Flow tong quat

1. Nguoi dung chon che do GUI hoac CLI.
2. He thong xac dinh OS, dich vu va phien ban dich vu.
3. Catalog chon module kiem tra phu hop.
4. Scanner xac dinh duong dan file cau hinh can doc.
5. Rule duoc doi chieu voi cau hinh thuc te.
6. Scoring tinh hardening index va grade.
7. Report duoc tao de nguoi dung xem ket qua.

Chi tiet nam trong `SOURCE_FLOW.md`.
