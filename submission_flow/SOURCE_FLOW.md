# Source Flow Chuan

Tai lieu nay mo ta luong chay logic cua VulnMngSys theo cach doc kien truc, khong yeu cau chay chuong trinh.

## 1. Lop khoi dong

Nguoi dung co the tiep can he thong qua hai huong:

- Desktop GUI: giao dien React duoc host trong cua so desktop.
- CLI: phu hop voi moi truong headless hoac khi can thao tac nhanh.

Trong ban dong goi xem xet nay, cac file khoi dong truc tiep da duoc loai bo de tranh viec tai lap ung dung thanh ban chay.

## 2. Lop dieu phoi ung dung

Composition root tao cac thanh phan mac dinh:

- Scanner mac dinh.
- Report writer mac dinh.
- Cac abstraction cho phep thay the scanner/report writer khi test hoac mo rong.

Muc dich cua lop nay la tach viec tao doi tuong khoi logic nghiep vu.

## 3. Catalog module

Catalog tra ve danh sach module hardcoded theo:

- He dieu hanh: Linux, Windows, macOS.
- Phien ban he dieu hanh: vi du Ubuntu 22.04, Ubuntu 24.04, Windows 11, macOS 14.
- Loai dich vu: SSH, Apache HTTP Server, Apache Tomcat.

Catalog giup he thong chon dung bo rule va config path theo ngu canh cua may dich.

## 4. Lua chon module

He thong co hai cach chon module:

- Chon tu dong theo host family, OS version va service type.
- Chon tuong tac trong CLI, khi nguoi dung muon chi dinh dich vu, module, OS version hoac service version.

Neu khong tim thay module khop, flow dung lai voi loi co mo ta.

## 5. Phat hien moi truong

Thanh phan platform probe co nhiem vu:

- Xac dinh he dieu hanh dang chay.
- Xac dinh phien ban OS neu co the.
- Xac dinh phien ban dich vu nhu SSH, Apache HTTP Server hoac Tomcat.

Thong tin nay duoc dua vao scanner va CVE intelligence de danh gia chinh xac hon.

## 6. Scanner

Scanner nhan vao module da chon va thuc hien cac buoc:

1. Lay danh sach candidate path cua file cau hinh.
2. Chon path ton tai dau tien, neu khong co thi giu path mac dinh de bao loi ro rang.
3. Doc noi dung file cau hinh bang text reader.
4. Duyet tung rule trong module.
5. Tim bang chung trong file cau hinh.
6. Tao rule result gom trang thai pass/fail, muc do nghiem trong, ly do va dong lien quan neu co.

Scanner khong phu thuoc truc tiep vao UI. UI/CLI chi nhan ket qua da duoc chuan hoa.

## 7. Scoring

Sau khi co danh sach rule result, scoring strategy tinh:

- Tong so check.
- So check dat.
- So check khong dat.
- Hardening index.
- Grade A/B/C/D.
- Warning cho cac loi critical/high.

Cong thuc tong quat:

```text
hardening_index = round((passed_checks / total_checks) * 100)
```

Grade:

```text
A >= 90
B >= 75
C >= 60
D < 60
```

## 8. CVE intelligence

Neu nguoi dung cung cap hoac he thong phat hien duoc phien ban dich vu, CVE intelligence danh gia them:

- Apache HTTP/Tomcat version range.
- OpenSSH version range.
- Ket hop OS context voi service version.

Ket qua CVE duoc dua vao report nhu nhom canh bao rieng.

## 9. Report

Report writer nhan ScanReport va ghi ket qua thanh bao cao text. Bao cao gom:

- Ten module.
- Diem hardening.
- Grade.
- Danh sach rule pass/fail.
- Canh bao CVE neu co.

Trong ban dong goi xem xet nay, output report sinh ra khi chay thuc te da duoc loai bo.

## 10. Flow hoan chinh

```text
User
  -> GUI/CLI
  -> Application factory
  -> Module catalog
  -> Host/service detection
  -> Module selection
  -> Config path selector
  -> Config reader
  -> Rule evaluation
  -> Scoring strategy
  -> CVE intelligence
  -> Scan report
  -> Report writer
  -> Result displayed/saved
```

## 11. Ly do tach lop

- Domain giu model va contract thuan.
- Application tao thanh phan mac dinh.
- Infrastructure xu ly scan, catalog, platform, reporting va security.
- Interfaces gom CLI, GUI va desktop host.
- Modules chua rule definition theo OS/service.

Thiet ke nay giup them module moi ma khong can sua flow chinh.
