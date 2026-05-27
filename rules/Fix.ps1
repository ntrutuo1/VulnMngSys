<#
.SYNOPSIS
Script tự động map 'id' rule của CIS Benchmark ra 'service_name' và 'service_id' (ÉP KIỂU SỐ NGUYÊN).
#>

$ErrorActionPreference = "Stop"

# 1. Bảng từ điển ID cho các Services (CHẮC CHẮN LÀ SỐ)
$ServiceDict = @{
    "AccountPolicy"     = 1
    "AppxSvc"           = 2
    "Biometrics"        = 3
    "Core"              = 4
    "Cryptography"      = 5
    "Dnscache"          = 6
    "EventLog"          = 7
    "Explorer"          = 8
    "Kernel"            = 9
    "LanmanServer"      = 10
    "LanmanWorkstation" = 11
    "LSASS"             = 12
    "mpssvc"            = 13
    "NetBT"             = 14
    "Network"           = 15
    "PNRP"              = 16
    "Power"             = 17
    "RpcSs"             = 18
    "Spooler"           = 19
    "Tcpip"             = 20
    "Tcpip6"            = 21
    "TermService"       = 22
    "User"              = 23
    "W32Time"           = 24
    "WcmSvc"            = 25
    "Winlogon"          = 26
    "WinRM"             = 27
    "Wlansvc"           = 28
    "WpnService"        = 29
    "wuauserv"          = 30
    "Unknown"           = 99
}

# 2. Hàm gom nhóm Service dựa vào Rule ID
function Get-ServiceNameById {
    param([string]$Id)

    switch -Regex ($Id) {
        "^1\." { return "AccountPolicy" }
        "^2\.2\." { return "Core" }
        "^2\.3\.1\." { return "Core" }
        "^2\.3\.2\." { return "EventLog" }
        "^2\.3\.4\." { return "Spooler" }
        "^2\.3\.7\." { return "Winlogon" }
        "^2\.3\.8\." { return "LanmanWorkstation" }
        "^2\.3\.9\." { return "LanmanServer" }
        "^2\.3\.10\." { return "Network" }
        "^2\.3\.11\." { return "Network" }
        "^2\.3\.13\." { return "Core" }
        "^2\.3\.15\." { return "Core" }
        "^2\.3\.17\." { return "Core" }
        "^5\." { return "Spooler" }
        "^9\." { return "mpssvc" }
        "^17\." { return "EventLog" }
        "^18\.1\.1\." { return "Winlogon" }
        "^18\.1\.2\." { return "Core" }
        "^18\.1\.3$" { return "Explorer" }
        "^18\.4\.1$" { return "LanmanWorkstation" }
        "^18\.4\.2$" { return "LanmanServer" }
        "^18\.4\.3$" { return "Cryptography" }
        "^18\.4\.4$" { return "Kernel" }
        "^18\.4\.5$" { return "NetBT" }
        "^18\.5\.1$" { return "Winlogon" }
        "^18\.5\.$" { return "Tcpip6" } 
        "^18\.5\.(3|4|5|7|10)$" { return "Tcpip" }
        "^18\.5\.6$" { return "NetBT" }
        "^18\.5\.8$" { return "Kernel" }
        "^18\.5\.11$" { return "EventLog" }
        "^18\.6\.4\." { return "Dnscache" }
        "^18\.6\.5\." { return "Core" }
        "^18\.6\.7\." { return "LanmanServer" }
        "^18\.6\.8\." { return "LanmanWorkstation" }
        "^18\.6\.9\." { return "Network" }
        "^18\.6\.10\." { return "PNRP" }
        "^18\.6\.11\." { return "Network" }
        "^18\.6\.14\." { return "Network" }
        "^18\.6\.19\." { return "Tcpip6" }
        "^18\.6\.20\." { return "Wlansvc" }
        "^18\.6\.21\." { return "WcmSvc" }
        "^18\.7\." { return "Spooler" }
        "^18\.8\." { return "WpnService" }
        "^18\.9\.3\." { return "EventLog" }
        "^18\.9\.4\." { return "TermService" }
        "^18\.9\.5\." { return "Core" }
        "^18\.9\.7\." { return "Core" }
        "^18\.9\.13\." { return "Core" }
        "^18\.9\.17\." { return "Core" }
        "^18\.9\.19\." { return "Core" }
        "^18\.9\.20\.1\.(1|6)$" { return "Spooler" } 
        "^18\.9\.20\." { return "Core" }
        "^18\.9\.23\." { return "Core" }
        "^18\.9\.24\." { return "Core" }
        "^18\.9\.27\." { return "LSASS" }
        "^18\.9\.28\." { return "Winlogon" }
        "^18\.9\.29\." { return "Winlogon" }
        "^18\.9\.33\." { return "Core" }
        "^18\.9\.35\." { return "Power" }
        "^18\.9\.37\." { return "TermService" }
        "^18\.9\.38\." { return "RpcSs" }
        "^18\.9\.49\." { return "Core" }
        "^18\.9\.51\." { return "Core" }
        "^18\.9\.53\." { return "W32Time" }
        "^18\.10\.4\." { return "AppxSvc" }
        "^18\.10\.6\." { return "Core" }
        "^18\.10\.8\." { return "Explorer" }
        "^18\.10\.9\." { return "Biometrics" }
        "^18\.10\.11\." { return "Core" }
        "^18\.10\.13\." { return "Core" }
        "^18\.10\.14\." { return "Core" }
        "^18\.10\.15\." { return "Core" }
        "^18\.10\.16\." { return "Core" }
        "^18\.10\.18\." { return "AppxSvc" }
        "^18\.10\.26\." { return "EventLog" }
        "^18\.10\.29\." { return "Explorer" }
        "^18\.10\.36\." { return "Core" }
        "^18\.10\.40\." { return "Core" }
        "^18\.10\.41\." { return "Core" }
        "^18\.10\.56\." { return "AppxSvc" }
        "^18\.10\.57\." { return "TermService" }
        "^18\.10\.58\." { return "Explorer" }
        "^18\.10\.59\." { return "Explorer" }
        "^18\.10\.63\." { return "Core" }
        "^18\.10\.77\." { return "Core" }
        "^18\.10\.81\." { return "Core" }
        "^18\.10\.82\." { return "Core" }
        "^18\.10\.83\." { return "Winlogon" }
        "^18\.10\.88\." { return "Core" }
        "^18\.10\.90\." { return "WinRM" }
        "^18\.10\.91\." { return "WinRM" }
        "^18\.10\.93\." { return "Core" }
        "^18\.10\.94\." { return "wuauserv" }
        "^18\.11\." { return "Core" }
        "^19\." { return "User" }
        default { return "Unknown" }
    }
}

Write-Host "Bắt đầu quét và ÉP KIỂU SỐ cho service_id vào JSON..." -ForegroundColor Cyan

# 3. Quét tất cả các file JSON
$jsonFiles = Get-ChildItem -Path ".\" -Filter "*.json"
$totalRulesUpdated = 0

foreach ($file in $jsonFiles) {
    Write-Host "Đang xử lý file: $($file.Name)" -ForegroundColor Yellow
    
    $jsonContent = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
    $isModified = $false

    foreach ($rule in $jsonContent) {
        if ($null -ne $rule.id) {
            # Lấy tên và gán cứng kiểu [int] cho ID
            $correctServiceName = Get-ServiceNameById -Id $rule.id
            [int]$correctServiceId = 99 

            if ($ServiceDict.ContainsKey($correctServiceName)) {
                $correctServiceId = [int]$ServiceDict[$correctServiceName]
            }

            # Chỉnh lại Tên service cho chuẩn
            if ($rule.service -ne $correctServiceName) {
                $rule.service = $correctServiceName
                $isModified = $true
            }

            # ÉP KIỂU SỐ CHO service_id: Xóa key cũ nếu có dấu hiệu sai hoặc là chuỗi
            if ($null -ne $rule.PSObject.Properties['service_id']) {
                if ($rule.service_id -isnot [int] -or $rule.service_id -ne $correctServiceId) {
                    $rule.PSObject.Properties.Remove('service_id')
                    $rule | Add-Member -MemberType NoteProperty -Name "service_id" -Value $correctServiceId
                    $isModified = $true
                }
            } else {
                # Tạo mới nếu chưa có
                $rule | Add-Member -MemberType NoteProperty -Name "service_id" -Value $correctServiceId
                $isModified = $true
            }

            if ($isModified) {
                $totalRulesUpdated++
            }
        }
    }

    # 4. Ghi đè file
    if ($isModified) {
        $jsonContent | ConvertTo-Json -Depth 10 | Set-Content -Path $file.FullName -Encoding UTF8
        Write-Host "Đã lưu thành công: $($file.Name)" -ForegroundColor Green
    }
}

Write-Host "Hoàn tất! Tổng cộng đã sửa $totalRulesUpdated rules." -ForegroundColor Cyan