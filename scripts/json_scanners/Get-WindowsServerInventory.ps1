param(
    [switch]$AsJson
)

$ErrorActionPreference = "Stop"

function Get-ProductTypeName {
    param([int]$ProductType)
    switch ($ProductType) {
        1 { return "Workstation" }
        2 { return "DomainController" }
        3 { return "Server" }
        default { return "Unknown" }
    }
}

function Get-ProfileKey {
    param([string]$Caption)

    if (-not $Caption) {
        return $null
    }

    if ($Caption -match "Windows Server 2025") { return "Windows_Server_2025" }
    if ($Caption -match "Windows Server 2022") { return "Windows_Server_2022" }
    if ($Caption -match "Windows Server 2019") { return "Windows_Server_2019" }
    if ($Caption -match "Windows Server 2016") { return "Windows_Server_2016" }

    return "Windows_Server_Generic"
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem

$productTypeName = Get-ProductTypeName -ProductType $os.ProductType
$isServer = $os.ProductType -in 2, 3
$profileKey = Get-ProfileKey -Caption $os.Caption

# Danh sách tinh gọn: Chỉ chứa các Services/Drivers thực sự bị yêu cầu cấu hình trong CIS (Mục 1 đến 19)
$serviceCandidates = @(
    "Spooler",             # Print Spooler (Mục 5.1, 18.7)
    "mrxsmb10",            # SMB 1.x MiniRedirector Driver (Mục 18.4.1)
    "LanmanServer",        # Server / SMB Server (Mục 18.4.2, 2.3.9.x)
    "LanmanWorkstation",   # Workstation / SMB Client (Mục 18.6.8.x, 2.3.8.x)
    "lltdio",              # Link-Layer Topology Discovery Mapper I/O (Mục 18.6.9.1)
    "rspndr",              # Link-Layer Topology Discovery Responder (Mục 18.6.9.2)
    "PNRPsvc",             # Peer Name Resolution Protocol (Đại diện cho P2P - Mục 18.6.10.2)
    "p2psvc",              # Peer Networking Grouping (Đại diện cho P2P - Mục 18.6.10.2)
    "p2pimsvc",            # Peer Networking Identity Manager (Đại diện cho P2P - Mục 18.6.10.2)
    "W32Time",             # Windows Time Service (Mục 18.9.53.1.1)
    "PushToInstall",       # Push To Install (Mục 18.10.56.1)
    "WinRM",               # Windows Remote Management (Mục 18.10.90.x)
    "RpcEptMapper",        # RPC Endpoint Mapper (Mục 18.9.38.1)
    "RpcSs",               # Remote Procedure Call (Mục 18.9.38.2)
    "DiagTrack",           # Connected User Experiences and Telemetry (Mục 18.10.16.2)
    "EventLog",            # Windows Event Log (Mục 18.10.26.x)
    "mpssvc",              # Windows Defender Firewall (Mục 9.x)
    "TermService"          # Remote Desktop Services (Mục 18.10.57.x)
)

$detectedServices = @()
foreach ($svcName in $serviceCandidates) {
    # Dùng Get-Service. Các mục không tồn tại trên OS hiện tại sẽ bị bỏ qua (SilentlyContinue)
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        $detectedServices += [PSCustomObject]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            Status      = [string]$svc.Status
            StartType   = [string]$svc.StartType
        }
    }
}

$inventory = [PSCustomObject]@{
    ComputerName         = $env:COMPUTERNAME
    Domain               = $cs.Domain
    OsCaption            = $os.Caption
    OsVersion            = $os.Version
    BuildNumber          = $os.BuildNumber
    ProductType          = $productTypeName
    IsServer             = $isServer
    ProfileKey           = $profileKey
    LastBootUpTime       = $os.LastBootUpTime
    DetectedServiceCount = $detectedServices.Count
    DetectedServices     = $detectedServices
    TimestampUtc         = [DateTime]::UtcNow.ToString("o")
}

if ($AsJson) {
    $inventory | ConvertTo-Json -Depth 6
}
else {
    $inventory
}