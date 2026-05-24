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

$serviceCandidates = @(
    "WinDefend", "EventLog", "W32Time", "LanmanServer", "MpsSvc",
    "RemoteRegistry", "TermService", "W3SVC", "MSSQLSERVER", "DNS",
    "NTDS", "ADWS", "DHCPServer", "Schedule", "RpcSs"
)

$detectedServices = @()
foreach ($svcName in $serviceCandidates) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        $detectedServices += [PSCustomObject]@{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            Status = [string]$svc.Status
            StartType = [string]$svc.StartType
        }
    }
}

$inventory = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Domain = $cs.Domain
    OsCaption = $os.Caption
    OsVersion = $os.Version
    BuildNumber = $os.BuildNumber
    ProductType = $productTypeName
    IsServer = $isServer
    ProfileKey = $profileKey
    LastBootUpTime = $os.LastBootUpTime
    DetectedServiceCount = $detectedServices.Count
    DetectedServices = $detectedServices
    TimestampUtc = [DateTime]::UtcNow.ToString("o")
}

if ($AsJson) {
    $inventory | ConvertTo-Json -Depth 6
}
else {
    $inventory
}
