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

function Get-EditionSuffix {
    param([string]$Caption)
    if ($Caption -match "Azure") { return "_AZURE" }
    if ($Caption -match "Standard") { return "_STANDARD" }
    if ($Caption -match "Datacenter") { return "_DATACENTER" }
    return ""
}

function Get-ProfileKey {
    param([string]$Caption)
    if (-not $Caption) { return "Windows_Server_Generic" }

    $suffix = Get-EditionSuffix -Caption $Caption
    if ($Caption -match "Windows Server 2025") { return "Windows_Server_2025$suffix" }
    if ($Caption -match "Windows Server 2022") { return "Windows_Server_2022$suffix" }
    if ($Caption -match "Windows Server 2019") { return "Windows_Server_2019$suffix" }
    if ($Caption -match "Windows Server 2016") { return "Windows_Server_2016$suffix" }
    if ($Caption -match "Windows Server 2012 R2") { return "Windows_Server_2012_R2$suffix" }
    if ($Caption -match "Windows Server 2012") { return "Windows_Server_2012_nonR2$suffix" }
    return "Windows_Server_Generic"
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem

$productTypeName = Get-ProductTypeName -ProductType $os.ProductType
$inventory = [PSCustomObject]@{
    ComputerName   = $env:COMPUTERNAME
    Domain         = $cs.Domain
    OsCaption      = $os.Caption
    OsVersion      = $os.Version
    BuildNumber    = $os.BuildNumber
    ProductType    = $productTypeName
    IsServer       = $os.ProductType -in 2, 3
    ProfileKey     = Get-ProfileKey -Caption $os.Caption
    LastBootUpTime = $os.LastBootUpTime
    TimestampUtc   = [DateTime]::UtcNow.ToString("o")
}

if ($AsJson) {
    $inventory | ConvertTo-Json -Depth 4
}
else {
    $inventory
}
