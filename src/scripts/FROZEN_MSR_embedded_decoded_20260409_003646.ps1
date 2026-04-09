# =================================================================
# MASTER SECURITY REVIEW v3.4.1 (FINAL - NULL SAFE + NO SPAM WARNINGS)
# =================================================================
# Descripción: Herramienta de auditoría de seguridad para Windows.
#              Recopila información de procesos, servicios, red,
#              navegadores, extensiones, firewall, WMI, tareas
#              programadas, drivers, etc., y genera un informe
#              con opciones de redacción de datos sensibles.
# =================================================================

$ErrorActionPreference = 'Continue'

# ===== COMPROBACIÓN DE ADMINISTRADOR =====
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Host "⚠️  ADVERTENCIA: No ejecutas como Administrador." -ForegroundColor Yellow
    Write-Host "   Algunas funciones (exclusiones de Defender, ciertos servicios) mostrarán información limitada." -ForegroundColor Yellow
    Write-Host "   Para información completa, ejecuta PowerShell como Administrador." -ForegroundColor Yellow
    Write-Host ""
}

# ===== OPCIONES =====
$ApplyUntappedHardening = $false   # true = quitar autoinicio de Untapped + bloquear inbound
$RemoveMetaMaskFiles    = $false   # true = elimina carpetas de MetaMask (si existe)
$RunDefenderFullScan    = $false   # true = lanza examen completo de Defender al final
$PauseAtEnd             = $true    # true = mantiene la ventana abierta al terminar
$FallbackPauseSeconds   = 45       # si Read-Host falla en consola efímera, espera N segundos
$MaxRecursionDepth      = 10       # profundidad máxima para serialización de objetos
$MaxCacheSize           = 10000    # tamaño máximo de la caché de confianza y rutas

# ===== AJUSTES =====
$UntappedPath = Join-Path $env:LOCALAPPDATA "Programs\untapped-companion\Untapped.gg Companion.exe"
$MetaMaskId   = "nkbihfbeogaeaoehlefnkodbefgpgknn"
$ChromeRoot   = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"
$EdgeRoot     = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data"
$Desktop      = [Environment]::GetFolderPath("Desktop")
$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$OutFile      = $null

# ===== CACHES Y ESTADO GLOBAL =====
$script:AuditWarnings = New-Object System.Collections.Generic.List[string]
$script:TrustCache = [hashtable]::Synchronized(@{})
$script:ExecutablePathCache = [hashtable]::Synchronized(@{})
$script:ReportPrivacyProfile = $null
$script:FatalError = $null
$script:StepIndex = 0

# ===== WHITELIST DE PATHS LEGÍTIMOS (con variables de entorno) =====
$script:WhitelistPathsRaw = @(
    "%LOCALAPPDATA%\Google",
    "%LOCALAPPDATA%\Microsoft",
    "%APPDATA%\Spotify",
    "%APPDATA%\Discord",
    "%APPDATA%\Slack",
    "%APPDATA%\Telegram Desktop",
    "%APPDATA%\Zoom",
    "%ProgramFiles%\WindowsApps",
    "%ProgramFiles%\Microsoft",
    "%ProgramFiles(x86)%\Microsoft"
)

# ===== FUNCIONES AUXILIARES (definidas al principio) =====
function Write-Info {
    param([string]$Message, [ConsoleColor]$Color = 'White')
    Write-Host $Message -ForegroundColor $Color
}

function Add-Warning {
    param([string]$Message)
    $script:AuditWarnings.Add($Message) | Out-Null
    Write-Info -Message "WARN: $Message" -Color Yellow
}

function Clear-CachesIfNeeded {
    if ($script:TrustCache.Count -gt $MaxCacheSize) {
        $script:TrustCache.Clear()
        Add-Warning "Caché de TrustCache limpiada por exceder $MaxCacheSize elementos"
    }
    if ($script:ExecutablePathCache.Count -gt $MaxCacheSize) {
        $script:ExecutablePathCache.Clear()
        Add-Warning "Caché de ExecutablePathCache limpiada por exceder $MaxCacheSize elementos"
    }
}

function Read-Choice {
    param(
        [string]$Prompt,
        [string[]]$Allowed,
        [string]$Default
    )

    $isInteractive = $Host.Name -eq 'ConsoleHost' -and [Environment]::UserInteractive

    if (-not $isInteractive) {
        Write-Info "$Prompt [usando default: $Default]" -Color Yellow
        return $Default
    }

    while ($true) {
        $suffix = if ($Default) { " [$Default]" } else { "" }
        $answer = Read-Host "$Prompt$suffix"
        if ($null -eq $answer) { $answer = "" }
        $answer = $answer.Trim()

        if (-not $answer -and $Default) {
            $answer = $Default
        }

        if ($Allowed -contains $answer) {
            return $answer
        }

        Write-Info "Valor no válido. Opciones permitidas: $($Allowed -join ', ')" -Color Yellow
    }
}

function Confirm-DestructiveAction {
    param(
        [string]$Action,
        [string]$Target
    )

    $isInteractive = $Host.Name -eq 'ConsoleHost' -and [Environment]::UserInteractive
    if (-not $isInteractive) {
        Write-Info "Modo no interactivo: omitiendo acción destructiva '$Action' en '$Target'" -Color Yellow
        return $false
    }

    Write-Info "⚠️  ACCIÓN DESTRUCTIVA: $Action" -Color Red
    Write-Info "   Objetivo: $Target" -Color Yellow
    $confirm = Read-Choice -Prompt "¿Estás seguro? (S/N)" -Allowed @("S","N","s","n") -Default "N"
    return ($confirm.ToUpper() -eq "S")
}

function Get-ReportPrivacyProfile {
    Write-Info "" -Color Cyan
    Write-Info "==================================================" -Color Cyan
    Write-Info "CONFIGURACIÓN DE PRIVACIDAD DEL INFORME" -Color Cyan
    Write-Info "==================================================" -Color Cyan
    Write-Info "Elige cómo quieres generar la revisión maestra:"
    Write-Info ""
    Write-Info "1) FULL / INTERNO"
    Write-Info "   Máximo detalle para análisis local. No recomendado para compartir."
    Write-Info ""
    Write-Info "2) REVIEW / CHAT-SAFE  (recomendado)"
    Write-Info "   Oculta datos sensibles del equipo y mantiene contexto útil."
    Write-Info ""
    Write-Info "3) PERSONALIZADO"
    Write-Info "   Tú decides qué mostrar u ocultar en hashes, rutas, IDs y red."
    Write-Info ""

    $modeChoice = Read-Choice -Prompt "Escribe 1, 2 o 3" -Allowed @("1","2","3") -Default "2"

    $profile = [ordered]@{
        Mode            = "Review"
        IncludeSHA      = $false
        PathMode        = "Redacted"
        CommandLineMode = "Redacted"
        IdMode          = "Masked"
        NetworkMode     = "Masked"
    }

    switch ($modeChoice) {
        "1" {
            $profile.Mode            = "Full"
            $profile.IncludeSHA      = $true
            $profile.PathMode        = "Full"
            $profile.CommandLineMode = "Full"
            $profile.IdMode          = "Full"
            $profile.NetworkMode     = "Full"
        }

        "2" {
            $profile.Mode            = "Review"
            $profile.IncludeSHA      = $false
            $profile.PathMode        = "Redacted"
            $profile.CommandLineMode = "Redacted"
            $profile.IdMode          = "Masked"
            $profile.NetworkMode     = "Masked"
        }

        "3" {
            $profile.Mode = "Custom"

            Write-Info "" -Color Cyan
            Write-Info "CONFIGURACIÓN PERSONALIZADA" -Color Cyan
            Write-Info ""

            $shaChoice = Read-Choice -Prompt "¿Incluir hashes SHA256 completos? (S/N)" -Allowed @("S","N","s","n") -Default "N"
            $profile.IncludeSHA = ($shaChoice.ToUpper() -eq "S")

            Write-Info ""
            Write-Info "RUTAS DE ARCHIVOS Y CARPETAS:"
            Write-Info "1) Full       -> completas"
            Write-Info "2) Redacted   -> redactadas"
            Write-Info "3) Hidden     -> ocultas"
            $pathChoice = Read-Choice -Prompt "Elige 1, 2 o 3" -Allowed @("1","2","3") -Default "2"
            $profile.PathMode = switch ($pathChoice) {
                "1" { "Full" }
                "2" { "Redacted" }
                "3" { "Hidden" }
            }

            Write-Info ""
            Write-Info "COMMAND LINE:"
            Write-Info "1) Full       -> completa"
            Write-Info "2) Redacted   -> redactada"
            Write-Info "3) Hidden     -> oculta"
            $cmdChoice = Read-Choice -Prompt "Elige 1, 2 o 3" -Allowed @("1","2","3") -Default "2"
            $profile.CommandLineMode = switch ($cmdChoice) {
                "1" { "Full" }
                "2" { "Redacted" }
                "3" { "Hidden" }
            }

            Write-Info ""
            Write-Info "IDs / IDENTIFICADORES INTERNOS:"
            Write-Info "1) Full       -> completos"
            Write-Info "2) Masked     -> enmascarados"
            Write-Info "3) Hidden     -> ocultos"
            $idChoice = Read-Choice -Prompt "Elige 1, 2 o 3" -Allowed @("1","2","3") -Default "2"
            $profile.IdMode = switch ($idChoice) {
                "1" { "Full" }
                "2" { "Masked" }
                "3" { "Hidden" }
            }

            Write-Info ""
            Write-Info "IPs / RED / DNS / PROXY:"
            Write-Info "1) Full       -> completos"
            Write-Info "2) Masked     -> enmascarados"
            Write-Info "3) Hidden     -> ocultos"
            $netChoice = Read-Choice -Prompt "Elige 1, 2 o 3" -Allowed @("1","2","3") -Default "2"
            $profile.NetworkMode = switch ($netChoice) {
                "1" { "Full" }
                "2" { "Masked" }
                "3" { "Hidden" }
            }
        }
    }

    Write-Info "" -Color Green
    Write-Info "RESUMEN DE PRIVACIDAD ELEGIDO" -Color Green
    Write-Info ("Modo............: {0}" -f $profile.Mode)
    Write-Info ("SHA256..........: {0}" -f ($(if ($profile.IncludeSHA) { "Sí" } else { "No" })))
    Write-Info ("Rutas...........: {0}" -f $profile.PathMode)
    Write-Info ("CommandLine.....: {0}" -f $profile.CommandLineMode)
    Write-Info ("IDs.............: {0}" -f $profile.IdMode)
    Write-Info ("Red / IPs.......: {0}" -f $profile.NetworkMode)
    Write-Info ""

    return [PSCustomObject]$profile
}

function Start-ReportStep {
    param([string]$Title)
    $script:StepIndex++
    Write-Info ("[{0:02}] {1}" -f $script:StepIndex, $Title) -Color DarkCyan
}

function Add-Section {
    param([string]$Title)
    $line = "`r`n=== $Title ==="
    Write-Info $line
    $line | Add-Content -Path $OutFile -Encoding UTF8
}

function Add-Text {
    param([string]$Text)
    $safeText = Protect-FieldValue -FieldName "" -Value $Text
    $safeText | Add-Content -Path $OutFile -Encoding UTF8
}

function Add-Object {
    param([object]$Obj)
    try {
        $safeObj = Convert-ReportObject -InputObject $Obj -Depth 0 -MaxDepth $MaxRecursionDepth
        if ($null -ne $safeObj) {
            ($safeObj | Out-String -Width 4096) | Add-Content -Path $OutFile -Encoding UTF8
        }
    } catch {
        $msg = $_.Exception.Message
        Add-Warning "Fallo serializando objeto: $msg"
        ("[SERIALIZATION_ERROR] {0}" -f $msg) | Add-Content -Path $OutFile -Encoding UTF8
    }
}

function Expand-EnvString {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    try {
        return [Environment]::ExpandEnvironmentVariables($Value)
    } catch {
        Add-Warning "No se pudo expandir variables de entorno: $Value"
        return $Value
    }
}

function Is-PathWhitelisted {
    param([string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { return $false }

    $lowerPath = $Path.ToLower()
    foreach ($rawPath in $script:WhitelistPathsRaw) {
        $expanded = Expand-EnvString -Value $rawPath
        if ([string]::IsNullOrEmpty($expanded)) { continue }
        $lowerWhitelist = $expanded.ToLower()
        if ($lowerPath -like "$lowerWhitelist*") {
            return $true
        }
    }
    return $false
}

function Protect-PathText {
    param(
        [string]$Text,
        [ValidateSet("Full","Redacted","Hidden")]
        [string]$Mode = "Redacted"
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    switch ($Mode) {
        "Full"   { return $Text }
        "Hidden" { return "[PATH_HIDDEN]" }
        "Redacted" {
            $s = $Text
            $s = $s -replace '(?i)\bC:\\Users\\[^\\]+', 'C:\Users\[USER]'
            $s = $s -replace '(?i)\bC:\\Program Files\\WindowsApps\\[^\\]+', 'C:\Program Files\WindowsApps\[APP_PACKAGE]'
            $s = $s -replace '(?i)\\AppData\\Local\\Packages\\[^\\]+', '\AppData\Local\Packages\[PACKAGE]'
            $s = $s -replace '(?i)\\AppData\\Roaming\\[^\\]+', '\AppData\Roaming\[APP]'
            $s = $s -replace '(?i)\\AppData\\Local\\[^\\]+', '\AppData\Local\[APP]'
            $s = $s -replace '(?i)\\ProgramData\\[^\\]+', '\ProgramData\[APP]'
            $s = [regex]::Replace($s, '(?i)\b([A-Z]:\\)(?:[^\\\r\n\|"]+\\)+([^\\\r\n\|"]+)', '$1[PATH_REDACTED]\$2')
            return $s
        }
    }
}

function Protect-HashText {
    param(
        [string]$Text,
        [bool]$IncludeSHA
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    if ($IncludeSHA) { return $Text }

    return ($Text -replace '\b[A-Fa-f0-9]{64}\b', '[SHA256_REDACTED]')
}

function Protect-IdText {
    param(
        [string]$Text,
        [ValidateSet("Full","Masked","Hidden")]
        [string]$Mode = "Masked"
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    switch ($Mode) {
        "Full"   { return $Text }
        "Hidden" { return "[ID_HIDDEN]" }
        "Masked" {
            $s = $Text
            $s = $s -replace '\b[a-p]{32}\b', '[EXTENSION_ID_REDACTED]'
            $s = $s -replace '\bS-\d-\d+(?:-\d+){1,14}\b', '[SID_REDACTED]'
            $s = $s -replace '\b[0-9a-fA-F]{8}\-(?:[0-9a-fA-F]{4}\-){3}[0-9a-fA-F]{12}\b', '[GUID_REDACTED]'
            return $s
        }
    }
}

function Protect-NetworkText {
    param(
        [string]$Text,
        [ValidateSet("Full","Masked","Hidden")]
        [string]$Mode = "Masked"
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    switch ($Mode) {
        "Full"   { return $Text }
        "Hidden" { return "[NETWORK_HIDDEN]" }
        "Masked" {
            $s = $Text
            $ipv4 = '(?<![\w-])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w-])'
            $ipv6 = '(?<![\w-])(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}(?![\w-])'
            $s = $s -replace $ipv4, '[IP_REDACTED]'
            $s = $s -replace $ipv6, '[IPv6_REDACTED]'
            return $s
        }
    }
}

function Protect-CommandLineText {
    param(
        [string]$Text,
        [ValidateSet("Full","Redacted","Hidden")]
        [string]$Mode = "Redacted"
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    switch ($Mode) {
        "Full"   { return $Text }
        "Hidden" { return "[COMMANDLINE_HIDDEN]" }
        "Redacted" {
            $m = [regex]::Match($Text, '(?i)([A-Za-z0-9._\-\s]+\.(exe|cmd|bat|ps1|vbs|js|dll))')
            if ($m.Success) {
                return "[COMMANDLINE_REDACTED] $($m.Groups[1].Value)"
            }
            return "[COMMANDLINE_REDACTED]"
        }
    }
}

function Protect-FieldValue {
    param(
        [string]$FieldName,
        [object]$Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [ValueType]) { return $Value }

    $text = [string]$Value
    if ($null -eq $script:ReportPrivacyProfile) { return $text }

    $skipTransform = @('DisplayName', 'ProductName', 'Name', 'ProcessName', 'Browser', 'Profile', 'Permission', 'Setting')
    if ($FieldName -in $skipTransform) {
        return $text
    }

    switch -Regex ($FieldName) {
        '^(SHA256|Hash)$' {
            return (Protect-HashText -Text $text -IncludeSHA $script:ReportPrivacyProfile.IncludeSHA)
        }

        '^(CommandLine|CommandLineTemplate|Arguments)$' {
            $result = Protect-CommandLineText -Text $text -Mode $script:ReportPrivacyProfile.CommandLineMode
            if ($script:ReportPrivacyProfile.IdMode -ne 'Full') {
                $result = Protect-IdText -Text $result -Mode $script:ReportPrivacyProfile.IdMode
            }
            if ($script:ReportPrivacyProfile.NetworkMode -ne 'Full') {
                $result = Protect-NetworkText -Text $result -Mode $script:ReportPrivacyProfile.NetworkMode
            }
            return $result
        }

        '^(Path|ExecutablePath|FilePath|ProcessPath|Program|ExecReal|PathName|FullName|File|Resources|Filename|Execute)$' {
            $result = Protect-PathText -Text $text -Mode $script:ReportPrivacyProfile.PathMode
            if ($script:ReportPrivacyProfile.IdMode -ne 'Full') {
                $result = Protect-IdText -Text $result -Mode $script:ReportPrivacyProfile.IdMode
            }
            return $result
        }

        '^(ExtensionId|UserId|Filter|Consumer|Id)$' {
            return (Protect-IdText -Text $text -Mode $script:ReportPrivacyProfile.IdMode)
        }

        '^(LocalAddress|RemoteAddress|ServerAddresses|ProxyServer|AutoConfigURL|Site|UpdateUrl|RemotePort|LocalPort)$' {
            return (Protect-NetworkText -Text $text -Mode $script:ReportPrivacyProfile.NetworkMode)
        }

        default {
            $result = $text
            if ($script:ReportPrivacyProfile.PathMode -ne 'Full') {
                $result = Protect-PathText -Text $result -Mode 'Redacted'
            }
            if ($script:ReportPrivacyProfile.IdMode -ne 'Full') {
                $result = Protect-IdText -Text $result -Mode 'Masked'
            }
            return $result
        }
    }
}

function Convert-ToReportSimpleValue {
    param(
        [string]$FieldName,
        [object]$Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [string] -or $Value -is [ValueType]) {
        return (Protect-FieldValue -FieldName $FieldName -Value $Value)
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        $flat = @()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            if ($item -is [string] -or $item -is [ValueType]) {
                $flat += (Protect-FieldValue -FieldName $FieldName -Value $item)
            } else {
                $flat += (Protect-FieldValue -FieldName $FieldName -Value ([string]$item))
            }
        }
        return ($flat -join " | ")
    }

    return (Protect-FieldValue -FieldName $FieldName -Value ([string]$Value))
}

function Convert-ReportObject {
    param(
        [object]$InputObject,
        [int]$Depth = 0,
        [int]$MaxDepth = $MaxRecursionDepth,
        [System.Collections.Generic.HashSet[object]]$Visited = $null
    )

    if ($Depth -gt $MaxDepth) {
        return "[MAX_DEPTH_RECURSION]"
    }

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [string]) {
        return (Protect-FieldValue -FieldName "" -Value $InputObject)
    }

    if ($InputObject -is [ValueType]) {
        return $InputObject
    }

    if ($null -eq $Visited) {
        $Visited = [System.Collections.Generic.HashSet[object]]::new()
    }

    if ($Visited.Contains($InputObject)) {
        return "[CIRCULAR_REFERENCE]"
    }
    $Visited.Add($InputObject) | Out-Null

    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ,(Convert-ReportObject -InputObject $item -Depth ($Depth + 1) -MaxDepth $MaxDepth -Visited $Visited)
        }
        return $items
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $dict = [ordered]@{}
        foreach ($k in $InputObject.Keys) {
            $dict[[string]$k] = Convert-ToReportSimpleValue -FieldName ([string]$k) -Value $InputObject[$k]
        }
        return [PSCustomObject]$dict
    }

    # Manejo seguro de objetos PSObject
    $isPsObject = $false
    try {
        $isPsObject = ($InputObject -is [psobject]) -or ($InputObject.PSObject -ne $null)
    } catch {
        $isPsObject = $false
    }

    if ($isPsObject) {
        try {
            $props = $InputObject.PSObject.Properties
            if ($props -and ($props.Count -gt 0)) {
                $out = [ordered]@{}
                foreach ($prop in $props) {
                    if (-not $prop.IsGettable) { continue }
                    $name = $prop.Name
                    if ($name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
                    try {
                        $out[$name] = Convert-ToReportSimpleValue -FieldName $name -Value $prop.Value
                    } catch {
                        $out[$name] = "[PROPERTY_READ_ERROR]"
                    }
                }
                return [PSCustomObject]$out
            }
        } catch {
            # No registrar warning aquí para evitar spam
        }
    }

    return (Protect-FieldValue -FieldName "" -Value ([string]$InputObject))
}

function Normalize-WindowsPath {
    param([string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { return $null }

    $p = $Path.Trim()

    if ($p.StartsWith('\\?\')) {
        $p = $p.Substring(4)
    } elseif ($p.StartsWith('\??\')) {
        $p = $p.Substring(4)
    }

    if ($p.StartsWith('"') -and $p.EndsWith('"')) {
        $p = $p.Trim('"')
    }

    $systemRoot = [Environment]::GetEnvironmentVariable("SystemRoot")
    if ([string]::IsNullOrEmpty($systemRoot)) {
        $systemRoot = "$env:WINDIR"
    }

    if ($p -match '^(\\SystemRoot|SystemRoot)\\') {
        $suffix = $p -replace '^(\\SystemRoot|SystemRoot)', ''
        return (Join-Path $systemRoot $suffix.TrimStart('\'))
    }

    if ($p -match '^system32\\') {
        return (Join-Path $systemRoot $p)
    }

    return (Expand-EnvString $p)
}

function Get-ExecutablePathFromCommandLine {
    param([string]$CommandLine)

    if ([string]::IsNullOrEmpty($CommandLine)) { return $null }

    Clear-CachesIfNeeded

    if ($script:ExecutablePathCache.ContainsKey($CommandLine)) {
        return $script:ExecutablePathCache[$CommandLine]
    }

    $cmd = Expand-EnvString ($CommandLine.Trim())
    if ([string]::IsNullOrEmpty($cmd)) {
        $script:ExecutablePathCache[$CommandLine] = $null
        return $null
    }

    $patterns = @(
        '^\s*"(?<path>[^"]+\.(?:exe|com|bat|cmd|dll|sys))"',
        '^\s*(?<path>[A-Za-z]:\\.*?\.(?:exe|com|bat|cmd|dll|sys))(?=\s|$)',
        '^\s*(?<path>%[^%]+%\\.*?\.(?:exe|com|bat|cmd|dll|sys))(?=\s|$)'
    )

    foreach ($pattern in $patterns) {
        $m = [regex]::Match($cmd, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($m.Success) {
            $candidate = Normalize-WindowsPath $m.Groups['path'].Value
            if ($candidate -and (Test-Path $candidate -PathType Leaf -ErrorAction SilentlyContinue)) {
                $script:ExecutablePathCache[$CommandLine] = $candidate
                return $candidate
            }
        }
    }

    $script:ExecutablePathCache[$CommandLine] = $null
    return $null
}

function Get-FileTrustInfo {
    param([string]$Path)

    $resolved = Normalize-WindowsPath $Path
    # Siempre devolver un objeto, nunca $null
    $defaultObj = [PSCustomObject]@{
        FilePath        = $null
        Exists          = $false
        SHA256          = ""
        SigStatus       = ""
        Signer          = ""
        Issuer          = ""
        CompanyName     = ""
        ProductName     = ""
        FileVersion     = ""
        IsWindowsPath   = $false
        IsMicrosoftHint = $false
    }

    if ([string]::IsNullOrEmpty($resolved)) {
        return $defaultObj
    }

    Clear-CachesIfNeeded

    if ($script:TrustCache.ContainsKey($resolved)) {
        return $script:TrustCache[$resolved]
    }

    $exists = Test-Path $resolved -PathType Leaf -ErrorAction SilentlyContinue

    $obj = [ordered]@{
        FilePath        = $resolved
        Exists          = $exists
        SHA256          = ""
        SigStatus       = ""
        Signer          = ""
        Issuer          = ""
        CompanyName     = ""
        ProductName     = ""
        FileVersion     = ""
        IsWindowsPath   = $false
        IsMicrosoftHint = $false
    }

    if (-not $exists) {
        $result = [PSCustomObject]$obj
        $script:TrustCache[$resolved] = $result
        return $result
    }

    $systemRoot = [Environment]::GetEnvironmentVariable("SystemRoot")
    if ([string]::IsNullOrEmpty($systemRoot)) {
        $systemRoot = "$env:WINDIR"
    }

    $lower = $resolved.ToLower()
    if ($lower -like "$($systemRoot.ToLower())*") {
        $obj.IsWindowsPath = $true
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $resolved -ErrorAction Stop
        $obj.SigStatus = [string]$sig.Status
        if ($sig.SignerCertificate) {
            $obj.Signer = [string]$sig.SignerCertificate.Subject
            $obj.Issuer = [string]$sig.SignerCertificate.Issuer
            if ($obj.Signer -match 'Microsoft') { $obj.IsMicrosoftHint = $true }
        }
    } catch {
        Add-Warning "No se pudo leer firma: $resolved"
    }

    try {
        $hash = Get-FileHash -Path $resolved -Algorithm SHA256 -ErrorAction Stop
        $obj.SHA256 = [string]$hash.Hash
    } catch {
        Add-Warning "No se pudo calcular SHA256: $resolved"
    }

    try {
        $vi = (Get-Item $resolved -ErrorAction Stop).VersionInfo
        $obj.CompanyName = [string]$vi.CompanyName
        $obj.ProductName = [string]$vi.ProductName
        $obj.FileVersion = [string]$vi.FileVersion
        if ($obj.CompanyName -match 'Microsoft') { $obj.IsMicrosoftHint = $true }
    } catch {
        Add-Warning "No se pudo leer VersionInfo: $resolved"
    }

    $result = [PSCustomObject]$obj
    $script:TrustCache[$resolved] = $result
    return $result
}

function Test-IsMicrosoftTrusted {
    param($TrustInfo)

    if ($null -eq $TrustInfo) { return $false }
    if (-not $TrustInfo.Exists) { return $false }
    if ($TrustInfo.SigStatus -ne 'Valid') { return $false }

    if ($TrustInfo.Signer -match 'Microsoft') { return $true }
    if ($TrustInfo.CompanyName -match 'Microsoft') { return $true }

    return $false
}

function Test-IsSuspiciousPath {
    param([string]$Path, [bool]$IsMicrosoftTrusted = $false)

    if ([string]::IsNullOrEmpty($Path)) { return $false }
    if ($IsMicrosoftTrusted) { return $false }
    if (Is-PathWhitelisted -Path $Path) { return $false }

    $lowerPath = $Path.ToLower()
    $suspiciousPatterns = @('appdata', 'temp\\', '\\users\\[^\\]+\\', '\\programdata\\', 'powershell', 'pwsh', 'cmd\.exe', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32')

    foreach ($pattern in $suspiciousPatterns) {
        if ($lowerPath -match $pattern) {
            return $true
        }
    }
    return $false
}

function Join-Reasons {
    param([string[]]$Reasons)
    $clean = @($Reasons | Where-Object { $_ } | Select-Object -Unique)
    return ($clean -join ' | ')
}

function Get-ChromiumProfiles {
    param([string]$UserDataPath)

    if (-not (Test-Path $UserDataPath)) { return @() }

    return Get-ChildItem -Path $UserDataPath -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(Default|Profile \d+)$' }
}

function Get-ChromiumExtensions {
    param(
        [string]$BrowserName,
        [string]$UserDataPath
    )

    $Results = @()
    if (-not (Test-Path $UserDataPath)) { return $Results }

    $Profiles = Get-ChromiumProfiles -UserDataPath $UserDataPath
    $warnedLargePrefs = $false

    foreach ($Profile in $Profiles) {
        $PrefPath = Join-Path $Profile.FullName "Preferences"
        $ExtSettings = $null
        try {
            if (Test-Path $PrefPath) {
                $RawContent = Get-Content -Path $PrefPath -Raw -ErrorAction Stop
                if ($RawContent.Length -lt 10MB) {
                    $Prefs = $RawContent | ConvertFrom-Json -ErrorAction Stop
                    $ExtSettings = $Prefs.extensions.settings
                } elseif (-not $warnedLargePrefs) {
                    Add-Warning "Preferences demasiado grande para parsear en $BrowserName (se omitirá el análisis de estado de extensiones)"
                    $warnedLargePrefs = $true
                }
            }
        } catch {
            Add-Warning "No se pudo parsear Preferences para extensiones: $BrowserName / $($Profile.Name)"
        }

        $ExtRoot = Join-Path $Profile.FullName "Extensions"
        if (-not (Test-Path $ExtRoot)) { continue }

        $ExtDirs = Get-ChildItem -Path $ExtRoot -Directory -ErrorAction SilentlyContinue
        foreach ($ExtDir in $ExtDirs) {
            $VersionDir = Get-ChildItem -Path $ExtDir.FullName -Directory -ErrorAction SilentlyContinue |
                Sort-Object {
                    try { [version]$_.Name } catch { [version]'0.0' }
                } -Descending |
                Select-Object -First 1

            $Enabled = $null
            $InstallType = ""
            $UpdateUrl = ""

            try {
                if ($ExtSettings -and $ExtSettings.PSObject.Properties.Name -contains $ExtDir.Name) {
                    $extNode = $ExtSettings.$($ExtDir.Name)
                    $Enabled = [bool]($extNode.state -eq 1)
                    $InstallType = [string]$extNode.location
                    $UpdateUrl = [string]$extNode.update_url
                }
            } catch {
                Add-Warning "No se pudo leer estado de extensión: $BrowserName / $($Profile.Name) / $($ExtDir.Name)"
            }

            if (-not $VersionDir) {
                $Results += [PSCustomObject]@{
                    Browser         = $BrowserName
                    Profile         = $Profile.Name
                    ExtensionId     = $ExtDir.Name
                    Name            = "[Sin manifest]"
                    Enabled         = $Enabled
                    InstallType     = $InstallType
                    UpdateUrl       = $UpdateUrl
                    Permissions     = ""
                    HostPermissions = ""
                    RiskFlags       = ""
                    Path            = $ExtDir.FullName
                }
                continue
            }

            $ManifestPath = Join-Path $VersionDir.FullName "manifest.json"
            if (-not (Test-Path $ManifestPath)) {
                $Results += [PSCustomObject]@{
                    Browser         = $BrowserName
                    Profile         = $Profile.Name
                    ExtensionId     = $ExtDir.Name
                    Name            = "[Sin manifest]"
                    Enabled         = $Enabled
                    InstallType     = $InstallType
                    UpdateUrl       = $UpdateUrl
                    Permissions     = ""
                    HostPermissions = ""
                    RiskFlags       = ""
                    Path            = $VersionDir.FullName
                }
                continue
            }

            try {
                $Manifest = Get-Content -Path $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $Name = [string]$Manifest.name
                if ([string]::IsNullOrEmpty($Name)) { $Name = "[Sin nombre]" }

                $Perms = @()
                if ($Manifest.permissions) {
                    $Perms += @($Manifest.permissions | ForEach-Object { [string]$_ })
                }

                $HostPerms = @()
                if ($Manifest.host_permissions) {
                    $HostPerms += @($Manifest.host_permissions | ForEach-Object { [string]$_ })
                }

                foreach ($p in $Perms) {
                    if ($p -match '^\<all_urls\>$' -or $p -match '^\*?https?:\/\/' -or $p -match '^\*://') {
                        $HostPerms += $p
                    }
                }

                $All = (($Perms + $HostPerms) -join " | ").ToLower()
                $Flags = @()
                if ($All -match '<all_urls>|\*://\*/\*|https?://\*/\*|http://\*/\*') { $Flags += "ALL_SITES" }
                if ($All -match 'cookies') { $Flags += "COOKIES" }
                if ($All -match 'webrequest') { $Flags += "WEBREQUEST" }
                if ($All -match 'webrequestblocking') { $Flags += "WEBREQUEST_BLOCKING" }
                if ($All -match 'tabs') { $Flags += "TABS" }
                if ($All -match 'history') { $Flags += "HISTORY" }
                if ($All -match 'clipboard(read|write)|clipboardread|clipboardwrite') { $Flags += "CLIPBOARD" }
                if ($All -match 'downloads') { $Flags += "DOWNLOADS" }
                if ($All -match 'debugger') { $Flags += "DEBUGGER" }
                if ($All -match 'nativemessaging') { $Flags += "NATIVE_MESSAGING" }

                $Results += [PSCustomObject]@{
                    Browser         = $BrowserName
                    Profile         = $Profile.Name
                    ExtensionId     = $ExtDir.Name
                    Name            = $Name
                    Enabled         = $Enabled
                    InstallType     = $InstallType
                    UpdateUrl       = $UpdateUrl
                    Permissions     = ($Perms -join " | ")
                    HostPermissions = ($HostPerms -join " | ")
                    RiskFlags       = ($Flags -join " | ")
                    Path            = $VersionDir.FullName
                }
            } catch {
                Add-Warning "No se pudo leer manifest de extensión: $BrowserName / $($Profile.Name) / $($ExtDir.Name)"
                $Results += [PSCustomObject]@{
                    Browser         = $BrowserName
                    Profile         = $Profile.Name
                    ExtensionId     = $ExtDir.Name
                    Name            = "[No se pudo leer manifest]"
                    Enabled         = $Enabled
                    InstallType     = $InstallType
                    UpdateUrl       = $UpdateUrl
                    Permissions     = ""
                    HostPermissions = ""
                    RiskFlags       = ""
                    Path            = $VersionDir.FullName
                }
            }
        }
    }

    return $Results
}

function Get-ChromiumSensitivePermissions {
    param(
        [string]$BrowserName,
        [string]$UserDataPath
    )

    $Results = @()
    if (-not (Test-Path $UserDataPath)) { return $Results }

    $Profiles = Get-ChromiumProfiles -UserDataPath $UserDataPath
    $warnedLargePrefs = $false

    foreach ($Profile in $Profiles) {
        $PrefPath = Join-Path $Profile.FullName "Preferences"
        if (-not (Test-Path $PrefPath)) { continue }

        try {
            $RawContent = Get-Content -Path $PrefPath -Raw -ErrorAction Stop
            if ($RawContent.Length -gt 10MB) {
                if (-not $warnedLargePrefs) {
                    Add-Warning "Preferences demasiado grande en $BrowserName, omitiendo permisos sensibles"
                    $warnedLargePrefs = $true
                }
                continue
            }
            $Prefs = $RawContent | ConvertFrom-Json -ErrorAction Stop
            $Patterns = $Prefs.profile.content_settings.exceptions.PSObject.Properties
            foreach ($Perm in $Patterns) {
                $PermName = $Perm.Name
                if ($PermName -notin @(
                    "notifications","push_messaging","media_stream_camera","media_stream_mic",
                    "geolocation","clipboard","popups","automatic_downloads"
                )) { continue }

                foreach ($Entry in $Perm.Value.PSObject.Properties) {
                    $Val = $Entry.Value.setting
                    $SettingText = switch ($Val) {
                        1 { "Allow" }
                        2 { "Block" }
                        3 { "Ask" }
                        default { [string]$Val }
                    }

                    $Results += [PSCustomObject]@{
                        Browser    = $BrowserName
                        Profile    = $Profile.Name
                        Permission = $PermName
                        Site       = $Entry.Name
                        Setting    = $SettingText
                    }
                }
            }
        } catch {
            Add-Warning "No se pudo parsear permisos sensibles: $BrowserName / $($Profile.Name)"
        }
    }

    return $Results
}

function Get-ChromiumSessionHints {
    param(
        [string]$BrowserName,
        [string]$UserDataPath
    )

    $Results = @()
    if (-not (Test-Path $UserDataPath)) { return $Results }

    $Profiles = Get-ChromiumProfiles -UserDataPath $UserDataPath
    $warnedLargePrefs = $false

    foreach ($Profile in $Profiles) {
        $PrefPath = Join-Path $Profile.FullName "Preferences"
        $HasAccountInfo = $false
        $HasSigninHint  = $false

        if (Test-Path $PrefPath) {
            try {
                $RawContent = Get-Content -Path $PrefPath -Raw -ErrorAction Stop
                if ($RawContent.Length -le 10MB) {
                    $Prefs = $RawContent | ConvertFrom-Json -ErrorAction Stop
                    if ($Prefs.account_info) { $HasAccountInfo = $true }
                    if ($Prefs.google -and $Prefs.google.services -and $Prefs.google.services.account_id) { $HasSigninHint = $true }
                } elseif (-not $warnedLargePrefs) {
                    Add-Warning "Preferences demasiado grande en $BrowserName, omitiendo indicadores de sesión"
                    $warnedLargePrefs = $true
                }
            } catch {
                Add-Warning "No se pudo parsear indicadores de sesión: $BrowserName / $($Profile.Name)"
            }
        }

        $Results += [PSCustomObject]@{
            Browser        = $BrowserName
            Profile        = $Profile.Name
            HasAccountInfo = $HasAccountInfo
            HasSigninHint  = $HasSigninHint
            CookiesFile    = (Test-Path (Join-Path $Profile.FullName "Network\Cookies"))
            LoginDataFile  = (Test-Path (Join-Path $Profile.FullName "Login Data"))
            WebDataFile    = (Test-Path (Join-Path $Profile.FullName "Web Data"))
        }
    }

    return $Results
}

function Get-ChromiumMetaMaskTextHits {
    param(
        [string]$BrowserName,
        [string]$UserDataPath
    )

    $Hits = @()
    if (-not (Test-Path $UserDataPath)) { return $Hits }

    $Profiles = Get-ChromiumProfiles -UserDataPath $UserDataPath
    foreach ($Profile in $Profiles) {
        foreach ($File in @(
            (Join-Path $Profile.FullName "Preferences"),
            (Join-Path $Profile.FullName "Secure Preferences")
        )) {
            if (-not (Test-Path $File)) { continue }

            try {
                $Raw = Get-Content -Path $File -Raw -ErrorAction Stop
                if ($Raw -and $Raw -match [regex]::Escape($MetaMaskId)) {
                    $Hits += [PSCustomObject]@{
                        Browser = $BrowserName
                        Profile = $Profile.Name
                        File    = $File
                    }
                }
            } catch {
                Add-Warning "No se pudo leer archivo para MetaMask textual: $BrowserName / $($Profile.Name) / $File"
            }
        }
    }

    return $Hits
}

function Remove-MetaMaskFolders {
    param([string]$Root, [string]$Label)
    if (-not (Test-Path $Root)) { return }

    if (-not (Confirm-DestructiveAction -Action "Eliminar carpetas de MetaMask" -Target "$Label en $Root")) {
        Add-Text "Eliminación de MetaMask cancelada por el usuario."
        return
    }

    foreach ($Profile in (Get-ChromiumProfiles -UserDataPath $Root)) {
        $ExtPath = Join-Path $Profile.FullName ("Extensions\" + $MetaMaskId)
        if (Test-Path $ExtPath) {
            Remove-Item $ExtPath -Recurse -Force -ErrorAction SilentlyContinue
            Add-Text ("Eliminado en {0}: {1}" -f $Label, $ExtPath)
        }
    }
}

function Get-RegistryValues {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return @() }

    try {
        $Props = Get-ItemProperty -Path $Path -ErrorAction Stop
        $result = $Props.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' } |
            Select-Object @{Name='RegistryKey';Expression={$Path}}, Name, Value
        return @($result)
    } catch {
        Add-Warning "No se pudo leer clave de registro: $Path"
        return @()
    }
}

# ===== INICIO DEL SCRIPT PRINCIPAL =====
try {
    $script:ReportPrivacyProfile = Get-ReportPrivacyProfile

    $ReportPrivacySuffix = switch ($script:ReportPrivacyProfile.Mode) {
        "Full"   { "full" }
        "Review" { "review" }
        "Custom" { "custom" }
        default  { "review" }
    }

    $OutFile = Join-Path $Desktop ("revision_maestra_seguridad_v3_4_1_{0}_{1}.txt" -f $ReportPrivacySuffix, $Timestamp)
    "MASTER SECURITY REVIEW v3.4.1 - $(Get-Date)" | Out-File $OutFile -Encoding UTF8

    if (-not $IsAdmin) {
        Add-Section "NOTA SOBRE PRIVILEGIOS"
        Add-Text "Este script se ejecutó SIN privilegios de administrador."
        Add-Text "La información de exclusiones de Defender y ciertos servicios puede estar incompleta."
        Add-Text "Para un análisis completo, ejecuta PowerShell como Administrador."
    }

    # Comprobación de disponibilidad de cmdlets de red (para sistemas antiguos)
    $netCmdletsAvailable = (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) -ne $null
    if (-not $netCmdletsAvailable) {
        Add-Warning "Cmdlets de red (Get-NetTCPConnection, etc.) no disponibles. Las secciones TCP/UDP/Firewall se omitirán."
    }

    $firewallCmdletsAvailable = (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) -ne $null
    if (-not $firewallCmdletsAvailable) {
        Add-Warning "Cmdlets de firewall (Get-NetFirewallRule) no disponibles. La sección de reglas de firewall se omitirá."
    }

    Start-ReportStep "Configuración de privacidad"
    Add-Section "CONFIGURACION DE PRIVACIDAD"
    Add-Object ([PSCustomObject]@{
        Mode            = $script:ReportPrivacyProfile.Mode
        IncludeSHA      = $script:ReportPrivacyProfile.IncludeSHA
        PathMode        = $script:ReportPrivacyProfile.PathMode
        CommandLineMode = $script:ReportPrivacyProfile.CommandLineMode
        IdMode          = $script:ReportPrivacyProfile.IdMode
        NetworkMode     = $script:ReportPrivacyProfile.NetworkMode
    })

    Start-ReportStep "Procesos"
    Add-Section "PROCESOS"
    $ProcBasic = Get-Process -ErrorAction SilentlyContinue | Sort-Object ProcessName |
        Select-Object ProcessName, Id, CPU, WS, Path
    Add-Object $ProcBasic

    Start-ReportStep "Servicios en ejecución"
    Add-Section "SERVICIOS EN EJECUCION"
    $SvcRunning = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Running' } |
        Sort-Object Name |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    Add-Object $SvcRunning

    Start-ReportStep "Procesos detallados"
    Add-Section "PROCESOS DETALLADOS"
    $ProcDetailed = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'System Idle Process' } |
        Sort-Object Name |
        Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine
    Add-Object $ProcDetailed

    Start-ReportStep "Procesos fuera de Windows (con firma)"
    Add-Section "PROCESOS FUERA DE WINDOWS (CON FIRMA)"
    $systemRoot = [Environment]::GetEnvironmentVariable("SystemRoot")
    if ([string]::IsNullOrEmpty($systemRoot)) { $systemRoot = "$env:WINDIR" }

    $ProcOutsideWindows = foreach ($proc in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $exe = $proc.ExecutablePath
        if ([string]::IsNullOrEmpty($exe)) { continue }

        $norm = Normalize-WindowsPath $exe
        if ([string]::IsNullOrEmpty($norm)) { continue }
        if ($norm.ToLower().StartsWith($systemRoot.ToLower())) { continue }

        $fi = Get-FileTrustInfo -Path $norm
        [PSCustomObject]@{
            Name               = $proc.Name
            ProcessId          = $proc.ProcessId
            ParentProcess      = $proc.ParentProcessId
            FilePath           = $fi.FilePath
            Exists             = $fi.Exists
            SigStatus          = $fi.SigStatus
            Signer             = $fi.Signer
            CompanyName        = $fi.CompanyName
            ProductName        = $fi.ProductName
            FileVersion        = $fi.FileVersion
            SHA256             = $fi.SHA256
            IsMicrosoftTrusted = (Test-IsMicrosoftTrusted $fi)
            CommandLine        = $proc.CommandLine
        }
    }
    Add-Object ($ProcOutsideWindows | Sort-Object Name, ProcessId)

    Start-ReportStep "Red TCP established"
    Add-Section "TCP ESTABLISHED"
    if ($netCmdletsAvailable) {
        $TcpEstablished = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Sort-Object RemoteAddress, RemotePort |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
                @{Name='ProcessName';Expression={ try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { 'N/A' } }},
                @{Name='ProcessPath';Expression={ try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).Path } catch { 'N/A' } }}
        Add-Object $TcpEstablished
    } else {
        Add-Text "Cmdlet Get-NetTCPConnection no disponible en este sistema."
    }

    Start-ReportStep "Red TCP listening"
    Add-Section "TCP LISTENING"
    if ($netCmdletsAvailable) {
        $TcpListening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
            $owningPid = $_.OwningProcess
            $pname = 'N/A'
            $ppath = 'N/A'
            $sigStatus = ''
            $signer = ''
            $company = ''

            try {
                $p = Get-Process -Id $owningPid -ErrorAction Stop
                $pname = $p.ProcessName
                $ppath = $p.Path
                if ($ppath) {
                    $fi = Get-FileTrustInfo -Path $ppath
                    $sigStatus = $fi.SigStatus
                    $signer = $fi.Signer
                    $company = $fi.CompanyName
                }
            } catch {}

            [PSCustomObject]@{
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                OwningProcess = $owningPid
                ProcessName   = $pname
                ProcessPath   = $ppath
                SigStatus     = $sigStatus
                Signer        = $signer
                CompanyName   = $company
            }
        }
        Add-Object ($TcpListening | Sort-Object LocalPort, ProcessName)
    } else {
        Add-Text "Cmdlet Get-NetTCPConnection no disponible en este sistema."
    }

    Start-ReportStep "Red UDP"
    Add-Section "UDP ENDPOINTS"
    if ($netCmdletsAvailable) {
        $UdpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Sort-Object LocalPort |
            Select-Object LocalAddress, LocalPort, OwningProcess,
                @{Name='ProcessName';Expression={ try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { 'N/A' } }},
                @{Name='ProcessPath';Expression={ try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).Path } catch { 'N/A' } }}
        Add-Object $UdpEndpoints
    } else {
        Add-Text "Cmdlet Get-NetUDPEndpoint no disponible en este sistema."
    }

    Start-ReportStep "Arranque y tareas"
    Add-Section "RUN / RUNONCE"
    $RunKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($Key in $RunKeys) {
        Add-Text ("--- {0} ---" -f $Key)
        Add-Object (Get-RegistryValues -Path $Key)
    }

    Add-Section "WINLOGON"
    $WinlogonKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )
    foreach ($Key in $WinlogonKeys) {
        Add-Text ("--- {0} ---" -f $Key)
        $Vals = Get-RegistryValues -Path $Key | Where-Object { $_.Name -in @("Shell","Userinit") }
        Add-Object $Vals
    }

    Add-Section "IFEO DEBUGGER"
    $IfeoRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $IfeoRoot) {
        try {
            $IfeoHits = Get-ChildItem -Path $IfeoRoot -ErrorAction Stop | ForEach-Object {
                $Debugger = Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
                if ($Debugger.Debugger) {
                    [PSCustomObject]@{
                        ImageName = $_.PSChildName
                        Debugger  = $Debugger.Debugger
                    }
                }
            }
            Add-Object ($IfeoHits | Sort-Object ImageName)
        } catch {
            Add-Warning "No se pudo enumerar IFEO Debugger."
            Add-Text "No disponible."
        }
    } else {
        Add-Text "No disponible."
    }

    Add-Section "APPINIT_DLLS"
    $AppInitPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )
    foreach ($Key in $AppInitPaths) {
        Add-Text ("--- {0} ---" -f $Key)
        $Vals = Get-RegistryValues -Path $Key | Where-Object { $_.Name -in @("AppInit_DLLs","LoadAppInit_DLLs","RequireSignedAppInit_DLLs") }
        Add-Object $Vals
    }

    Add-Section "STARTUP USER"
    $StartupUser = [Environment]::GetFolderPath("Startup")
    Add-Text ("Ruta: {0}" -f $StartupUser)
    $StartupUserItems = Get-ChildItem -Path $StartupUser -Force -ErrorAction SilentlyContinue |
        Select-Object Name, FullName, CreationTime, LastWriteTime
    Add-Object $StartupUserItems

    Add-Section "STARTUP ALL USERS"
    $StartupAll = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    Add-Text ("Ruta: {0}" -f $StartupAll)
    $StartupAllItems = Get-ChildItem -Path $StartupAll -Force -ErrorAction SilentlyContinue |
        Select-Object Name, FullName, CreationTime, LastWriteTime
    Add-Object $StartupAllItems

    Add-Section "TAREAS PROGRAMADAS NO MICROSOFT"
    $TaskReport = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskPath -notlike "\Microsoft\*"
    } | ForEach-Object {
        $Task = $_
        $Info = Get-ScheduledTaskInfo -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction SilentlyContinue

        $actions = @($Task.Actions)
        $ExecutableActions = $actions | Where-Object { $_.PSObject.Properties.Name -contains 'Execute' }
        $Exec = ($ExecutableActions | Select-Object -ExpandProperty Execute) -join " | "
        $Args = ($ExecutableActions | Where-Object { $_.PSObject.Properties.Name -contains 'Arguments' } | Select-Object -ExpandProperty Arguments) -join " | "

        $ExecReal = $null
        if (@($ExecutableActions).Count -gt 0) {
            $firstAction = $ExecutableActions | Select-Object -First 1
            $combined = ('"{0}" {1}' -f $firstAction.Execute, $firstAction.Arguments)
            $ExecReal = Get-ExecutablePathFromCommandLine -CommandLine $combined
            if ([string]::IsNullOrEmpty($ExecReal) -and $firstAction.Execute) {
                $ExecReal = Get-ExecutablePathFromCommandLine -CommandLine $firstAction.Execute
            }
        }

        $fi = Get-FileTrustInfo -Path $ExecReal
        if ($null -eq $fi) {
            $fi = [PSCustomObject]@{ FilePath = $null; Exists = $false; SigStatus = ""; Signer = ""; CompanyName = ""; SHA256 = ""; IsMicrosoftTrusted = $false }
        }
        $isMicrosoftTrusted = Test-IsMicrosoftTrusted $fi

        [PSCustomObject]@{
            TaskName           = $Task.TaskName
            TaskPath           = $Task.TaskPath
            State              = $Task.State
            Hidden             = $Task.Settings.Hidden
            Author             = $Task.Author
            UserId             = $Task.Principal.UserId
            RunLevel           = $Task.Principal.RunLevel
            Execute            = $Exec
            Arguments          = $Args
            ExecReal           = $fi.FilePath
            ExecExists         = $fi.Exists
            SigStatus          = $fi.SigStatus
            Signer             = $fi.Signer
            CompanyName        = $fi.CompanyName
            SHA256             = $fi.SHA256
            IsMicrosoftTrusted = $isMicrosoftTrusted
            LastRunTime        = $Info.LastRunTime
            NextRunTime        = $Info.NextRunTime
            LastTaskResult     = $Info.LastTaskResult
        }
    }
    Add-Object ($TaskReport | Sort-Object TaskPath, TaskName)

    Add-Section "TAREAS FILTRADAS SOSPECHOSAS"
    $SuspiciousTasks = $TaskReport | ForEach-Object {
        $Reasons = @()

        if (Test-IsSuspiciousPath -Path $_.Execute -IsMicrosoftTrusted $_.IsMicrosoftTrusted) {
            $Reasons += "SUSPICIOUS_PATH"
        }
        if (Test-IsSuspiciousPath -Path $_.Arguments -IsMicrosoftTrusted $_.IsMicrosoftTrusted) {
            $Reasons += "SUSPICIOUS_ARGUMENTS"
        }

        if (-not $_.ExecReal) {
            $Reasons += "NO_EXEC_REAL"
        } elseif (-not $_.ExecExists) {
            $Reasons += "EXEC_NOT_FOUND"
        }

        if ($_.ExecExists -and $_.SigStatus -and $_.SigStatus -ne 'Valid' -and -not $_.IsMicrosoftTrusted) {
            $Reasons += "INVALID_SIGNATURE"
        }

        if ($Reasons.Count -gt 0) {
            $_ | Add-Member -NotePropertyName Reason -NotePropertyValue (Join-Reasons $Reasons) -Force
            $_
        }
    }
    Add-Object ($SuspiciousTasks | Sort-Object TaskPath, TaskName)

    Start-ReportStep "Defender, red sutil y WMI"
    Add-Section "DEFENDER - EXCLUSIONES"
    try {
        $Mp = Get-MpPreference
        $MpSummary = [PSCustomObject]@{
            ExclusionPath      = ($Mp.ExclusionPath -join " | ")
            ExclusionExtension = ($Mp.ExclusionExtension -join " | ")
            ExclusionProcess   = ($Mp.ExclusionProcess -join " | ")
            ExclusionIpAddress = ($Mp.ExclusionIpAddress -join " | ")
        }
        Add-Object $MpSummary
    } catch {
        $errMsg = if (-not $IsAdmin) { "Ejecuta como Administrador para ver exclusiones." } else { "No se pudo leer Get-MpPreference." }
        Add-Warning $errMsg
        Add-Text $errMsg
    }

    Add-Section "DEFENDER - ESTADO"
    try {
        $MpStatus = Get-MpComputerStatus | Select-Object FullScanAge, QuickScanAge, AntivirusEnabled, RealTimeProtectionEnabled
        Add-Object $MpStatus
    } catch {
        Add-Warning "No se pudo leer Get-MpComputerStatus."
        Add-Text "No disponible."
    }

    Add-Section "PROXY WINHTTP"
    try {
        Add-Text (netsh winhttp show proxy | Out-String)
    } catch {
        Add-Warning "No se pudo leer proxy WinHTTP."
        Add-Text "No disponible."
    }

    Add-Section "PROXY USUARIO"
    try {
        $ProxyKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $ProxyUser = Get-ItemProperty -Path $ProxyKey -ErrorAction Stop |
            Select-Object ProxyEnable, ProxyServer, AutoConfigURL, AutoDetect
        Add-Object $ProxyUser
    } catch {
        Add-Warning "No se pudo leer proxy de usuario."
        Add-Text "No disponible."
    }

    Add-Section "DNS"
    try {
        $Dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } |
            Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses
        Add-Object $Dns
    } catch {
        Add-Warning "No se pudo leer DNS."
        Add-Text "No disponible."
    }

    Add-Section "HOSTS"
    $HostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
    if (Test-Path $HostsPath) {
        try {
            $HostsLines = Get-Content $HostsPath -ErrorAction Stop |
                Where-Object { $_.Trim() -and -not $_.Trim().StartsWith("#") }
            Add-Object $HostsLines
        } catch {
            Add-Warning "No se pudo leer hosts."
            Add-Text "No disponible."
        }
    }

    Add-Section "SERVICIOS SOSPECHOSOS"
    try {
        $SuspiciousServices = Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
            $RawPath = $_.PathName
            $ExecReal = Get-ExecutablePathFromCommandLine -CommandLine $RawPath
            $fi = Get-FileTrustInfo -Path $ExecReal
            $isMicrosoftTrusted = Test-IsMicrosoftTrusted $fi

            $Reasons = @()

            if (Test-IsSuspiciousPath -Path $fi.FilePath -IsMicrosoftTrusted $isMicrosoftTrusted) {
                $Reasons += "SUSPICIOUS_PATH"
            }

            if (-not $fi.FilePath) {
                $Reasons += "NO_EXEC_REAL"
            } elseif (-not $fi.Exists) {
                $Reasons += "EXEC_NOT_FOUND"
            }

            if ($RawPath -match 'powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32') {
                $Reasons += "SCRIPT_OR_INTERPRETER"
            }

            if ($fi.Exists -and $fi.SigStatus -and $fi.SigStatus -ne 'Valid' -and -not $isMicrosoftTrusted) {
                $Reasons += "INVALID_SIGNATURE"
            }

            if ($Reasons.Count -gt 0) {
                [PSCustomObject]@{
                    Name               = $_.Name
                    DisplayName        = $_.DisplayName
                    State              = $_.State
                    StartMode          = $_.StartMode
                    StartName          = $_.StartName
                    PathName           = $_.PathName
                    ExecReal           = $fi.FilePath
                    ExecExists         = $fi.Exists
                    SigStatus          = $fi.SigStatus
                    Signer             = $fi.Signer
                    CompanyName        = $fi.CompanyName
                    SHA256             = $fi.SHA256
                    IsMicrosoftTrusted = $isMicrosoftTrusted
                    Reason             = (Join-Reasons $Reasons)
                }
            }
        }
        Add-Object ($SuspiciousServices | Sort-Object Name)
    } catch {
        Add-Warning "No se pudo enumerar servicios sospechosos."
        Add-Text "No disponible."
    }

    Add-Section "SERVICIOS FUERA DE WINDOWS"
    try {
        $NonWindowsServices = foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
            $ExecReal = Get-ExecutablePathFromCommandLine -CommandLine $svc.PathName
            $fi = Get-FileTrustInfo -Path $ExecReal
            if (-not $fi.FilePath) { continue }
            if ($fi.IsWindowsPath) { continue }

            [PSCustomObject]@{
                Name               = $svc.Name
                DisplayName        = $svc.DisplayName
                State              = $svc.State
                StartMode          = $svc.StartMode
                StartName          = $svc.StartName
                PathName           = $svc.PathName
                ExecReal           = $fi.FilePath
                ExecExists         = $fi.Exists
                SigStatus          = $fi.SigStatus
                Signer             = $fi.Signer
                CompanyName        = $fi.CompanyName
                ProductName        = $fi.ProductName
                FileVersion        = $fi.FileVersion
                SHA256             = $fi.SHA256
                IsMicrosoftTrusted = (Test-IsMicrosoftTrusted $fi)
            }
        }
        Add-Object ($NonWindowsServices | Sort-Object Name)
    } catch {
        Add-Warning "No se pudo enumerar servicios fuera de Windows."
        Add-Text "No disponible."
    }

    Add-Section "WMI __EventFilter"
    try {
        $WmiFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop |
            Select-Object Name, EventNamespace, QueryLanguage, Query
        Add-Object $WmiFilters
    } catch {
        Add-Warning "No se pudo leer WMI __EventFilter."
        Add-Text "No disponible."
    }

    Add-Section "WMI Consumers"
    try {
        $WmiCmd = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
            Select-Object Name, CommandLineTemplate, ExecutablePath
        $WmiScript = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue |
            Select-Object Name, ScriptingEngine, ScriptText
        $WmiLog = Get-CimInstance -Namespace root\subscription -ClassName LogFileEventConsumer -ErrorAction SilentlyContinue |
            Select-Object Name, FileName, Text
        Add-Object $WmiCmd
        Add-Object $WmiScript
        Add-Object $WmiLog
    } catch {
        Add-Warning "No se pudo leer WMI Consumers."
        Add-Text "No disponible."
    }

    Add-Section "WMI Bindings"
    try {
        $WmiBind = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop |
            Select-Object Filter, Consumer
        Add-Object $WmiBind
    } catch {
        Add-Warning "No se pudo leer WMI Bindings."
        Add-Text "No disponible."
    }

    Start-ReportStep "Firewall"
    Add-Section "REGLAS FIREWALL NO ESTANDAR"
    if ($firewallCmdletsAvailable) {
        $FwRules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | ForEach-Object {
            $r = $_
            $app = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
            if ($app.Program) {
                $fi = Get-FileTrustInfo -Path $app.Program
                [PSCustomObject]@{
                    DisplayName        = $r.DisplayName
                    Enabled            = $r.Enabled
                    Direction          = $r.Direction
                    Action             = $r.Action
                    Profile            = $r.Profile
                    Program            = $fi.FilePath
                    ProgramExists      = $fi.Exists
                    SigStatus          = $fi.SigStatus
                    Signer             = $fi.Signer
                    CompanyName        = $fi.CompanyName
                    IsMicrosoftTrusted = (Test-IsMicrosoftTrusted $fi)
                }
            }
        } | Where-Object {
            $_.Program -and $_.Program -notlike "$env:WINDIR\*" -and $_.Program -ne 'System'
        }
        Add-Object ($FwRules | Sort-Object DisplayName)

        Add-Section "REGLAS FIREWALL LLAMATIVAS"
        $FwSuspicious = $FwRules | ForEach-Object {
            $Reasons = @()

            if (Test-IsSuspiciousPath -Path $_.Program -IsMicrosoftTrusted $_.IsMicrosoftTrusted) {
                $Reasons += "SUSPICIOUS_PATH"
            }

            if (-not $_.ProgramExists) {
                $Reasons += "EXEC_NOT_FOUND"
            }

            if ($_.SigStatus -and $_.SigStatus -ne 'Valid' -and -not $_.IsMicrosoftTrusted) {
                $Reasons += "INVALID_SIGNATURE"
            }

            if ($Reasons.Count -gt 0) {
                $_ | Add-Member -NotePropertyName Reason -NotePropertyValue (Join-Reasons $Reasons) -Force
                $_
            }
        }
        Add-Object ($FwSuspicious | Sort-Object DisplayName)
    } else {
        Add-Text "Cmdlets de firewall no disponibles en este sistema."
    }

    Start-ReportStep "Navegadores"
    Add-Section "EXTENSIONES CHROME"
    $ChromeExt = Get-ChromiumExtensions -BrowserName "Chrome" -UserDataPath $ChromeRoot
    Add-Object ($ChromeExt | Sort-Object Profile, Name, ExtensionId)

    Add-Section "EXTENSIONES EDGE"
    $EdgeExt = Get-ChromiumExtensions -BrowserName "Edge" -UserDataPath $EdgeRoot
    Add-Object ($EdgeExt | Sort-Object Profile, Name, ExtensionId)

    $AllExt = @($ChromeExt) + @($EdgeExt)

    Add-Section "EXTENSIONES CON PERMISOS POTENTES"
    $RiskyExt = $AllExt | Where-Object { $_.RiskFlags }
    Add-Object ($RiskyExt | Sort-Object Browser, Profile, Name, ExtensionId)

    Add-Section "EXTENSIONES CON ACCESO A TODOS LOS SITIOS"
    $AllSitesExt = $AllExt | Where-Object { $_.RiskFlags -match 'ALL_SITES' }
    Add-Object ($AllSitesExt | Sort-Object Browser, Profile, Name, ExtensionId)

    Add-Section "PERMISOS SENSIBLES CHROME"
    $ChromePerms = Get-ChromiumSensitivePermissions -BrowserName "Chrome" -UserDataPath $ChromeRoot
    Add-Object ($ChromePerms | Sort-Object Permission, Site, Profile)

    Add-Section "PERMISSOS SENSIBLES EDGE"
    $EdgePerms = Get-ChromiumSensitivePermissions -BrowserName "Edge" -UserDataPath $EdgeRoot
    Add-Object ($EdgePerms | Sort-Object Permission, Site, Profile)

    Add-Section "PERMISSOS DELICADOS EN ALLOW"
    $SensitiveAllow = ((@($ChromePerms) + @($EdgePerms)) | Where-Object {
        $_.Setting -eq "Allow" -and $_.Permission -in @(

            "notifications","push_messaging","media_stream_camera","media_stream_mic","geolocation"
        )
    })
    Add-Object ($SensitiveAllow | Sort-Object Browser, Permission, Site, Profile)

    Add-Section "INDICADORES DE SESIÓN CHROME"
    $ChromeSessions = Get-ChromiumSessionHints -BrowserName "Chrome" -UserDataPath $ChromeRoot
    Add-Object ($ChromeSessions | Sort-Object Profile)

    Add-Section "INDICADORES DE SESIÓN EDGE"
    $EdgeSessions = Get-ChromiumSessionHints -BrowserName "Edge" -UserDataPath $EdgeRoot
    Add-Object ($EdgeSessions | Sort-Object Profile)

    Add-Section "RESTOS TEXTUALES DE METAMASK"
    $MetaHits = @()
    $MetaHits += Get-ChromiumMetaMaskTextHits -BrowserName "Chrome" -UserDataPath $ChromeRoot
    $MetaHits += Get-ChromiumMetaMaskTextHits -BrowserName "Edge" -UserDataPath $EdgeRoot
    if ($MetaHits.Count -eq 0) {
        Add-Text "No se detectan referencias textuales a MetaMask."
    } else {
        Add-Object ($MetaHits | Sort-Object Browser, Profile, File)
    }

    Start-ReportStep "Drivers"
    Add-Section "DRIVERS FUERA DE WINDOWS / NO MICROSOFT"
    try {
        $Drivers = Get-CimInstance Win32_SystemDriver -ErrorAction Stop | ForEach-Object {
            $ExecReal = Get-ExecutablePathFromCommandLine -CommandLine $_.PathName
            $fi = Get-FileTrustInfo -Path $ExecReal
            $isMicrosoftTrusted = Test-IsMicrosoftTrusted $fi
            $isInteresting = $false

            if (-not $fi.FilePath) {
                $isInteresting = $true
            } elseif (-not $fi.IsWindowsPath) {
                $isInteresting = $true
            } elseif (-not $isMicrosoftTrusted) {
                $isInteresting = $true
            }

            if ($isInteresting) {
                [PSCustomObject]@{
                    Name               = $_.Name
                    DisplayName        = $_.DisplayName
                    State              = $_.State
                    StartMode          = $_.StartMode
                    PathName           = $_.PathName
                    ExecReal           = $fi.FilePath
                    ExecExists         = $fi.Exists
                    SigStatus          = $fi.SigStatus
                    Signer             = $fi.Signer
                    CompanyName        = $fi.CompanyName
                    FileVersion        = $fi.FileVersion
                    SHA256             = $fi.SHA256
                    IsMicrosoftTrusted = $isMicrosoftTrusted
                }
            }
        }
        Add-Object ($Drivers | Sort-Object Name)
    } catch {
        Add-Warning "No se pudo enumerar drivers."
        Add-Text "No disponible."
    }

    Start-ReportStep "Hardening opcional"
    if ($ApplyUntappedHardening) {
        Add-Section "HARDENING UNTAPPED"
        if (Test-Path $UntappedPath) {
            Add-Text ("Untapped encontrado: {0}" -f $UntappedPath)

            if (Confirm-DestructiveAction -Action "Eliminar autoinicio de Untapped y bloquear inbound" -Target $UntappedPath) {
                $RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
                $RunProps = Get-ItemProperty -Path $RunKey -ErrorAction SilentlyContinue
                if ($RunProps) {
                    $Names = $RunProps.PSObject.Properties |
                        Where-Object {
                            $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' -and
                            [string]$_.Value -match 'untapped'
                        } |
                        Select-Object -ExpandProperty Name
                    foreach ($n in $Names) {
                        Remove-ItemProperty -Path $RunKey -Name $n -ErrorAction SilentlyContinue
                        Add-Text ("Eliminado del Run: {0}" -f $n)
                    }
                }

                $StartupFolder = [Environment]::GetFolderPath("Startup")
                Get-ChildItem -Path $StartupFolder -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match 'untapped' } |
                    ForEach-Object {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        Add-Text ("Eliminado de Startup: {0}" -f $_.FullName)
                    }

                if ($firewallCmdletsAvailable) {
                    $RuleName = "Block Inbound - Untapped Companion"
                    $ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
                    if (-not $ExistingRule) {
                        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -Enabled True -Program $UntappedPath -Profile Any | Out-Null
                        Add-Text ("Regla creada: {0}" -f $RuleName)
                    } else {
                        Add-Text ("La regla ya existe: {0}" -f $RuleName)
                    }
                } else {
                    Add-Text "No se pudo crear regla de firewall porque los cmdlets no están disponibles."
                }
            } else {
                Add-Text "Hardening de Untapped cancelado por el usuario."
            }
        } else {
            Add-Text "Untapped no encontrado."
        }
    }

    if ($RemoveMetaMaskFiles) {
        Add-Section "ELIMINAR METAMASK (CARPETAS)"
        if (Confirm-DestructiveAction -Action "Cerrar navegadores y eliminar MetaMask" -Target "Chrome y Edge") {
            Get-Process chrome, msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Remove-MetaMaskFolders -Root $ChromeRoot -Label "Chrome"
            Remove-MetaMaskFolders -Root $EdgeRoot -Label "Edge"
        } else {
            Add-Text "Eliminación de MetaMask cancelada por el usuario."
        }
    }

    Start-ReportStep "Detecciones Defender"
    Add-Section "DETECCIONES DEFENDER"
    try {
        $Threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Select-Object InitialDetectionTime, ThreatName, SeverityID, ActionSuccess, Resources
        if ($Threats) {
            Add-Object $Threats
        } else {
            Add-Text "Sin detecciones registradas."
        }
    } catch {
        Add-Warning "No se pudo consultar Get-MpThreatDetection."
        Add-Text "No disponible."
    }

    Start-ReportStep "Full scan opcional"
    if ($RunDefenderFullScan) {
        Add-Section "LANZAR FULL SCAN DEFENDER"
        try {
            if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
                Start-MpScan -ScanType FullScan
                Add-Text "Full Scan lanzado."
            } else {
                Add-Text "Start-MpScan no disponible en este sistema."
            }
        } catch {
            Add-Warning "No se pudo lanzar Start-MpScan."
            Add-Text "No se pudo lanzar Start-MpScan."
        }
    }

    Start-ReportStep "Avisos"
    Add-Section "AVISOS DE LECTURA / PARSE"
    if ($script:AuditWarnings.Count -eq 0) {
        Add-Text "Sin avisos."
    } else {
        Add-Object ($script:AuditWarnings | Sort-Object -Unique)
    }
}
catch {
    $script:FatalError = $_
    $fatalText = ($_ | Out-String).Trim()
    Write-Info "" -Color Red
    Write-Info "ERROR FATAL EN LA EJECUCIÓN" -Color Red
    Write-Info $fatalText -Color Red

    if ($OutFile) {
        try {
            Add-Section "ERROR FATAL"
            Add-Text $fatalText
        } catch {}
    }
}
finally {
    if ($OutFile) {
        try {
            Add-Section "FIN"
            Add-Text ("Informe guardado en: {0}" -f $OutFile)
            if ($script:FatalError) {
                Add-Text "Estado final: ERROR"
            } else {
                Add-Text "Estado final: OK"
                Add-Text ("Total de advertencias: {0}" -f $script:AuditWarnings.Count)
            }
        } catch {}
        Write-Info ("`nInforme guardado en: {0}" -f $OutFile) -Color Green
    }

    if ($PauseAtEnd) {
        Write-Info ""
        $isInteractive = $Host.Name -eq 'ConsoleHost' -and [Environment]::UserInteractive
        if ($isInteractive) {
            try {
                Read-Host "Pulsa Enter para cerrar" | Out-Null
            } catch {
                Write-Info ("No se pudo mantener la consola interactiva; esperando {0} segundos..." -f $FallbackPauseSeconds) -Color Yellow
                Start-Sleep -Seconds $FallbackPauseSeconds
            }
        } else {
            Write-Info ("Modo no interactivo detectado; esperando {0} segundos..." -f $FallbackPauseSeconds) -Color Yellow
            Start-Sleep -Seconds $FallbackPauseSeconds
        }
    }
}
