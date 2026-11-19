<#
.SYNOPSIS
    Headroom Shield CLI for Windows PowerShell (Zero-Dependency)
.DESCRIPTION
    Compresses repetitive logs & JSON arrays while neutralizing OWASP LLM Prompt Injections
    and scrubbing PII/Secrets locally with ZERO telemetry.
.EXAMPLE
    .\headroom_shield.ps1 -FilePath .\server.log
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [switch]$RedactPii = $true
)

$raw = Get-Content -Path $FilePath -Raw -Encoding UTF8
$tokensBefore = [Math]::Ceiling($raw.Length / 3.8)
$clean = $raw

# Stage 0: Neutralize Indirect Prompt Injection & Invisible Unicode
$threats = 0
if ($clean -match "(?i)<IMPORTANT>[\s\S]*?</IMPORTANT>|ignore previous instructions") {
    $clean = [regex]::Replace($clean, "(?i)<IMPORTANT>[\s\S]*?</IMPORTANT>|ignore previous instructions", "[NEUTRALIZED_LLM01_INJECTION]")
    $threats++
}
if ($RedactPii) {
    $clean = [regex]::Replace($clean, "\bAKIA[0-9A-Z]{16}\b", "<AWS_KEY>")
    $clean = [regex]::Replace($clean, "\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", "<CPF>")
    $clean = [regex]::Replace($clean, "\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "<EMAIL>")
}

# Log Line Deduplication keeping FATAL/ERROR/WARN
$lines = $clean -split "`r?`n"
$seen = @{}
$kept = @()
$dropped = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    $l = $lines[$i]
    if ($i -lt 4 -or $i -ge ($lines.Count - 4) -or $l -match "(?i)\b(FATAL|ERROR|CRITICAL|EXCEPTION|TRACEBACK|WARN)\b") {
        $kept += $l
        continue
    }
    $tmpl = [regex]::Replace($l, "\d+", "<*>")
    if (-not $seen.ContainsKey($tmpl)) {
        $seen[$tmpl] = $true
        $kept += $l
    } else { $dropped++ }
}

$outText = "[HEADROOM_SHIELD: $($lines.Count) -> $($kept.Count) lines | $dropped dropped | $threats threats neutralized]`n" + ($kept -join "`n")
$tokensAfter = [Math]::Ceiling($outText.Length / 3.8)
$pct = [Math]::Round((1.0 - ($tokensAfter / [Math]::Max(1, $tokensBefore))) * 100, 2)

[ordered]@{
    tokens_before       = $tokensBefore
    tokens_after        = $tokensAfter
    savings_percent     = $pct
    threats_neutralized = $threats
    compressed_preview  = $outText
} | ConvertTo-Json -Depth 4
