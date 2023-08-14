param (
    [string]$hashes=".\hashes.txt",
    [string]$apy_kf=".\api.key",
    [string]$out="vt_result.txt"
)

Set-Variable -Name apiS -Value 0 -Scope Global
$api_keys = Get-Content -path $apy_kf
$api_keys = [array]$api_keys
$apiKey = ""
$result = @()

function NewToken() {
    if ($apiS -gt $api_keys.Length - 1) {
        Write-Host "All quotas exceeded"
        Set-Variable -Name apiS -Value 0 -Scope Global
        Start-Sleep -Seconds 15
    }
    Set-Variable -Name apiS -Value ($apiS + 1) -Scope Global
    Write-Host $api_keys[($apiS-1)]
	return $apiS - 1
}

function Process{
    param(
    $hashV,
	$headers,
	$apiKeys
    )
    $str =""
    $uri = "https://www.virustotal.com/api/v3/files/$hashV"
    Try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        $stats = $response.data.attributes.last_analysis_stats
        $sc = $stats.malicious + $stats.suspicious
        if ($sc -eq 0) {
            $str = "$hashV CLEAN"
        } else {
            $str = "$hashV MALICIOUS or SUSPICIOUS($sc)"
        }
    } Catch [System.Net.WebException] {
            if ($_ -like '*not found*') {
                $str = "$hashV CLEAN"
            } else {
                Write-Host $_
                $idx = NewToken
				$key = $api_keys[$idx]
				$headers = @{ "X-Apikey" = $key }
                $str = Process -hashV $hashV -headers $headers -apiKeys $api_keys
            }
    }
    return $str
}

$idx = NewToken
$key = $api_keys[$idx]
$headers = @{ "X-Apikey" = $key }

$progress = @()
if (-not (Test-Path -Path $out)) {
    New-Item -Path $out
}

foreach ($x in $(Get-Content -path $out)) {
    $progress += $x.Split(" ")[0]
    $result += $x
}

$i = 1

$count = (Get-Content $hashes).Length - ($progress | Get-Unique).Length

Get-Content $hashes | where {$_.Length -ne 0 -and !($_ -in $progress)} | ForEach-Object {
    $hash = $_
    $str = ""
    Write-Host $i / $count
    $i++
    $str = Process -hashV $hash -headers $headers -apiKeys $api_keys
    $result += $str
    Add-Content -Path $out -Value $str
}

$result | Out-File -FilePath $out