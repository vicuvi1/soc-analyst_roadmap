# Reads your public TryHackMe profile and writes thm.js next to index.html.
# The site re-reads thm.js every minute and ticks every room you have completed.
#   sync-thm.ps1            one sync, then exit
#   sync-thm.ps1 -Loop      sync every 2 minutes for up to 12 hours (started hidden by the launcher)
param([string]$User = 'vicuvi1', [switch]$Loop, [int]$EverySeconds = 120, [int]$MaxHours = 12)
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Sync-Thm {
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $codes = @(); $page = 1
    do {
      $url = "https://tryhackme.com/api/v2/public-profile/completed-rooms?username=$User&limit=100&page=$page"
      $r = Invoke-RestMethod -Uri $url -TimeoutSec 15 -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' -ErrorAction Stop
      $codes += @($r.data.docs | ForEach-Object { $_.code })
      $more = [bool]$r.data.hasNextPage; $page++
    } while ($more -and $page -le 30)
    if ($codes.Count -eq 0) { throw 'no rooms returned' }
    $ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $list = ($codes | ForEach-Object { '"' + ($_ -replace '[^A-Za-z0-9_\-]', '') + '"' }) -join ','
    $pf = 'null'
    try {
      $p = (Invoke-RestMethod -Uri "https://tryhackme.com/api/v2/public-profile?username=$User" -TimeoutSec 15 -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' -ErrorAction Stop).data
      $league = ([string]$p.leagueTier) -replace '[^A-Za-z]', ''
      $pf = "{level:$([int]$p.level),points:$([int]$p.totalPoints),rank:$([int]$p.rank),top:$([int]$p.topPercentage),badges:$([int]$p.badgesNumber),streak:$([int]$p.streak),best:$([int]$p.largestStreak),league:`"$league`",rooms:$([int]$p.completedRoomsNumber)}"
    } catch { }
    $js = "window.THM_SYNC={user:`"$User`",at:$ms,live:$(if ($Loop) { 'true' } else { 'false' }),codes:[$list],profile:$pf};"
    $tmp = Join-Path $dir 'thm.js.tmp'
    [IO.File]::WriteAllText($tmp, $js, (New-Object Text.UTF8Encoding($false)))
    Move-Item -Force $tmp (Join-Path $dir 'thm.js')
    Write-Host "TryHackMe sync: $($codes.Count) completed rooms."
  } catch {
    Write-Host "TryHackMe sync skipped: $($_.Exception.Message)"
  }
}

if (-not $Loop) { Sync-Thm; exit 0 }

# Loop mode: only one copy runs at a time.
$created = $false
$mutex = New-Object Threading.Mutex($true, 'SOC12_ThmSync', [ref]$created)
if (-not $created) { exit 0 }
try {
  $stop = (Get-Date).AddHours($MaxHours)
  while ((Get-Date) -lt $stop) { Sync-Thm; Start-Sleep -Seconds $EverySeconds }
} finally { $mutex.ReleaseMutex() }
