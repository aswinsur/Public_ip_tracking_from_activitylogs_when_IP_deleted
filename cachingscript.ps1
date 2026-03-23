<# 
    Purpose: Seed/Sync Automation variable PipLastKnownIps with last-known IPs of all (or scoped) Public IP resources.
    Usage examples:
      - Default (current subscription):         Start-AzAutomationRunbook ... -Name Seed-CacheAllPIPs
      - Specific RG only:                       ... -Name Seed-CacheAllPIPs -Parameters @{ ResourceGroup = "assurendran-rg" }
      - Multiple subs:                          ... -Name Seed-CacheAllPIPs -Parameters @{ SubscriptionIds = @("subId1","subId2") }
      - All accessible subs:                    ... -Name Seed-CacheAllPIPs -Parameters @{ AllSubscriptions = $true }
      - Dry run:                                ... -Name Seed-CacheAllPIPs -Parameters @{ WhatIf = $true }
      - Prune missing entries:                  ... -Name Seed-CacheAllPIPs -Parameters @{ PruneMissing = $true }
#>

param(
  [string] $ResourceGroup,
  [string[]] $SubscriptionIds,
  [switch] $AllSubscriptions,
  [switch] $PruneMissing,
  [switch] $WhatIf
)

Write-Output "### SEED/SYNC START ### $(Get-Date -Format o)"

# -------- Sign in with Managed Identity --------
try {
  Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
} catch {
  Write-Output "ERROR: Managed Identity sign-in failed. $_"
  return
}

# -------- Helper functions --------
function Normalize-ResourceId([string]$rid) {
  if ([string]::IsNullOrWhiteSpace($rid)) { return $rid }
  return $rid.Trim().ToLowerInvariant()
}

function Load-IpCache {
  try {
    $raw = Get-AutomationVariable -Name 'PipLastKnownIps'
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
    $ht = ConvertFrom-Json -InputObject $raw -AsHashtable
    # Repair any casing issues on load
    $fixed = @{}
    foreach ($k in $ht.Keys) {
      $lk = Normalize-ResourceId $k
      $fixed[$lk] = $ht[$k]
    }
    return $fixed
  } catch {
    Write-Output "WARN: Could not read Automation variable 'PipLastKnownIps'. Create it as a String with value {}."
    return @{}
  }
}

function Save-IpCache([hashtable]$cache) {
  try {
    $json = ($cache | ConvertTo-Json -Depth 5)
    if (-not $WhatIf) {
      Set-AutomationVariable -Name 'PipLastKnownIps' -Value $json
    }
  } catch {
    Write-Output "WARN: Failed to persist PipLastKnownIps. Ensure the variable exists (String) and MI has permissions. $_"
  }
}

# -------- Determine subscription list --------
$targetSubs = @()
if ($AllSubscriptions) {
  try {
    $targetSubs = (Get-AzSubscription -ErrorAction Stop | Select-Object -ExpandProperty Id)
  } catch {
    Write-Output "ERROR: Failed to list subscriptions. $_"
    return
  }
} elseif ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
  $targetSubs = $SubscriptionIds
} else {
  $ctx = Get-AzContext
  if (-not $ctx -or -not $ctx.Subscription.Id) {
    Write-Output "ERROR: No active Azure context or subscription found. Ensure the Managed Identity has Reader on at least one subscription."
    return
  }
  $targetSubs = @($ctx.Subscription.Id)
}

Write-Output ("Scanning {0} subscription(s)..." -f $targetSubs.Count)

# -------- Load existing cache --------
$cache = Load-IpCache
$initialCount = $cache.Count
$updated = 0
$pruned  = 0
$seenNow = New-Object 'System.Collections.Generic.HashSet[string]'

# -------- Enumerate PIPs --------
foreach ($sub in $targetSubs) {
  try {
    Select-AzSubscription -SubscriptionId $sub -ErrorAction Stop | Out-Null
    Write-Output "Using subscription: $sub"
  } catch {
    Write-Output "WARN: Cannot select subscription $sub. Skipping. $_"
    continue
  }

  # Get PIPs in scope
  try {
    if ($ResourceGroup) {
      $pips = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
    } else {
      $pips = Get-AzPublicIpAddress -ErrorAction SilentlyContinue
    }
  } catch {
    Write-Output "WARN: Failed to enumerate Public IPs in subscription $sub. $_"
    continue
  }

  foreach ($pip in $pips) {
    # Only cache if there is/was an actual IP address
    if (-not $pip.IpAddress) { continue }

    $ridKey = Normalize-ResourceId $pip.Id
    $entry = @{
      Ip   = $pip.IpAddress
      Name = $pip.Name
      When = (Get-Date).ToUniversalTime().ToString("s") + "Z"
    }

    $seenNow.Add($ridKey) | Out-Null

    $prevIp = $null
    if ($cache.ContainsKey($ridKey)) { $prevIp = $cache[$ridKey].Ip }

    if ($prevIp -ne $entry.Ip) {
      if ($WhatIf) {
        Write-Output "WhatIf: Cache set/update: $ridKey -> $($entry.Ip)"
      } else {
        $cache[$ridKey] = $entry
        $updated++
        Write-Output "Cache set/update: $ridKey -> $($entry.Ip)"
      }
    }
  }
}

# -------- Optional prune missing entries --------
if ($PruneMissing) {
  # Build current universe if we scanned multiple subs/RGs
  Write-Output "Pruning entries not seen in this run..."
  $toRemove = @()
  foreach ($k in $cache.Keys) {
    if (-not $seenNow.Contains($k)) { $toRemove += $k }
  }
  foreach ($k in $toRemove) {
    if ($WhatIf) {
      Write-Output "WhatIf: Prune $k"
    } else {
      $null = $cache.Remove($k)
      $pruned++
      Write-Output "Pruned: $k"
    }
  }
}

# -------- Save and summarize --------
if (-not $WhatIf) { Save-IpCache $cache }

Write-Output "### SEED/SYNC SUMMARY ###"
Write-Output ("Initial entries : {0}" -f $initialCount)
Write-Output ("Updated/Added   : {0}" -f $updated)
Write-Output ("Pruned          : {0}" -f $pruned)
Write-Output ("Final entries   : {0}" -f $cache.Count)
Write-Output "### SEED/SYNC END ###"
