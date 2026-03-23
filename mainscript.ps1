param(
  [Parameter(Mandatory = $false)]
  [object] $WebhookData
)

# =========================================================
#  Public IP Alert Runbook (Log Alerts + Activity Log)
#  - Resolves exact IP via ARM with short polling
#  - Falls back to a "last known IP" cache (Automation Variable)
#  - Normalizes ResourceIds (lowercase, trimmed) to avoid key mismatches
#  - Robust cache lookup (tolerates stray whitespace / case / variants)
#  - Handles Log Alerts with/without inline SearchResults
#  - Fallbacks to Activity Log (Administrative) payload
#  - Emits pretty details AND a compact CSV + HTML table (Action, IP, EventTime, Caller)
#
#  Prereqs (one-time):
#   1) Automation Variable (String) named  PipLastKnownIps   with value {}
#   2) This Automation Account Managed Identity = Reader on your subscription(s)
#   3) Your Log Alert KQL emits PIP events (WRITE Success, DELETE Start/Accept/Succeeded,
#      NIC ipConfigurations/WRITE, LB/WRITE), window=10m, eval=1m
# =========================================================

# Buffer for CSV/HTML output (script-scope so helpers can append safely)
$script:__rows = New-Object System.Collections.Generic.List[object]
# -------------------- Guard & Parse ----------------------
if (-not $WebhookData) { throw "This runbook must be triggered via Azure Monitor webhook (Common Alert Schema)." }
$rawJson = [string]$WebhookData.RequestBody
$payload = $rawJson | ConvertFrom-Json
$ess     = $payload.data.essentials
$ctx     = $payload.data.alertContext

Write-Output "### RUNBOOK START ### $(Get-Date -Format o)"
Write-Output ("### Payload bytes: {0}" -f $rawJson.Length)

# ---------------- Managed Identity Sign-in ---------------
try {
  Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
} catch {
  Write-Output "ERROR: Managed Identity sign-in failed. $_"
  # We still want the finally{} to run (for consistent footer), so don't return from here
  throw
}

# -------------------- Helpers ----------------------------
function Normalize-ResourceId([string]$rid) {
  if ([string]::IsNullOrWhiteSpace($rid)) { return $rid }
  return $rid.Trim().ToLowerInvariant()
}

function Parse-PipResourceId([string]$rid) {
  $rid = Normalize-ResourceId $rid
  # /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/publicIPAddresses/<name>
  $m = [regex]::Match($rid, "/subscriptions/([^/]+)/resourcegroups/([^/]+)/providers/microsoft\.network/publicipaddresses/([^/]+)")
  if ($m.Success) {
    return @{ SubscriptionId=$m.Groups[1].Value; ResourceGroup=$m.Groups[2].Value; Name=$m.Groups[3].Value }
  }
  return @{ SubscriptionId=''; ResourceGroup=''; Name='' }
}

function Find-PipIds-InRawJson([string]$json) {
  $pat = "/subscriptions/[0-9a-fA-F-]+/resource[Gg]roups/[^/""\s]+/providers/Microsoft\.Network/publicIPAddresses/[^/""\s]+"
  $m = [Text.RegularExpressions.Regex]::Matches($json, $pat)
  if ($m.Count -gt 0) { return ($m | ForEach-Object { Normalize-ResourceId $_.Value } | Select-Object -Unique) }
  return @()
}

function Get-ActivityLog-PipId($essentials, $context, [string]$raw) {
  # Try alertTargetIDs first
  if ($essentials.alertTargetIDs) {
    $pip = ($essentials.alertTargetIDs | Where-Object { $_ -match "/providers/Microsoft\.Network/publicIPAddresses/" })[0]
    if ($pip) { return (Normalize-ResourceId $pip) }
  }
  # Then authorization.scope
  if ($context.authorization.scope -and $context.authorization.scope -match "/providers/Microsoft\.Network/publicIPAddresses/") {
    return (Normalize-ResourceId $context.authorization.scope)
  }
  # Then context.resourceId
  if ($context.resourceId -and $context.resourceId -match "/providers/Microsoft\.Network/publicIPAddresses/") {
    return (Normalize-ResourceId $context.resourceId)
  }
  # Finally, mine raw JSON
  $cands = Find-PipIds-InRawJson $raw
  if ($cands.Count -gt 0) { return $cands[0] }
  return $null
}

function Get-PipSnapshot([string]$resourceId, [int]$attempts = 8) {
  # Returns PSCustomObject { Name, Ip, Location, Sku, Allocation }
  $resourceId = Normalize-ResourceId $resourceId
  $out = [pscustomobject]@{ Name=''; Ip='N/A'; Location='N/A'; Sku='N/A'; Allocation='Unknown' }
  if ([string]::IsNullOrWhiteSpace($resourceId)) { return $out }

  for ($i=1; $i -le $attempts; $i++) {
    # 1) ARM GET
    try {
      $uri = "https://management.azure.com$resourceId?api-version=2023-09-01"
      $arm = Invoke-AzRestMethod -Method GET -Uri $uri -ErrorAction Stop
      $obj = $arm.Content | ConvertFrom-Json
      if ($obj) {
        $out.Name       = $obj.name
        $out.Ip         = $obj.properties.ipAddress
        $out.Location   = $obj.location
        $out.Sku        = $obj.sku.name
        $out.Allocation = $obj.properties.publicIPAllocationMethod
        if ($out.Allocation -eq 'Static' -and $out.Ip) { return $out }
        if ($out.Ip) { return $out }
      }
    } catch {
      try { if ($_.Exception.Response.StatusCode.Value__ -eq 404) { Write-Output "ARM GET 404 for $resourceId (already deleted or not yet available)." } } catch {}
    }

    # 2) Az cmdlet fallback (if module present)
    $parts = Parse-PipResourceId $resourceId
    if ($parts.ResourceGroup -and $parts.Name) {
      try {
        $pip = Get-AzPublicIpAddress -ResourceGroupName $parts.ResourceGroup -Name $parts.Name -ErrorAction Stop
        $out.Name       = $pip.Name
        $out.Ip         = $pip.IpAddress
        $out.Location   = $pip.Location
        $out.Sku        = $pip.Sku.Name
        $out.Allocation = $pip.PublicIpAllocationMethod
        if ($out.Allocation -eq 'Static' -and $out.Ip) { return $out }
        if ($out.Ip) { return $out }
      } catch { }
    }

    if ($i -lt $attempts) { Start-Sleep -Seconds 3 }
  }
  return $out
}

# --------------- Cache: load/save/get (robust) ----------
function Load-IpCache {
  try {
    $raw = Get-AutomationVariable -Name 'PipLastKnownIps'
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
    $ht = ConvertFrom-Json -InputObject $raw -AsHashtable
    # Normalize keys to lowercase+trim on load
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
    Set-AutomationVariable -Name 'PipLastKnownIps' -Value ($cache | ConvertTo-Json -Depth 5)
  } catch {
    Write-Output "WARN: PipLastKnownIps variable missing or write failed. Ensure a String variable named 'PipLastKnownIps' exists with initial value {}. $_"
  }
}
function Get-FromCache([hashtable]$cache, [string]$rid) {
  if (-not $cache -or -not $rid) { return $null }
  $needle = (Normalize-ResourceId $rid)
  if ($cache.ContainsKey($needle)) { return $cache[$needle] }
  foreach ($k in $cache.Keys) {
    if (([string]$k).Trim().ToLowerInvariant() -eq $needle) { return $cache[$k] }
  }
  return $null
}

$IpCache = Load-IpCache
# One more normalization pass (repairs any hand-edited values)
$norm = @{}
foreach ($k in $IpCache.Keys) {
  $nk = ([string]$k).Trim().ToLowerInvariant()
  $norm[$nk] = $IpCache[$k]
}
$IpCache = $norm
Write-Output ("CACHE: entries loaded = {0}" -f $IpCache.Count)

# ----------------- Emit / Print block -------------------
function Emit-Output([string]$rid, [string]$opName, [string]$status, [string]$time, [string]$caller) {
  $rid = Normalize-ResourceId $rid
  $parts = Parse-PipResourceId $rid
  $snap  = Get-PipSnapshot -resourceId $rid -attempts 8
  $action = if ($opName -match "delete") { "DELETE" } elseif ($opName -match "write") { "WRITE" } else { "UPDATE" }

  # Update cache if we have an IP now
  $nowIso = (Get-Date).ToUniversalTime().ToString("s") + "Z"
  if ($snap.Ip -and $snap.Ip -ne 'N/A') {
    $IpCache[$rid] = @{ Ip = $snap.Ip; Name = ($snap.Name ?? $parts.Name); When = $nowIso }
    Save-IpCache $IpCache
  }
  # DELETE fallback from cache
  if ($action -eq 'DELETE' -and ($snap.Ip -eq 'N/A' -or [string]::IsNullOrWhiteSpace($snap.Ip))) {
    $cached = Get-FromCache -cache $IpCache -rid $rid
    if ($cached) {
      if ($cached.Ip) {
        $snap.Ip = $cached.Ip
        if (-not $snap.Name) { $snap.Name = $cached.Name }
        Write-Output "INFO: Using cached IP ($($cached.Ip)) captured at $($cached.When)."
      } else {
        Write-Output "INFO: Cache entry has no IP for $rid."
      }
      # Optional cleanup after delete: remove any key variant equal to rid
      $removed = 0
      foreach ($k in @($IpCache.Keys)) {
        if (([string]$k).Trim().ToLowerInvariant() -eq $rid) {
          $null = $IpCache.Remove($k)
          $removed++
        }
      }
      if ($removed -gt 0) { Save-IpCache $IpCache }
    } else {
      Write-Output "INFO: No cache entry for $rid."
    }
  }

  # Pretty print (detailed)
  Write-Output "==============================="
  Write-Output " Azure Public IP Alert Details"
  Write-Output "==============================="
  Write-Output ("Action        : {0}" -f $action)
  Write-Output ("Status        : {0}" -f $status)
  Write-Output ("Public IP Name: {0}" -f $snap.Name)
  Write-Output ("IP Address    : {0}" -f $snap.Ip)
  Write-Output ("Location      : {0}" -f $snap.Location)
  Write-Output ("Allocation    : {0}" -f $snap.Allocation)
  Write-Output ("Resource ID   : {0}" -f $rid)
  Write-Output ("Caller        : {0}" -f $caller)
  Write-Output ("Event Time    : {0}" -f $time)
  Write-Output ("Subscription  : {0}" -f $parts.SubscriptionId)
  Write-Output ("ResourceGroup : {0}" -f $parts.ResourceGroup)
  Write-Output "==============================="

  [pscustomobject]@{
    Action        = $action
    Status        = $status
    Name          = $snap.Name
    IPAddress     = $snap.Ip
    Location      = $snap.Location
    Allocation    = $snap.Allocation
    ResourceId    = $rid
    Caller        = $caller
    EventTime     = $time
    Subscription  = $parts.SubscriptionId
    ResourceGroup = $parts.ResourceGroup
  } | ConvertTo-Json -Depth 5 | Write-Output

  # Collect compact row for CSV/HTML
  $script:__rows.Add([pscustomobject]@{
    Action    = $action
    IPAddress = $snap.Ip
    EventTime = $time
    Caller    = $caller
  })
}

function Finalize-CompactOutputs {
  if ($script:__rows -and $script:__rows.Count -gt 0) {
    $ordered = $script:__rows |
      Sort-Object Action, IPAddress, EventTime, Caller -Unique |
      Select-Object Action, IPAddress, EventTime, Caller

    Write-Output ""
    Write-Output "----- CSV (Action,IPAddress,EventTime,Caller) -----"
    ($ordered | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine | Write-Output

    $html = $ordered |
      ConvertTo-Html -Property Action, IPAddress, EventTime, Caller -PreContent @"
<style>
  body { font-family: Segoe UI, Arial, sans-serif; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ddd; padding: 8px; }
  th { background: #f3f3f3; text-align: left; }
  tr:nth-child(even) { background-color: #fafafa; }
</style>
<h3>Azure Public IP Events</h3>
<p>Fields: Action, IP Address, Event Time, Caller</p>
"@ -PostContent ""

    Write-Output ""
    Write-Output "----- HTML Table -----"
    Write-Output $html
  } else {
    Write-Output "No rows collected for CSV/HTML."
  }
}

# ================== MAIN WORKFLOW ==================
try {
  $signalType = $ess.signalType  # "Log" or "ActivityLog"
  $hasSearch = ($ctx -and $ctx.PSObject.Properties.Name -contains 'SearchResults' -and $ctx.SearchResults -ne $null)

  # Try to enrich Log alerts that omit SearchResults by calling the Results API
  if (-not $hasSearch -and $signalType -eq 'Log') {
    Write-Output "No inline SearchResults; trying condition.allOf links..."
    $links = @()
    try {
      foreach ($c in $ctx.condition.allOf) {
        if ($c.linkToFilteredSearchResultsAPI) { $links += $c.linkToFilteredSearchResultsAPI }
        elseif ($c.linkToSearchResultsAPI)     { $links += $c.linkToSearchResultsAPI }
      }
    } catch {}

    if ($links.Count -gt 0) {
      try {
        $token = (Get-AzAccessToken -ResourceUrl "https://api.loganalytics.io").Token
        foreach ($u in $links) {
          Write-Output "Fetching results via: $u"
          $resp = Invoke-RestMethod -Method GET -Uri $u -Headers @{ Authorization = "Bearer $token" }
          if ($resp -and $resp.tables -and $resp.tables.Count -gt 0) {
            $ctx | Add-Member -NotePropertyName "SearchResults" -NotePropertyValue $resp -Force
            $hasSearch = $true
            break
          }
        }
      } catch { Write-Output "WARN: Failed fetching SearchResults via API link. $_" }
    } else {
      Write-Output "No Results API links found in condition.allOf."
    }
  }

  # -------------------- LOG ALERT path ---------------------
  if ($signalType -eq 'Log' -and $hasSearch) {
    $table   = $ctx.SearchResults.tables[0]
    $columns = $table.columns
    $rows    = $table.rows

    function ColIndex([string]$n) { for ($i=0; $i -lt $columns.Count; $i++) { if ($columns[$i].name -eq $n) { return $i } }; return -1 }

    $ixRid = ColIndex "ResourceId"
    $ixOp  = ColIndex "OperationNameValue"
    $ixSt  = ColIndex "ActivityStatusValue"
    $ixTm  = ColIndex "TimeGenerated"
    $ixCl  = ColIndex "Caller"

    if ($rows -and $rows.Count -gt 0) {
      foreach ($r in $rows) {
        $rid = if ($ixRid -ge 0) { Normalize-ResourceId $r[$ixRid] } else { $null }
        if ([string]::IsNullOrWhiteSpace($rid)) {
          $rid = (Find-PipIds-InRawJson $rawJson | Select-Object -First 1)
        }
        if (-not $rid -or $rid -notmatch "microsoft\.network/publicipaddresses") {
          Write-Output "Row skipped (no PIP ResourceId): $rid"
          continue
        }

        $op  = if ($ixOp -ge 0) { $r[$ixOp] } else { "" }
        $st  = if ($ixSt -ge 0) { $r[$ixSt] } else { "" }
        $tm  = if ($ixTm -ge 0) { $r[$ixTm] } else { "" }
        $cl  = if ($ixCl -ge 0) { $r[$ixCl] } else { "" }

        Emit-Output -rid $rid -opName $op -status $st -time $tm -caller $cl
      }
      # Do NOT return; finalize will emit CSV/HTML
    } else {
      Write-Output "SearchResults present but empty."
    }
  }

  # --------------- ACTIVITY LOG fallback path --------------
  if (-not ($signalType -eq 'Log' -and $hasSearch)) {
    $ridAL = Get-ActivityLog-PipId -essentials $ess -context $ctx -raw $rawJson
    $opAL  = $ctx.operationName
    $stAL  = $ctx.status
    $tmAL  = $ctx.eventTimestamp
    $clAL  = $ctx.caller

    if ($ridAL -and $ridAL -match "microsoft\.network/publicipaddresses") {
      Emit-Output -rid $ridAL -opName $opAL -status $stAL -time $tmAL -caller $clAL
    } else {
      Write-Output "No usable Public IP ResourceId found in payload. SignalType='$signalType'."
      if ($ridAL) { Write-Output "Found RID candidate but not PIP: $ridAL" }
    }
  }

} finally {
  Finalize-CompactOutputs
  Write-Output "### RUNBOOK END ###"
}
