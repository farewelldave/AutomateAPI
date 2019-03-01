function Compare-AutomateWebroot {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High')]
    param (
        [Parameter(ValueFromPipeline = $true)]
        $ComputerObject,

        # GSM key as defined in the Webroot Portal
        [Parameter(ParameterSetName = 'manualcredential', Mandatory = $False)]
        [Parameter(Mandatory = $true)]
        [string]$GsmKey,

        # Admin user that is used on the Webroot Portal (normally the one you login with)
        [Parameter(ParameterSetName = 'manualcredential', Mandatory = $False)]
        [Parameter(Mandatory = $true)]
        [string]$WebrootUser,

        # Admin user password that is used on the Webroot Portal (normally the one you login with)
        [Parameter(ParameterSetName = 'manualcredential', Mandatory = $False)]
        [Parameter(Mandatory = $true)]
        [string]$WebrootPassword,

        # API Client ID (Generated in Webroot Portal)
        [Parameter(ParameterSetName = 'manualcredential', Mandatory = $False)]
        [Parameter(Mandatory = $true)]
        [string]$APIClientID,

        # API Password (Generated in Webroot Portal)
        [Parameter(ParameterSetName = 'manualcredential', Mandatory = $False)]
        [Parameter(Mandatory = $true)]
        [string]$APIPassword,

        # Remove any duplicates found, will keep the one that was last seen 
        [Parameter()]
        [switch]$RemoveDuplicates,

        # Supress host output 
        [Parameter()]
        [switch]$Quiet
    )
    begin {
        $AllComputerObjects = @()
        $FinalResultObject = @()
        $WebrootEndpoints = @()

        $BaseURL = 'https://unityapi.webrootcloudav.com'
        $TokenURL = "$BaseURL/auth/token"
        $SiteIDURL = "$BaseURL/service/api/console/gsm/$GsmKey/sites"
        $Credentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($APIClientID+":"+$APIPassword ))
    }
    
    process {
        $AllComputerObjects += $ComputerObject
    }
    
    end {
        # Get Token for Webroot
        $Token = Get-WebrootToken $Credentials $TokenURL $WebrootUser $WebrootPassword

        # Build the REST submission to get sites
        $Params = @{
                    "ErrorAction" = "Stop"
                    "URI" = $SiteIDURL
                    "ContentType" = "application/json"
                    "Headers" = @{"Authorization" = "Bearer "+ $Token.AccessToken}
                    "Method" = "Get"
                }

        # Get all the sites into one Variable
        $WebrootSites = Invoke-RestMethod @Params
        $FilteredWebrootSites = $WebrootSites.sites | Where-Object {$_.Deactivated -eq $false}

        # Loop through the sites and put all endpoints in on Object
        foreach ($WebrootSite in $FilteredWebrootSites) {
            If(!$Quiet){Write-Host -BackgroundColor Yellow -ForegroundColor Black "$($WebrootSite.SiteName) - Starting endpoint lookups"}
            $EndpointIDURL = "$BaseURL/service/api/console/gsm/$GsmKey/sites/$($WebrootSite.SiteId)/endpoints?type=activated%pageSize=300"
            $TimeDiff = Check-WebrootTokenTimer $Token.TokenStartTime
            #If Token is over 4 minutes old, get new one and reset timer
            if ($TimeDiff.Minutes -eq 4) {
                $Token = Get-WebrootToken $Credentials $TokenURL $WebrootUser $WebrootPassword
            }

            $Params2 = @{
                "ErrorAction" = "Stop"
                "URI" = $EndpointIDURL
                "ContentType" = "application/json"
                "Headers" = @{"Authorization" = "Bearer "+ $Token.AccessToken}
                "Method" = "Get"
            }
            
            # Get all endpoint for this particular site
            $SiteEndpoints = (Invoke-RestMethod @Params2).endpoints | Where-Object {$_.Deactivated -eq $false}
            If(!$Quiet){Write-Host -BackgroundColor Yellow -ForegroundColor Black "$($WebrootSite.SiteName) - Found $($SiteEndpoints.Count) activated endpoints"}

            # Add some parameters while we are here that will help later
            $SiteEndpoints | 
			foreach-object {$_|add-member -type noteproperty -name SiteName -value $($WebrootSite.SiteName);$_} | 
            foreach-object {$_|add-member -type noteproperty -name Duplicate -value $false;$_} | 
            foreach-object {$_|add-member -type noteproperty -name DuplicateOf -value "";$_} |
            foreach-object {$_|add-member -type noteproperty -name ShouldBeDeleted -value $false;$_} |
            foreach-object {$_|add-member -type noteproperty -name Explanation -value "";$_} |
            foreach-object {$_|add-member -type noteproperty -name MatchedToComputerID -value "";$_} |
            foreach-object {$_|add-member -type noteproperty -name MatchedToComputerName -value "";$_} |
            foreach-object {$_|add-member -type noteproperty -name MatchedToAutomateClient -value "";$_} |
            foreach-object {$_|add-member -type noteproperty -name SiteMismatch -value $False;$_} |
            foreach-object {$_|add-member -type noteproperty -name NeedsReview -value $False;$_} |
            foreach-object {$_|add-member -type noteproperty -name MatchedToMultipleMachines -value $false;$_} |
            foreach-object {$_|add-member -type noteproperty -name NoMacAddressMatch -value $false;$_} |   
			foreach-object {$_|add-member -type noteproperty -name SiteID -value $($WebrootSite.SiteId);$_} |
            foreach-object {$_|add-member -type noteproperty -name AutomateFriendlyMac -value $($_.MACAddress -replace ":", "-");$_} | Out-Null

            # Group by MAC Address so we can identify duplicates
            $WebrootSiteMACDuplicates = $SiteEndpoints | group-object -Property MACAddress | Where-Object -Filter {$_.Count -ge "2"}
            If(!$Quiet){Write-Host -BackgroundColor Red -ForegroundColor White "$($WebrootSite.SiteName) - Found $($WebrootSiteMACDuplicates.Count) endpoints that are duplicated"}
            
            # Loop through each group match of MAC addresses and update the Object
            foreach ($MACAddressDuplicateGroup in $WebrootSiteMACDuplicates) {
                foreach ($InvididualAgent in $MACAddressDuplicateGroup.Group)
                {
                    $Duplicates = ($MACAddressDuplicateGroup.Group | Where-Object {$_.EndpointID -ne $InvididualAgent.EndpointId} | Select -ExpandProperty HostName) -join ","
                    $LastSeenEndpointWinner = $MACAddressDuplicateGroup.Group | Sort-Object -Property {[DateTime]$_.LastSeen} -Descending | Select -First 1
                    If($LastSeenEndpointWinner.EndpointID -eq $InvididualAgent.EndpointID){$DeleteRequired = $False}else{$DeleteRequired = $True}

                    # Update the endpoint with what we have seen
                    $EndpointUpdate = $SiteEndpoints | Where-Object {$_.EndpointID -eq $InvididualAgent.EndpointId} | Select -First 1
                    $EndpointUpdate.DuplicateOf = $Duplicates
                    $EndpointUpdate.Duplicate = $True
                    $EndpointUpdate.Explanation = $EndpointUpdate.Explanation += "Duplicate agent. "
                    If($DeleteRequired){$EndpointUpdate.Explanation = $EndpointUpdate.Explanation += "Should be deleted. "}
                    $EndpointUpdate.ShouldBeDeleted = $DeleteRequired
                }
            }

            if (($RemoveDuplicates) -and (($SiteEndpoints | ?{$_.ShouldBeDeleted} | Measure-Object | Select-Object -ExpandProperty Count) -gt 0)) {
                $EndpointIDURLRemove = "$BaseURL/service/api/console/gsm/$GsmKey/sites/$($WebrootSite.SiteId)/endpoints/deactivate"
                $TimeDiff = Check-WebrootTokenTimer $Token.TokenStartTime
                #If Token is over 4 minutes old, get new one and reset timer
                if ($TimeDiff.Minutes -eq 4) {
                    $Token = Get-WebrootToken $Credentials $TokenURL $WebrootUser $WebrootPassword
                }

                $Body = @{
                     EndpointsList = ($SiteEndpoints | ?{$_.ShouldBeDeleted} | Select-Object -ExpandProperty EndpointID) -join ","
                }
                $JsonBody = $Body | ConvertTo-Json
    
                $Params3 = @{
                    "ErrorAction" = "Stop"
                    "URI" = $EndpointIDURLRemove
                    "ContentType" = "application/json"
                    "Headers" = @{"Authorization" = "Bearer "+ $Token.AccessToken}
                    "Method" = "POST"
                    "Body" = $JsonBody
                }

                
                Write-Host -ForegroundColor Black -BackgroundColor Green "Attempted to remove duplicates with $Result"

                If ($PSCmdlet.ShouldProcess("$($WebrootSite.SiteName): Perform an endpoint deactivation of $($Body.EndpointsList) comprising of $(($SiteEndpoints | ?{$_.ShouldBeDeleted} | Select-Object -ExpandProperty HostName) -join ",")")) {
                    # Add code here that does an invoke to remove
                    try{
                        $Result = Invoke-RestMethod @Params3
                    }
                    catch
                    {
                        Write-Output "Failed to remove endpoints with $($_.Exception.Message)"
                    }
                }
            }
            
            $WebrootEndpoints += $SiteEndpoints
        }

        # We now have all Computer Objects and all Webroot Endpoints. We now need to match them
        # Match on MAC Address
        foreach ($we in $WebrootEndpoints) {
            $CWAResult = $AllComputerObjects | Where-Object {$_.MacAddress -eq $we.AutomateFriendlyMac}
            $CWAResultCount = $CWAResult | Measure-Object | Select -ExpandProperty Count

            # There are duplicate macs
            if ($CWAResultCount -gt 1) {
                If(!$Quiet){Write-Warning "There are machines in Automate that have duplicate macs. $We.HostName in Webroot conflicts with $CWAResult"}
                $we.MatchedToMultipleMachines = $true
                $we.NeedsReview = $true
                $we.Explanation = $we.Explanation += "This agent has another computer in Automate with the same MAC address. "
            }

            # There is a matching mac
            If ($CWAResultCount -eq 1)
            {
                $we.MatchedToComputerID = $CWAResult.ID
                $We.MatchedToComputerName = $CWAResult.ComputerName
                $we.MatchedToAutomateClient = $CWAResult.Client.Name
                $we.Explanation = $we.Explanation += "Matched on MAC Address. "
                # Check the site matches too
                If ($CWAResult.Client.Name -ne $We.SiteName)
                {
                    $we.Explanation = $we.Explanation += "Site name doesn't match between Automate and Webroot. "
                    $we.SiteMismatch = $true
                }
            }

            # There are no macs matching
            If ($CWAResultCount -eq 0)
            {
                $we.NoMacAddressMatch = $true
                $we.Explanation = $we.Explanation += "Couldn't match by MAC Address. "
                # Try to match on full Computer Name
                $CWAResult2 = $AllComputerObjects | Where-Object {($we.Hostname -like "*$($_.ComputerName)*")}
                $CWAResultCount2 = $CWAResult2 | Measure-Object | Select -ExpandProperty Count
                
                # If there is a single match based on Computer Name
                If ($CWAResultCount2 -eq 1)
                {
                    $we.Explanation = $we.Explanation += "Matched on Computer Name. "
                    $we.MatchedToComputerID = $CWAResult2.ID
                    $We.MatchedToComputerName = $CWAResult2.ComputerName
                    $we.MatchedToAutomateClient = $CWAResult2.Client.Name
                    # Check the site matches too
                    If ($CWAResult2.Client.Name -ne $We.SiteName)
                    {
                        $we.SiteMismatch = $true
                        $we.NeedsReview = $true
                        $we.Explanation = $we.Explanation += "Site name doesn't match between Automate and Webroot. Needs review."
                    }
                }

                If ($CWAResultCount2 -gt 1)
                {
                    $we.Explanation = $we.Explanation += "Matched on Multiple Automate Computers so needs Manual Review. "
                    $we.NeedsReview = $true
                }

                If ($CWAResultCount2 -eq 0)
                {
                    $we.Explanation = $we.Explanation += "Couldn't match by Computer Name so should be deleted. "
                    $we.ShouldBeDeleted = $true
                }
                

            }

            

        }

        # Find sites which don't match - we should warn on them
        $WebrootSitesNotMatching = @()
        foreach ($site in $FilteredWebrootSites) {
            $SiteMatchTest = $FilteredWebrootSites | Where-Object {$AllComputerObjects.Client.Name -eq $Site.SiteName}
            $SiteMatchTestCount = $SiteMatchTest | Measure-Object | Select -ExpandProperty Count
            If($SiteMatchTestCount -eq 0)
            {
                $WebrootSitesNotMatching += $Site.SiteName
            }
        }

        If(!$Quiet){Write-Host -BackgroundColor Green -ForegroundColor Black "Total endpoints found in Webroot: $($WebrootEndpoints.Count)"}
        If(!$Quiet){Write-Host -BackgroundColor Green -ForegroundColor Black "Total endpoints found in Automate with Webroot: $($AllComputerObjects.Count)"}
        If(!$Quiet){Write-Host -BackgroundColor Red -ForegroundColor White "Unable to find site matches for: $(($WebrootSitesNotMatching) -join ',')"}


        return $WebrootEndpoints
    }
    
}