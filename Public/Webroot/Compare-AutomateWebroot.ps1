function Compare-AutomateWebroot {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High')]
    param (
        [Parameter(ValueFromPipeline = $true)]
        $ComputerObject,

        # GSM key as defined in the Webroot Portal
        [Parameter(Mandatory = $true)]
        [string]$GsmKey,

        # Admin user that is used on the Webroot Portal (normally the one you login with)
        [Parameter(Mandatory = $true)]
        [string]$WebrootUser,

        # Admin user password that is used on the Webroot Portal (normally the one you login with)
        [Parameter(Mandatory = $true)]
        [string]$WebrootPassword,

        # API Client ID (Generated in Webroot Portal)
        [Parameter(Mandatory = $true)]
        [string]$APIClientID,

        # API Password (Generated in Webroot Portal)
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

        # Loop through the sites and put all endpoints in on Object
        foreach ($WebrootSite in $WebrootSites.sites) {
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

                If ($PSCmdlet.ShouldProcess("$($WebrootSite.SiteName): Perform an endpoint deactivation of $($Body.EndpointsList) comprising of $(($SiteEndpoints | ?{$_.ShouldBeDeleted} | Select-Object -ExpandProperty HostName) -join ",")")) {
                    # Add code here that does an invoke to remove
                    try{
                        $Test = "Remove"
                    }
                    catch
                    {
                        $Catch = "Error"
                    }
                }
            }
            
            $WebrootEndpoints += $SiteEndpoints
        }

        # We now have all Computer Objects and all Webroot Endpoints. We now need to match them
        return $WebrootEndpoints
    }
    
}