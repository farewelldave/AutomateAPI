iwr 'https://raw.githubusercontent.com/LabtechConsulting/ConnectWise-Manage-Powershell/master/CWManage.psm1' | iex
Import-Module "$PSScriptRoot\DataAccess\AutomateAPI" -Force
Import-Module "$PSScriptRoot\DataAccess\ControlAPI" -Force

$Script:LTPoShURI = 'https://raw.githubusercontent.com/LabtechConsulting/LabTech-Powershell-Module/master/LabTech.psm1'

#Ignore SSL errors
Add-Type -Debug:$False @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#Enable TLS, TLS1.1, TLS1.2 in this session if they are available
IF ([Net.SecurityProtocolType]::Tls) { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls }
IF ([Net.SecurityProtocolType]::Tls11) { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls11 }
IF ([Net.SecurityProtocolType]::Tls12) { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 }

function Compare-AutomateControlStatus
{
    <#
    .SYNOPSIS
    Compares Automate Online Status with Control, and outputs all machines online in Control and not in Automate
    .DESCRIPTION
    Compares Automate Online Status with Control, and outputs all machines online in Control and not in Automate
    .PARAMETER ComputerObject
    Can be taken from the pipeline in the form of Get-AutomateComputer -ComputerID 5 | Compare-AutomateControlStatus
    .PARAMETER AllResults
    Instead of outputting a comparison it outputs everything, which include two columns indicating online status
    .PARAMETER Quiet
    Doesn't output any log messages
    .OUTPUTS
    An object containing Online status for Control and Automate
    .NOTES
    Version:        1.4
    Author:         Gavin Stone
    Creation Date:  20/01/2019
    Purpose/Change: Initial script development

    Update Date:    2019-02-23
    Author:         Darren White
    Purpose/Change: Added SessionID parameter to Get-ControlSessions call.

    Update Date:    2019-02-26
    Author:         Darren White
    Purpose/Change: Reuse incoming object to preserve properties passed on the pipeline.

    Update Date:    2019-06-24
    Author:         Darren White
    Purpose/Change: Update to use objects returned by Get-ControlSessions

    .EXAMPLE
    Get-AutomateComputer -ComputerID 5 | Compare-AutomateControlStatus
    .EXAMPLE
    Get-AutomateComputer -Online $False | Compare-AutomateControlStatus
    #>
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true)]
		$ComputerObject,
		[Parameter()]
		[switch]$AllResults,
		[Parameter()]
		[switch]$Quiet
	)
	
	Begin
	{
		$ComputerArray = @()
		$ObjectRebuild = @()
		$ReturnedObject = @()
	}
	
	Process
	{
		If ($ComputerObject)
		{
			$ObjectRebuild += $ComputerObject
		}
	}
	
	End
	{
		# The primary concern now is to get out the ComputerIDs of the machines of the objects
		# We want to support all ComputerIDs being called if no computer object is passed in
		If (!$Quiet) { Write-Host -BackgroundColor Blue -ForegroundColor White "Checking to see if the recommended Internal Monitor is present" }
		$AutoControlSessions = @{ };
		$Null = Get-AutomateAPIGeneric -Endpoint "InternalMonitorResults" -allresults -condition "(Name like '%GetControlSessionIDs%')" -EA 0 | Where-Object { ($_.computerid -and $_.computerid -gt 0 -and $_.IdentityField -and $_.IdentityField -match '.+') } | ForEach-Object { $AutoControlSessions.Add($_.computerid, $_.IdentityField) };
		
		# Check to see if any Computers were specified in the incoming object
		If (!$ObjectRebuild.Count -gt 0) { $FullLookupMethod = $true }
		
		If ($FullLookupMethod)
		{
			$ObjectRebuild = Get-AutomateComputer -AllComputers | Select-Object Id, ComputerName, @{ Name = 'ClientName'; Expression = { $_.Client.Name } }, OperatingSystemName, Status
		}
		
		Foreach ($computer in $ObjectRebuild)
		{
			If (!$AutoControlSessions[[int]$Computer.ID])
			{
				$AutomateControlGUID = Get-AutomateControlInfo -ComputerID $($computer | Select-Object -ExpandProperty id) | Select-Object -ExpandProperty SessionID
			}
			Else
			{
				$AutomateControlGUID = $AutoControlSessions[[int]$Computer.ID]
			}
			
			$FinalComputerObject = $computer
			$Null = $FinalComputerObject | Add-Member -MemberType NoteProperty -Name ComputerID -Value $Computer.ID -Force -EA 0
			$Null = $FinalComputerObject | Add-Member -MemberType NoteProperty -Name OnlineStatusAutomate -Value $Computer.Status -Force -EA 0
			$Null = $FinalComputerObject | Add-Member -MemberType NoteProperty -Name SessionID -Value $AutomateControlGUID -Force -EA 0
			If ([string]::IsNullOrEmpty($Computer.ClientName))
			{
				$Null = $FinalComputerObject | Add-Member -MemberType NoteProperty -Name ClientName -Value $Computer.Client.Name -Force -EA 0
			}
			$Null = $FinalComputerObject.PSObject.properties.remove('ID')
			$Null = $FinalComputerObject.PSObject.properties.remove('Status')
			
			$ComputerArray += $FinalComputerObject
		}
		
		#GUIDs to get Control information for
		$GUIDsToLookupInControl = $ComputerArray | Where-Object { $_.SessionID -match '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' } | Select-Object -ExpandProperty SessionID
		If ($GUIDsToLookupInControl.Count -gt 100) { $GUIDsToLookupInControl = $Null } #For larger groups, just retrieve all sessions.
		
		#Control Sessions
		$ControlSessions = @{ };
		Get-ControlSessions -SessionID $GUIDsToLookupInControl | ForEach-Object { $ControlSessions.Add($_.SessionID, $($_ | Select-Object -Property OnlineStatusControl, LastConnected)) }
		
		Foreach ($Final in $ComputerArray)
		{
			$CAReturn = $Final
			If (![string]::IsNullOrEmpty($Final.SessionID))
			{
				If ($ControlSessions.Containskey($Final.SessionID))
				{
					$Null = $CAReturn | Add-Member -MemberType NoteProperty -Name OnlineStatusControl -Value $($ControlSessions[$Final.SessionID].OnlineStatusControl) -Force -EA 0
					$Null = $CAReturn | Add-Member -MemberType NoteProperty -Name LastConnectedControl -Value $($ControlSessions[$Final.SessionID].LastConnected) -Force -EA 0
				}
				Else
				{
					$Null = $CAReturn | Add-Member -MemberType NoteProperty -Name OnlineStatusControl -Value "GUID Not in Control or No Connection Events" -Force -EA 0
				}
			}
			Else
			{
				$Null = $CAReturn | Add-Member -MemberType NoteProperty -Name OnlineStatusControl -Value "Control not installed or GUID not in Automate" -Force -EA 0
			}
			
			$ReturnedObject += $CAReturn
		}
		
		If ($AllResults)
		{
			$ReturnedObject
		}
		Else
		{
			$ReturnedObject | Where-Object{ ($_.OnlineStatusControl -eq $true) -and ($_.OnlineStatusAutomate -eq 'Offline') }
		}
	}
}

function Connect-ControlSession
{
    <#
    .SYNOPSIS
        Will open a ConnectWise Control Remote Support session against a given machine.
    .DESCRIPTION
        Will open a ConnectWise Control Remote Support session against a given machine.

    .PARAMETER ComputerName
        The Automate computer name to connect to
    .PARAMETER ComputerID
        The Automate ComputerID to connect to
    .PARAMETER ID
        Taken from the Pipeline, IE Get-AutomateComputer -ComputerID 5 | Connect-ControlSession
    .PARAMETER ComputerObjects
        Used for Pipeline input from Get-AutomateComputer
    .OUTPUTS
        None (opens a Connect Control Remote Support session URL, via a URL to the default browser)
    .NOTES
        Version:        1.0
        Author:         Jason Rush
        Creation Date:  2019-10-15
        Purpose/Change: Initial script development

    .EXAMPLE
        Connect-ControlSession -ComputerName TestComputer
    .EXAMPLE
        Connect-ControlSession -ComputerId 123
    .EXAMPLE
        Get-AutomateComputer -ComputerID 5 | Connect-ControlSession
    #>
	[CmdletBinding(DefaultParameterSetName = 'Name')]
	param
	(
		[Parameter(ParameterSetName = 'Name', Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $False)]
		[string[]]$ComputerName,
		[Parameter(ParameterSetName = 'ID', Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $False)]
		[int16[]]$ComputerID,
		[Parameter(ParameterSetName = 'pipeline', ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
		[int16[]]$ID,
		[Parameter(ParameterSetName = 'pipeline', ValueFromPipeline = $true, Mandatory = $True)]
		$ComputerObjects
		
	)
	
	Process
	{
		#If not pipeline mode, build ComputerObjects
		If (($PSCmdlet.ParameterSetName -eq 'ID') -or ($PSCmdlet.ParameterSetName -eq 'Name'))
		{
			$ComputerObjects = @()
		}
		
		If ($PSCmdlet.ParameterSetName -eq 'ID')
		{
			ForEach ($ComputerIDSingle in $ComputerID)
			{
				$ComputerObjects += (Get-AutomateComputer -ComputerID $ComputerIDSingle)
			}
		}
		
		If ($PSCmdlet.ParameterSetName -eq 'Name')
		{
			ForEach ($ComputerNameSingle in $ComputerName)
			{
				$ComputerObjects += (Get-AutomateComputer -ComputerName $ComputerNameSingle)
			}
		}
		
		ForEach ($Computer in $ComputerObjects)
		{
			try
			{
				$(Get-AutomateControlInfo $Computer.ID).LaunchSession()
			}
			catch { }
		} #End ForEach
	} #End Process
	
} #End Connect-ControlSession

function Get-AutomateClient
{
    <#
    .SYNOPSIS
        Get Client information out of the Automate API
    .DESCRIPTION
        Connects to the Automate API and returns one or more full client objects
    .PARAMETER AllClients
        Returns all clients in Automate, regardless of amount
    .PARAMETER Condition
        A custom condition to build searches that can be used to search for specific things. Supported operators are '=', 'eq', '>', '>=', '<', '<=', 'and', 'or', '()', 'like', 'contains', 'in', 'not'.
        The 'not' operator is only used with 'in', 'like', or 'contains'. The '=' and 'eq' operator are the same. String values can be surrounded with either single or double quotes. IE (RemoteAgentLastContact <= 2019-12-18T00:50:19.575Z)
        Boolean values are specified as 'true' or 'false'. Parenthesis can be used to control the order of operations and group conditions.
    .PARAMETER OrderBy
        A comma separated list of fields that you want to order by finishing with either an asc or desc.
    .PARAMETER ClientName
        Client name to search for, uses wildcards so full client name is not needed
    .PARAMETER LocationName
        Location name to search for, uses wildcards so full location name is not needed
    .PARAMETER ClientID
        ClientID to search for, integer, -ClientID 1
    .PARAMETER LocationID
        LocationID to search for, integer, -LocationID 2
    .OUTPUTS
        Client objects
    .NOTES
        Version:        1.0
        Author:         Gavin Stone and Andrea Mastellone
        Creation Date:  2019-03-19
        Purpose/Change: Initial script development
    .EXAMPLE
        Get-AutomateClient -AllClients
    .EXAMPLE
        Get-AutomateClient -ClientId 4
    .EXAMPLE
        Get-AutomateClient -ClientName "Rancor"
    .EXAMPLE
        Get-AutomateClient -Condition "(City != 'Baltimore')"
    #>
	param (
		[Parameter(Mandatory = $false, Position = 0, ParameterSetName = "IndividualClient")]
		[Alias('ID')]
		[int32[]]$ClientId,
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[switch]$AllClients,
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$Condition,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$IncludeFields,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$ExcludeFields,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$OrderBy,
		[Alias("Client")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$ClientName,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$LocationId,
		[Alias("Location")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$LocationName
	)
	
	$ArrayOfConditions = @()
	
	
	if ($ClientID)
	{
		Return Get-AutomateAPIGeneric -AllResults -Endpoint "clients" -IDs $(($ClientID) -join ",")
	}
	
	if ($AllClients)
	{
		Return Get-AutomateAPIGeneric -AllResults -Endpoint "clients" -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
	}
	
	if ($Condition)
	{
		Return Get-AutomateAPIGeneric -AllResults -Endpoint "clients" -Condition $Condition -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
	}
	
	if ($ClientName)
	{
		$ArrayOfConditions += "(Name like '%$ClientName%')"
	}
	
	if ($LocationName)
	{
		$ArrayOfConditions += "(Location.Name like '%$LocationName%')"
	}
	
	if ($LocationID)
	{
		$ArrayOfConditions += "(Location.Id = $LocationId)"
	}
	
	$ClientFinalCondition = Get-ConditionsStacked -ArrayOfConditions $ArrayOfConditions
	
	$Clients = Get-AutomateAPIGeneric -AllResults -Endpoint "clients" -Condition $ClientFinalCondition -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
	
	$FinalResult = @()
	foreach ($Client in $Clients)
	{
		$ArrayOfConditions = @()
		$ArrayOfConditions += "(Client.Id = '$($Client.Id)')"
		$LocationFinalCondition = Get-ConditionsStacked -ArrayOfConditions $ArrayOfConditions
		$Locations = Get-AutomateAPIGeneric -AllResults -Endpoint "locations" -Condition $LocationFinalCondition -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
		$FinalClient = $Client
		Add-Member -inputobject $FinalClient -NotePropertyName 'Locations' -NotePropertyValue $locations
		$FinalResult += $FinalClient
	}
	
	return $FinalResult
}

function Get-AutomateComputer
{
        <#
        .SYNOPSIS
            Get Computer information out of the Automate API
        .DESCRIPTION
            Connects to the Automate API and returns one or more full computer objects
        .PARAMETER ComputerID
            Can take either single ComputerID integer, IE 1, or an array of ComputerID integers, IE 1,5,9
        .PARAMETER AllComputers
            Returns all computers in Automate, regardless of amount
        .PARAMETER Condition
            A custom condition to build searches that can be used to search for specific things. Supported operators are '=', 'eq', '>', '>=', '<', '<=', 'and', 'or', '()', 'like', 'contains', 'in', 'not'.
            The 'not' operator is only used with 'in', 'like', or 'contains'. The '=' and 'eq' operator are the same. String values can be surrounded with either single or double quotes. IE (RemoteAgentLastContact <= 2019-12-18T00:50:19.575Z)
            Boolean values are specified as 'true' or 'false'. Parenthesis can be used to control the order of operations and group conditions.
        .PARAMETER IncludeFields
            A comma separated list of fields that you want including in the returned computer object.
        .PARAMETER ExcludeFields
            A comma separated list of fields that you want excluding in the returned computer object.
        .PARAMETER OrderBy
            A comma separated list of fields that you want to order by finishing with either an asc or desc.  
        .PARAMETER ClientName
            Client name to search for, uses wildcards so full client name is not needed
        .PARAMETER LocationName
            Location name to search for, uses wildcards so full location name is not needed
        .PARAMETER ClientID
            ClientID to search for, integer, -ClientID 1
        .PARAMETER LocationID
            LocationID to search for, integer, -LocationID 2
        .PARAMETER ComputerName
            Computer name to search for, uses wildcards so full computer name is not needed
        .PARAMETER OpenPort
            Searches through all computers and finds where a UDP or TCP port is open. Can either take a single number, ie -OpenPort "443"
        .PARAMETER OperatingSystem
            Operating system name to search for, uses wildcards so full OS Name not needed. IE: -OperatingSystem "Windows 7"
        .PARAMETER DomainName
            Domain name to search for, uses wildcards so full OS Name not needed. IE: -DomainName ".local"
        .PARAMETER NotSeenInDays
            Returns all computers that have not been seen in an amount of days. IE: -NotSeenInDays 30
        .PARAMETER Comment
            Returns all computers that have a comment set with the computer in Automate. Wildcard search.
        .PARAMETER LastWindowsUpdateInDays
            Returns computers where the LastWindowUpdate in days is over a certain amount. This is not based on patch manager information but information in Windows
        .PARAMETER AntiVirusDefinitionInDays
            Returns computers where the Antivirus definitions are older than x days
        .PARAMETER LocalIPAddress
            Returns computers with a specific local IP address
        .PARAMETER GatewayIPAddress
            Returns the external IP of the Computer
        .PARAMETER MacAddress
            Returns computers with an mac address as a wildcard search
        .PARAMETER LoggedInUser
            Returns computers with a certain logged in user, using wildcard search, IE: -LoggedInUser "Gavin" will find all computers where a Gavin is logged in.
        .PARAMETER Master
            Returns computers that are Automate masters
        .PARAMETER NetworkProbe
            Returns computers that are Automate network probes
        .PARAMETER InMaintenanceMode
            Returns computers that are in maintenance mode
        .PARAMETER IsVirtualMachine
            Returns computers that are virtual machines
        .PARAMETER DDay
            Returns agents that are affected by the Automate Binary issue hitting on 9th March 2019
        .PARAMETER Online
            Returns agents that are online or offline, IE -Online $true or alternatively -Online $false
        .PARAMETER UserIdleLongerThanMinutes
            Takes an integer in minutes and brings back all users who have been idle on their machines longer than that. IE -UserIdleLongerThanMinutes 60
        .PARAMETER UptimeLongerThanMinutes
            Takes an integer in minutes and brings back all computers that have an uptime longer than x minutes. IE -UptimeLongerThanMinutes 60
        .PARAMETER AssetTag
            Return computers with a certain asset tag - a wildcard search
        .PARAMETER Server
            Return computers that are servers, boolean value can be used as -Server $true or -Server $false
        .PARAMETER Workstation
            Return computers that are workstations, boolean value can be used as -Workstation $true or -Workstation $false 
        .PARAMETER AntivirusScanner
            Return computers that have a certain antivirus. Wildcard search.
        .PARAMETER RebootNeeded
            Return computers that need a reboot. Bool. -RebootNeeded $true or -RebootNeeded $false
        .PARAMETER VirtualHost
            Return computers that are virtual hosts. Bool. -VirtualHost $true or -VirtualHost $false  
        .PARAMETER SerialNumber
            Return computers that have a serial number specified. Wildcard Search
        .PARAMETER BiosManufacturer
            Return computers with a specific Bios Manufacturer. Wildcard search.
        .PARAMETER BiosVersion
            Return computers with a specific BIOS Version. This is a string search and a wildcard.
        .PARAMETER LocalUserAccounts
            Return computers where certain local user accounts are present
        .OUTPUTS
            Computer Objects
        .NOTES
            Version:        1.0
            Author:         Gavin Stone
            Creation Date:  2019-01-20
            Purpose/Change: Initial script development
        .EXAMPLE
            Get-AutomateComputer -AllComputers
        .EXAMPLE
            Get-AutomateComputer -OperatingSystem "Windows 7"
        .EXAMPLE
            Get-AutomateComputer -ClientName "Rancor"
        .EXAMPLE
            Get-AutomateComputer -Condition "(Type != 'Workstation')"
        #>
	param (
		[Parameter(Mandatory = $false, Position = 0, ParameterSetName = "IndividualPC")]
		[Alias('ID')]
		[int32[]]$ComputerID,
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[switch]$AllComputers,
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$Condition,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$IncludeFields,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$ExcludeFields,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$OrderBy,
		[Alias("Client")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$ClientName,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$ClientId,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$LocationId,
		[Alias("Location")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$LocationName,
		[Alias("Computer", "Name", "Netbios")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$ComputerName,
		[Alias("Port")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$OpenPort,
		[Alias("OS", "OSName")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$OperatingSystem,
		[Alias("Domain")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$DomainName,
		[Alias("OfflineSince", "OfflineInDays")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$NotSeenInDays,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$Comment,
		[Alias("WindowsUpdateInDays")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$LastWindowsUpdateInDays,
		[Alias("AVDefinitionInDays")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$AntiVirusDefinitionInDays,
		[Alias("IPAddress", "IP")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$LocalIPAddress,
		[Alias("ExternalIPAddress", "ExternalIP", "IPAddressExternal", "IPExternal")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$GatewayIPAddress,
		[Alias("Mac")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$MacAddress,
		[Alias("User", "Username")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$LoggedInUser,
		[Alias("IsMaster")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[bool]$Master,
		[Alias("IsNetworkProbe")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[bool]$NetworkProbe,
		[Alias("InMaintenanceMode")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[bool]$MaintenanceMode,
		[Alias("IsVirtualMachine")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[bool]$VirtualMachine,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[switch]$DDay,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[bool]$Online,
		[Alias("Idle")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$UserIdleLongerThanMinutes,
		[Alias("Uptime")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$UptimeLongerThanMinutes,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$AssetTag,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[bool]$Server,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[bool]$Workstation,
		[Alias("AV", "VirusScanner", "Antivirus")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$AntivirusScanner,
		[Alias("PendingReboot", "RebootRequired")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[bool]$RebootNeeded,
		[Alias("IsVirtualHost")]
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[bool]$VirtualHost,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$SerialNumber,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$BiosManufacturer,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$BiosVersion,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$LocalUserAccounts
		
	)
	
	$ArrayOfConditions = @()
	
	if ($ComputerID)
	{
		Return Get-AutomateAPIGeneric -AllResults -Endpoint "computers" -IDs $(($ComputerID) -join ",")
	}
	
	if ($AllComputers)
	{
		Return Get-AutomateAPIGeneric -AllResults -Endpoint "computers" -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
	}
	
	if ($Condition)
	{
		Return Get-AutomateAPIGeneric -AllResults -Endpoint "computers" -Condition $Condition -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
	}
	
	if ($ClientName)
	{
		$ArrayOfConditions += "(Client.Name like '%$ClientName%')"
	}
	
	if ($LocationName)
	{
		$ArrayOfConditions += "(Location.Name like '%$LocationName%')"
	}
	
	if ($ClientID)
	{
		$ArrayOfConditions += "(Client.Id = $ClientID)"
	}
	
	if ($LocationID)
	{
		$ArrayOfConditions += "(Location.Id = $LocationID)"
	}
	
	if ($ComputerName)
	{
		$ArrayOfConditions += "(ComputerName like '%$ComputerName%')"
	}
	
	if ($OpenPort)
	{
		$ArrayOfConditions += "((OpenPortsTCP contains $OpenPort) or (OpenPortsUDP contains $OpenPort))"
	}
	
	if ($Dday)
	{
		$ArrayOfConditions += "((RemoteAgentVersion < '190.58') and (RemoteAgentVersion > '120.451'))"
	}
	
	if ($OperatingSystem)
	{
		$ArrayOfConditions += "(OperatingSystemName like '%$OperatingSystem%')"
	}
	
	if ($DomainName)
	{
		$ArrayOfConditions += "(DomainName like '%$DomainName%')"
	}
	
	if ($NotSeenInDays)
	{
		$CurrentDateMinusVar = (Get-Date).AddDays(- $($NotSeenInDays))
		$Final = (Get-Date $CurrentDateMinusVar -Format s)
		$ArrayOfConditions += "(RemoteAgentLastContact <= $Final)"
	}
	
	if ($Comment)
	{
		$ArrayOfConditions += "(Comment like '%$Comment%')"
	}
	
	if ($LastWindowsUpdateInDays)
	{
		$Final = (Get-Date).AddDays(- $($LastWindowsUpdateInDays)).ToString('s')
		$OnInLast2Days = (Get-Date).AddDays(-2).ToString('s')
		$ArrayOfConditions += "((WindowsUpdateDate <= $Final) and (RemoteAgentLastContact >= $OnInLast2Days) and (OperatingSystemName not like '%Mac%') and (OperatingSystemName not like '%Linux%'))"
	}
	
	if ($AntiVirusDefinitionInDays)
	{
		$Final = (Get-Date).AddDays(- $($AntiVirusDefinitionInDays)).ToString('s')
		$OnInLast2Days = (Get-Date).AddDays(-2).ToString('s')
		$ArrayOfConditions += "((AntiVirusDefinitionDate <= $Final) and (RemoteAgentLastContact >= $OnInLast2Days))"
	}
	
	if ($LocalIPAddress)
	{
		$ArrayOfConditions += "(LocalIPAddress = '$LocalIPAddress')"
	}
	
	if ($GatewayIPAddress)
	{
		$ArrayOfConditions += "(GatewayIPAddress = '$GatewayIPAddress')"
	}
	
	if ($MacAddress)
	{
		$ArrayOfConditions += "(MacAddress like '%$MacAddress%')"
	}
	
	if ($LoggedInUser)
	{
		$ArrayOfConditions += "(LoggedInUsers.LoggedInUserName like '%$LoggedInUser%')"
	}
	
	if ($PSBoundParameters.ContainsKey('Master'))
	{
		$ArrayOfConditions += "(IsMaster = $Master)"
	}
	
	if ($PSBoundParameters.ContainsKey('NetworkProbe'))
	{
		$ArrayOfConditions += "(IsNetworkProbe = $NetworkProbe)"
	}
	
	if ($PSBoundParameters.ContainsKey('MaintenanceMode'))
	{
		$ArrayOfConditions += "(IsMaintenanceModeEnabled = $MaintenanceMode)"
	}
	
	if ($PSBoundParameters.ContainsKey('Virtualmachine'))
	{
		$ArrayOfConditions += "(IsVirtualMachine = $Virtualmachine)"
	}
	
	if (($PSBoundParameters.ContainsKey('Online')) -and ($Online))
	{
		$ArrayOfConditions += "(Status = 'Online')"
	}
	
	if (($PSBoundParameters.ContainsKey('Online')) -and (!$Online))
	{
		$ArrayOfConditions += "(Status = 'Offline')"
	}
	
	if ($UserIdleLongerThanMinutes)
	{
		#        $Seconds = $UserIdleLongerThanMinutes * 60
		$ArrayOfConditions += "((Status = 'Online') and (UserIdleTime >= $UserIdleLongerThanMinutes))"
	}
	
	if ($UptimeLongerThanMinutes)
	{
		#        $Seconds = $UptimeLongerThanMinutes * 60
		$ArrayOfConditions += "((Status = 'Online') and (SystemUptime >= $UptimeLongerThanMinutes))"
	}
	
	if ($AssetTag)
	{
		$ArrayOfConditions += "(AssetTag like '%$AssetTag%')"
	}
	
	if (($PSBoundParameters.ContainsKey('Server')) -and (!$Server))
	{
		$ArrayOfConditions += "(Type != 'Server')"
	}
	
	if (($PSBoundParameters.ContainsKey('Server')) -and ($Server))
	{
		$ArrayOfConditions += "(Type = 'Server')"
	}
	
	if (($PSBoundParameters.ContainsKey('Workstation')) -and (!$Workstation))
	{
		$ArrayOfConditions += "(Type != 'Workstation')"
	}
	
	if (($PSBoundParameters.ContainsKey('Workstation')) -and ($Workstation))
	{
		$ArrayOfConditions += "(Type = 'Workstation')"
	}
	
	if ($AntivirusScanner)
	{
		$ArrayOfConditions += "(VirusScanner.Name like '%$AntivirusScanner%')"
	}
	
	if ($PSBoundParameters.ContainsKey('RebootNeeded'))
	{
		$ArrayOfConditions += "(IsRebootNeeded = $RebootNeeded)"
	}
	
	if ($PSBoundParameters.ContainsKey('VirtualHost'))
	{
		$ArrayOfConditions += "(IsVirtualHost = $VirtualHost)"
	}
	
	if ($SerialNumber)
	{
		$ArrayOfConditions += "(SerialNumber like '%$SerialNumber%')"
	}
	
	if ($BiosManufacturer)
	{
		$ArrayOfConditions += "(BIOSManufacturer like '%$BIOSManufacturer%')"
	}
	
	if ($BiosVersion)
	{
		$ArrayOfConditions += "(BIOSFlash like '%$BIOSVersion%')"
	}
	
	if ($LocalUserAccounts)
	{
		$ArrayOfConditions += "(UserAccounts Contains '$LocalUserAccounts')"
	}
	
	
	$FinalCondition = Get-ConditionsStacked -ArrayOfConditions $ArrayOfConditions
	
	$FinalResult = Get-AutomateAPIGeneric -AllResults -Endpoint "computers" -Condition $FinalCondition -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
	
	return $FinalResult
}

function Get-AutomateControlInfo
{
            <#
            .SYNOPSIS
            Retrieve data from Automate API Control Extension
            .DESCRIPTION
            Connects to the Automate API Control Extension and returns an object with Control Session data
            .PARAMETER ComputerID
            The Automate ComputerID to retrieve information on
            .PARAMETER ID
            Taken from the Pipeline, IE Get-AutomateComputer -ComputerID 5 | Get-AutomateControlInfo
            .PARAMETER ComputerObjects
            Used for Pipeline input from Get-AutomateComputer
            .OUTPUTS
            Custom object with the ComputerID and Control SessionID. Additional properties from the return data will be included.
            .NOTES
            Version:        1.0
            Author:         Gavin Stone
            Creation Date:  2019-01-20
            Purpose/Change: Initial script development
            
            Update Date:    2019-02-12
            Author:         Darren White
            Purpose/Change: Modified returned object data
            
            .EXAMPLE
            Get-AutomateControlInfo -ComputerId 123
            #>
	[CmdletBinding(DefaultParameterSetName = 'ID')]
	param
	(
		[Parameter(ParameterSetName = 'ID', Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $False)]
		[int16[]]$ComputerID,
		[Parameter(ParameterSetName = 'pipeline', ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
		[int16[]]$ID,
		[Parameter(ParameterSetName = 'pipeline', ValueFromPipeline = $true, Mandatory = $True)]
		$ComputerObjects
		
	)
	
	Begin
	{
		$defaultDisplaySet = 'SessionID'
		#Create the default property display set
		$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]$defaultDisplaySet)
		$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
	} #End Begin
	
	Process
	{
		#If not pipeline mode, build custom objects.
		If ($PSCmdlet.ParameterSetName -eq 'ID')
		{
			$ComputerObjects = @()
			ForEach ($ComputerIDSingle in $ComputerID)
			{
				$OurResult = [pscustomobject]@{
					ID	      = $ComputerIdSingle
					SessionID = 'Not Found'
				}
				$Null = $OurResult.PSObject.TypeNames.Insert(0, 'CWControl.Information')
				$Null = $OurResult | Add-Member MemberSet PSStandardMembers $PSStandardMembers
				$ComputerObjects += $OurResult
			}
		}
		
		ForEach ($Computer in $ComputerObjects)
		{
			If ($PSCmdlet.ParameterSetName -eq 'pipeline')
			{
				$Null = $Computer | Add-Member -NotePropertyName 'SessionID' -NotePropertyValue 'Not Found'
			}
			$url = ($Script:CWAServer + "/cwa/api/v1/extensionactions/control/$($Computer.ID)")
			Try
			{
				$Result = Invoke-RestMethod -Uri $url -Headers $script:CWAToken -ContentType "application/json"
				
				$ResultMatch = $Result | select-string -Pattern '^(https?://[^?]*)\??(.*)' -AllMatches
				If ($ResultMatch.Matches)
				{
					$Null = $Computer | Add-Member -NotePropertyName LaunchURL -NotePropertyValue $($ResultMatch.Matches.Groups[0].Value)
					$Null = $Computer | Add-Member -MemberType ScriptMethod -Name 'LaunchSession' -Value { Start-Process "$($this.LaunchURL)" }
					ForEach ($NameValue in $($ResultMatch.Matches.Groups[2].Value -split '&'))
					{
						$xName = $NameValue -replace '=.*$', ''
						$xValue = $NameValue -replace '^[^=]*=?', ''
						If ($Computer | Get-Member -Name $xName)
						{
							$Computer.$xName = $xValue
						}
						Else
						{
							$Null = $Computer | Add-Member -NotePropertyName $xName -NotePropertyValue $xValue
						} #End If
					} #End ForEach
				} #End If
			}
			Catch { }
			$Null = $Computer | Add-Member -MemberType AliasProperty -Name ControlGUID -Value SessionID
			$Null = $Computer | Add-Member -MemberType AliasProperty -Name ComputerID -Value ID
			$Computer
		} #End ForEach
	} #End Process
	
} #End Get-AutomateControlInfo

function Get-AutomateTicket
{
                <#
                .SYNOPSIS
                    Get Ticket information out of the Automate API
                .DESCRIPTION
                    Connects to the Automate API and returns one or more full ticket objects
                .PARAMETER AllTickets
                    Returns all tickets in Automate, regardless of amount
                .PARAMETER Condition
                    A custom condition to build searches that can be used to search for specific things. Supported operators are '=', 'eq', '>', '>=', '<', '<=', 'and', 'or', '()', 'like', 'contains', 'in', 'not'.
                    The 'not' operator is only used with 'in', 'like', or 'contains'. The '=' and 'eq' operator are the same. String values can be surrounded with either single or double quotes. IE (RemoteAgentLastContact <= 2019-12-18T00:50:19.575Z)
                    Boolean values are specified as 'true' or 'false'. Parenthesis can be used to control the order of operations and group conditions.
                .PARAMETER IncludeFields
                    A comma separated list of fields that you want including in the returned ticket object.
                .PARAMETER ExcludeFields
                    A comma separated list of fields that you want excluding in the returned ticket object.
                .PARAMETER OrderBy
                    A comma separated list of fields that you want to order by finishing with either an asc or desc.  
                .NOTES
                    Version:        1.0
                    Author:         Gavin Stone
                    Creation Date:  2019-02-25
                    Purpose/Change: Initial script development
                .EXAMPLE
                    Get-AutomateTicket -AllTickets
                #>
	param (
		
		[Parameter(Mandatory = $false, Position = 0, ParameterSetName = "IndividualTicket")]
		[Alias('ID')]
		[int32[]]$TicketID,
		[Parameter(Mandatory = $false, ParameterSetName = "IndividualComputerTicket")]
		[int32[]]$ComputerID,
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[switch]$AllTickets,
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$Condition,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$IncludeFields,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$ExcludeFields,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
		[Parameter(Mandatory = $false, ParameterSetName = "ByCondition")]
		[string]$OrderBy,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$StatusID,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Alias('Status')]
		[string]$StatusName,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$Subject,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$PriorityID,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Alias('Priority')]
		[string]$PriorityName,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$From,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[string]$CC,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$SupportLevel,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[int]$ExternalID,
		[Parameter(Mandatory = $false, ParameterSetName = "CustomBuiltCondition")]
		[Alias('ManageUnsycned')]
		[switch]$UnsyncedTickets
		
		
	)
	
	$ArrayOfConditions = @()
	
	if ($TicketID)
	{
		Return Get-AutomateAPIGeneric -AllResults -Endpoint "tickets" -IDs $(($TicketID) -join ",")
	}
	
	if ($ComputerID)
	{
		Return $(Get-AutomateAPIGeneric -AllResults -Endpoint "computers" -Expand "tickets" -IDs $(($ComputerID) -join ",") | Select-Object Id, ComputerName, Tickets)
	}
	
	if ($AllComputers)
	{
		Return Get-AutomateAPIGeneric -AllResults -Endpoint "tickets" -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
	}
	
	if ($Condition)
	{
		Return Get-AutomateAPIGeneric -AllResults -Endpoint "tickets" -Condition $Condition -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
	}
	
	if ($StatusID)
	{
		$ArrayOfConditions += "(Status.Id = $StatusID)"
	}
	
	if ($StatusName)
	{
		$ArrayOfConditions += "(Status.Name like '%$StatusName%')"
	}
	
	if ($Subject)
	{
		$ArrayOfConditions += "(Subject like '%$Subject%')"
	}
	
	if ($PriorityID)
	{
		$ArrayOfConditions += "(Priority.Id = $PriorityID)"
	}
	
	if ($PriorityName)
	{
		$ArrayOfConditions += "(Priority.Name like '%$PriorityName%')"
	}
	
	if ($From)
	{
		$ArrayOfConditions += "(From like '%$From%')"
	}
	
	if ($CC)
	{
		$ArrayOfConditions += "(CC like '%$CC%')"
	}
	
	if ($SupportLevel)
	{
		$ArrayOfConditions += "(SupportLevel = $SupportLevel)"
	}
	
	if ($ExternalID)
	{
		$ArrayOfConditions += "(ExternalID = $ExternalID)"
	}
	
	if ($UnsyncedTickets)
	{
		$ArrayOfConditions += "(ExternalID = 0)"
	}
	
	
	$FinalCondition = Get-ConditionsStacked -ArrayOfConditions $ArrayOfConditions
	
	$FinalResult = Get-AutomateAPIGeneric -AllResults -Endpoint "tickets" -Condition $FinalCondition -IncludeFields $IncludeFields -ExcludeFields $ExcludeFields -OrderBy $OrderBy
	
	return $FinalResult
}
function Get-ControlSessions
{
                    <#
                    .Synopsis
                       Gets bulk session info from Control using the Automate Control Reporting Extension
                    .DESCRIPTION
                       Gets bulk session info from Control using the Automate Control Reporting Extension
                    .PARAMETER SessionID
                        The GUID identifier(s) for the machine you want status information on. If not provided, all sessions will be returned.
                    .NOTES
                        Version:        1.4
                        Author:         Gavin Stone 
                        Modified By:    Darren White
                        Purpose/Change: Initial script development
                    
                        Update Date:    2019-02-23
                        Author:         Darren White
                        Purpose/Change: Added SessionID parameter to return information only for requested sessions.
                    
                        Update Date:    2019-02-26
                        Author:         Darren White
                        Purpose/Change: Include LastConnected value if reported.
                    
                        Update Date:    2019-06-24
                        Author:         Darren White
                        Purpose/Change: Modified output to be collection of objects instead of a hastable.
                    
                    .EXAMPLE
                       Get-ControlSesssions
                    .INPUTS
                       None
                    .OUTPUTS
                       Custom object of session details for all sessions
                    #>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $False, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[guid[]]$SessionID
	)
	
	begin
	{
		$SessionIDCollection = @()
		$SCConnected = @{ };
	}
	
	process
	{
		# Gather Sessions from the pipeline for Bulk Processing.
		If ($SessionID)
		{
			$SessionIDCollection += $SessionID
		}
	}
	
	end
	{
		# Ensure the session list does not contain duplicate values.
		$SessionIDCollection = @($SessionIDCollection | Select-Object -Unique)
		#Split the list into groups of no more than 100 items
		$SplitGUIDsArray = Split-Every -list $SessionIDCollection -count 100
		If (!$SplitGUIDsArray) { Write-Debug "Resetting to include all GUIDs"; $SplitGUIDsArray = @('') }
		$Now = Get-Date
		ForEach ($GUIDs in $SplitGUIDsArray)
		{
			If ('' -ne $GUIDs)
			{
				Write-Verbose "Starting on a new array $($GUIDs)"
				$GuidCondition = $(ForEach ($GUID in $GUIDs) { "sessionid='$GUID'" }) -join ' OR '
				If ($GuidCondition) { $GuidCondition = "($GuidCondition) AND" }
			}
			$Body = ConvertTo-Json @("SessionConnectionEvent", @("SessionID", "EventType"), @("LastTime"), "$GuidCondition SessionConnectionProcessType='Guest' AND (EventType = 'Connected' OR EventType = 'Disconnected')", "", 20000) -Compress
			$RESTRequest = @{
				'URI' = "${Script:ControlServer}/App_Extensions/fc234f0e-2e8e-4a1f-b977-ba41b14031f7/ReportService.ashx/GenerateReportForAutomate"
				'Method' = 'POST'
				'ContentType' = 'application/json'
				'Body' = $Body
			}
			
			If ($Script:ControlAPIKey)
			{
				$RESTRequest.Add('Headers', @{ 'CWAIKToken' = (Get-CWAIKToken) })
			}
			Else
			{
				$RESTRequest.Add('Credential', ${Script:ControlAPICredentials})
			}
			
			Write-Debug "Submitting Request to $($RESTRequest.URI)`nHeaders:`n$(ConvertTo-JSON $($RESTRequest.Headers) -Depth 5 -Compress)`nBody:`n$($RESTRequest.Body | Out-String)"
			$AllData = $Null
			Try
			{
				$SCData = Invoke-RestMethod @RESTRequest
				Write-Debug "Request Result: $($SCData | select-object -property * | convertto-json -Depth 10 -Compress)"
				If ($SCData.FieldNames -contains 'SessionID' -and $SCData.FieldNames -contains 'EventType' -and $SCData.FieldNames -contains 'LastTime')
				{
					$AllData = $($SCData.Items.GetEnumerator() | select-object @{ Name = 'SessionID'; Expression = { $_[0] } }, @{ Name = 'Event'; Expression = { $_[1] } }, @{ Name = 'Date'; Expression = { $_[2] } } | sort-Object SessionID, Event -Descending)
				}
				Else
				{
					Throw "Session report data was not returned: Error $_.Exception.Message"
					Return
				}
			}
			Catch
			{
				Write-Debug "Request FAILED! Request Result: $($SCData | select-object -property * | convertto-json -Depth 10)"
			}
			
			$AllData | ForEach-Object {
				# Build $SCConnected hashtable with information from report request in $AllData
				If ($_.Event -like 'Disconnected')
				{
					$SCConnected.Add($_.SessionID, $_.Date)
				}
				Else
				{
					If ($_.Date -ge $SCConnected[$_.SessionID])
					{
						If ($SCConnected.ContainsKey($_.SessionID))
						{
							$SCConnected[$_.SessionID] = $True
						}
						Else
						{
							$SCConnected.Add($_.SessionID, $True)
						}
					}
				}
			}
		}
		#Build final output objects with session information gathered into $SCConnected hashtable
		$SCStatus = $(
			Foreach ($sessid IN $($SCConnected.Keys))
			{
				write-debug "assigning status for $sessid"
				$SessionResult = [pscustomobject]@{
					SessionID		    = $sessid
					OnlineStatusControl = $Null
					LastConnected	    = $Null
				}
				If ($SCConnected[$sessid] -eq $True)
				{
					$SessionResult.OnlineStatusControl = $True
					$SessionResult.LastConnected = $Now.ToUniversalTime()
				}
				Else
				{
					$SessionResult.OnlineStatusControl = $False
					$SessionResult.LastConnected = $SCConnected[$sessid]
				}
				$SessionResult
			}
		)
		Return $SCStatus
	}
}

function Invoke-ControlCommand
{
                        <#
                        .SYNOPSIS
                            Will issue a command against a given machine and return the results.
                        .DESCRIPTION
                            Will issue a command against a given machine and return the results.
                        .PARAMETER SessionID
                            The GUID identifier for the machine you wish to connect to.
                            You can retrieve session info with the 'Get-ControlSessions' commandlet
                            SessionIDs can be provided via the pipeline.
                            IE - Get-AutomateComputer -ComputerID 5 | Get-ControlSessions | Invoke-ControlCommand -Powershell -Command "Get-Service"
                        .PARAMETER Command
                            The command you wish to issue to the machine.
                        .PARAMETER MaxLength
                            The maximum number of bytes to return from the remote session. The default is 5000 bytes.
                        .PARAMETER PowerShell
                            Issues the command in a powershell session.
                        .PARAMETER TimeOut
                            The amount of time in milliseconds that a command can execute. The default is 10000 milliseconds.
                        .PARAMETER BatchSize
                            Number of control sessions to invoke commands in parallel.
                        .OUTPUTS
                            The output of the Command provided.
                        .NOTES
                            Version:        2.2
                            Author:         Chris Taylor
                            Modified By:    Gavin Stone 
                            Modified By:    Darren White
                            Creation Date:  1/20/2016
                            Purpose/Change: Initial script development
                    
                            Update Date:    2019-02-19
                            Author:         Darren White
                            Purpose/Change: Enable Pipeline support. Enable processing using Automate Control Extension. The cached APIKey will be used if present.
                    
                            Update Date:    2019-02-23
                            Author:         Darren White
                            Purpose/Change: Enable command batching against multiple sessions. Added OfflineAction parameter.
                            
                            Update Date:    2019-06-24
                            Author:         Darren White
                            Purpose/Change: Updates to process object returned by Get-ControlSessions
                            
                        .EXAMPLE
                            Get-AutomateComputer -ComputerID 5 | Get-AutomateControlInfo | Invoke-ControlCommand -Powershell -Command "Get-Service"
                                Will retrieve Computer Information from Automate, Get ControlSession data and merge with the input object, then call Get-Service on the computer.
                        .EXAMPLE
                            Invoke-ControlCommand -SessionID $SessionID -Command 'hostname'
                                Will return the hostname of the machine.
                        .EXAMPLE
                            Invoke-ControlCommand -SessionID $SessionID -TimeOut 120000 -Command 'iwr -UseBasicParsing "https://bit.ly/ltposh" | iex; Restart-LTService' -PowerShell
                                Will restart the Automate agent on the target machine.
                        #>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[guid[]]$SessionID,
		[string]$Command,
		[int]$TimeOut = 10000,
		[int]$MaxLength = 5000,
		[switch]$PowerShell,
		[ValidateSet('Wait', 'Queue', 'Skip')]
		$OfflineAction = 'Wait',
		[ValidateRange(1, 100)]
		[int]$BatchSize = 20
	)
	
	Begin
	{
		
		$Server = $Script:ControlServer -replace '/$', ''
		
		# Format command
		$FormattedCommand = @()
		if ($Powershell)
		{
			$FormattedCommand += '#!ps'
		}
		$FormattedCommand += "#timeout=$TimeOut"
		$FormattedCommand += "#maxlength=$MaxLength"
		$FormattedCommand += $Command
		$FormattedCommand = $FormattedCommand | Out-String
		$SessionEventType = 44
		
		If ($Script:ControlAPIKey)
		{
			$User = 'AutomateAPI'
		}
		ElseIf ($Script:ControlAPICredentials.UserName)
		{
			$User = $Script:ControlAPICredentials.UserName
		}
		Else
		{
			$User = ''
		}
		
		$SessionIDCollection = @()
		$ResultSet = @()
		
	}
	
	Process
	{
		If (!($Server -match 'https?://[a-z0-9][a-z0-9\.\-]*(:[1-9][0-9]*)?(\/[a-z0-9\.\-\/]*)?$')) { throw "Control Server address ($Server) is in an invalid format. Use Connect-ControlAPI to assign the server URL."; return }
		If ($SessionID)
		{
			$SessionIDCollection += $SessionID
		}
	}
	
	End
	{
		$SplitGUIDsArray = Split-Every -list $SessionIDCollection -count $BatchSize
		ForEach ($GUIDs in $SplitGUIDsArray)
		{
			If (!$GUIDs) { Continue } #Skip if Null value
			$RemainingGUIDs = { $GUIDs }.Invoke()
			If ($OfflineAction -ne 'Wait')
			{
				#Check Online Status. Weed out sessions that have never connected or are not valid.
				$ControlSessions = @{ };
				Get-ControlSessions -SessionID $RemainingGUIDs | ForEach-Object { $ControlSessions.Add($_.SessionID, $($_ | Select-Object -Property OnlineStatusControl, LastConnected)) }
				If ($OfflineAction -eq 'Skip')
				{
					ForEach ($GUID in $ControlSessions.Keys)
					{
						If (!($ControlSessions[$GUID].OnlineStatusControl -eq $True))
						{
							$ResultSet += [pscustomobject]@{
								'SessionID' = $GUID
								'Output'    = 'Skipped. Session was not connected.'
							}
							$Null = $RemainingGUIDs.Remove($GUID)
						}
					}
				}
			}
			
			If (!$RemainingGUIDs)
			{
				Continue; #Nothing to process
			}
			$xGUIDS = @(ForEach ($x in $RemainingGUIDs) { $x })
			$Body = ConvertTo-Json @($User, $xGUIDS, $SessionEventType, $FormattedCommand) -Compress
			
			$RESTRequest = @{
				'URI' = "$Server/App_Extensions/fc234f0e-2e8e-4a1f-b977-ba41b14031f7/ReplicaService.ashx/PageAddEventToSessions"
				'Method' = 'POST'
				'ContentType' = 'application/json'
				'Body' = $Body
			}
			If ($Script:ControlAPIKey)
			{
				$RESTRequest.Add('Headers', @{ 'CWAIKToken' = (Get-CWAIKToken) })
			}
			Else
			{
				$RESTRequest.Add('Credential', $Script:ControlAPICredentials)
			}
			
			# Issue command
			Try
			{
				$Results = Invoke-WebRequest @RESTRequest
			}
			Catch
			{
				Write-Error "$(($_.ErrorDetails | ConvertFrom-Json).message)"
				return
			}
			$RequestTimer = [diagnostics.stopwatch]::StartNew()
			
			$EventDate = Get-Date $($Results.Headers.Date)
			$EventDateFormatted = (Get-Date $EventDate.ToUniversalTime() -UFormat "%Y-%m-%d %T")
			
			$Looking = $True
			$TimeOutDateTime = (Get-Date).AddMilliseconds($TimeOut)
			
			while ($Looking)
			{
				Start-Sleep -Seconds $(Get-SleepDelay -Seconds $([int]($RequestTimer.Elapsed.TotalSeconds)) -TotalSeconds $([int]($TimeOut / 1000)))
				
				#Build GUID Conditional
				$GuidCondition = $(ForEach ($GUID in $RemainingGUIDs) { "sessionid='$GUID'" }) -join ' OR '
				# Look for results of command
				$Body = ConvertTo-Json @("SessionConnectionEvent", @(), @("SessionID", "Time", "Data"), "($GuidCondition) AND EventType='RanCommand' AND Time>='$EventDateFormatted'", "", 200) -Compress
				$RESTRequest = @{
					'URI' = "$Server/App_Extensions/fc234f0e-2e8e-4a1f-b977-ba41b14031f7/ReportService.ashx/GenerateReportForAutomate"
					'Method' = 'POST'
					'ContentType' = 'application/json'
					'Body' = $Body
				}
				
				If ($Script:ControlAPIKey)
				{
					$RESTRequest.Add('Headers', @{ 'CWAIKToken' = (Get-CWAIKToken) })
				}
				Else
				{
					$RESTRequest.Add('Credential', $Script:ControlAPICredentials)
				}
				
				Try
				{
					$SessionEvents = Invoke-RestMethod @RESTRequest
				}
				Catch
				{
					Write-Error $($_.Exception.Message)
				}
				
				$FNames = $SessionEvents.FieldNames
				$Events = ($SessionEvents.Items | ForEach-Object { $x = $_; $SCEventRecord = [pscustomobject]@{ }; for ($i = 0; $i -lt $FNames.Length; $i++) { $Null = $SCEventRecord | Add-Member -NotePropertyName $FNames[$i] -NotePropertyValue $x[$i] }; $SCEventRecord } | Sort-Object -Property Time, SessionID -Descending)
				foreach ($Event in $Events)
				{
					if ($Event.Time -ge $EventDate.ToUniversalTime() -and $RemainingGUIDs.Contains($Event.SessionID))
					{
						$Output = $Event.Data
						if (!$PowerShell)
						{
							$Output = $Output -replace '^[\r\n]*', ''
						}
						$ResultSet += [pscustomobject]@{
							'SessionID' = $Event.SessionID
							'Output'    = $Output
						}
						$Null = $RemainingGUIDs.Remove($Event.SessionID)
					}
				}
				
				$WaitingForGUIDs = $RemainingGUIDs
				If ($OfflineAction -eq 'Queue')
				{
					$WaitingForGUIDs = $(
						ForEach ($GUID in $WaitingForGUIDs)
						{
							Write-Debug "Checking if GUID $GUID is online: $($ControlSessions[$GUID.ToString()].OnlineStatusControl)"
							If ($ControlSessions[$GUID.ToString()].OnlineStatusControl -eq $True) { $GUID }
						}
					)
				}
				
				Write-Debug "$($WaitingForGUIDs.Count) sessions remaining after $($RequestTimer.Elapsed.TotalSeconds) seconds."
				If (!($WaitingForGUIDs.Count -gt 0))
				{
					$Looking = $False
					If ($RemainingGUIDs)
					{
						ForEach ($GUID in $RemainingGUIDs)
						{
							$ResultSet += [pscustomobject]@{
								'SessionID' = $GUID
								'Output'    = 'Command was queued for the session.'
							}
						}
						return $Output -Join ""
					}
				}
				
				if ($Looking -and $(Get-Date) -gt $TimeOutDateTime.AddSeconds(1))
				{
					$Looking = $False
					ForEach ($GUID in $RemainingGUIDs)
					{
						If ($OfflineAction -ne 'Wait' -and $ControlSessions[$GUID.ToString()].OnlineStatusControl -eq $False)
						{
							$ResultSet += [pscustomobject]@{
								'SessionID' = $GUID
								'Output'    = 'Command was queued for the session'
							}
						}
						Else
						{
							$ResultSet += [pscustomobject]@{
								'SessionID' = $GUID
								'Output'    = 'Command timed out when sent to Agent'
							}
						}
					}
				}
			}
		}
		If ($ResultSet.Count -eq 1)
		{
			Return $ResultSet | Select-Object -ExpandProperty Output -ErrorAction 0
		}
		Else
		{
			Return $ResultSet
		}
	}
}

function Repair-AutomateAgent
{
                        <#
                        .Synopsis
                           Takes changed detected in Compare-AutomateControlStatus and performs a specified repair on them
                        .DESCRIPTION
                           Takes changed detected in Compare-AutomateControlStatus and performs a specified repair on them
                        .PARAMETER Action
                           Takes either Update, Restart, Reinstall or Check
                        .PARAMETER BatchSize
                           When multiple jobs are run, they run in Parallel. Batch size determines how many jobs can run at once. Default is 10
                        .PARAMETER LTPoShURI 
                           If you do not wish to use the LT Posh module on GitHub you can use your own link to the LTPosh Module with this parameter
                        .PARAMETER AutomateControlStatusObject
                           Object taken from the Pipeline from Compare-AutomateControlStatus
                        .EXAMPLE
                           Get-AutomateComputer -Online $False | Compare-AutomateControlStatus | Repair-AutomateAgent -Action Check
                        .EXAMPLE
                           Get-AutomateComputer -Online $False | Compare-AutomateControlStatus | Repair-AutomateAgent -Action Restart
                        .INPUTS
                           Compare-AutomateControlStatus Object
                        .OUTPUTS
                           Object containing result of job(s)
                        #>
	[CmdletBinding(
				   SupportsShouldProcess = $true,
				   ConfirmImpact = 'High')]
	param (
		[ValidateSet('Update', 'Restart', 'ReInstall', 'Check')]
		[String]$Action = 'Check',
		[Parameter(Mandatory = $False)]
		[ValidateRange(1, 50)]
		[int]$BatchSize = 10,
		[Parameter(Mandatory = $False)]
		[String]$LTPoShURI = $Script:LTPoShURI,
		[Parameter(ValueFromPipeline = $true)]
		$AutomateControlStatusObject
	)
	
	Begin
	{
		$ResultArray = @()
		$ObjectCapture = @()
		$null = Get-RSJob | Remove-RSJob | Out-Null
		$ControlServer = $Script:ControlServer
		$ControlAPIKey = $Script:ControlAPIKey
		$ControlAPICredentials = $Script:ControlAPICredentials
		$ConnectOptions = $Null
	}
	
	Process
	{
		If ($ControlServer -and $ControlAPIKey)
		{
			$ConnectOptions = @{
				'Server' = $ControlServer
				'APIKey' = $ControlAPIKey
			}
		}
		ElseIf ($ControlServer -and $ControlAPICredentials)
		{
			$ConnectOptions = @{
				'Server'	 = $ControlServer
				'Credential' = $ControlAPICredentials
			}
		}
		Else
		{
			Return
		}
		Foreach ($igu in $AutomateControlStatusObject)
		{
			If ($igu.ComputerID -and $igu.SessionID)
			{
				If ($PSCmdlet.ShouldProcess("Automate Services on $($igu.ComputerID) - $($igu.ComputerName)", $Action))
				{
					if ($igu.OperatingSystemName -like '*windows*')
					{
						Write-Host -BackgroundColor DarkGray -ForegroundColor Yellow "$($igu.ComputerID) - $($igu.ComputerName) -  Attempting to $Action Automate Services - job will be queued"
						$ObjectCapture += $AutomateControlStatusObject
					}
					Else
					{
						Write-Host -BackgroundColor Yellow -ForegroundColor Red "This is not a windows machine - there is no Mac/Linux support at present in this module"
					}
				}
			}
			Else
			{
				Write-Host -BackgroundColor Yellow -ForegroundColor Red "An object was passed that is missing a required property (ComputerID, SessionID)"
			}
		}
	}
	
	End
	{
		If (!$ConnectOptions)
		{
			Throw "Control Server information must be assigned with Connect-ControlAPI function first."
			Return
		}
		if ($ObjectCapture)
		{
			Write-Host -ForegroundColor Green "Starting fixes"
			If ($Action -eq 'Check')
			{
				$ObjectCapture | Start-RSJob -Throttle $BatchSize -Name { "$($_.ComputerName) - $($_.ComputerID) - Check Service" } -ScriptBlock {
					Import-Module AutomateAPI -Force
					$ConnectOptions = $Using:ConnectOptions
					If (Connect-ControlAPI @ConnectOptions -SkipCheck -Quiet)
					{
						$ServiceRestartAttempt = Invoke-ControlCommand -SessionID $($_.SessionID) -Powershell -Command "(new-object Net.WebClient).DownloadString('$($Using:LTPoShURI)') | iex; Get-LTServiceInfo" -TimeOut 60000 -MaxLength 10240
						return $ServiceRestartAttempt
					}
				} | out-null
			}
			ElseIf ($Action -eq 'Update')
			{
				$ObjectCapture | Start-RSJob -Throttle $BatchSize -Name { "$($_.ComputerName) - $($_.ComputerID) - Update Service" } -ScriptBlock {
					Import-Module AutomateAPI -Force
					$ConnectOptions = $Using:ConnectOptions
					If (Connect-ControlAPI @ConnectOptions -SkipCheck -Quiet)
					{
						$ServiceRestartAttempt = Invoke-ControlCommand -SessionID $($_.SessionID) -Powershell -Command "(new-object Net.WebClient).DownloadString('$($Using:LTPoShURI)') | iex; Update-LTService" -TimeOut 300000 -MaxLength 10240
						return $ServiceRestartAttempt
					}
				} | out-null
			}
			ElseIf ($Action -eq 'Restart')
			{
				$ObjectCapture | Start-RSJob -Throttle $BatchSize -Name { "$($_.ComputerName) - $($_.ComputerID) - Restart Service" } -ScriptBlock {
					Import-Module AutomateAPI -Force
					$ConnectOptions = $Using:ConnectOptions
					If (Connect-ControlAPI @ConnectOptions -SkipCheck -Quiet)
					{
						$ServiceRestartAttempt = Invoke-ControlCommand -SessionID $($_.SessionID) -Powershell -Command "(new-object Net.WebClient).DownloadString('$($Using:LTPoShURI)') | iex; Restart-LTService" -TimeOut 120000 -MaxLength 10240
						return $ServiceRestartAttempt
					}
				} | out-null
			}
			ElseIf ($Action -eq 'Reinstall')
			{
				$ObjectCapture | Start-RSJob -Throttle $BatchSize -Name { "$($_.ComputerName) - $($_.ComputerID) - ReInstall Service" } -ScriptBlock {
					Import-Module AutomateAPI -Force
					$ConnectOptions = $Using:ConnectOptions
					If (Connect-ControlAPI @ConnectOptions -SkipCheck -Quiet)
					{
						$ServiceRestartAttempt = Invoke-ControlCommand -SessionID $($_.SessionID) -Powershell -Command "(new-object Net.WebClient).DownloadString('$($Using:LTPoShURI)') | iex; ReInstall-LTService" -TimeOut 300000 -MaxLength 10240
						return $ServiceRestartAttempt
					}
				} | out-null
			}
			Else
			{
				Write-Host -BackgroundColor Yellow -ForegroundColor Red "Action $Action is not currently supported."
			}
			
			Write-Host -ForegroundColor Green "All jobs are queued. Waiting for them to complete. Reinstall jobs can take up to 10 minutes"
			while ($(Get-RSJob | Where-Object { $_.State -ne 'Completed' } | Measure-Object | Select-Object -ExpandProperty Count) -gt 0)
			{
				Start-Sleep -Milliseconds 10000
				Write-Host -ForegroundColor Yellow "$(Get-Date) - There are currently $(Get-RSJob | Where-Object{ $_.State -ne 'Completed' } | Measure-Object | Select-Object -ExpandProperty Count) jobs left to complete"
			}
			
			$AllServiceJobs = Get-RSJob | Where-Object { $_.Name -like "*$($Action) Service*" }
			
			foreach ($Job in $AllServiceJobs)
			{
				$RecJob = ""
				$RecJob = Receive-RSJob -Name $Job.Name
				If ($Action -eq 'Check')
				{
					If ($RecJob -like '*LastSuccessStatus*') { $AutofixSuccess = $true }
					else { $AutofixSuccess = $false }
				}
				ElseIf ($Action -eq 'Update')
				{
					If ($RecJob -like '*successfully*') { $AutofixSuccess = $true }
					else { $AutofixSuccess = $false }
				}
				ElseIf ($Action -eq 'Restart')
				{
					If ($RecJob -like '*Restarted successfully*') { $AutofixSuccess = $true }
					else { $AutofixSuccess = $false }
				}
				ElseIf ($Action -eq 'ReInstall')
				{
					If ($RecJob -like '*successfully*') { $AutofixSuccess = $true }
					else { $AutofixSuccess = $false }
				}
				Else
				{
					$AutofixSuccess = $true
				}
				$ResultArray += [pscustomobject] @{
					JobName = $Job.Name
					JobType = "$($Action) Automate Services"
					JobState = $Job.State
					JobHasErrors = $Job.HasErrors
					JobResultStream = "$RecJob"
					AutofixSuccess = $AutofixSuccess
				}
			}
			
			Write-Host -ForegroundColor Green "All jobs completed"
			return $ResultArray
		}
		Else
		{
			'No Queued Jobs'
		}
	}
}
                        <#
	.SYNOPSIS
		Fetches credentials stored by the Set-CredentialsLocallStored function.
	
	.DESCRIPTION
		Defaults to "$($env:USERPROFILE)\AutomateAPI\" to fetch credentials
	
	.PARAMETER Automate
		When specified, fetches credentials from disk and loads them into the variables necessary for Automate related cmdlets to function
	
	.PARAMETER Control
		When specified, fetches credentials from disk and loads them into the variables necessary for Control related cmdlets to function
	
	.PARAMETER All
		When specified, fetches credentials from disk and loads them into the variables necessary for Automate and Control related cmdlets to function
	
	.PARAMETER CredentialPath
		Overrides default credential file path
	
	.PARAMETER CredentialDirectory
		Overrides default credential folder path
	
	.EXAMPLE
		Import-Module AutomateAPI
		if(!$Connected)
		{
		    try
		    {
		        Get-CredentialsLocallyStored -All
		        $Connected = $true   
		    }
		    catch
		    {
		        try
		        {
		            Set-CredentialsLocallyStored -All
		            $Connected = $true
		        }
		        catch
		        {

		        }
		    }   
		}

		Get-AutomateComputer -ComputerID 171 | Get-AutomateControlInfo | Invoke-ControlCommand -Command { "Hello World" } -PowerShell
	
	.NOTES
		Does not return a credential object!
		You do not need to run Connect-AutomateAPI or Connect-ControlAPI, this method calls those methods to validate the credentials
		To prevent reconnection each time, you will want to store the connection state yourself as shown in the above example
#>
function Get-CredentialsLocallyStored
{
	[CmdletBinding()]
	param (
		[Parameter(ParameterSetName = 'Automate')]
		[switch]$Automate,
		[Parameter(ParameterSetName = 'Control')]
		[switch]$Control,
		[Parameter(ParameterSetName = "All")]
		[switch]$All,
		[Parameter(ParameterSetName = 'Custom', Mandatory = $True)]
		[string]$CredentialPath,
		[Parameter(ParameterSetName = 'Automate')]
		[Parameter(ParameterSetName = 'Control')]
		[string]$CredentialDirectory = "$($env:USERPROFILE)\AutomateAPI\"
		
	)
	
	If ($All)
	{
		$Automate = $True
		$Control = $True
	}
	
	If ($Automate)
	{
		$CredentialPath = "$($CredentialDirectory)\Automate - Credentials.txt"
		If (-not (Test-Path $CredentialPath -EA 0))
		{
			Throw [System.IO.FileNotFoundException] "Automate Credentials not found at $($CredentialPath)"
		}
		$StoreVariables = @(
			@{ 'Name' = 'CWAServer'; 'Scope' = 'Script' },
			@{ 'Name' = 'CWACredentials'; 'Scope' = 'Script' },
			@{ 'Name' = 'CWATokenKey'; 'Scope' = 'Script' },
			@{ 'Name' = 'CWATokenInfo'; 'Scope' = 'Script' }
		)
		$StoreBlock = Get-Content $CredentialPath | ConvertFrom-Json
		Foreach ($SaveVar in $StoreVariables)
		{
			If (!($StoreBlock.$($SaveVar.Name))) { Continue }
			If ($SaveVar.Name -match 'Credential')
			{
				Try
				{
					$Null = Set-Variable @SaveVar -Value $(New-Object System.Management.Automation.PSCredential -ArgumentList $($StoreBlock.$($SaveVar.Name).Username), $(ConvertTo-SecureString $($StoreBlock.$($SaveVar.Name).Password)))
				}
				Catch
				{
					Write-Warning "Failed to restore $($SaveVar.Name). The stored password is invalid."
				}
			}
			ElseIf ($SaveVar.Name -match 'Key')
			{
				Try
				{
					$Null = Set-Variable @SaveVar -Value $(ConvertTo-SecureString $($StoreBlock.$($SaveVar.Name)))
				}
				Catch
				{
					Write-Warning "Failed to restore $($SaveVar.Name). The stored secure value is invalid."
				}
			}
			Else
			{
				$Null = Set-Variable @SaveVar -Value $($StoreBlock.$($SaveVar.Name))
			}
		}
		If ($Script:CWATokenKey -and $Script:CWATokenKey.GetType() -match 'SecureString')
		{
			$AuthorizationToken = $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:CWATokenKey)))
			$AutomateToken = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$AutomateToken.Add("Authorization", "Bearer $AuthorizationToken")
			$Script:CWAToken = $AutomateToken
		}
		If (!(Connect-AutomateAPI -Verify -Quiet -ErrorAction 0))
		{
			Write-Error "Automate Credentials failed to successfully validate. Call Connect-AutomateAPI to establish a valid session." -ErrorAction 'Continue'
		}
	}
	
	If ($Control)
	{
		$CredentialPath = "$($CredentialDirectory)\Control - Credentials.txt"
		If (-not (Test-Path $CredentialPath -EA 0))
		{
			Throw [System.IO.FileNotFoundException] "Control Credentials not found at $($CredentialPath)"
		}
		$StoreVariables = @(
			@{ 'Name' = 'ControlAPICredentials'; 'Scope' = 'Script' },
			@{ 'Name' = 'ControlServer'; 'Scope' = 'Script' },
			@{ 'Name' = 'ControlAPIKey'; 'Scope' = 'Script' }
		)
		
		$StoreBlock = Get-Content $CredentialPath | ConvertFrom-Json
		Foreach ($SaveVar in $StoreVariables)
		{
			If (!($StoreBlock.$($SaveVar.Name))) { Continue }
			If ($SaveVar.Name -match 'Credential')
			{
				Try
				{
					$Null = Set-Variable @SaveVar -Value $(New-Object System.Management.Automation.PSCredential -ArgumentList $($StoreBlock.$($SaveVar.Name).Username), $(ConvertTo-SecureString $($StoreBlock.$($SaveVar.Name).Password)))
				}
				Catch
				{
					Write-Warning "Failed to restore $($SaveVar.Name). The stored password is invalid."
				}
			}
			ElseIf ($SaveVar.Name -match 'Key')
			{
				Try
				{
					$Null = Set-Variable @SaveVar -Value $(ConvertTo-SecureString $($StoreBlock.$($SaveVar.Name)))
				}
				Catch
				{
					Write-Warning "Failed to restore $($SaveVar.Name). The stored secure value is invalid."
				}
			}
			Else
			{
				$Null = Set-Variable @SaveVar -Value $($StoreBlock.$($SaveVar.Name))
			}
		}
		If (!(Connect-ControlAPI -Verify -Quiet -ErrorAction 0))
		{
			Write-Error "Control Credentials failed to successfully validate. Call Connect-ControlAPI to establish a valid session." -ErrorAction 'Continue'
		}
	}
	
	If ($Custom)
	{
		If (-not (Test-Path "$($CredentialPath)"))
		{
			Throw [System.IO.FileNotFoundException] "Credentials not found at $($CredentialPath)"
		}
		$StoreBlock = Get-Content $CredentialPath | ConvertFrom-Json
		
		Try
		{
			$CustomCredentialObject = New-Object System.Management.Automation.PSCredential -ArgumentList $($StoreBlock.CustomCredentials.Username), $(ConvertTo-SecureString $($StoreBlock.CustomCredentials.Password))
		}
		Catch
		{
			Write-Warning "Failed to restore CustomCredential from $($CredentialPath). The stored password is invalid."
		}
		Return $CustomCredentialObject
	}
	
}
function Set-CredentialsLocallyStored
{
    <#
.SYNOPSIS
   Sets credential objects on a server that has never had them before

.DESCRIPTION
   This function takes a Powershell script and sets credentials on the local disk encrypted with the local system
.PARAMETER Save
   Saves the credentials that are currently in use
   When not present, the user will be required to provide credentials interactively
.PARAMETER All
   Will save both Automate and Control credentials
.EXAMPLE
   Set-CredentialsLocallyStored -Automate

.Example
   Set-CredentialsLocallyStored -Custom -CredentialDisplayName 'Office365' -CredentialDirectory "C:\Credentials"

#>
	[CmdletBinding()]
	param (
		[Parameter(ParameterSetName = "Automate")]
		[switch]$Automate,
		[Parameter(ParameterSetName = "All")]
		[switch]$All,
		[Parameter(ParameterSetName = "Control")]
		[switch]$Control,
		[Parameter(ParameterSetName = "Custom", Mandatory = $True)]
		[switch]$Custom,
		[Parameter(ParameterSetName = "Custom", Mandatory = $True)]
		[string]$CredentialDisplayName,
		[Parameter(ParameterSetName = 'Automate')]
		[Parameter(ParameterSetName = 'Control')]
		[Parameter(ParameterSetName = 'All')]
		[alias("Save")]
		[switch]$SaveCurrent,
		[Parameter(ParameterSetName = 'Automate')]
		[Parameter(ParameterSetName = 'Control')]
		[Parameter(ParameterSetName = "Custom", Mandatory = $True)]
		[string]$CredentialDirectory = "$($env:USERPROFILE)\AutomateAPI\"
	)
	
	If ($All)
	{
		$Automate = $True
		$Control = $True
	}
	
	If (-not (Test-Path $CredentialDirectory))
	{
		New-Item -ItemType Directory -Force -Path $CredentialDirectory | ForEach-Object{ $_.Attributes = "hidden" }
	}
	
	If ($Automate)
	{
		If (!$SaveCurrent)
		{
			# The Connect-AutomateAPI Cmdlet will interrogate the user for when give passed the following parameters
			# The variables are stored in script scope variables
			Connect-AutomateAPI -Server '' -Force
		}
		
		$StoreVariables = @(
			@{ 'Name' = 'CWAServer'; 'Scope' = 'Script' },
			@{ 'Name' = 'CWACredentials'; 'Scope' = 'Script' },
			@{ 'Name' = 'CWATokenKey'; 'Scope' = 'Script' },
			@{ 'Name' = 'CWATokenInfo'; 'Scope' = 'Script' }
		)
		
		$StoreBlock = [pscustomobject]@{ }
		$CredentialPath = "$($CredentialDirectory)\Automate - Credentials.txt"
		
		Foreach ($SaveVar in $StoreVariables)
		{
			If (!(Get-Variable @SaveVar -ErrorAction 0)) { Continue }
			If ($SaveVar.Name -match 'Credential')
			{
				Try
				{
					Write-Debug "Trying to save $($SaveVar.Name)"
					$x_Credential = @{ 'UserName' = (Get-Variable @SaveVar -ValueOnly).UserName; 'Password' = ((Get-Variable @SaveVar -ValueOnly).Password | ConvertFrom-SecureString) }
					$Null = $StoreBlock | Add-Member -NotePropertyName $($SaveVar.Name) -NotePropertyValue $x_Credential
				}
				Catch
				{
					Write-Warning "Failed to store $($SaveVar.Name), it is not a valid Credential."
				}
			}
			ElseIf ($SaveVar.Name -match 'Key')
			{
				Try
				{
					$x_Key = (Get-Variable @SaveVar -ValueOnly | ConvertFrom-SecureString)
					$Null = $StoreBlock | Add-Member -NotePropertyName $($SaveVar.Name) -NotePropertyValue $x_Key
				}
				Catch
				{
					Write-Warning "Failed to store $($SaveVar.Name), it is not a valid Secure String."
				}
			}
			Else
			{
				$Null = $StoreBlock | Add-Member -NotePropertyName $($SaveVar.Name) -NotePropertyValue (Get-Variable @SaveVar -ValueOnly)
			}
		}
		
		$StoreBlock | ConvertTo-JSON -Depth 10 | Out-File -FilePath $CredentialPath -Force -NoNewline
		Write-Output "Automate Credentials Set"
	}
	
	If ($Control)
	{
		If (!$SaveCurrent)
		{
			# This forces the Connect-ControlAPI function to interrogate the user for credentials
			# The variables are stored in script scope variables
			Connect-ControlAPI -Server ''
		}
		
		$StoreVariables = @(
			@{ 'Name' = 'ControlAPICredentials'; 'Scope' = 'Script' },
			@{ 'Name' = 'ControlServer'; 'Scope' = 'Script' },
			@{ 'Name' = 'ControlAPIKey'; 'Scope' = 'Script' }
		)
		
		$StoreBlock = [pscustomobject]@{ }
		$CredentialPath = "$($CredentialDirectory)\Control - Credentials.txt"
		# Here we read the variables that were stored by the Connect-ControlAPI method and ultimately store them
		Foreach ($SaveVar in $StoreVariables)
		{
			If (!(Get-Variable @SaveVar -ErrorAction 0)) { Continue }
			If ($SaveVar.Name -match 'Credential')
			{
				Try
				{
					$x_Credential = @{ 'UserName' = (Get-Variable @SaveVar -ValueOnly).UserName; 'Password' = ((Get-Variable @SaveVar -ValueOnly).Password | ConvertFrom-SecureString) }
					$Null = $StoreBlock | Add-Member -NotePropertyName $($SaveVar.Name) -NotePropertyValue $x_Credential
				}
				Catch
				{
					Write-Warning "Failed to store $($SaveVar.Name), it is not a valid Credential."
				}
			}
			ElseIf ($SaveVar.Name -match 'Key')
			{
				Try
				{
					$x_Key = (Get-Variable @SaveVar -ValueOnly | ConvertFrom-SecureString)
					$Null = $StoreBlock | Add-Member -NotePropertyName $($SaveVar.Name) -NotePropertyValue $x_Key
				}
				Catch
				{
					Write-Warning "Failed to store $($SaveVar.Name), it is not a valid Secure String."
				}
			}
			Else
			{
				$Null = $StoreBlock | Add-Member -NotePropertyName $($SaveVar.Name) -NotePropertyValue (Get-Variable @SaveVar -ValueOnly)
			}
		}
		
		$StoreBlock | ConvertTo-JSON -Depth 10 | Out-File -FilePath $CredentialPath -Force -NoNewline
		Write-Output "Control Credentials Set"
	}
	
	If ($Custom)
	{
		$StoreBlock = [pscustomobject]@{ }
		$CredentialPath = "$($CredentialDirectory)\$($CredentialDisplayName).txt"
		$CustomCredentials = Get-Credential -Message "Please enter the Custom Username and Password to store"
		$Null = $StoreBlock | Add-Member -NotePropertyName 'CustomCredentials' -NotePropertyValue @{ 'UserName' = $CustomCredentials.UserName; 'Password' = ($CustomCredentials.Password | ConvertFrom-SecureString) }
		
		$StoreBlock | ConvertTo-JSON -Depth 10 | Out-File -FilePath $CredentialPath -Force -NoNewline
		Write-Output "Custom Credentials Set for $($CredentialDisplayName)"
	}
	
}
function Get-ConditionsStacked
{
	param (
		[Parameter()]
		[string[]]$ArrayOfConditions
	)
	
	$FinalString = ($ArrayOfConditions) -join " And "
	Return $FinalString
}
function Get-CWAIKToken
{
	param (
		[Parameter(Position = 0)]
		$APIKey = ([SecureString]$Script:ControlAPIKey)
	)
	
	If (!$APIKey)
	{
		Throw "The API Key is not defined and must be provided"
		Continue
	}
	
	If ($APIKey.GetType() -match 'SecureString')
	{
		$APIKey = $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($APIKey)))
	}
	
	# If you bothered to actually inspect this module thoroughly, come PM @Gavsto in Slack and win a free Gavsto Karma Point ;)
	
	$TimeStepSeconds = 600
	$origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
	$epochsteps = [long]$((New-TimeSpan -Start $origin -End $(get-date).ToUniversalTime()).TotalSeconds/$TimeStepSeconds)
	$barray = [System.BitConverter]::GetBytes($epochsteps); [array]::Reverse($barray)
	$hmacsha = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($APIKey))
	If ($hmacsha)
	{
		$Local:CWAIKToken = [Convert]::ToBase64String($hmacsha.ComputeHash($barray))
	}
	If ($Local:CWAIKToken)
	{
		Write-Debug "Generated CWAIKToken ""$($Local:CWAIKToken)"""
	}
	Else
	{
		Write-Debug "Error. CWAIKToken was not generated using APIKey $APIKey."
	}
	Return $Local:CWAIKToken
}
function Get-SleepDelay
{
	param ($seconds = 1,
		$totalseconds)
	if (!$totalseconds) { $totalseconds = $seconds * 2 }
	Try { $Delay = [math]::Ceiling([math]::pow(($totalseconds / 2) - [math]::Abs($seconds - ($totalseconds / 2)), 1 / 3)) }
	Catch { $Delay = 1 }
	Finally { If ([double]::IsNaN($Delay) -or $Delay -lt 1) { $Delay = 1 } }
	Write-Debug "Sleep Delay is $Delay"
	return $Delay
}

Function Split-Every($list, $count = 4)
{
	$aggregateList = @()
	
	$blocks = [Math]::Floor($list.Count / $count)
	$leftOver = $list.Count % $count
	$start = 0
	for ($i = 0; $i -lt $blocks; $i++)
	{
		$end = $count * ($i + 1) - 1
		
		$aggregateList += @( ,$list[$start .. $end])
		$start = $end + 1
	}
	if ($leftOver -gt 0)
	{
		$aggregateList += @( ,$list[$start .. ($start + $leftOver - 1)])
	}
	If ($list.Count -le $count) { $aggregateList = @( ,$aggregateList) }
	$aggregateList
}
Export-ModuleMember -Function @('Compare-AutomateControlStatus', 'Connect-ControlSession', 'Get-AutomateClient', 'Get-AutomateComputer', 'Get-AutomateControlInfo', 'Get-AutomateTicket', 'Get-ControlSessions', 'Invoke-ControlCommand', 'Repair-AutomateAgent', 'Get-CredentialsLocallyStored', 'Set-CredentialsLocallyStored')