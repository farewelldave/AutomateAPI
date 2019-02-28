Function Get-WebrootToken {
	Param (
		$myCredentials,
		$myTokenURL,
		$myWebrootUser,
		$myWebrootPassword
	)
	write-host "Requesting REST token..." -ForegroundColor Green
	$TokenParams = @{
				"ErrorAction" = "Stop"
				"URI" = $myTokenURL
				"Headers" = @{"Authorization" = "Basic "+ $myCredentials}
				"Body" = @{
							  "username" = $myWebrootUser
							  "password" = $myWebrootPassword
							  "grant_type" = 'password'
							  "scope" = 'Console.GSM'
							}
				"Method" = 'post'
				"ContentType" = 'application/x-www-form-urlencoded'
				}
	#create hash table to hold variables we want to return
	[hashtable]$Return = @{} 
	$Return.AccessToken = (Invoke-RestMethod @TokenParams).access_token
	#start token timer
	$Return.TokenStartTime = get-date -format HH:mm:ss
	#Output these 2 var
	Return $Return
}