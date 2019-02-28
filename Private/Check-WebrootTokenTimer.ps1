Function Check-WebrootTokenTimer {
	Param (
	[DateTime]$myTokenStartTime
	)
	$TimeNow = get-date -format HH:mm:ss
	$TimeDiff = New-TimeSpan $myTokenStartTime $TimeNow
	
	#return the time difference
	Return $TimeDiff
}