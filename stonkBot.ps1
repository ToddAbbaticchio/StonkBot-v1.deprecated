#Region Functions
    #Region Logging/Messaging Related functions
    function Write-Log {
        param (
            $severity,
            $message,
            $channel,
            [switch]$noNewLine = $false
        )

        $wlString = "Write-Host `"$message`""
        if ($noNewLine) { $wlString += " -noNewLine" }

        switch ($severity) {
            "discordPost" {
                if ($noNewLine) {
                    Write-Host "$message" -nonewline -ForegroundColor Black -BackgroundColor Green
                    Invoke-DiscordPost -message "$message" -channel "$channel"
                    return
                }
                Write-Host "$message" -ForegroundColor Black -BackgroundColor Green
                Invoke-DiscordPost -message "$message" -channel "$channel"
                # Play buzzer when we get a match
                #for ($i = 1; $i -le 3; $i++) {
                #    [console]::beep(200,200)
                #}
            }
            "tag" {
                if ($noNewLine) {
                    Write-Host "$message" -nonewline -ForegroundColor DarkGray
                    return
                }
                Write-Host "$message" -ForegroundColor DarkGray
            }
            "debug" {
                if ($noNewLine) {
                    Write-Host "$message" -nonewline -ForegroundColor DarkGray
                    return
                }
                Write-Host "$message" -ForegroundColor DarkGray
            }
            "info" {
                if ($noNewLine) {
                    Write-Host "$message" -nonewline -ForegroundColor DarkCyan
                    return
                }
                Write-Host "$message" -ForegroundColor DarkCyan
            }
            "warning" {
                if ($noNewLine) {
                    Write-Host "$message" -nonewline -ForegroundColor DarkYellow
                    return
                }
                Write-Host "$message" -ForegroundColor DarkYellow
            }
            "error" {
                if ($noNewLine) {
                    Write-Host "$message" -nonewline -ForegroundColor Red
                    return
                }
                Write-Host "$message" -ForegroundColor Red
            }
        }
    }

    function Invoke-DiscordPost {
        [cmdletbinding()]
        param (
            $message,
            $channel,
            $imagePath
        )

        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }

        process {
            if ($script:messagePref -eq "silenced") {
                Write-Log -Severity Warning -Message "This is a test run - no posting to discord!"
                return
            }

            switch ($channel) {
                "patternA" { $chatBotUrl = "redacted" }
                "patternB" { $chatBotUrl = "redacted" }
                "patternC" { $chatBotUrl = "redacted" }
                "patternD" { $chatBotUrl = "redacted" }
                "oiRatio" { $chatBotUrl = "redacted" }
                "postChart" { $chatBotUrl = "redacted" }
                "dailyVolumeAlert" { $chatBotUrl = "redacted" }
                "ES" { $chatBotUrl = "redacted" }
                "buyPointA" { $chatBotUrl = "redacted" }
            }
            
            try {
                $postJson = [PSCustomObject]@{ content = $message } | ConvertTo-Json
                invoke-RestMethod -uri $chatBotUrl -Method Post -Headers @{ "Content-Type" = "application/json" } -body $postJson | Out-Null
            }
            catch {
                Write-Log -severity error -message "Error posting to Discord: $($_.Exception.Message)"
            }
        }

        end {
            #Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }

    function New-OutputFile {
        [cmdletbinding()]
        param (
            $stonklist = $stonklist,
            [string]$runMode = "nightlyReport"
        )
        
        begin {
            Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }
    
        process {
            switch ($runMode) {
                "nightlyReport" { $filePath = $nightlyReport }
                "middayReport" { $filePath = $middayReport }
            }

            if (Test-Path -path $filePath) {
                try {
                    Remove-Item -path $filePath -force
                    Write-Log -severity debug -message "Removed old report: $filePath"
                }
                catch {
                    Write-Log -severity error -message "Error removing old report: $filepath - $($_.Exception.Message)"
                }
            }
    
            foreach ($stonk in $stonkList) {
                # grab historical data
                $hData = Invoke-StonkQuery -stonk $stonk -historical
    
                # Get today's data and construct an obj that matches historical data structure
                $realTimeData = Invoke-StonkQuery -stonk $stonk
                [double]$targetPrice = ($script:targetPriceFile | Where-Object { $_.Date -eq (Get-Date).toString("MM/dd/yy") }).$stonk
    
                # Handle closeVar for midday report
                if ($runMode -eq "middayReport") {
                    $todayObj = @{
                        ticker = $stonk
                        open = $realTimeData.openprice
                        close = $realTimeData.lastprice
                        high = $realTimeData.highPrice
                        low = $realtimedata.lowPrice
                        volume = $realtimedata.totalVolume
                        date = (Get-Date).tostring("MM/dd/yy")
                        targetPrice = $targetPrice
                    }
                    $hData += $todayObj
                }
    
                # do the stuff
                foreach ($day in $hData) {
                    # if runMode is 'updateReport' skip every day except today
                    if ($runMode -eq "updateReport" -and $day.date -ne (Get-Date).toString("MM/dd/yy")) {
                        write-log -severity debug -message "runMode: updateReport and day isn't today.  Skipping!"
                        continue
                    }
    
                    [datetime]$temp = $day.date
                    $dayOfWeek = $temp.toString("dddd")
    
                    write-log -severity debug -message "Processing $stonk - $($day.date) for $runMode..." -nonewline
    
                    # Get previous day's data
                    $prevDayDate = (Get-AdjacentTradeDay -previous -startDate $day.date).toString("MM/dd/yy")
                    $prevDay = Get-DbData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq $prevDayDate }
                    if (!$prevDay) {
                        Write-Log -severity warning -message "No historical data available for targetDate: $prevDayDate"
                        continue
                    }
    
                    # KUp
                    [bool]$kUp = !($day.open -ge $day.close)
    
                    # Compare prevDay
                    if ($day.open -gt $prevDay.open -and $day.close -gt $prevDay.close) { $comparePrevDay = "1" }
                    elseif ($day.open -lt $prevDay.open -and $day.close -lt $prevDay.close) { $comparePrevDay = "-1"}
                    else { $comparePrevDay = "0" }
                    
                    # JumpPass
                    if ($day.targetPrice -ne 0 -and $prevDay.targetPrice -ne 0) {
                        if ($prevDay.high -lt $prevDay.targetPrice -and $day.low -gt $day.targetPrice) { $jumpPass = "1" }
                        elseif ($prevDay.low -gt $prevDay.targetPrice -and $day.high -lt $day.targetPrice) { $jumpPass = "-1" }
                        else { $jumpPass = "0" }
                    }
                    else { $jumpPass = "" }
                    
                    # RealPass
                    [array]$realPassArray = ($day.open,$day.close) | Sort-Object { [double]$_ }
                    [bool]$realPass = ($realPassArray[0] -le $day.targetPrice -and $day.targetPrice -le $realPassArray[1])
    
                    # LinePass
                    if ($day.targetPrice -ne 0) {
                        $arr = ($day.open,$day.close,$day.high,$day.low) | Sort-Object -Descending { [int]$_ }
                        [bool]$linePass = (($arr[1] -lt $day.targetPrice -and $day.targetPrice -le $arr[0]) -or ($arr[3] -le $day.targetPrice -and $day.targetPrice -lt $arr[2]))
                    }
                    else { [string]$linePass = "" }
    
                    # LCross
                    [bool]$lCross = (($jumpPass -eq "1" -or $jumpPass -eq "-1") -or $realPass -or $linePass)
    
                    # LAbove
                    if ($day.targetPrice -ne 0) {
                        if ($day.targetPrice -lt $day.low) { $lAbove = "-1" }
                        elseif ($day.targetPrice -gt $day.high) { $lAbove = "1" }
                        else { $lAbove = "0" }
                    }
                    else { [string]$lAbove = "" }
    
                    if ($day.targetPrice -eq 0) { [string]$day.targetPrice = ""}
                    
                    # Build initial content string
                    $content = "$($day.date),$dayOfWeek,$stonk,$($day.targetPrice),$($day.open),$($day.close),$($day.high),$($day.low),$kUp,$compareprevDay,$jumpPass,$realPass,$linePass,$lCross,$lAbove"
    
                    # Attempt to get next trade day's data
                    $nextDayDate = (Get-AdjacentTradeDay -next -startDate $day.date).toString("MM/dd/yy")
                    $nextDay = Get-DbData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq $nextDayDate }
                    if (!$nextDay) {
                        Write-Log -severity debug -message "No data available for 'next day' targetDate: $nextDayDate."
                        $content | Out-File -path $filePath -Append -Force
                        Write-Log -severity debug -message "Wrote output for $stonk"
                        continue
                    }
    
                    try {
                        $nextDayPercent = ($nextDay.close - $nextDay.open) / $nextDay.open
                        $content += ",$($nextDayPercent.toString("P"))"
                    }
                    catch {
                        write-log -severity error -message "Error calculating nextDayPercent: $($_.Exception.Message)"
                    }
    
                    try {
                        $nextDayComp = ($nextDay.close - $day.close) / $day.close
                        $content += ",$($nextDayComp.toString("P"))"
                    }
                    catch {
                        write-log -severity error -message "Error calculating nextDayCompPercent: $($_.Exception.Message)"
                    }
    
                    try {
                        # Write header row if file doesn't exist
                        if (!(Test-Path -Path $filePath)) { "Date,Day,Ticker,TargetPrice,Open,Close,High,Low,KUp,CompareYesteday,JumpPass,RealPass,LinePass,L-Cross,L-Above,NextDay%,NextDay/YesterdayComp" | Out-File -path $filePath -Force }
                        
                        # Append content from historical data pulls
                        $content | Out-File -path $filePath -Append -Force
                    }
                    catch {
                        Write-Log -Severity error -message "Error writing to file: $filePath - $($_.Exception.Message)"
                    }
                }

                Write-Log -Severity Debug -Message "Done!"
            }
        }
    
        end {
            Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }
    #EndRegion

    #Region TDAmeritradeAPI Related functions
    function Invoke-GenerateTokens {
        [cmdletbinding()]
        param (
            [string]$redirectUrl = "https://localhost:8080/",
            [string]$clientId = $tdClientId
        )
    
        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)" -noNewLine
        }
    
        process {
            $tokenUrl = "https://api.tdameritrade.com/v1/oauth2/token"
            Add-Type -AssemblyName System.Web
        
            # If refresh token was passed...
            if ($refreshToken) {
                $tokenParameters = @{
                    grant_type = 'refresh_token'
                    refresh_token = $refreshToken
                    client_id = "$ClientId@AMER.OAUTHAP"
                }
                try {
                    $refreshTokenResponse = Invoke-WebRequest -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -Uri $tokenUrl -Method Post -body $tokenParameters
                }
                catch {
                    Write-Log -severity error -message "Error requesting new access token via refresh token: $($_.Exception.Message)"
                }
            }
            # Otherwise generate using redirectURL...
            else {
                $paramObj = @{
                    response_type = 'code'
                    redirect_uri = $RedirectUrl
                    client_id = "$ClientId@AMER.OAUTHAP"
                }
        
                $query = ($paramObj.Keys | ForEach-Object { "$($_)=$([System.Uri]::EscapeDataString($paramObj[$_]))"}) -join "&"
                
                # Root CA
                $rootCert = New-SelfSignedCertificate -CertStoreLocation cert:\CurrentUser\My -DnsName "RootCA" -keyusage CertSign,CRLSign -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.4,1.3.6.1.5.5.7.3.3,1.3.6.1.5.5.7.3.8,1.3.6.1.5.5.7.3.1","2.5.29.19={critical}{text}ca=TRUE")
                [System.Security.SecureString]$rootcertPassword = ConvertTo-SecureString -String "password" -Force -AsPlainText
                [String]$rootCertPath = Join-Path -Path 'cert:\CurrentUser\My\' -ChildPath "$($rootcert.Thumbprint)"
                Export-PfxCertificate -Cert $rootCertPath -FilePath 'RootCA.pfx' -Password $rootcertPassword | Out-Null
                Export-Certificate -Cert $rootCertPath -FilePath 'RootCA.crt' | Out-Null
                
                # ssl cert
                $testCert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName "localhost" -KeyExportPolicy Exportable -KeyLength 2048 -KeyUsage DigitalSignature,KeyEncipherment -textextension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") -Signer $rootCert
                #[String]$testCertPath = Join-Path -Path 'cert:\LocalMachine\My\' -ChildPath "$($testCert.Thumbprint)"
                
                # import CA into trusted root
                Import-PfxCertificate -FilePath "$PWD\RootCA.pfx" -CertStoreLocation Cert:\LocalMachine\Root -Confirm:$false -Password $rootcertPassword | Out-Null
        
                # remove CA from My
                Remove-Item -Force "cert:\CurrentUser\My\$($rootCert.Thumbprint)" | Out-Null
        
                $appid = [System.Guid]::NewGuid().Guid
                $hash = $testCert.Thumbprint
                netsh http delete sslcert hostnameport=localhost:8080 | Out-Null
                netsh http add sslcert hostnameport=localhost:8080 certhash=$hash appid=`{$appid`} certstorename=my | Out-Null
        
                $listener = New-Object -TypeName System.Net.HttpListener
                $listener.Prefixes.Add("https://localhost:8080/")
                $listener.Start()
        
                Write-Log -severity info -message "Launching browser.  Please log in to TD Ameritrade with your brokerage account credentials."
                Start-Process "https://auth.tdameritrade.com/auth?$query"
        
                $task = $listener.GetContextAsync()
                while (!$context) {
                    if ($task.Wait(500)) {
                        $context = $task.Result
                    }
                    Start-Sleep -Milliseconds 100
                }
                $redirectRequestUrl = $context.Request.Url
        
                $content = [System.Text.Encoding]::UTF8.GetBytes("
                <!doctype html>
                <html lang='en'>
                    <head>
                        <meta charset=""utf-8"">
                        <meta name=""viewport"" content=""width=device-width, initial-scale=1, shrink-to-fit=no"">
                        <link rel=""stylesheet"" href=""https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"" integrity=""sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"" crossorigin=""anonymous"">
                        <title>TD Ameritrade Login Redirect Landing Page</title>
                    </head>
                    <body>
                        <div class=""container"">
                            <div class=""jumbotron container"">
                                <h1 class=""display-4"">TD Ameritrade API Login Redirect Page</h1>
                                <p class=""lead"">Served locally by temporary web host in PowerShell.</p>
                            </div>
                            <div class=""card mb-3"">
                                <h5 class=""card-header"">Recieved the following request from TD Ameritrade login</h5>
                                <div class=""card-body"">
                                    <pre><code>$($redirectRequestUrl.AbsoluteUri)</code></pre>
                                </div>
                            </div>")
                $context.Response.ContentType = "text/html"
                $context.Response.OutputStream.Write($content, 0, $content.Length)
                $code = [System.Web.HttpUtility]::ParseQueryString($redirectRequestUrl.Query)['code']
                $tokenParameters = @{
                    grant_type = 'authorization_code'
                    access_type = 'offline'
                    code = $code
                    client_id = "$ClientId@AMER.OAUTHAP"
                    redirect_uri = $RedirectUrl
                }
                $refreshTokenResponse = Invoke-WebRequest -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -Uri $tokenUrl -Method Post -body $tokenParameters
                $outputValue = $refreshTokenResponse.Content | ConvertFrom-Json
                $content = [System.Text.Encoding]::UTF8.GetBytes("
                            <div class=""card mb-3"">
                                <h5 class=""card-header"">Retrieved access token and refresh token</h5>
                                <div class=""card-body"">
                                    <p class=""card-text"">This content was also provided in the return value of the powershell function</p>
                                    <pre><code>$($refreshTokenResponse.Content)</code></pre>
                                </div>
                            </div>
                            <div class=""card mb-3"">
                                <h5 class=""card-header"">Your current Authorization header for API requests</h5>
                                <div class=""card-body"">
                                    <pre><code>Authorization : Bearer $($outputValue.access_token)</code></pre>
                                </div>
                            </div>
                        </div>
                        <script src=""https://code.jquery.com/jquery-3.3.1.slim.min.js"" integrity=""sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo"" crossorigin=""anonymous""></script>
                        <script src=""https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"" integrity=""sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1"" crossorigin=""anonymous""></script>
                        <script src=""https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"" integrity=""sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM"" crossorigin=""anonymous""></script>
                    </body>
                </html>")
                $context.Response.OutputStream.Write($content, 0, $content.Length)
                $context.Response.OutputStream.Close()
                $context.Response.Close();
                Start-Sleep -Seconds 5
                $listener.Stop()
                $listener.Close()
                $listener.Dispose()
            }
        
            # Parse response / get new tokens
            try {
                $response = $refreshTokenResponse.Content | ConvertFrom-Json
                if ($response.access_token -and $response.refresh_token) {
                    $tokenObj = @{
                        accessToken = $response.access_token
                        refreshToken = $response.refresh_token
                    }
                    add-dbdata -table "oauth_tokens" -dataObj $tokenObj
                }

                if ($response.access_token -and !$response.refresh_token) {
                    $tokenObj = @{
                        accessToken = $response.access_token
                        refreshToken = (get-dbdata -table "oauth_tokens").refreshToken | Select-Object -last 1
                    }
                    update-dbdata -table "oauth_tokens" -dataObj $tokenObj -scope "refreshToken is not null"
                }

                Update-OauthTokens
            }
            catch {
                Write-Log -severity error -message "Error converting token response to json object: $($_.Exception.Message)"
            }
        
        
        }
    
        end {
            Write-Log -severity tag -message "...Done!"
        }
    }

    function Invoke-OpenStreamingSocket {
        [cmdletbinding()]
        param ()

        begin {
            Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }

        process {
            try {  
                while ($streamingSocket.State -ne 'open') {
                    $url = ""
                    $socket = New-Object System.Net.WebSockets.ClientWebSocket
                    $cancellationToken = New-Object System.Threading.CancellationToken
                    $socket.Options.UseDefaultCredentials = $true
                    $size = 1024
                    $array = [byte[]] @(,0) * $size

                    $task = $socket.ConnectAsync($url, $cancellationToken)
                    while (!($task.IsCompleted)) {
                        Start-Sleep -milliseconds 100
                    }
                    Write-Log -Severity Info -Message "Connected to: $url"

                    $startStream = [System.Text.Encoding]::UTF8.GetBytes("ACTION=Command")
                    $sendRequest = New-Object System.ArraySegment[byte] -ArgumentList @(,$startStream)
                    $task = $socket.SendAsync($sendRequest, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cancellationToken)
                    while (!($task.IsCompleted)) {
                        Start-Sleep -milliseconds 100
                    }
                    Write-Log -Severity Info -Message "Sent request to start stream!"

                    #Start reading the received items
                    while ($socket.State -eq 'Open') {
                        $streamFrame = New-Object System.ArraySegment[byte] -ArgumentList @(,$array)
                        $task = $socket.ReceiveAsync($streamFrame, $cancellationToken)
                        While (!($task.IsCompleted)) {
                            Start-Sleep -Milliseconds 100
                        }
                        Write-Host [System.Text.Encoding]::utf8.GetString($Recv.array)
                    }
                }
            }
            catch {
                Write-Log -severity Error -Message "An error occured during $($MyInvocation.MyCommand.Name): $($_.Exception.Message)"
            }
            finally {
                if ($socket) { $socket.Dispose() }
            }
        }

        end {
            Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }

    function Invoke-StonkQuery {
        [cmdletbinding()]
        param (
            $stonk,
            [switch]$historical = $false,
            [switch]$realTime = $false,
            [switch]$forcePull = $false,
            [switch]$multi = $false
        )
        
        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name) targeting: $stonk"
        }
        
        process {
            for ($i = 1; $i -le 5; $i++) {
                #Region Historical data stuff
                if ($historical) {
                    # Stop if we were sent a list of stonks instead of just one
                    if ($stonk.Contains(",")) {
                        Write-Log -Severity Warning -Message "Historical pulls must target one ticker at a time."
                        return
                    }
                    
                    # If data already exists in the DB, return it
                    if (!$forcePull) {
                        $stonkHistory = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk }
                        if ($stonkHistory) {
                            return $stonkHistory
                        }
                    }
                    
                    # If we don't have it then get the last month
                    try {
                        #$apiResponse = Invoke-WebRequest "https://api.tdameritrade.com/v1/marketdata/$stonk/pricehistory?periodType=month&period=1&frequencyType=daily&frequency=1" -Headers @{Authorization="Bearer $accessToken"}
                        $apiResponse = Invoke-WebRequest "https://api.tdameritrade.com/v1/marketdata/$stonk/pricehistory?periodType=year&period=1&frequencyType=daily&frequency=1" -Headers @{Authorization="Bearer $accessToken"}
                        if ($apiResponse.Content) {
                            # Make a temp object from the return
                            $tempObj = ($apiResponse.Content | ConvertFrom-Json).candles
                            
                            # iterate through and replace the nonsense datetime with a reasonable one
                            foreach ($day in $tempObj) {
                                [datetime]$realDay = get-date -unixTimeSeconds ([int64]$day.dateTime / 1000)
                                $day.datetime = $realDay.toString("MM/dd/yy")
                            
                                # If we have a targetPrice for today / this stock shove that in there too
                                [double]$targetPrice = ($script:targetPriceFile | Where-Object { $_.Date -eq $realDay }).$stonk
                                $day | Add-Member -MemberType NoteProperty -Name "TargetPrice" -Value $targetPrice
                            }
                            return $tempObj
                        }
                    }
                    catch {
                        if (($_.Exception.Message -like "*access token being passed has expired or is invalid*") -or ($_.Exception.Message -like "*401 (Unauthorized)*")) {
                            Write-Log -nonewline -severity Warning -message "Received expired token response. Generating new tokens and retrying..."
                            Invoke-GenerateTokens
                        }
    
                        if ($_.Exception.Message -like "*Too many requests*") {
                            Write-Log -severity warning -message "TDAmeritrade is crying because we're hammering too hard.  Slow the roll."
                            Start-Sleep -seconds 15
                            continue
                        }
                        Write-Log -severity warning -message "Attempt: $i of 5 querying stonk: $stonk on $date resulted in an error: $($_.Exception.Message)"
                    }
                    
                    if ($i -lt 5) {
                        Write-Log -severity error -message "Attempt: $i of 5 querying stonk: $stonk on $date was unsuccessful, but didn't error. Retry!"
                        start-sleep -seconds 1
                        continue
                    }
                    else {
                        Write-Log -severity error -message "Failed to pull data for $stonk on $date after 5 tries.  This shouldn't happen."
                        return
                    }
                }
                #EndRegion

                #Region Real-Time data stuff
                try {
                    $apiResponse = Invoke-WebRequest "https://api.tdameritrade.com/v1/marketdata/quotes?symbol=$([uri]::EscapeDataString(`"$stonk`"))" -Headers @{Authorization="Bearer $accessToken"}
                    if ($apiResponse.Content -eq "{}") { throw "`$apiResponse.Content is null or empty" }
                    
                    $stonkList = $stonk -split ","
                    $responseContent = $apiResponse.Content | ConvertFrom-Json
                    for ($i = 0; $i -lt $stonkList.Count; $i++) {
                        $curStonk = $responseContent.($stonkList[$i])
                        if (($curStonk.assetType -eq "Equity" -and !$curStonk.lastPrice) -or ($curStonk.assetType -eq "Future" -and !$curStonk.closePriceInDouble)) {
                            throw "Missing data for $($curStonk.symbol)"
                        }
                    }

                    if ($multi) {
                        return $responseContent
                    }
                    else {
                        return $responseContent | Select-Object -expand $stonk
                    }
                }
                catch {
                    if (($_.Exception.Message -like "*access token being passed has expired or is invalid*") -or ($_.Exception.Message -like "*401 (Unauthorized)*")) {
                        Write-Log -severity Warning -message "Received expired token response from server - attempting to generate new accessToken..."
                        Invoke-GenerateTokens
                    }
                    Write-Log -severity warning -message "Attempt: $i of 5 querying stonk: $stonk resulted in an error: $($_.Exception.Message)"
                }
                #EndRegion
            }
        }
        
        end {
            #Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name) targeting: $stonk"  
        }
    }

    function Get-OptionChain {
        [cmdletbinding()]
        param (
            $stonk
        )
    
        try {
            for ($i = 1; $i -le 5; $i++) {
                try {
                    $getOptionChain = Invoke-WebRequest "https://api.tdameritrade.com/v1/marketdata/chains?symbol=$stonk&contractType=ALL&strikeCount=99999" -Headers @{Authorization="Bearer $accessToken"}
                    $chainObj = $getOptionChain.Content | ConvertFrom-Json
                    if ($chainObj.Status -eq "SUCCESS") {

                        # Compare dates in call and put tables
                        $callDates = $chainObj.callExpDateMap.psobject.Properties.name
                        $putDates = $chainObj.putExpDateMap.psobject.Properties.name
                        if (Compare-Object $calldates $putDates) {
                            throw "`$callDates and `$putDates objects don't match. This is likely a problem?"
                        }
                
                        # Compare call/put strike prices
                        foreach ($date in $callDates) {
                            $callPrices = $chainObj.callExpDateMap.$date.psobject.Properties.name
                            $putPrices = $chainObj.putExpDateMap.$date.psobject.Properties.name
                            if (Compare-Object $callPrices $putPrices) {
                                throw "`$callPrices and `$putPrices objects don't match. This is likely a problem?"
                            }
                        }

                        # tests passed.  break out of loop
                        return $chainObj
                    }
                    else {
                        if ($i -eq 5) {
                            Write-Log -severity Warning -Message "All 5 attempts to pull option chain history for $stonk failed. This real bad - chainObj.Status is $($chainObj.Status)"
                        }
                        continue
                    }
                }
                catch {
                    if (($_.Exception.Message -like "*access token being passed has expired or is invalid*") -or ($_.Exception.Message -like "*401 (Unauthorized)*")) {
                        Write-Log -severity Warning -message "Received expired token response from server - attempting to generate new accessToken..."
                        Invoke-GenerateTokens
                        continue
                    }
                    else {
                        throw "Error pulling optionChain for $stonk`: $($_.Exception.Message)"
                    }
                }
        
                Write-Log -severity Warning -Message "Attempt: $i of 5 - Retrying in 5 seconds..."
                Start-Sleep -seconds 5
            }
        
            # If we're still here we ran out of retries.
            Write-Log -Severity Error -Message "Failed to retrieve the chain history for $stonk after 5 tries.  Sad times."
        }
        catch {
            Write-Log -severity Error -Message "Error getting and verifying the option chain: $($_.Exception.Message)"
            return $null
        }
    }

    function Update-LocalHistory {
        [cmdletbinding()]
        param (
            [switch]$single = $false,
            [switch]$historical = $false,
            [string]$targetDate,
            $stonk
        )
    
        begin {
            Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }
    
        process {
            if ((Get-Date).toString("dddd") -eq "Saturday" -or (Get-Date).toString("dddd") -eq "Sunday") {
                Write-Log -Severity Warning -Message "You don't pay me to update history files on the weekend!"
                return
            }

            $hFiles = (get-dbdata -table "history_data").ticker | Select-Object -unique | Where-Object { $_ -ne "XLNX" }
            # override for updating a single file when required
            if ($single -and $stonk) {
                $hFiles = $stonk
            }

            foreach ($stonk in $hFiles) {
                #Region targetDate handling
                if ($targetDate) {
                    $dataCheck = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.Date -eq $targetDate }
                    if ($dataCheck) {
                        Write-Log -severity Debug -Message "Data already exists for $stonk on $targetDate"
                        continue
                    }

                    # Data doesn't exist - get historical data and add it
                    $targetDateData = invoke-stonkQuery -historical -forcepull -stonk $stonk | Where-Object { $_.dateTime -eq "$targetDate" }
                    if ($targetDateData) {
                        $dataObj = @{
                            ticker = $stonk
                            open = $targetDateData.open
                            close = $targetDateData.close
                            high = $targetDateData.high
                            low = $targetDateData.low
                            volume = $targetDateData.volume
                            date = $targetDateData.dateTime
                            fsColor = ""
                            fsPhase = ""
                            targetPrice = ""
                        }
                        Add-DBData -table "history_data" -dataObj $dataObj
                        write-host "Added data for $stonk on date: $targetDate!"
                    }
                    continue
                }
                #EndRegion

                if ($historical) {
                    # get data for the last month
                    $hData = Invoke-StonkQuery -historical -forcePull -stonk $stonk

                    foreach ($day in $hData) {
                        $dataCheck = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq $day.datetime }
                        if ($dataCheck) {
                            Write-Log -severity debug -message "$stonk data for $($day.dateTime) already exists in database. Skipping!"
                            continue
                        }

                        # data for this day does not exist, so add it
                        $thisDayObj = @{
                            ticker = $stonk
                            open = $day.open
                            close = $day.close
                            high = $day.high
                            low = $day.low
                            volume = $day.volume
                            date = $day.datetime
                            fsColor = ""
                            fsPhase = ""
                            targetPrice = ""
                        }

                        [double]$targetPrice = ($targetPriceFile | Where-Object { $_.Date -eq $day.datetime }).$stonk
                        if ($targetPrice) {
                            $thisDayObj.targetPrice = $targetPrice
                        }

                        try {
                            add-dbData -table "history_data" -dataObj $thisDayObj
                            Write-Log -severity debug -message "Updated $stonk history data for $($day.datetime)!"
                        }
                        catch {
                            Write-Log -severity Error -Message "Error updating database for $stonk on $($day.datetime)`: $($_.Exception.Message)"
                        }
                    }

                    continue
                }

                # Check to see if today's data already exists
                $todayCheck = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.Date -eq (Get-Date).toString("MM/dd/yy") }
                if ($todayCheck) {
                    Write-Log -severity debug -message "$stonk data for today already exists in the database.  Skipping!"
                    continue
                }
                
                # Get today's data and construct an obj that matches historical data structure
                $realTimeData = Invoke-StonkQuery -stonk $stonk
                $todayObj = @{
                    ticker = $stonk
                    open = $realTimeData.openprice
                    close = $Realtimedata.regularMarketLastPrice
                    high = $realTimeData.highPrice
                    low = $realtimedata.lowPrice
                    volume = $realtimedata.totalVolume
                    date = (Get-Date).tostring("MM/dd/yy")
                    fsColor = ""
                    fsPhase = ""
                    targetPrice = ""
                }
                
                [double]$targetPrice = ($targetPriceFile | Where-Object { $_.Date -eq (Get-Date).toString("MM/dd/yy") }).$stonk
                if ($targetPrice) {
                    $todayObj.targetPrice = $targetPrice
                }

                try {
                    add-dbData -table "history_data" -dataObj $todayObj
                    Write-Log -severity debug -message "Updated $stonk history with today's data!"
                }
                catch {
                    Write-Log -severity Error -Message "Error updating database for $stonk`: $($_.Exception.Message)"
                }
            }
        }
    
        end {
            Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }

    function Get-UserPrincipalsResponse {
        [cmdletbinding()]
        param ()

        begin {
            Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }

        process {
            for ($i = 1; $i -le 5; $i++) {
                try {
                    $apiResponse = Invoke-WebRequest "https://api.tdameritrade.com/v1/userprincipals?fields=streamerSubscriptionKeys,streamerConnectionInfo" -Headers @{Authorization="Bearer $accessToken"}
                    if (!$apiResponse.Content) {
                        throw "The API response.content is null or empty."
                    }

                    $response = $apiResponse.Content | ConvertFrom-Json
                    return $response
                }
                catch {
                    if (($_.Exception.Message -like "*access token being passed has expired or is invalid*") -or ($_.Exception.Message -like "*401 (Unauthorized)*")) {
                        Write-Log -nonewline -severity Warning -message "Received expired token response. Generating new tokens and retrying..."
                        Invoke-GenerateTokens
                    }

                    if ($_.Exception.Message -like "*Too many requests*") {
                        Write-Log -severity warning -message "TDAmeritrade is crying because we're hammering too hard.  Slow the roll."
                        Start-Sleep -seconds 15
                        continue
                    }
                    Write-Log -severity warning -message "Attempt: $i of 5 querying stonk: $stonk on $date resulted in an error: $($_.Exception.Message)"
                }
            }
        }

        end {
            Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }

    function Get-Transactions {
        [cmdletbinding()]
        param (
            $startDate = (Get-Date).toString("yyyy-MM-dd"),
            $endDate = (Get-Date).toString("yyyy-MM-dd")
        )

        $apiResponse = Invoke-WebRequest "https://api.tdameritrade.com/v1/accounts/498382622/transactions?type=TRADE&startDate=$startDate&endDate=$endDate" -Headers @{Authorization="Bearer $accessToken"}
        return $apiResponse
    }
    #EndRegion

    #Region Database / Local Resource File related functions
    function Update-OauthTokens {
        [cmdletbinding()]
        param ()
    
        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }
    
        process {
            $tokens = get-dbdata -table "oauth_tokens"
            $global:accessToken = $tokens.accessToken
            $global:refreshToken = $tokens.refreshToken

            if (!$accessToken -or !$refreshtoken) {
                Write-Log -Severity Error -Message "Failed to update oAuth Tokens from the database! Probs a big problem!" -noNewLine
            }
            <# else {
                Write-Log -Severity Info -Message "accesstoken: $accessToken"
                Write-Log -Severity Info -Message "refreshToken: $refreshToken"
            } #>
        }
    
        end {
            #Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }

    function Add-DBData {
        [cmdletbinding()]
        param (
            $table,
            $dataObj
        )
        
        try {
            foreach ($key in $dataObj.keys) {
                $objKeys += "$key, "
                $objValues += "@$key, "
            }
            $objkeys = $objKeys.trimend(", ")
            $objvalues = $objValues.trimend(", ")
            $query = "INSERT INTO $table ($objKeys) VALUES ($objValues)"

            switch ($table) {
                "HISTORY_GEX" { $allowedFields = @("ticker", "gex", "date", "time") }
                "HISTORY_OI" { $allowedFields = @("ticker", "optiontype", "lastprice", "strikeprice", "volume", "openinterest", "oivolratio", "date", "time", "delta", "contractprice") }
                "HISTORY_DATA" { $allowedFields = @("ticker", "open", "high", "low", "close", "volume", "targetPrice", "date", "fsColor", "fsPhase") }
                "HISTORY_ES" { $allowedFields = @("open", "close", "low", "high", "volume", "market", "date", "absflux", "dayflux", "nightflux", "abslow", "abshigh") }
                "OAUTH_TOKENS" { $allowedFields = @("accessToken", "refreshToken") }
                "G2S_DATA" { $allowedFields = @("ticker", "date", "arrLevels", "arrBar1", "arrBar2", "arrBar3", "arrBar4") }
                "ALERT_POINTS" { $allowedFields = @("ticker", "date", "p1", "p2") }
            }

            if ($allowedFields) {
                foreach ($key in $dataObj.keys) {
                    if (!($allowedFields.contains($key))) {
                        throw "The field: $key doesn't exist in the targeted table! ($table)"
                    }
                }
            }
            else {
                Write-Log -Severity Warning -Message "Hey, maybe consider adding validation for the database object you're jamming in here. Jackass."
            }

            Invoke-SqLiteQuery -SqLiteConnection $dbCon -Query $query -SqlParameters $dataObj
        }
        catch {
            Write-Log -Severity Error -Message "Error during $($MyInvocation.MyCommand.Name): $($_.Exception.Message)"
        }
    }

    function Get-DBData {
        [cmdletbinding()]
        param (
            $table,
            $query
        )
    
        if (!$query) { $query = "SELECT * FROM $table" }
        $dbReturn = Invoke-SqLiteQuery -SqLiteConnection $dbCon -query $query
        return $dbReturn
    }
    
    function Update-DBData {
        <# example: 
            $newData = @{
                targetPrice = 123
                fsColor = RED
                fsPhase = PhaseSeventeen
            }

            Update-DbData -table "HISTORY_DATA" -dataObj $newData -scope "ticker='AAPL' AND date='$(get-date).tostring(`"MM/dd/yy`"))'"

            Note: The provided scope must be specific enough to only match on 1 row in the database.
        #>

        [cmdletbinding()]
        param (
            $table,
            $dataObj,
            $scope
        )

        try {
            $returnType = (Get-DBData -table "$table" -query "SELECT * FROM $table WHERE $scope").getType().Name
        }
        catch {
            Write-Log -severity error -message "Error verifying that the supplied query terms ($scope) only matched to one field in the table: $table - $($_.Exception.Message))" 
        }

        switch ($returnType) {
            "PSCustomObject" {
                try {
                    foreach ($item in $dataObj.keys) {
                        Invoke-SqliteQuery -SQLiteConnection $dbCon -query "UPDATE OR FAIL $table SET $item='$($dataObj.$item)' WHERE $scope"
                    }
                }
                catch {
                    write-host "Shocker, that didn't work: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            "Object[]" { Write-Host "The provided scope targets more than one object in table: $table so I'm not going to do that."; return }
            default { "The provided scope didn't target a specific object in table: $table so I'm not going to do that."; return }
        }
    }
    #EndRegion

    #Region Utility Functions
    function Get-AdjacentTradeDay {
        [cmdletbinding()]
        param (
            [datetime]$startDate,
            [int]$count = 1,
            [switch]$previous = $false,
            [switch]$next = $false
        )

        $currentDay = $startDate
        while ($count -gt 0) {
            $i = 1
            while ($closedDays.Contains($currentDay.AddDays(-$i).ToString("dddd")) -or $closedDays.Contains($currentDay.AddDays(-$i).ToString("MM/dd/yy"))) {
                $i++
            }
        
            if ($previous) {
                $currentDay = $currentDay.AddDays(-$i)
                #write-log -severity info -message "count is $count and currDay = $currentDay"
            }
    
            if ($next) {
                $currentDay = $currentDay.AddDays($i)
                #write-log -severity info -message "count is $count and currDay = $currentDay"
            }

            $count = $count - 1
        }

        return $currentDay
    }

    function Get-fluxValue {
        [cmdletbinding()]
        param(
            [string]$targetDate = (get-date).toString("MM/dd/yy"),
            [switch]$dayOnly = $false,
            [switch]$nightOnly = $false
        )

        $dayHistory = get-dbdata -table "history_es" -query "SELECT * FROM HISTORY_ES WHERE Date < '$targetDate'" | Where-Object { $_.Market -eq "day" } | Sort-Object -Property date | Select-Object -last 4
        $nightHistory= get-dbdata -table "history_es" -query "SELECT * FROM HISTORY_ES WHERE Date < '$targetDate'" | Where-Object { $_.Market -eq "night" } | Sort-Object -Property date | Select-Object -last 4

        if ($dayHistory.count -ne 4 -or $nightHistory.count -ne 4) {
            Write-Log -severity Warning -Message "DayHistory count: $($dayHistory.Count) NightHistory count: $($nightHistory.count) - Is this a problem?"
            return
        }

        # Compare dayLow/nightLow and dayHigh/nightHigh for the last 4 days. Select the lowest low and highest high for each day
        $fluxLow = @()
        $fluxHigh = @()
        for ($i = 0; $i -le 3; $i++) {
            if ($dayOnly) {
                $fluxLow += $dayHistory[$i].low
                $fluxHigh += $dayHistory[$i].high
                #write-log -severity info -message "$($dayHistory[$i].date) : DayOnly! dayLow: $($dayHistory[$i].low) dayHigh: $($dayHistory[$i].High)"
            }
            elseif ($nightOnly) {
                $fluxLow += $nightHistory[$i].low
                $fluxHigh += $nightHistory[$i].high
                #write-log -severity info -message "$($nightHistory[$i].date) : NightOnly! nightLow: $($nightHistory[$i].low) nightHigh: $($nightHistory[$i].High)"
            }
            else {
                if ($dayHistory[$i].low -le $nightHistory[$i].low) { 
                    #write-log -severity info -message "$($dayHistory[$i].date) : dayLow: $($dayHistory[$i].low) nightLow: $($nightHistory[$i].low) - Using dayLow"
                    $fluxLow += $dayHistory[$i].low
                }
                else {
                    #write-log -severity info -message "$($nightHistory[$i].date) : dayLow: $($dayHistory[$i].low) nightLow: $($nightHistory[$i].low) - Using nightLow"
                    $fluxLow += $nightHistory[$i].low
                }
    
                if ($dayHistory[$i].high -ge $nightHistory[$i].high) { 
                    #write-log -severity info -message "$($dayHistory[$i].date) : dayhigh: $($dayHistory[$i].high) nightHigh: $($nightHistory[$i].high) - Using dayHigh"
                    $fluxHigh += $dayHistory[$i].high
                }
                else {
                    #write-log -severity info -message "$($nightHistory[$i].date) : dayhigh: $($dayHistory[$i].high) nightHigh: $($nightHistory[$i].high) - Using nightHigh"
                    $fluxHigh += $nightHistory[$i].high
                }
            }
        }

        # Calculate fluxValue
        $sumDiff = 0
        for ($i = 0; $i -le 3; $i++) {
            $diff = $fluxHigh[$i] - $fluxLow[$i]
            $sumDiff += $diff
        }
        $fluxValue = [math]::round(($sumDiff / 4),2)

        return $fluxValue
    }

    function Get-OutputFileData {
        [cmdletbinding()]
        param (
            $csvObj,
            $date,
            $stonk
        )
    
        try {
            $toReturn = $csvObj | Where-Object { $_.Date -eq "$date" -and $_.Ticker -eq "$stonk" }
        }
        catch {
            Write-Log -severity error -message "Error getting the dataObject for $stonk on $date from csvObject"
            $toReturn = $null
        }
    
        return $toReturn
    }

    function Invoke-DrawChart {
        [cmdletbinding()]
        param (
            $chartType,
            $Title,
            [array]$xData,
            [array]$yData,
            $pointLabel,
            $chartPath,
            [switch]$showChart = $false
        )

        try {
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Windows.Forms.DataVisualization
    
            $Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
            $area3DStyle = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea3DStyle
            $area3DStyle.Enable3D = $true
            $chartArea = $chart.ChartAreas.Add('ChartArea')
            $chartArea.Area3DStyle = $area3DStyle
            $chartArea.BackColor = [System.Drawing.Color]::White
            
            $Series = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Series
            $Series.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::$chartType
            $Series.Points.dataObject()
            $Series.Points.DataBindXY($xData, $yData)
            $Series.LabelBackColor = [System.Drawing.Color]::Black
            $Series.LabelForeColor = [System.Drawing.Color]::White
            $Series.LabelBorderColor = [System.Drawing.Color]::White
            $Series.LabelBorderWidth = 2
            $Series.Label = " `n #VALX `n #VALY `n "
    
            $Chart.Series.Add($Series)
            $Chart.Width = 1600
            $Chart.Height = 900
            $Chart.Left = 10
            $Chart.Top = 10
            $Chart.BackColor = [System.Drawing.Color]::White
            $Chart.BorderColor = [System.Drawing.Color]::Black
            $Chart.BorderDashStyle = 'Solid'
    
            $ChartTitle = New-Object System.Windows.Forms.DataVisualization.Charting.Title
            $ChartTitle.Text = "$title"
            $Font = New-Object System.Drawing.Font @('Microsoft Sans Serif','12', [System.Drawing.FontStyle]::Bold)
            $ChartTitle.Font = $Font
            $Chart.Titles.Add($ChartTitle)
            
            # Kill existing graph and save new one
            if (Test-Path -path $chartPath) {
                Remove-Item -Path $chartPath -force
            }
            try {
                $chart.SaveImage($chartPath, "jpeg")
                #Write-Log -severity Info -message "Saved chart to: $chartPath"
            }
            catch {
                throw "Error saving generated chart: $($_.Exception.Message)"
            }
    
            # Create windows form to display graph (optionally)
            if ($showChart) {
                $AnchorAll = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
                $Form = New-Object Windows.Forms.Form
                $Form.Width = 2560
                $Form.Height = 1440
                $Form.controls.add($Chart)
                $Chart.Anchor = $AnchorAll
                $Form.Add_Shown({$Form.Activate()})
                [void]$Form.ShowDialog()
            }
        }
        catch {
            Write-Log -Severity Error -Message "Error during $($MyInvocation.MyCommand.Name): $($_.Exception.Message)"
        }
    }

    function testChart {
        [cmdletbinding()]
        param (
            $candles
        )

        try {
            try {
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Windows.Forms.DataVisualization
                $Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
                $price = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Series
                $chart.Series.add($price)
                $chart.Series["price"]["ChartType"] = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Candlestick
                $chart.Series["price"]["OpenCloseStyle"] = "Triangle"
                $chart.Series["price"]["ShowOpenClose"] = "Both"
                $chart.Series["price"]["PointWidth"] = "1.0"
                $chart.Series["price"]["PriceUpColor"] = "Green"
                $chart.Series["price"]["PriceDownColor"] = "Red"
      
                
                for ($i = 0; $i -lt $candles.count; $i++) {
                    if ([string]::isnullorempty($candles[$i])) { continue }

                    Write-Host "adding candle: $i to chart!"
                    $chart.Series["price"].Points.AddXY([DateTime]$candles[$i].chartTime, $candles[$i].High)
                    $chart.Series["price"].Points[$i].YValues[1] = $candles[$i].low
                    $chart.Series["price"].Points[$i].YValues[2] = $candles[$i].open
                    $chart.Series["price"].Points[$i].YValues[3] = $candles[$i].close
                }
            }
            catch {
                throw "found the error: $_"
            }
            
            $chart

            <# $area3DStyle = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea3DStyle
            $area3DStyle.Enable3D = $true
            $chartArea = $chart.ChartAreas.Add('ChartArea')
            $chartArea.Area3DStyle = $area3DStyle
            $chartArea.BackColor = [System.Drawing.Color]::White
            
            $Series = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Series
            $Series.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::$chartType
            $Series.Points.dataObject()
            $Series.Points.DataBindXY($xData, $yData)
            $Series.LabelBackColor = [System.Drawing.Color]::Black
            $Series.LabelForeColor = [System.Drawing.Color]::White
            $Series.LabelBorderColor = [System.Drawing.Color]::White
            $Series.LabelBorderWidth = 2
            $Series.Label = " `n #VALX `n #VALY `n "
    
            $Chart.Series.Add($Series)
            $Chart.Width = 1600
            $Chart.Height = 900
            $Chart.Left = 10
            $Chart.Top = 10
            $Chart.BackColor = [System.Drawing.Color]::White
            $Chart.BorderColor = [System.Drawing.Color]::Black
            $Chart.BorderDashStyle = 'Solid'
    
            $ChartTitle = New-Object System.Windows.Forms.DataVisualization.Charting.Title
            $ChartTitle.Text = "$title"
            $Font = New-Object System.Drawing.Font @('Microsoft Sans Serif','12', [System.Drawing.FontStyle]::Bold)
            $ChartTitle.Font =$Font
            $Chart.Titles.Add($ChartTitle) #>
    
            
    
            # Create windows form to display graph (optionally)
            $AnchorAll = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
            $Form = New-Object Windows.Forms.Form
            $Form.Width = 2560
            $Form.Height = 1440
            $Form.controls.add($Chart)
            $Chart.Anchor = $AnchorAll
            $Form.Add_Shown({$Form.Activate()})
            [void]$Form.ShowDialog()
        }
        catch {
            Write-Log -Severity Error -Message "Error during $($MyInvocation.MyCommand.Name): $($_.Exception.Message)"
        }
    }

    function Get-ClosestValue {
        [cmdletbinding()]
        param (
            $inputArray,
            $targetValue
        )

        $props = @{
            value = ""
            absDiff = ""
        }
        $diffArray = @()
        foreach ($value in $inputArray) {
            $diffObj = new-Object -TypeName psobject -Property $props
            $diffObj.value = $value
            $diffObj.absDiff = [math]::Abs($targetValue - $value)
            $diffArray += $diffObj
        }

        $smallestDiff = $diffArray.absDiff | Sort-Object | Select-Object -first 1
        if ($smallestDiff.Count -gt 1) {
            Write-Log -severity warning -message "More than one item in our array is reporting the same delta when compared to the targetValue: $targetValue - $inputArray"
        }
        $closestValue = ($diffArray | Where-Object { $_.absDiff -eq $smallestDiff }).Value
        return $closestValue
    }

    function Get-AvgVolume {
        [cmdletbinding()]
        param (
            $stonk,
            $numberOfDays
        )

        [int]$dailyVol = 0
        $foundCount = $numberOfDays
        
        for ($i = 1; $i -le $numberOfDays; $i++) {
            $targetDate = (Get-AdjacentTradeDay -previous -count $i -startDate (Get-Date)).toString("MM/dd/yy")
            $targetData = Get-DbData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq $targetDate }

            if (!$targetData) {
                Write-Log -severity Warning -Message "No data available for $stonk on previous trade day: $targetDate"
                $foundCount = $foundCount - 1
                continue
            }
            $dailyVol += $targetData.volume
        }

        $avgVolume = $dailyVol / $foundCount
        return $avgVolume
    }

    function Get-CandleChart {
        # $test = get-candleChart -stonk "AAPL" -startDate "03/28/22 9:00 am" -endDate "03/28/22 11:45 am"
        [cmdletbinding()]
        param (
            $stonk,
            $startDateTime,
            $endDateTime
        )

        [datetime]$originTime = (get-date("01/01/1970"))
        $startDate = [math]::Floor(((get-date($startDateTime))-$originTime).TotalMilliseconds)
        $endDate = [math]::Floor(((get-date($endDateTime))-$originTime).TotalMilliseconds)

        for ($i = 1; $i -le 5; $i++) {
            try {
                $apiResponse = Invoke-WebRequest "https://api.tdameritrade.com/v1/marketdata/$stonk/pricehistory?startDate=$startDate&endDate=$endDate&frequencyType=minute&frequency=5" -Headers @{Authorization="Bearer $accessToken"}
            }
            catch {
                if (($_.Exception.Message -like "*access token being passed has expired or is invalid*") -or ($_.Exception.Message -like "*401 (Unauthorized)*")) {
                    Write-Log -nonewline -severity Warning -message "Received expired token response. Generating new tokens and retrying..."
                    Invoke-GenerateTokens
                    continue
                }
                write-host "Error pulling today's candle chart info: $($_.Exception.Message)"
            }
        }

        if ($apiResponse.Content) {
            # Make a temp object from the return
            $tempObj = ($apiResponse.Content | ConvertFrom-Json).candles | Sort-Object -Property datetime
            
            # iterate through and replace the nonsense datetime with a reasonable one
            foreach ($day in $tempObj) {
                if ($day.datetime) {
                    [datetime]$realDay = get-date -unixTimeSeconds ([int64]$day.dateTime / 1000)
                    $day.datetime = $realDay
                }
            }
        }

        return $tempObj
    }

    function Draw-CandleChart {
        [cmdletbinding()]
        param (
            [datetime]$targetDay
        )

        # get candles
        $candles = Get-DBData -table "es_candles" | Where-Object { $_.chartTime.Contains($targetDay.toString("yyyy-MM-dd")) }
        
        # draw chart
        #Invoke-DrawChart -chartType "Candlestick" -Title "/ES 1min - $($targetDay.toString("MM-dd-yyyy"))" -xData $todayData.time -yData $todayData.gex -chartPath "C:\Users\tabba\OneDrive\_Dev\StonkBotCharts\dailyGEX-$stonk.jpeg"

        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Windows.Forms.DataVisualization
        $Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
        $area3DStyle = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea3DStyle
        $area3DStyle.Enable3D = $true
        $chartArea = $chart.ChartAreas.Add('ChartArea')
        $chartArea.Area3DStyle = $area3DStyle
        $chartArea.BackColor = [System.Drawing.Color]::White
        
        $Series = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Series
        $Series.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::"Candlestick"
        $Series.Points.DataBindXY($candles.chartTime, $candles.open)
        $Series.LabelBackColor = [System.Drawing.Color]::Black
        $Series.LabelForeColor = [System.Drawing.Color]::White
        $Series.LabelBorderColor = [System.Drawing.Color]::White
        $Series.LabelBorderWidth = 2
        $Series.Label = " `n #VALX `n #VALY `n "

        $Chart.Series.Add($Series)
        $Chart.Width = 1600
        $Chart.Height = 900
        $Chart.Left = 10
        $Chart.Top = 10
        $Chart.BackColor = [System.Drawing.Color]::White
        $Chart.BorderColor = [System.Drawing.Color]::Black
        $Chart.BorderDashStyle = 'Solid'

        $ChartTitle = New-Object System.Windows.Forms.DataVisualization.Charting.Title
        $ChartTitle.Text = "TestChart"
        $Font = New-Object System.Drawing.Font @('Microsoft Sans Serif','12', [System.Drawing.FontStyle]::Bold)
        $ChartTitle.Font =$Font
        $Chart.Titles.Add($ChartTitle)

        # Create windows form to display graph (optionally)
        $AnchorAll = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
        $Form = New-Object Windows.Forms.Form
        $Form.Width = 2560
        $Form.Height = 1440
        $Form.controls.add($Chart)
        $Chart.Anchor = $AnchorAll
        $Form.Add_Shown({$Form.Activate()})
        [void]$Form.ShowDialog()
    }

    function Invoke-DanThing {
        $toWrite = $null
        $scriptPath = "C:\Users\tabba\Desktop\stock_list\stock list"
        $qqq = import-csv -Path "$scriptPath\indexLists\qqq.csv"
        $iwm = import-csv -Path "$scriptPath\indexLists\iwm.csv"
        $spy = import-csv -Path "$scriptPath\indexLists\spy.csv"
        $dia = import-csv -path "$scriptpath\indexLists\dia.csv"

        $industryFiles = Get-ChildItem -Path $scriptPath -Filter '*.csv'

        $toWrite = "GICS Sector,Industry,Symbol,Category,Market Cap,Average Volume,InSPY,InQQQ,InIWM,InDIA"
        $fileCount = 1
        foreach ($file in $industryFiles){
            $thisFile = import-csv -path $file.FullName
            Write-Host "Processing file: $($file.BaseName)!  fileCount: $fileCount" -ForegroundColor DarkCyan

            foreach ($item in $thisFile){
                $inSPY = ($spy.Symbol.Contains($item.Symbol))
                $inQQQ = ($qqq.Symbol.Contains($item.Symbol))
                $iniwm = ($iwm.Symbol.Contains($item.Symbol))
                $inDia = ($dia.Symbol.Contains($item.Symbol))
                $toWrite += "`n`"$($item.'GICS Sector')`",`"$($file.BaseName)`",`"$($item.Symbol)`",`"$($item.Category3)`",`"$($item.'Market cap')`",`"$($item.'Average Volume')`",$inspy,$inqqq,$iniwm,$india"
            }
            $fileCount++
        }

        $toWrite | Out-file -FilePath "C:\users\tabba\Desktop\stock_list\industries_outFile.csv" -Force

        return

        <# $readOutput = import-csv -path "C:\users\tabba\Desktop\stock_list\industries_outFile.csv"
        
        $secondFile = $null
        $secondFile = "Symbol,Date,Open,Close,Low,High,Volume"
        $stonkCount = 1
        foreach ($line in $readOutput){
            Write-Host "$stonkCount - Processing symbol: $($line.symbol)"
            $lastYear = Invoke-StonkQuery -stonk $line.Symbol -historical
            foreach ($day in $lastYear){
                if (!$secondFile){
                    $secondFile += "$($line.symbol),$($day.datetime),`"$($day.Open)`",`"$($day.Close)`",`"$($day.low)`",`"$($day.high)`",`"$($day.volume)`""
                }
                else {
                    $secondFile += "`n$($line.symbol),$($day.datetime),`"$($day.Open)`",`"$($day.Close)`",`"$($day.low)`",`"$($day.high)`",`"$($day.volume)`""
                }
            }
            $secondFile | Out-File -filePath "C:\users\tabba\desktop\stock_list\lastYearInfo_outFile.csv" -Append
            $secondFile = $null
            $stonkCount++
        } #>
    }

    #EndRegion

    #Region PatternMatching and control functions
    function New-DailyVolumeAlert {
        [cmdletbinding()]
        param ()
    
        begin {
            Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }
    
        process {
            $output = "$sbPath\Output\DailyVolumeAlert.csv"
            $cloudCopy = "C:\Users\tabba\OneDrive\_Dev\StonkBotCharts\DailyVolumeAlert.csv"
    
            # read file / generate stock list
            $stonkList = Get-Content -path "$sbPath\Input\oiStockList.csv" | Where-Object { !("DDN,XLNX".contains($_)) } | Sort-Object
    
            foreach ($stonk in $stonkList) {
                Write-Log -severity debug -message "Processing $stonk..." -nonewline
                $content = ""
    
                # get price info from today/yesterday and optionsChain data
                try {
                    $rtd = Invoke-StonkQuery -stonk $stonk

                    # try to get yesterday's data
                    $prevTradeDay = (Get-AdjacentTradeDay -previous -startDate (Get-Date)).toString("MM/dd/yy")
                    $yesterday = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq $prevTradeDay }
                    $today = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq (Get-Date).toString("MM/dd/yy") }
                    $chainObj = Get-OptionChain -stonk $stonk

                    if (!$yesterday -or !$today) {
                        # if we're missing local data for this stock, then pull the last month
                        update-localHistory -stonk $stonk -single -historical
                        $prevTradeDay = (Get-AdjacentTradeDay -previous -startDate (Get-Date)).toString("MM/dd/yy")
                        $yesterday = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq $prevTradeDay }
                        $today = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq (Get-Date).toString("MM/dd/yy") }
                        $chainObj = Get-OptionChain -stonk $stonk
                    }
                    if (!$yesterday -or !$today -or !$chainObj) {
                        Write-Log -Severity Error -Message "Failed to gather required data to do check on $stonk. YesterdayData: $([bool]($yesterday)) TodayData: $([bool]$today) ChainObj: $([bool]$chainObj)"
                        continue
                    }
                }
                catch {
                    Write-Log -Severity Error -Message "Error pulling data on $stonk prior to calculations: $($_.Exception.Message)"
                }
    
                # Do all the maths and stuffs
                try {
                    # get nearest expDay from option chain and clean up date format
                    $chainDate = ($chainObj.putexpdatemap.psobject.properties | select-object -first 1).Name
                    $chainDate -match "\d{4}-\d{2}-\d{2}" | out-null
                    $badDate = $matches[0].split("-")
                    $expDate = "$($badDate[1])-$($badDate[2])-$($badDate[0])"
    
                    # get average volume over the last 7 days and calculate volIncrease%
                    [double]$avgVol = Get-AvgVolume -stonk $stonk -numberOfDays 7
                    $strVolIncrease = (($rtd.totalvolume - $avgVol) / $avgVol).toString("P")

                    # Calc 'up from yesterday'
                    $upFromYesterday = (($today.close - $yesterday.close) / $yesterday.close).toString("P")

                    # Calc 'up today'
                    $upToday = (($today.close - $today.open) / $today.open).toString("P")
                    
                    # find highest openInterest on next expDay and it's strike price for call and put chains
                    $callData = $chainObj.callExpDateMap.$chainDate
                    $maxCallOI = $callData.psobject.properties.value.openInterest | Sort-Object -descending | Select-Object -first 1
                    $putData = $chainObj.putExpDateMap.$chainDate
                    $maxPutOI = $putData.psobject.properties.value.openInterest | Sort-Object -descending | Select-Object -first 1
                    if ($maxCallOI -eq 0 -and $maxPutOI -eq 0) { continue }
                    if ($maxCallOI -ne 0) { $callStrikes = ($callData.psobject.properties | Where-Object { $_.value.openInterest -eq $maxCallOI }).name }
                    if ($maxPutOI -ne 0) { $putStrikes = ($putData.psobject.properties | Where-Object { $_.value.openInterest -eq $maxPutOI }).name }
                    
                    # If the call/put strikes return more than one value, select the value closest to the regMarketLastPrice
                    $callStrike = Get-ClosestValue -inputArray $callStrikes -targetValue $today.close
                    $putStrike = Get-ClosestValue -inputArray $putStrikes -targetValue $today.close

                    # Is today's close between maxPutOI and upFromYesterday?
                    $arr = ($callStrike,$putStrike,$today.close) | Sort-Object
                    [bool]$splitStrikes = ($arr[1] -eq $today.close)
    
                    # if volIncrease% is > | 200% |
                    if ([math]::Abs(($rtd.totalvolume - $avgVol) / $avgVol) -ge 2) {
                        Write-Log -severity discordPost -message "``$stonk`` Volume increased by (**$strVolIncrease**)! upFromYesterday(**$upFromYesterday**) upToday(**$upToday**)" -channel "dailyVolumeAlert"
                    }
                }
                catch {
                    Write-Log -Severity Error -Message "Error performing evals on data for $stonk`: $($_.Exception.Message)"
                }
    
                # write file
                try {
                    # Write header row if file doesn't exist
                    if (!(Test-Path -Path $output)) { "TodayDate,Stonk,NextExpDate,OpenPrice,LowPrice,ClosePrice,HighPrice,Volume,VolumeIncrease%,Call-MaxOpenInterest,Call-StrikePrice,Put-MaxOpenInterest,Put-StrikePrice,UpFromYesterday,UpToday,CloseSplitsStrikes" | Out-File -path $output -Force }
                    # Append content from historical data pulls
                    $content = "$((Get-Date).toString("MM/dd/yy")),$stonk,$expDate,$($today.open),$($today.low),$($today.close),$($today.high),$($rtd.totalVolume),$strVolIncrease,$maxCallOI,$callStrike,$maxPutOI,$putStrike,$upFromYesterday,$upToday,$splitStrikes"
                    $content | Out-File -path $output -Append -Force
                }
                catch {
                    Write-Log -Severity error -message "Error writing to file: $output - $($_.Exception.Message)"
                }

                write-log -severity info -message "Done!"
            }
    
            # Copy to oneDrive location
            try {
                Copy-item -path $output -Destination $cloudCopy -force
            }
            catch {
                Write-Log -severity Error -message "Error copying report from: $output to: $cloudCopy - $($_.Exception.Message)"
            }
        }
    
        end {
            Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }
    
    function Invoke-BuyPointADailyCheck {
        [cmdletbinding()]
        param ()
    
        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }

        process {
            # Get list of tickers to check
            [array]$oiStockList = Get-Content -path "$sbPath\Input\oiStockList.csv"
            $oiStockList | Sort-Object | ForEach-Object { $oiList += "$($_)," }
            $oiList = $oiList.trim(",")

            foreach ($stonk in $stonks) {
                # Get our days!
                $today = (get-date).toString("MM/dd/yy")
                $d1 = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq (Get-AdjacentTradeDay -previous -count 4 -startDate $today).toString("MM/dd/yy") }
                $d2 = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq (Get-AdjacentTradeDay -previous -count 3 -startDate $today).toString("MM/dd/yy") }
                $d3 = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq (Get-AdjacentTradeDay -previous -count 2 -startDate $today).toString("MM/dd/yy") }
                $d4 = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq (Get-AdjacentTradeDay -previous -count 1 -startDate $today).toString("MM/dd/yy") }

                # Test for fail points in establishing our pattern. Bail when we find a break.
                if ($d1.close -lt $d1.open) { return }
                if ($d2.close -lt $d2.open) { return }
                $d3x = @($d3.open, $d3.close) | sort-object | select-object -first 1
                $d3Range = $d3.high - $d3.low
                $d3Tail = $d3x - $d3.low
                if (($d3Tail / $d3Range) -lt (2/3)) { return }
                if ($d4.close -lt $d3.low -and $d4.close -lt $d4.open) {
                    # PATTERN ESTABLISHED!
                    $candle = get-candleChart -stonk $stonk -startDate (get-Date) -endDate (get-date) | Select-Object -last 1
                    $d3y = @($d3.open, $d3.close) | sort-object | select-object -last 1

                    # Send alert to discord
                    Write-Log -severity discordPost -Message "``$stonk`` Buypoint! LastPrice: $($candle.close) - (5 day pattern criteria met)" -channel "buyPointA"
                    
                    # Record info so we can watch for next buyPoint
                    $alertPoint = @{
                        ticker = $stonk.toString()
                        date =  (Get-Date).toString("MM/dd/yy")
                        p1 = $d3y
                        p2 = $d4.low
                    }
                    Add-DbData -table "alert_points" -dataObj $alertPoint
                }
            }
        }

        end {
            #Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }

    function Invoke-BuyPointARTCheck {
        [cmdletbinding()]
        param ()
    
        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }

        process {
            # Get list of tickers to check
            [array]$oiStockList = Get-Content -path "$sbPath\Input\oiStockList.csv"
            $oiStockList | Sort-Object | ForEach-Object { $oiList += "$($_)," }
            $oiList = $oiList.trim(",")

            foreach ($stonk in $stonks) {
                $candle = get-candleChart -stonk $stonk -startDate (get-Date) -endDate (get-date) | Select-Object -last 1

                # Check db for previous price points
                $priceData = get-dbdata -table "alert_points" | Where-Object { $_.ticker -eq $stonk -and ([datetime]$($_.date)).toString("yy") -eq (get-date).toString("yy") } | Sort-Object -Property date | Select-Object -last 1
                if (!$priceData) { continue }

                # If lastPrice is between the two target prices from the most recent entry
                $testArray = @($candle.close,$priceData.p1,$priceData.p2) | Sort-Object
                if ($testArray[1] -eq $candle.close) {
                    # Send alert to discord
                    Write-Log -severity discordPost -Message "``$stonk`` Buypoint! LastPrice: $($candle.close) - (Back in the target window set by last buypoint on: $($priceData.date))" -channel "buyPointA"
                } 
            }
        }

        end {
            #Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }

    function Invoke-OIRatioQuery {
        [cmdletbinding()]
        param()
        
        # Do the real-time-data megapull
        [array]$oiStockList = Get-Content -path "$sbPath\Input\oiStockList.csv" | Where-Object { !("DDN,XLNX".contains($_)) }
        $oiStockList | Sort-Object | ForEach-Object { $oiList += "$($_)," }
        $oiList = $oiList.trim(",")
        $mRtd = invoke-stonkQuery -stonk $oiList -multi
        
        foreach ($stonk in $oiStockList) {
            $rtd = $mRtd.$stonk
            $callProps = $null
            $putProps = $null

            #write-log -severity debug -message "Processing $stonk OIRatio..."
            $chainObj = Get-OptionChain -stonk $stonk
            try {
                # get nearest expDay from option chain and clean up date format
                $chainDate = ($chainObj.putexpdatemap.psobject.properties | select-object -first 1).Name
                $chainDate -match "\d{4}-\d{2}-\d{2}" | out-null
                $badDate = $matches[0].split("-")
                $expDate = "$($badDate[1])-$($badDate[2])-$($badDate[0])"
                $callData = $chainObj.callExpDateMap.$chainDate
                $putData = $chainObj.putExpDateMap.$chainDate

                # Loop, but not really to control where breakpoints return us to
                for ($i = 1; $i -le 1; $i++) {
                    # find highest openInterest on $chainDate and it's strike price
                    $maxOI = $callData.psobject.properties.value.openInterest | Sort-Object -descending | Select-Object -first 1
                    if (!$maxOI) { Write-Log -severity warning -Message "Somehow we didn't find a maxOI (call) for $stonk on $chainDate -  Investigate."; break }

                    $strikePrice = ($callData.psobject.properties | Where-Object { $_.value.openInterest -eq $maxOI }).name
                    if ($strikePrice.count -gt 1) {
                        if (!$rtd) { $rtd = invoke-stonkquery -stonk $stonk }
                        $strikePrice = Get-ClosestValue -inputArray $strikePrice -targetValue $rtd.lastPrice
                    }
                    
                    if ($callData.$thisStrikePrice.totalVolume -gt $callData.$thisStrikePrice.openInterest) {
                        if (!$rtd) { Write-Log -severity Warning -Message "The RTD megapull doesn't have data for $stonk - Single Pull!"; $rtd = invoke-stonkquery -stonk $stonk }
                        if (!$callData.$thisStrikePrice.openInterest) { continue }

                        $callOiVolRatio = ($callData.$thisStrikePrice.totalVolume - $callData.$thisStrikePrice.openInterest) / $callData.$thisStrikePrice.openInterest
                        if (!$putData.$thisStrikePrice.openInterest) {
                            $putOiVolRatio = 0
                        }
                        else {
                            $putOiVolRatio = ($putData.$thisStrikePrice.totalVolume - $putData.$thisStrikePrice.openInterest) / $putData.$thisStrikePrice.openInterest
                        }

                        # Ignore if oiVolRatio isn't at least 30%, or if the delta isn't >= .2, of if the strikePrice isn't within 25% of the rtd.LastPrice
                        if ($callOiVolRatio -le 0 -or ([math]::abs($callData.$thisStrikePrice.delta) -gt .2) -or ([math]::abs($thisStrikePrice - $rtd.LastPrice) -le $rtd.lastPrice * .25)) {
                            continue
                        }

                        $callOiVolRatio = $callOiVolRatio.toString("P")
                        $putOiVolRatio = $putOiVolRatio.toString("P")

                        # Make psobject, write to database
                        $callProps = @{
                            ticker = $stonk.toString()
                            optiontype = "CALL"
                            lastprice = $rtd.lastPrice
                            strikeprice = $thisStrikePrice
                            volume = $callData.$thisStrikePrice.totalVolume
                            openinterest = $callData.$thisStrikePrice.openInterest
                            oivolratio = $callOiVolRatio
                            date = (Get-Date).toString("MM/dd/yy")
                            time = (Get-Date).toString("HH:mm")
                            delta = $callData.$thisStrikePrice.delta
                            contractprice = $callData.$thisStrikePrice.last * 100
                        }
                        Add-DBData -table "HISTORY_OI" -dataObj $callProps

                        $putProps = @{
                            ticker = $stonk.toString()
                            optiontype = "PUT"
                            lastprice = $rtd.LastPrice
                            strikeprice = $thisStrikePrice
                            volume = $putData.$thisStrikePrice.totalVolume
                            openinterest = $putData.$thisStrikePrice.openInterest
                            oivolratio = $putOiVolRatio
                            date =  (Get-Date).toString("MM/dd/yy")
                            time = (Get-Date).toString("HH:mm")
                            delta = $putData.$thisStrikePrice.delta
                            contractprice = $putData.$thisStrikePrice.last * 100
                        }
                        Add-DbData -table "HISTORY_OI" -dataObj $putProps

                        Write-Log -severity discordPost -Message "``$stonk`` CALL - lastPrice(**$($rtd.lastPrice)**) volume(**$($callData.$thisStrikePrice.totalVolume)**) >= openInterest(**$($callData.$thisStrikePrice.openInterest)**) for strikePrice(**$thisStrikePrice**) on $expDate. oiVolRatio(**$callOiVolRatio**)" -channel "oiRatio"
                    }
                }

                # Loop, but not really to control where breakpoints return us to
                for ($i = 1; $i -le 1; $i++) {
                    # find highest openInterest on $chainDate and it's strike price
                    $maxOI = $putData.psobject.properties.value.openInterest | Sort-Object -descending | Select-Object -first 1
                    if (!$maxOI) { Write-Log -severity warning -Message "Somehow we didn't find a maxOI (put) for $stonk on $chainDate -  Investigate."; break }

                    $strikePrice = ($putData.psobject.properties | Where-Object { $_.value.openInterest -eq $maxOI }).name
                    if ($strikePrice.count -gt 1) {
                        if (!$rtd) { $rtd = invoke-stonkquery -stonk $stonk }
                        $strikePrice = Get-ClosestValue -inputArray $strikePrice -targetValue $rtd.lastPrice
                    }
                    if ($putData.$thisStrikePrice.totalVolume -gt $putData.$thisStrikePrice.openInterest) {
                        if (!$rtd) { Write-Log -severity Warning -Message "The RTD megapull doesn't have data for $stonk - Single Pull!"; $rtd = invoke-stonkquery -stonk $stonk }
                        if (!$putData.$thisStrikePrice.openInterest) { continue }

                        if (!$callData.$thisStrikePrice.openInterest) {
                            $callOiVolRatio = 0
                        }
                        else {
                            $callOiVolRatio = ($callData.$thisStrikePrice.totalVolume - $callData.$thisStrikePrice.openInterest) / $callData.$thisStrikePrice.openInterest
                        }
                        $putOiVolRatio = ($putData.$thisStrikePrice.totalVolume - $putData.$thisStrikePrice.openInterest) / $putData.$thisStrikePrice.openInterest

                        # Ignore if oiVolRatio isn't at least 30%, or if the delta isn't >= .2, of if the strikePrice isn't within 25% of the rtd.LastPrice
                        if ($putOiVolRatio -le 0 -or ([math]::abs($putData.$thisStrikePrice.delta) -gt .2) -or ([math]::abs($thisStrikePrice - $rtd.LastPrice) -le $rtd.lastPrice * .25)) {
                            continue
                        }

                        $callOiVolRatio = $callOiVolRatio.toString("P")
                        $putOiVolRatio = $putOiVolRatio.toString("P")

                        # Make psobject, write to database
                        $callProps = @{
                            ticker = $stonk.toString()
                            optiontype = "CALL"
                            lastprice = $rtd.lastPrice
                            strikeprice = $thisStrikePrice
                            volume = $callData.$thisStrikePrice.totalVolume
                            openinterest = $callData.$thisStrikePrice.openInterest
                            oivolratio = $callOiVolRatio
                            date = (Get-Date).toString("MM/dd/yy")
                            time = (Get-Date).toString("HH:mm")
                            delta = $callData.$thisStrikePrice.delta
                            contractprice = $callData.$thisStrikePrice.last * 100
                        }
                        Add-DBData -table "HISTORY_OI" -dataObj $callProps

                        $putProps = @{
                            ticker = $stonk.toString()
                            optiontype = "PUT"
                            lastprice = $rtd.LastPrice
                            strikeprice = $thisStrikePrice
                            volume = $putData.$thisStrikePrice.totalVolume
                            openinterest = $putData.$thisStrikePrice.openInterest
                            oivolratio = $putOiVolRatio
                            date =  (Get-Date).toString("MM/dd/yy")
                            time = (Get-Date).toString("HH:mm")
                            delta = $putData.$thisStrikePrice.delta
                            contractprice = $putData.$thisStrikePrice.last * 100
                        }
                        Add-DbData -table "HISTORY_OI" -dataObj $putProps

                        Write-Log -severity discordPost -Message "``$stonk`` PUT - lastPrice(**$($rtd.lastPrice)**) volume(**$($putData.$thisStrikePrice.totalVolume)**) >= openInterest(**$($putData.$thisStrikePrice.openInterest)**) for strikePrice(**$thisStrikePrice**) on $expDate. oiVolRatio(**$putOiVolRatio**)" -channel "oiRatio"
                    }
                }
            }
            catch {
                Write-Log -severity Error -message "Error in Invoke-OIRatioQuery for $stonk`: $($_.Exception.Message)"
                $_ | FL *
            }
        }
    }

    function Invoke-MultiQuery {
        [cmdletbinding()]
        param (
            $stonkList,
            [array]$allowedPatterns
        )
        
        begin {
            Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }
    
        process {
            foreach ($stonk in $stonkList) {
                #Region GetTodayData -------------------------------------------------------------------------------------------------------------------------------------------------------
                $realTimeData = $null
                # get todays targetPrice from inputFile
                $today = $script:targetPriceFile | Where-Object { $_.Date -eq $(Get-Date -format MM/dd/yyyy) -or $_.Date -eq $(Get-Date -format MM/dd/yy) }
                if (!$today) { Write-Log -severity warning -message "Didn't find an object in inputFile that matches today's date." } 
                if (!$today.$stonk) { Write-Log -severity debug -message "No targetPrice for $stonk today. PatternA matching impossible."; $allowedPatterns = $allowedPatterns | Where-Object { $_ -notlike "patternA" }}
                [double]$targetPrice = $today.$stonk
    
                # get realtime stock price info
                for ($i = 1; $i -le 5; $i++) {
                    $realTimeData = Invoke-StonkQuery -stonk $stonk
                    if ($realTimeData.LastPrice) { break }
                    Write-Log -severity warning -message "Attempt $i of 5 to pull data on $stonk returned a null LastPrice. Retrying..."
                }
                if (!$realTimeData.LastPrice) { Write-Log -severity error -message "Multiple failed attempts to retrieve real time data for $stonk. IS SOMETHING WRONG?!?!"; continue }
    
                # Get our outputFile data
                try {
                    $outputObj = Import-CSV -path $script:nightlyReport -ErrorAction Stop
                }
                catch {
                    Write-Log -severity error -message "Error converting outputFile: $script:nightlyReport to a csvObject for processing: $($_.Exception.Message)"
                    break
                }
                #EndRegion GetTodayData
    
                #Region Matching Patterns --------------------------------------------------------------------------------------------------------------------------------------------------
                Write-Log -severity debug -message "$stonk - Starting evaluations for pattern(s): $allowedPatterns"
                
                #Region PatternA
                if ($allowedPatterns.contains("PatternA")) {
                    # RealPass
                    [array]$realPassArray = ($realTimeData.openprice,$realTimeData.lastPrice) | Sort-Object { [double]$_ }
                    [bool]$realPass = ($realPassArray[0] -le $targetPrice -and $targetPrice -le $realPassArray[1])
                    if ($realPass) {
                        $aPatternRealPassList += "``$stonk``(**$targetPrice**), "
                    }
        
                    # LinePass
                    $arr = ($realTimeData.openprice,$realTimeData.lastPrice,$realTimeData.highprice,$realTimeData.lowprice) | Sort-Object -Descending { [int]$_ }
                    [bool]$linePass = (($arr[1] -lt $targetPrice -and $targetPrice -le $arr[0]) -or ($arr[3] -le $targetPrice -and $targetPrice -lt $arr[2]))
                    if ($linePass) {
                        $aPatternLinePassList += "``$stonk``(**$targetPrice**), "
                    }
                }
                #EndRegion
    
                #Region PatternB
                # Start with day before yesterday and check 8 previous trade days for patternB match
                if ($allowedPatterns.Contains("PatternB")) {
                    $lastCheckedDay = (Get-Date).AddDays(-1)
                    for ($i = 1; $i -le 8; $i++) {
                        $currentDayStr = (Get-AdjacentTradeDay -previous -startDate $lastCheckedDay.AddDays(-1).toString("MM/dd/yy")).toString("MM/dd/yy")                
                        [datetime]$lastCheckedDay = $currentDayStr
                        
                        # Get values from output file for this stock / this day
                        $currentDay = Get-OutputFileData -csvObj $outputObj -date $currentDayStr -stonk $stonk
                        if (!$currentDay) {
                            Write-Log -severity warning -message "PatternB: No Day / Ticker in outputFile matching $currentDay and $stonk"
                            continue
                        }
        
                        # Do the patternB match
                        if ($currentDay."L-Cross") {
                            $prevDay = Get-OutputFileData -csvObj $currentDay -date (Get-AdjacentTradeDay -previous -startDate $currentDayStr).ToString("MM/dd/yy") -stonk $stonk
                            $nextDay = Get-OutputFileData -csvObj $currentDay -date (Get-AdjacentTradeDay -next -startDate $currentDayStr).ToString("MM/dd/yy") -stonk $stonk
        
                            # Call Match
                            if ($currentDay.KUp -eq $true `
                                -and $prevDay."L-Above" -eq "1" `
                                -and $nextDay."L-Above" -eq "-1" `
                                -and (($realTimeData.lastprice -ge ($currentDay.open * .99) -and $realTimeData.lastprice -le ($currentDay.open * 1.01)) -or ($realTimeData.lastprice -ge ($currentDay.low * .99) -and $realtimedata.lastprice -le ($currentDay.low * 1.01)))) {
                                    [array]$patternBmsg += "``$stonk`` - **CALL** lastPrice(**$($realTimeData.lastprice)**)  |  LastPassDate(**$currentDayStr**) targetPrice(**$($currentDay.targetPrice)**) kUp(**$($currentDay.kUp)**) `
                                    prevDayLAbove(**$($prevDay."L-Above")**) nextDayLAbove(**$($nextDay."L-Above")**) open(**$($currentDay.open)**) low(**$($currentDay.low)**)`n"
                            }
        
                            # Put Match
                            if ($currentDay.KUp -eq $false `
                                -and $prevDay."L-Above" -eq "-1" `
                                -and $nextDay."L-Above" -eq "1" `
                                -and (($realTimeData.lastprice -ge ($currentDay.open * .99) -and $realtimedata.lastPrice -le ($currentDay.open * 1.01)) -or ($realtimedata.lastprice -ge ($currentDay.high * .99) -and $realTimeData.lastPrice -le ($currentDay.high * 1.01)))) {
                                    [array]$patternBmsg += "``$stonk`` - **PUT** lastPrice(**$($realTimeData.lastprice)**)  |  LastPassDate(**$currentDayStr**) targetPrice(**$($currentDay.targetPrice)**) kUp(**$($currentDay.KUp)**) `
                                    prevDayLAbove(**$($prevDay."L-Above")**) nextDayLAbove(**$($nextDay."L-Above")**) open(**$($currentDay.open)**) low(**$($currentDay.high)**)`n"
                            }
                        }
                    }
                }
                #EndRegion
    
                #Region PatternC
                if ($allowedPatterns.Contains("PatternC")) {
                    # Start with day before yesterday and check 8 previous trade days for patternC match
                    $lastCheckedDay = Get-Date
                    for ($i = 1; $i -le 9; $i++) {
                        $currentDayStr = (Get-AdjacentTradeDay -previous -startDate $lastCheckedDay.AddDays(-1).toString("MM/dd/yy")).toString("MM/dd/yy")                
                        [datetime]$lastCheckedDay = $currentDayStr
    
                        # Get values from output file for this stock / this day
                        $currentDay = Get-OutputFileData -csvObj $outputObj -date $currentDayStr -stonk $stonk
                        if (!$currentDay) {
                            Write-Log -severity warning -message "PatternB: No Day / Ticker in outputFile matching $currentDay and $stonk"
                            continue
                        }
    
                        # PatternC match
                        if ($currentDay."L-Cross") {
                            $prevDay = Get-OutputFileData -csvObj $currentDay -date (Get-AdjacentTradeDay -previous -startDate $currentDayStr).ToString("MM/dd/yy") -stonk $stonk
                            $nextDay = Get-OutputFileData -csvObj $currentDay -date (Get-AdjacentTradeDay -next -startDate $currentDayStr).ToString("MM/dd/yy") -stonk $stonk
    
                            if ($prevDay."L-Above" -ne "-1" `
                                -and $nextDay."L-Above" -eq "-1" `
                                -and ($realTimeData.LastPrice -ge ($realTimeData.openprice * .995) -and $realTimeData.lastprice -le ($realTimeData.openprice * 1.005))) {
                                    [array]$patternCMsg += "``$stonk`` - Pass/Open Match! LastPass(**$currentDayStr**) LastPrice:(**$($realTimeData.lastprice)**) OpenPrice:(**$($realTimeData.lastPrice)**) `n"
                            }
                        }
                    }
                }
                #EndRegion
    
                #Region PatternD
                if ($allowedPatterns.Contains("PatternD")) {
                    if ($realTimeData.lastprice -ge ($targetPrice * .99) -and $realTimeData.lastprice -le ($targetPrice * 1.01)) {
                        $patternDmsg += "``$stonk`` - lastPrice(**$($realTimeData.lastprice)**) targetPrice(**$targetPrice**)`n"
                    }
                }
                #EndRegion
                #EndRegion Matching Patterns
            }
    
            #Region Discord Messaging ------------------------------------------------------------------------------------------------------------------------------------------------------
            # PatternA messaging
            if ($aPatternLinePassList) {
                Write-Log -severity discordPost -message "-----  $(Get-Date -Format HH:mm) PatternA LinePass List  -----`n$aPatternLinePassList" -channel "patternA"
            }
            if ($aPatternRealPassList) {
                Write-Log -severity discordPost -message "-----  $(Get-Date -Format HH:mm) PatternA RealPass List  -----`n$aPatternRealPassList" -channel "patternA"
            }
    
            # PatternB messaging
            if ($patternBmsg) {
                foreach ($msg in $($patternBmsg | Select-Object -Unique)) { $bOut += $msg } 
                Write-Log -severity discordPost -message "-----  $(Get-Date -Format HH:mm) PatternB Matches  -----`n$bOut" -channel "patternB"
            }
    
            # PatternC messaging
            if ($patternCmsg) {
                foreach ($msg in $($patternCMsg | Select-Object -Unique)) { $cOut += $msg }
                Write-Log -severity discordPost -message "-----  $(Get-Date -Format HH:mm) Pass/Open Matches  -----`n$cOut" -channel "patternC"
            }
    
            # PatternD messaging
            if ($patternDmsg) {
                Write-Log -severity discordPost -message "-----  $(Get-Date -Format HH:mm) +/- 1% of TargetPrice  -----`n$patternDmsg" -channel "patternD"
            }
            #EndRegion Discord Messaging
        }
    
        end {
            Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }

    function Invoke-GEXHeartbeat {
        [cmdletbinding()]
        param ()

        Write-Log -Severity Debug -Message "Processing GEXHeartbeat for" -noNewLine
        $stonkList = "IWM","SPY","QQQ"
        foreach ($stonk in $stonkList) {
            Write-Log -severity Debug -Message " $stonk..." -noNewLine
            try {
                $chainObj = Get-OptionChain -stonk $stonk
            
                # get nearest expDay from option chain and clean up date format
                $chainDate = ($chainObj.callExpDateMap.psobject.properties | select-object -first 1).Name
                $chainPrices = $chainObj.callExpDateMap.$chainDate.psobject.Properties.name
    
                [int]$gex = 0
                # And loop through every price available for each date
                foreach ($price in $chainPrices) {
                    $callInfo = $chainObj.callExpDateMap.$chainDate.$price
                    $putInfo = $chainObj.putExpDateMap.$chainDate.$price
    
                    if ($callInfo.openInterest -and $callInfo.openInterest -ne 'NaN' -and $callInfo.gamma -and $callInfo.gamma -ne 'NaN') {
                        $gex += ($callInfo.openInterest * $callInfo.gamma * 100)
                    }
    
                    if ($putInfo.openInterest -and $putInfo.openInterest -ne 'NaN' -and $putInfo.gamma -and $putInfo.gamma -ne 'NaN') {
                        $gex += ($putInfo.openInterest * $putInfo.gamma * -100)
                    }
                }
                
                $currTime = Get-Date
                $dataObj = @{
                    ticker = $stonk
                    gex = $gex
                    date = $currTime.ToString("MM/dd/yy")
                    time = $currTime.toString("HH:mm")
                }
                Add-DBData -table "HISTORY_GEX" -dataObj $dataObj

                # Get today's data for each stonk
                $todayData = Get-DBData -table "HISTORY_GEX" | Where-Object { $_.ticker -eq $stonk -and $_.Date -eq $currTime.ToString("MM/dd/yy") }
                if ($todayData) { Invoke-DrawChart -chartType "Column" -Title "$stonk GEX - $($currTime.ToString("MM/dd/yy"))" -xData $todayData.time -yData $todayData.gex -chartPath "C:\Users\tabba\OneDrive\_Dev\StonkBotCharts\dailyGEX-$stonk.jpeg" }
            }
            catch {
                Write-Log -severity Error -Message "$($_.Exception | Format-List -Force | Out-String)"
                Write-Log -severity Error -Message "$($_.InvocationInfo | Format-List -Force | Out-String)"
            }
            Write-Log -Severity Debug -Message "Done!" -noNewLine
        }

        Write-Log -Severity Debug -Message " End of GEX ticker list!"
    }

    function Update-ESFuturesData {
        [cmdletbinding()]
        param (
            [string]$market
        )

        $today = (get-Date).toString("MM/dd/yy")

        # Get data from ES futures pull
        $todayES = invoke-stonkQuery -stonk "/ES"

        if ($todayES.closePriceInDouble) {
            $useClose = $todayES.closePriceInDouble
        }
        else {
            $useClose = $todayES.lastPriceInDouble
            Write-Log -Severity Warning -Message "/ES rtd has no closeprice. Using last price $useClose instead - Investigate this."
        }
        
        $dbCheck = get-dbdata -table "history_es" | Where-Object { $_.date -eq $today }

        switch ($market) {
            "day" {
                $dayData = $dbCheck | Where-Object { $_.market -eq "day"}
                $nightData = $dbCheck | Where-Object { $_.market -eq "night" }

                $absFlux = $dayData.absflux
                $dayFlux = $dayData.dayflux
                $nightFlux = $dayData.nightflux
    
                if (!$dayData) {
                    $absHigh = $nightData.high
                    $absLow = $nightData.low
                    break
                }
                
                if(!$nightData) {
                    $absHigh = $dayData.high
                    $absLow = $dayData.low
                    break
                }

                if ($dayData -and $nightdata) {
                    $absHigh = $nightData.high
                    if ($dayData.high -gt $nightData.high) {
                        $absHigh = $dayData.high
                    }
                    $absLow = $nightData.low
                    if ($nightData.low -gt $dayData.low) {
                        $absLow = $dayData.low
                    }
                }
                else {
                    write-log -severity error -message "Missing both day and night market data for today!"
                }
            }

            "night" {
                $absFlux = $null
                $dayFlux = $null
                $nightFlux = $null
                $absHigh = $null
                $absLow = $null
            }
        }
        
        $esObj = @{
            open = $todayES.openPriceInDouble
            close = $useClose
            low = $todayES.lowPriceInDouble
            high = $todayES.highPriceInDouble
            volume = $todayES.totalVolume
            market = $market
            date = $today
            absflux = $absFlux
            dayflux = $dayFlux
            nightflux = $nightFlux
            abslow = $absLow
            abshigh = $absHigh
        }
        
        if ($dbCheck) {
            Update-DBData -table "history_es" -dataObj $esObj -scope "market='$market' AND date='$today'"
            Write-Log -Severity debug -message "Updated $market market entry for today in the DB!"
        }
        else {
            add-dbdata -table "history_es" -dataObj $esObj
            Write-Log -severity debug -message "Added today's /ES history data to table!"
        }
    }

    function Invoke-FluxValueReports {
        [cmdletbinding()]
        param (
            [switch]$makeGraphs = $false,
            [switch]$calcValues = $false
        )

        $todayString = (get-date).ToString("MM/dd/yy")

        if ($calcValues) {
            try {
                $absFlux = get-fluxValue
                $dayFlux = get-fluxValue -dayOnly
                $nightFlux = get-fluxValue -nightOnly
                
                $open = (invoke-stonkQuery -stonk "/ES").lastPriceInDouble
                $open = [math]::round($open,2)
                if (!$open) {
                    Write-Log -severity warning -message "There is a problem pulling the open price for /ES... We got $open - Investigate this."
                    return
                }
                
                # Write fluxValue to database
                $esObj = @{
                    open = $open
                    close = $null
                    low = $null
                    high = $null
                    volume = $null
                    market = 'day'
                    date = (get-date).toString("MM/dd/yy")
                    absflux = $absFlux
                    dayflux = $dayFlux
                    nightflux = $nightFlux
                }
                add-dbdata -table "history_es" -dataObj $esObj
        
                # Discord message
                Write-Log -severity discordPost -channel "ES" -message "The four-day fluctuationValue is: ``$absFlux`` - Today's possible highs/lows are: ``$([math]::round($open + ($absFlux / 2),2)) / $([math]::round($open - ($absFlux / 2),2))`` and ``$([math]::round(($open + $absFlux),2)) / $([math]::round($open - $absFlux))``"
            }
            catch {
                Write-Log -severity Error -Message "Error running AM fluxValue report for today: $($_.Exception.Message)"
            } 
        }
        
        if ($makeGraphs) {
            # graphs max out at 15 days
            try {
                $fluxGraphData = get-dbdata -table "history_es" | Where-Object { !([string]::isnullorempty($_.absflux)) -and !([string]::isnullorempty($_.dayflux)) -and !([string]::isnullorempty($_.nightflux)) } | Sort-Object -Property date | Select-Object -last 15
                
                Invoke-DrawChart -chartType "Column" -Title "Absolute FluxVals - $todayString" -xData $fluxGraphData.date -yData $fluxGraphData.absflux -chartPath "C:\Users\tabba\OneDrive\_Dev\StonkBotCharts\dailyAbsFlux.jpeg"
                Invoke-DrawChart -chartType "Column" -Title "Day FluxVals - $todayString" -xData $fluxGraphData.date -yData $fluxGraphData.dayflux -chartPath "C:\Users\tabba\OneDrive\_Dev\StonkBotCharts\dailyDayFlux.jpeg"
                Invoke-DrawChart -chartType "Column" -Title "Night FluxVals - $todayString" -xData $fluxGraphData.date -yData $fluxGraphData.nightflux -chartPath "C:\Users\tabba\OneDrive\_Dev\StonkBotCharts\dailyNightFlux.jpeg"
            }
            catch {
                Write-Log -severity Error -Message "Error drawing fluxvalue charts: $($_.Exception.Message)"
            }   
        }
    }

    function Invoke-G2onES {
        [cmdletbinding()]
        param (
            [switch]$initialCheck = $false
        )
    
        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }

        process {
            if ($initialCheck) {
                $candle = get-candleChart -stonk $stonk -startDate ((get-Date).addHours(-24)) -endDate (get-date)
            }
        }

        end {
            #Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }

    function backfill-absvals {
        [cmdletbinding()]
        param (
            $targetDate
        )

        $dbCheck = get-dbdata -table "history_es" | Where-Object { $_.date -eq $targetDate }
        $dayData = $dbCheck | Where-Object { $_.market -eq "day"}
        $nightData = $dbCheck | Where-Object { $_.market -eq "night" }

        $absHigh = $dayData.high
        if ($dayData.High -lt $nightData.high) {
            $absHigh = $nightData.high
        }

        $absLow = $dayData.low
        if ($dayData.low -gt $nightData.low) {
            $absLow = $nightData.low
        }

        write-log -severity info -message "absLow: $absLow`nabsHigh: $absHigh"
    }

    # TODO
    <#      function Invoke-G2S {
        [cmdletbinding()]
        param (
            [switch]$initialCheck = $false
        )
    
        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }

        process {
            if ($initialCheck) {
                $hiCapStocks = "AAPL,MSFT,GOOGL,GOOG,AMZN,TSLA,NVDA,FB,TSM,V,JNJ,TCEHY,JPM,WMT,XOM,UNH,MA,HD,PFE,ABBV,LLY,KO,AVGO,DIS,COST,PEP,CSCO,ORCL,TMO,CRM,CMCSA,VZ,NKE,ADBE,AMD,QCOM,NFLX,LOW,PYPL,RBLX"
                $mRtd = invoke-stonkQuery -stonk $hiCapStocks -multi

                foreach ($stonk in $hiCapStocks) {
                    $rtd = $mRtd.$stonk
                    if (!$rtd) { $rtd = invoke-stonkquery -stonk $stonk }
                    $yDay = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq (Get-AdjacentTradeDay -previous -count 1 -startDate ((get-date).toString("MM/dd/yy"))).toString("MM/dd/yy") }

                    if ($rtd.open -ge ($yDay.close * 1.02)) {
                        $pIncrease = (($rtd.Open / $yDay.close) - 1).tostring("P")
                        write-log -severity discordPost -channel "TBD" -message "$stonk`: +$pIncrease - a1=$a1, a2=$a2, a3=$a3, a4=$a4"

                        $dataObj = [PSCustomObject]@{
                            ticker = $stonk
                            date = (get-date).toString("MM/dd/yy")
                            arrLevels = @(($yDay.close),($yDay.close * 1.02),($yDay.close * 1.05),($yDay.close * 1.07),($yDay.close * 1.1))
                        }
                        add-dbData -table "G2S_DATA" -dataObj $dataObj
                    }
                }
            }
            
            # Everything beyond the initial check!
            $flaggedStocks = get-dbdata -table "G2S_DATA" | Where-Object { $_.date -eq (get-date).toString("MM/dd/yy") }
            foreach ($data in $flaggedStocks) {
                if ($data.arrLevels) { $levels = invoke-expression $data.arrLevels }
                if ($data.arrBar1) { $bar1 = invoke-expression $data.arrBar1 }
                if ($data.arrBar2) { $bar2 = invoke-expression $data.arrBar2 }
                if ($data.arrBar3) { $bar3 = invoke-expression $data.arrBar3 }
                if ($data.arrBar4) { $bar4 = invoke-expression $data.arrBar4 }
                if (!$levels) { Write-Log -severity Error -message "`$levels is empty for $($data.ticker)! Investigate!!!"; continue }

                if ($bar4) {
                    # ???
                    write-log -severity debug -message "We have already identified a 4th bar. Do something already."
                    continue
                }

                # Get latest 5 minute bar and compare it to things!
                $candle = get-candleChart -stonk $stonk -startDate (get-Date) -endDate (get-date) | Select-Object -last 1

                if ($bar3) {

                }

                if ($bar2) {

                }

                if ($bar1) {

                }
            }
        

            foreach ($stonk in $stonks) {
                $rtd = $mRtd.$stonk
                if (!$rtd) { $rtd = invoke-stonkquery -stonk $stonk }
                $yDay = Get-DBData -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq (Get-AdjacentTradeDay -previous -count 1 -startDate ((get-date).toString("MM/dd/yy"))).toString("MM/dd/yy") }

                if ($rtd.open -ge ($yDay.close * 1.02)) {
                    $a0 = $yDay.close
                    $a1 = $yDay.close * 1.02
                    $a2 = $yDay.close * 1.05
                    $a3 = $yDay.close * 1.07
                    $a4 = $yDay.close * 1.1

                    if ($initialCheck) {
                        $pIncrease = (($rtd.Open / $yDay.close) - 1).tostring("P")
                        write-log -severity discordPost -channel "TBD" -message "$stonk`: +$pIncrease - a1=$a1, a2=$a2, a3=$a3, a4=$a4"
                    }

                    $candle = get-candleChart -stonk $stonk -startDate (get-Date) -endDate (get-date) | Select-Object -last 1
                    if (($candle.close -gt $a1) -and ($candle.close -gt $candle.open)) {
                        $a1Bar = @($a1, $candle.open, $candle.close, $candle.low, $candle.high)
                    }
                }



            }
        }

        end {
            #Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }
    #>
    <#      function Invoke-258Check {
        [cmdletbinding()]
        param ()
    
        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }

        process {
            # Get list of tickers to check
            [array]$oiStockList = Get-Content -path "$sbPath\Input\oiStockList.csv"
            $oiStockList | Sort-Object | ForEach-Object { $oiList += "$($_)," }
            $oiList = $oiList.trim(",")
            $mRtd = invoke-stonkQuery -stonk $oiList -multi

            foreach ($stonk in $stonks) {
                $rtd = $mRtd.$stonk
                if (!$rtd) { $rtd = invoke-stonkquery -stonk $stonk }

            }

        }

        end {
            #Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
        }
    }
    #>
    <#      function Invoke-FiveStepCheck {
            [cmdletbinding()]
            param()

            function get-lastPeak {
                [cmdletbinding()]
                param (
                    [datetime]$startDate
                )

                try {
                    $i = 0
                    $foundPeak = $false
                    while (!$foundPeak) {
                        $currDay = $startDate.addDays(-$i).toString("MM/dd/yy")
                        $prevDay = (Get-AdjacentTradeDay -previous -startDate $currDay).toString("MM/dd/yy")
                        $dataPair = get-dbdata -table "history_data" | Where-Object { $_.ticker -eq $stonk -and ($_.date -eq $currDay -or $_.date -eq $prevDay) }
                        if ($dataPair.count -ne 2) {
                            throw "The dataPair for $currDay and $prevDay doesn't contain two data objects. Problem?"
                        }
                        
                        # If currDay's high is higher than prevDay's high, this might be a peak.
                        if ($dataPair[1].high -gt $dataPair[0].high) {

                        }
                        
                        $i++
                    }
                }
                catch {

                }
            }

            function get-lastValley {
                [cmdletbinding()]
                param (
                    $startDate
                )

                try {
                    $i = 0
                    $foundValley = $false
                    while (!$foundValley) {
                        $currDay = $startDate.addDays(-$i).toString("MM/dd/yy")
                        $prevDay = (Get-AdjacentTradeDay -previous -startDate $currDay).toString("MM/dd/yy")
                        $dataPair = get-dbdata -table "history_data" | Where-Object { $_.ticker -eq $stonk -and ($_.date -eq $currDay -or $_.date -eq $prevDay) }
                        if ($dataPair.count -ne 2) {
                            throw "The dataPair for $currDay and $prevDay doesn't contain two data objects. Problem?"
                        }
                        
                        # If currDay's low is lower than prevDay's low, this might be a valley.
                        if ($dataPair[1].low -lt $dataPair[0].low) {

                        }
                        
                        $i++
                    }
                }
                catch {

                }


            }

            # Don't do stuff if we're running on the weekend for some reason
            if ((Get-Date).toString("dddd") -eq "Saturday" -or $today -eq "Sunday") {
                Write-Log -Severity Warning -Message "You don't pay me to update history files on the weekend!"
                return
            }

            # Get list of all stonks we've got history data for
            $hFiles = (get-dbdata -table "history_data").ticker | Select-Object -unique

            foreach ($stonk in $hFiles) {
                # check yesterday's info to determine what phase we're currently in
                $yesterdayPhase = (get-dbdata -table "history_data" | Where-Object { $_.ticker -eq $stonk -and $_.date -eq (Get-Date).addDays(-1).toString("MM/dd/yy") }).fsPhase

                switch ($yesterdayPhase) {
                    "G1" {}
                    "G2" {}
                    "G3" {}
                    "D1" {}
                    "D2" {}
                    default {


                    }
                }


            }
        }
    #>
    #EndRegion
#EndRegion

#Region Variables
$appData = Get-Content "E:\projects\_VSRepo\StonkBot_v1\appsettings.json" -Raw | ConvertFrom-Json
if (!$appData) {
    throw "Failure to read from AppData file - That's a problem!"
}

$global:tdClientId = $appData.tdClientId
$global:sbPath = $appData.dbRootFolder
$global:dbCon = new-sqliteconnection -datasource "$sbPath\$($appData.dbName)"

Update-OauthTokens

$global:closedDays = @("Saturday","Sunday","01/01/22","01/17/22","02/21/22","04/15/22","05/27/22","05/30/22","06/20/22","07/01/22","07/04/22","09/05/22","10/10/22","11/10/22","11/24/22","11/25/22","12/23/22","12/26/22","12/30/22")

$script:targetPriceFile = import-csv -path "$sbPath\Input\targetPriceFile.csv"
$script:nightlyReport = "$sbPath\Output\StonkBot_MegaFile.csv"
$script:middayReport = "$sbPath\Output\MiddayReport.csv"

# Get our stonkList
#$stonkList = $targetPriceFile[0].PSObject.Properties.Name | Where-Object { $_ -ne "Date" -and $_ -ne "Day" -and $_ -ne "/ES" }
#Write-Log -severity debug -message "Detected stonkList: ($stonkList)"

# Gen new tokens if not in the DB
if (!$accessToken -or !$refreshToken) {
    Write-Log -severity debug -message "Missing tokens - generating new!"
    Invoke-GenerateTokens
}
#EndRegion

# Main code execution function (not automatically run for now)
function Start-StonkBot {
    [cmdletbinding()]
    Param (
        [switch]$test = $false
    )

    function new-actionsObject {
        [cmdletbinding()]
        param()
        $actions = [pscustomobject]@{
            <# #Region Gone but not forgotten
            patternA = [pscustomobject]@{
                tick  = 60
                startTime = [datetime]"10:00"
                endTime = [dateTime]"16:00"
                command = "#`$allowedPatterns += 'PatternA'"
            }
            patternB = [pscustomobject]@{
                tick = 1.5
                startTime = [dateTime]"10:00"
                endTime = [dateTime]"16:00"
                command = "#`$allowedPatterns += 'PatternB'"
            }
            patternC = [pscustomobject]@{
                tick = 1.5
                startTime = [dateTime]"09:35"
                endTime = [dateTime]"15:30"
                command = "#`$allowedPatterns += 'PatternC'"
            }
            patternD = [pscustomobject]@{
                tick = 1.5
                startTime = [dateTime]"09:35"
                endTime = [dateTime]"16:00"
                command = "#`$allowedPatterns += 'PatternD'"
            }
            middayReport = [pscustomobject]@{
                tick = 1440
                startTime = [dateTime]"15:20"
                endTime = [dateTime]"16:00"
                command = "#New-OutputFile -runMode 'middayReport'"
            }
            nightlyReport = [pscustomobject]@{
                tick = 1440
                startTime = [dateTime]"20:15"
                endTime = [dateTime]"23:00"
                command = "#New-OutputFile -runMode 'nightlyReport'"
            }
            #EndRegion #>

            #Region Daily (AM) checks
            esNight = [pscustomobject]@{
                tick = 1440
                startTime = [dateTime]"09:28"
                endTime = [dateTime]"09:29"
                command = "Update-ESFuturesData -market `"night`""
            }
            esFluxValue = [pscustomobject]@{
                tick = 1440
                startTime = [dateTime]"09:31"
                endTime = [dateTime]"09:35"
                command = "Invoke-FluxValueReports -calcValues"
            }
            <# buyPointADaily = [PSCustomObject]@{
                tick = 1440
                startTime = [datetime]"09:31"
                endTime = [datetime]"10:00"
                command = "Invoke-BuyPointADailyCheck"
            } #>
            #EndRegion

            #Region Repeating actions
            <# buyPointARTCheck = [PSCustomObject]@{
                tick = 5
                startTime = [datetime]"09:35"
                endTime = [datetime]"16:00"
                command = "Invoke-BuyPointARTCheck"
            }
            oiRatioQuery = [pscustomobject]@{
                tick = 5
                startTime = [datetime]"09:35"
                endTime = [datetime]"16:00"
                command = "Invoke-OIRatioQuery"
            } #>
            <# gexHeartbeat = [pscustomobject]@{
                tick = 10
                startTime = [datetime]"09:35"
                endTime = [datetime]"16:00"
                command = "Invoke-GexHeartbeat"
            } #>
            #EndRegion

            #Region Daily (PM) Checks
            esDay = [pscustomobject]@{
                tick = 1440
                startTime = [dateTime]"16:58"
                endTime = [dateTime]"16:59"
                command = "Update-ESFuturesData -market `"day`""
            }
            updateLocalHistory = [pscustomobject]@{
                tick = 1440
                startTime = [dateTime]"20:05"
                endTime = [dateTime]"23:00"
                command = "Update-LocalHistory"
            }
            dailyVolumeAlert = [PSCustomObject]@{
                tick = 1440
                startTime = [datetime]"20:25"
                endTime = [datetime]"23:00"
                command = "New-DailyVolumeAlert"
            }
            #EndRegion
        }

        Write-Log -Severity Info -Message "Generated a new actions control object!"
        return $actions
    }

    $script:messagePref = "chatty"
    if ($test) {
        $script:messagePref = "silenced"
    }

    $Dan = "a butt"
    $startDay = (get-date)
    while ($Dan -eq "a butt") {
        # As long as Dan is a butt, perform eval loop. (loop forever)
        [datetime]$currTime = Get-Date
        if ($closedDays.Contains($currTime.ToString("dddd")) -or $closedDays.Contains($currTime.ToString("MM/dd/yy"))) {
            $dance = @("(>'-')~  ~('-'<)   ", "^('-')^  ^('-')^   ", "<('-'<)  (>'-')>   ", "^('-')^  ^('-')^   ")
            $i = 0
            while ((get-date).toString("MM/dd") -eq $currTime.toString("MM/dd")) {
                write-log -severity info -message "`rThe market is closed today.  ~Dance party~  $($dance[$i])" -noNewLine
                $i++
                if ($i -gt 3) { $i = 0 }
                start-sleep -seconds 2
            }
        }

        # If we don't have an actionsObject or the actionsObject is from yesterday regen the actionsObject
        if (!$actions -or $startDay.toString("MM/dd") -ne $currTime.toString("MM/dd")) {
            $startDay = (get-date)
            $actions = new-ActionsObject
        }

        # Loop through all actions on each pass
        $allowedPatterns = @()
        foreach ($name in $actions.psobject.properties.Name) {
            # Do nothing if we're not inside the action's time window
            if ($currTime -ge $actions.$name.startTime -and $currTime -le $actions.$name.endTime) {

                # Modify the action's next startTime based on the tick
                while ($actions.$name.startTime -le $currTime) {
                    $actions.$name.startTime = ($actions.$name.startTime).addMinutes($actions.$name.tick)
                }

                # Logging!  for funsies
                if (!($name.contains("pattern"))) {
                    write-log -severity Info -message "$currTime - Running: invoke-expression $($actions.$name.command)`nNext startTime: $($actions.$name.startTime)"
                }

                # Run the command associated with each object
                try {
                    invoke-expression $actions.$name.command
                }
                catch {
                    Write-Log -severity Error -Message "Error running: invoke-expression $($actions.$name.command) - $($_.Exception.Message)"
                }
            }
        }

        # If we have allowed patterns run the multi-query
        try {
            if ($allowedPatterns) {
                Write-Log -Severity Info -Message "currTime: $currTime - Running: Invoke-MultiQuery with patterns: $allowedPatterns"
                Invoke-MultiQuery -stonkList $stonkList -allowedPatterns $allowedPatterns
            }
        }
        catch {
            Write-Log -Severity Error -Message "Error running MultiQuery: $($_.Exception.Message)"
        }

        [system.gc]::Collect()
        Start-Sleep -Seconds 30
    }
}