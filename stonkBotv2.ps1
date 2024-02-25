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

    function Invoke-DanceParty {
        param (
            $danceMove
        )

        $danceMoves = @("(>'-')~  ~('-'<)   ", "^('-')^  ^('-')^   ", "<('-'<)  (>'-')>   ", "^('-')^  ^('-')^   ")

        if (!$danceMove -or $danceMove -gt 3) { $danceMove = 0 }
        write-log -severity info -message "`r~~ Dance party ~~  $($danceMoves[$danceMove])" -noNewLine
        return ($danceMove + 1)
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
                #Region Setup
                # Get UserPrincipals and build credential object
                $userPrincipals = Get-UserPrincipalsResponse
                $credentialObject = [PSCustomObject]@{
                    userid = $userPrincipals.accounts[0].accountId
                    token = $userPrincipals.streamerInfo.token
                    company = $userPrincipals.accounts[0].company
                    segment = $userPrincipals.accounts[0].segment
                    cddomain = $userPrincipals.accounts[0].accountCdDomainId
                    usergroup = $userPrincipals.streamerInfo.userGroup
                    accesslevel = $userPrincipals.streamerInfo.accessLevel
                    authorized = "Y"
                    timestamp = ([System.DateTimeOffset]$userPrincipals.streamerinfo.tokentimestamp).ToUnixTimeMilliseconds()
                    appid = $userPrincipals.streamerInfo.appId
                    acl = $userPrincipals.streamerInfo.acl
                }

                
                # Convert credentialObject into a query string
                $credentialQueryString = $null
                foreach ($item in $credentialObject.psobject.properties.Name) {
                    $credentialQueryString += "$item=$($credentialObject.$item)&"
                }
                $credentialQueryString = $credentialQueryString.trimend("&")

                write-log -severity Info -Message "Credential Query String:"
                write-log -severity Info -message $credentialQueryString

                # Build the request object
                $logonRequest = [PSCustomObject]@{
                    service = "ADMIN"
                    command = "LOGIN"
                    requestid = 0
                    account = $userPrincipals.accounts[0].accountId
                    source = $userPrincipals.streamerInfo.appId
                    parameters = [PSCustomObject]@{
                        credential = $credentialQueryString
                        token = $userPrincipals.streamerInfo.token
                        version = "1.0"
                    }
                }

                $esFuturesRequest = [PSCustomObject]@{
                    service = "CHART_FUTURES"
                    requestid = 1
                    command = "SUBS"
                    account = $userPrincipals.accounts[0].accountId
                    source = $userPrincipals.streamerInfo.appId
                    parameters = [PSCustomObject]@{
                        keys = "/ES"
                        fields = "0,1,2,3,4,5,6,7"
                    }
                }

                <# $accountActivityRequest = [PSCustomObject]@{
                    service = "ACCT_ACTIVITY"
                    requestid = 2
                    command = "SUBS"
                    account = $userPrincipals.accounts[0].accountId
                    source = $userPrincipals.streamerInfo.appId
                    parameters = [PSCustomObject]@{
                        keys = "$($userPrincipals.streamerSubscriptionKeys.Keys.Key)"
                        fields = "0,1,2,3"
                    }
                } #>

                $requestObject = [PSCustomObject]@{
                    requests = [PSCustomObject[]](
                        $logonRequest,
                        $esFuturesRequest
                        #$accountActivityRequest
                    )
                }
                $requestJson = $requestObject | ConvertTo-Json -depth 10

                Write-Log -severity Info -Message "RequestJson:"
                write-log -severity Info -Messsage "$($requestJson)"
                #EndRegion

                while ($streamingSocket.State -ne 'open') {
                    $url = "wss://$($userprincipals.streamerinfo.streamersocketurl)/ws"
                    $socket = New-Object System.Net.WebSockets.ClientWebSocket
                    $cancellationToken = New-Object System.Threading.CancellationToken
                    $size = 4096
                    $array = [byte[]] @(,0) * $size

                    $task = $socket.ConnectAsync($url, $cancellationToken)
                    while (!($task.IsCompleted)) {
                        Start-Sleep -milliseconds 100
                    }
                    Write-Log -Severity Info -Message "Connected to: $url"

                    $requestBytes = [System.Text.Encoding]::UTF8.GetBytes($requestJson)
                    $sendRequest = New-Object System.ArraySegment[byte] -ArgumentList @(,$requestBytes)
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
                        $streamResponse = [System.Text.Encoding]::utf8.GetString($streamFrame.array)
                        Invoke-ResponseController($streamResponse)
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
            if ($socket) { $socket.Dispose(); $socket = $null }
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
                "HISTORY_ES" { $allowedFields = @("open", "close", "low", "high", "volume", "market", "date", "absflux", "dayflux", "nightflux") }
                "OAUTH_TOKENS" { $allowedFields = @("accessToken", "refreshToken") }
                "G2S_DATA" { $allowedFields = @("ticker", "date", "arrLevels", "arrBar1", "arrBar2", "arrBar3", "arrBar4") }
                "ALERT_POINTS" { $allowedFields = @("ticker", "date", "p1", "p2") }
                "ES_CANDLES" { $allowedFields = @("open","close","low","high","volume","charttime") }
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

    function Start-StonkBot {
        [cmdletbinding()]
        Param ()
    
        $Dan = "a butt"
        while ($Dan -eq "a butt") {
            if (!$socket) {
                Write-Log -severity Info -Message "Streaming socket isn't open! Calling 'Invoke-OpenStreamingSocket'..."
                Invoke-OpenStreamingSocket
            }
    
            [system.gc]::Collect()
            Write-Log -Severity Info -Message "Snap, looks like the streaming API socket got closed. Reopening in 30 seconds..."
            Start-Sleep -Seconds 30
        }
    }
    #EndRegion

    #Region PatternMatching and control functions
    function Invoke-G2Pattern {
        [cmdletbinding()]
        param (
            $thisCandle,
            [switch]$initialCheck = $false
        )

        begin {
            #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
        }

        process {
            if ($initialCheck) {

            }
            
            
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

    function Invoke-FluxValueReports {
        [cmdletbinding()]
        param (
            [switch]$makeGraphs = $false,
            [switch]$calcValues = $false
        )

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
                
                Invoke-DrawChart -chartType "Column" -Title "Absolute FluxVals - $((get-date).ToString("MM/dd/yy"))" -xData $fluxGraphData.date -yData $fluxGraphData.absflux -chartPath "C:\Users\tabba\OneDrive\_Dev\StonkBotCharts\dailyAbsFlux.jpeg"
                Invoke-DrawChart -chartType "Column" -Title "Day FluxVals - $((get-date).ToString("MM/dd/yy"))" -xData $fluxGraphData.date -yData $fluxGraphData.dayflux -chartPath "C:\Users\tabba\OneDrive\_Dev\StonkBotCharts\dailyDayFlux.jpeg"
                Invoke-DrawChart -chartType "Column" -Title "Night FluxVals - $((get-date).ToString("MM/dd/yy"))" -xData $fluxGraphData.date -yData $fluxGraphData.nightflux -chartPath "C:\Users\tabba\OneDrive\_Dev\StonkBotCharts\dailyNightFlux.jpeg"
            }
            catch {
                Write-Log -severity Error -Message "Error drawing fluxvalue charts: $($_.Exception.Message)"
            }   
        }
    }

    #EndRegion
#EndRegion

#Region Variables
$appData = Get-Content .\appsettings.json -Raw | ConvertFrom-Json
if (!$appData) {
    throw "Failure to read from AppData file - That's a problem!"
}

$global:tdClientId = $appData.tdClientId
$global:sbPath = $appData.dbRootFolder
$global:dbCon = new-sqliteconnection -datasource "$sbPath\$($appData.dbName)"

Update-OauthTokens

$global:closedDays = @("Saturday","Sunday","01/01/22","01/17/22","02/21/22","04/15/22","05/27/22","05/30/22","06/20/22","07/01/22","07/04/22","09/05/22","10/10/22","11/10/22","11/24/22","11/25/22","12/23/22","12/26/22","12/30/22")
$global:lastResponseTime = ""

# Gen new tokens if not in the DB
if (!$accessToken -or !$refreshToken) {
    Write-Log -severity debug -message "Missing tokens - generating new!"
    Invoke-GenerateTokens
}

$global:danceParty = 0
#EndRegion

# This function called every time we receive a response on the streaming socket.  It's the heart beat function
function Invoke-ResponseController {
    [cmdletbinding()]
    param (
        $streamResponse
    )

    begin {
        #Write-Log -severity tag -message "Start of function: $($MyInvocation.MyCommand.Name)"
    }

    process {
        #$monitorFile = "C:\users\tabba\desktop\acct_activity.txt"
        
        switch -wildcard ($streamResponse) {
            "*CHART_FUTURES*" {
                $matchPattern = "`"seq`":(?'seq'.*?),`"key`":`"(?'key'.*?)`",`"1`":(?'time'.*?),`"2`":(?'open'.*?),`"3`":(?'high'.*?),`"4`":(?'low'.*?),`"5`":(?'close'.*?),`"6`":(?'volume'.*?)}"
                if ($streamResponse -match $matchPattern) {
                    [datetime]$responseTime = get-date -unixTimeSeconds ([int64]$matches.time / 1000)
                    if ($global:lastResponseTime -ne $responseTime) {
                        $thisCandle = @{
                            open = $matches.open
                            close = $matches.close
                            low = $matches.low
                            high = $matches.high
                            volume = $matches.volume
                            charttime = $responseTime
                        }
    
                        # Add data to the database!
                        try {
                            add-dbdata -table "ES_CANDLES" -dataObj $thisCandle
                        }
                        catch {
                            Write-Log -severity Error -message "Error writing data for $($thisCandle.charttime): $($_.Exception.Message)"
                        }
    
                        # Set vars / output
                        $global:lastResponseTime = $responseTime
                        $global:danceParty = Invoke-DanceParty -danceMove $global:danceParty
                    }
                }
                else {
                    Write-Log -severity Warning -message "chartFutures response didn't match our regex pattern:`n$streamResponse"
                }
                break
            }

            <# "*`"data`"*`"ACCT_ACTIVITY`"*" {
                Write-Log -severity Info -Message "Wrote streamResposne to outFile. Check it later!"
                $streamResponse | Out-File -filePath $monitorFile -append
                break
            } #>

            "*heartbeat*" {
                #ignore
                break
            }

            default {
                Write-Log -severity debug -message "Stream response didn't have an accountActivity or chartFutures header!`n$streamResponse"
            }
        }
    }

    end {
        #Write-Log -severity tag -message "End of function: $($MyInvocation.MyCommand.Name)"
    }
}