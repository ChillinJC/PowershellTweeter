$TwitterMessageString = "Hello TwitterVerse!"

<# Creating a condition that If there is no Tweet at the time, My tweets are being auto mated based on events being polled from a databse of active Emergency Services Dispatches. #> 

if ([string]::IsNullOrEmpty($TwitterMessageString)) {
    
    $DispatchTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "There is currently no dispatch AT $DispatchTime"

} else {
    
    $DispatchTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Attempting to Tweet as Follows: $TwitterMessageString at $DispatchTime"


#Stucture the OAuth signature for Twitter 
function Get-OAuthSignature {
    param(
        [string]$httpMethod,
        [string]$url,
        [string]$consumerKey,
        [string]$consumerSecret,
        [string]$token,
        [string]$tokenSecret,
        [string]$nonce,
        [string]$timestamp
    )

    $signatureBaseString = "$httpMethod&" + [uri]::EscapeDataString($url) + "&" +
        [uri]::EscapeDataString("oauth_consumer_key=$consumerKey&") +
        [uri]::EscapeDataString("oauth_nonce=$nonce&") +
        [uri]::EscapeDataString("oauth_signature_method=HMAC-SHA1&") +
        [uri]::EscapeDataString("oauth_timestamp=$timestamp&") +
        [uri]::EscapeDataString("oauth_token=$token&") +
        [uri]::EscapeDataString("oauth_version=1.0")

    $signingKey = [uri]::EscapeDataString($consumerSecret) + "&" + [uri]::EscapeDataString($tokenSecret)

    $hmacsha1 = New-Object System.Security.Cryptography.HMACSHA1
    $hmacsha1.Key = [Text.Encoding]::ASCII.GetBytes($signingKey)
    $signatureBytes = $hmacsha1.ComputeHash([Text.Encoding]::ASCII.GetBytes($signatureBaseString))
    $signature = [Convert]::ToBase64String($signatureBytes)

    return [uri]::EscapeDataString($signature)
}

#Create the Header
function Get-OAuthHeader {
    param(
        [string]$consumerKey,
        [string]$consumerSecret,
        [string]$token,
        [string]$tokenSecret,
        [string]$nonce,
        [string]$timestamp
    )

    $signature = Get-OAuthSignature -httpMethod 'POST' -url 'https://api.twitter.com/2/tweets' -consumerKey $consumerKey -consumerSecret $consumerSecret -token $token -tokenSecret $tokenSecret -nonce $nonce -timestamp $timestamp

    $header = @{
        'Authorization' = "OAuth oauth_consumer_key=`"$consumerKey`", " +
                          "oauth_token=`"$token`", " +
                          "oauth_signature_method=`"HMAC-SHA1`", " +
                          "oauth_timestamp=`"$timestamp`", " +
                          "oauth_nonce=`"$nonce`", " +
                          "oauth_version=`"1.0`", " +
                          "oauth_signature=`"$signature`""
        'Content-Type'  = 'application/json'
    }

    return $header
}

# I store My API Tokens in a Registry Key as strings sothey are not in the script or accessbile to users.
#Your Tokens are unique of course, get them from the Twitter Developers portal.
$registryPath = 'HKLM:\Software\TWITTERKEY'


# Read registry values
try {
    $consumerKey = (Get-ItemProperty -Path $registryPath -Name "consumerKey").consumerKey
    $consumerSecret= (Get-ItemProperty -Path $registryPath -Name "consumerSecret").consumerSecret
    $token = (Get-ItemProperty -Path $registryPath -Name "token").token
    $tokenSecret = (Get-ItemProperty -Path $registryPath -Name "tokensecret").tokensecret
}
catch {
    Write-Error "Failed to read registry values from: $registryPath"
}


#Pass the tweet string value of the outbound tweet to the incoming dispatch: I found this necesssary to keep the spacing the API wants. 
$tweetText = $TwitterMessageString

# Set API endpoint
$apiEndpoint = 'https://api.twitter.com/2/tweets'

# Generate OAuth headers
$nonce = Get-Random
$timestamp = [math]::floor((Get-Date).ToUniversalTime().Subtract((Get-Date "1970-01-01")).TotalSeconds)
$headers = Get-OAuthHeader -consumerKey $consumerKey -consumerSecret $consumerSecret -token $token -tokenSecret $tokenSecret -nonce $nonce -timestamp $timestamp

# Set tweet data
$tweetData = @{
    'text' = $tweetText
}

# Convert tweet data to JSON
$jsonTweetData = $tweetData | ConvertTo-Json

# Send tweet
Invoke-RestMethod -Uri $apiEndpoint -Method Post -Body $jsonTweetData -Headers $headers


}

#Thats It, a simple method of sending tweet texts from Powershell. 
