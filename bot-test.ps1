Import-Module Selenium

# Configure Chrome to run headless with a bot-like UA
$chromeOpts = New-SeChromeOptions
$chromeOpts.AddArgument('--headless')
$chromeOpts.AddArgument('--disable-gpu')
$chromeOpts.AddArgument('--window-size=1920,1080')
$chromeOpts.AddArgument('--user-agent=Mozilla/5.0 (compatible; TestBot/1.0; +https://example.com/bot)')

# Launch the browser
$driver = Start-SeChrome -Options $chromeOpts

try {
  # Navigate to your page
  $driver.Navigate().GoToUrl('https://home.newsparrow.in/')

  # Sit idle—no mouse or keyboard events—for 20 seconds
  Start-Sleep -Seconds 20

  Write-Host "✅ Bot run complete. Check your Traffic Cop dashboard for a blocked session."
}
finally {
  # Always clean up
  Stop-SeDriver -Driver $driver
}
