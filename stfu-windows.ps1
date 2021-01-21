# Ask for elevated permissions if required
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

# Disable AeroShake
Write-Host "Disabling AeroShake..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1

# Disable Telemetry
Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Disable Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

# Disable Bing Search in Start Menu
Write-Host "Disabling Bing Search in Start Menu..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0

# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

# Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

# Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

# Restrict Windows Update P2P only to local network
Write-Host "Restricting Windows Update P2P only to local network..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3

# Disable windows update seeding
Write-Output "Disable seeding of updates to other computers via Group Policies"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

# Stop and disable Diagnostics Tracking Service
Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled

# Disable Sticky keys prompt
Write-Host "Disabling Sticky keys prompt..."
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"

# Hide Search button / box
Write-Host "Hiding Search Box / Button..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

# Hide Task View button
Write-Host "Hiding Task View button..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

# Hide Cortana button
Write-Host "Hiding Cortana button..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0

# Hide People on the taskbar
Write-Host "Hiding People on the taskbar..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Type DWord -Value 1

# Show small icons in taskbar
Write-Host "Showing small icons in taskbar..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1

# Show titles in taskbar
Write-Host "Showing titles in taskbar..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1

# Hide tray icons as needed
Write-Host "Hiding all tray icons..."
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray"

# Show known file extensions
Write-Host "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# Show hidden files
Write-Host "Showing hidden files..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

# Change default Explorer view to "Computer"
Write-Host "Changing default Explorer view to `"Computer`"..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

# Disable OneDrive
Write-Host "Disabling OneDrive..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

Write-Output "Removing onedrive scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

# Uninstall default Microsoft applications
Write-Host "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ScreenSketch" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppPackage

Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Uninstalling default apps"
$apps = @(
    # default Windows 10 apps
    "Microsoft.3DBuilder"
    "Microsoft.Advertising.Xaml"
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    #"Microsoft.FreshPaint"
    "Microsoft.GamingServices"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MixedReality.Portal"
    "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.MicrosoftSolitaireCollection"
    #"Microsoft.MicrosoftStickyNotes"
    "Microsoft.MinecraftUWP"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.Office.OneNote"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    # "Microsoft.Windows.Photos"
    # "Microsoft.WindowsAlarms"
    # "Microsoft.WindowsCalculator"
    # "Microsoft.WindowsCamera"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    #"Microsoft.WindowsStore"   # can't be re-installed
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
#    "Microsoft.ZuneMusic"
#    "Microsoft.ZuneVideo"
    "Microsoft.Windows.CloudExperienceHost"
    "Microsoft.Windows.ContentDeliveryManager"
    "Microsoft.Windows.PeopleExperienceHost"
    "Microsoft.XboxGameCallableUI"

    # Threshold 2 apps
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.WindowsFeedbackHub"

    # Creators Update apps
    "Microsoft.Microsoft3DViewer"
    #"Microsoft.MSPaint"

    #Redstone apps
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.WindowsReadingList"

    # Redstone 5 apps
    "Microsoft.MixedReality.Portal"
    "Microsoft.ScreenSketch"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.YourPhone"

    # non-Microsoft
    "2FE3CB00.PicsArt-PhotoStudio"
    "46928bounde.EclipseManager"
    "4DF9E0F8.Netflix"
    "613EBCEA.PolarrPhotoEditorAcademicEdition"
    "6Wunderkinder.Wunderlist"
    "7EE7776C.LinkedInforWindows"
    "89006A2E.AutodeskSketchBook"
    "9E2F88E3.Twitter"
    "A278AB0D.DisneyMagicKingdoms"
    "A278AB0D.MarchofEmpires"
    "ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
    "CAF9E577.Plex"  
    "ClearChannelRadioDigital.iHeartRadio"
    "D52A8D61.FarmVille2CountryEscape"
    "D5EA27B7.Duolingo-LearnLanguagesforFree"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "DolbyLaboratories.DolbyAccess"
    "DolbyLaboratories.DolbyAccess"
    "Drawboard.DrawboardPDF"
    "Facebook.Facebook"
    "Fitbit.FitbitCoach"
    "Flipboard.Flipboard"
    "GAMELOFTSA.Asphalt8Airborne"
    "KeeperSecurityInc.Keeper"
    "NORDCURRENT.COOKINGFEVER"
    "PandoraMediaInc.29680B314EFC2"
    "Playtika.CaesarsSlotsFreeCasino"
    "ShazamEntertainmentLtd.Shazam"
    "SlingTVLLC.SlingTV"
    "SpotifyAB.SpotifyMusic"
    #"TheNewYorkTimes.NYTCrossword"
    "ThumbmunkeysLtd.PhototasticCollage"
    "TuneIn.TuneInRadio"
    "WinZipComputing.WinZipUniversal"
    "XINGAG.XING"
    "flaregamesGmbH.RoyalRevolt2"
    "king.com.*"
    "king.com.BubbleWitch3Saga"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"

    # apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.MicrosoftEdge"
    #"Microsoft.Windows.Cortana"
    #"Microsoft.WindowsFeedback"
    #"Microsoft.XboxGameCallableUI"
    #"Microsoft.XboxIdentityProvider"
    #"Windows.ContactSupport"

    # apps which other apps depend on
    "Microsoft.Advertising.Xaml"
)

foreach ($app in $apps) {
    Write-Output "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

    Get-AppXProvisionedPackage -Online |
        Where-Object DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
}

# Prevents Apps from re-installing
$cdm = @(
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "SilentInstalledAppsEnabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)

New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

# Prevents "Suggested Applications" returning
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

# This script removes all Start Menu Tiles from the .default user #
Set-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -Value '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <LayoutOptions StartTileGroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:StartLayout GroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  </DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        <taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:UWA AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        </taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      </defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '</LayoutModificationTemplate>'

$START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

$layoutFile="C:\Windows\StartMenuLayout.xml"

#Delete layout file if it already exists
If(Test-Path $layoutFile)
{
    Remove-Item $layoutFile
}

#Creates the blank layout file
$START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

$regAliases = @("HKLM", "HKCU")

#Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer"
    IF(!(Test-Path -Path $keyPath)) {
        New-Item -Path $basePath -Name "Explorer"
    }
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
    Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
}

#Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
Stop-Process -name explorer
Start-Sleep -s 5

#Enable the ability to pin items again by disabling "LockedStartLayout"
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer"
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
}

#Restart Explorer and delete the layout file
Stop-Process -name explorer
Start-Sleep -s 5

Remove-Item $layoutFile

# Set Windows to Dark Mode #
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f

##########
# Restart
##########
Write-Host
Write-Host "Please restart your system!" -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey()

