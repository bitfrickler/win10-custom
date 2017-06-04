@echo off

echo disable Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d 4 /f > nul 2>&1
regsvr32 /s /u "%ProgramFiles%\Windows Defender\shellext.dll"
taskkill /f /im MSASCuiL.exe > nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f > nul 2>&1

echo disable Windows Consumer Features 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f > nul

echo Setting: Open File Explorer to This PC instead of Quick Access 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f > nul
echo Setting: Show file extensions in File Explorer 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > nul
echo Setting: Launch folder windows in a separate process 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 1 /f > nul
echo Setting: Add Recycle Bin to Navigation Pane 
reg add "HKCU\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 1 /f > nul

echo disable Windows Firewall
netsh advfirewall set allprofiles state off > nul

echo block spyware domains
set spy_domains=^
	nullroute,^
	statsfe2.update.microsoft.com.akadns.net,fe2.update.microsoft.com.akadns.net,^
	survey.watson.microsoft.com,watson.microsoft.com,^
	watson.ppe.telemetry.microsoft.com,vortex.data.microsoft.com,^
	vortex-win.data.microsoft.com,telecommand.telemetry.microsoft.com,^
	telecommand.telemetry.microsoft.com.nsatc.net,oca.telemetry.microsoft.com,^
	sqm.telemetry.microsoft.com,sqm.telemetry.microsoft.com.nsatc.net,^
	watson.telemetry.microsoft.com,watson.telemetry.microsoft.com.nsatc.net,^
	redir.metaservices.microsoft.com,choice.microsoft.com,^
	choice.microsoft.com.nsatc.net,wes.df.telemetry.microsoft.com,^
	services.wes.df.telemetry.microsoft.com,sqm.df.telemetry.microsoft.com,^
	telemetry.microsoft.com,telemetry.appex.bing.net,telemetry.urs.microsoft.com,^
	settings-sandbox.data.microsoft.com,watson.live.com,statsfe2.ws.microsoft.com,^
	corpext.msitadfs.glbdns2.microsoft.com,www.windowssearch.com,ssw.live.com,^
	sls.update.microsoft.com.akadns.net,i1.services.social.microsoft.com,^
	diagnostics.support.microsoft.com,corp.sts.microsoft.com,^
	statsfe1.ws.microsoft.com,feedback.windows.com,feedback.microsoft-hohm.com,^
	feedback.search.microsoft.com,rad.msn.com,preview.msn.com,^
	df.telemetry.microsoft.com,reports.wes.df.telemetry.microsoft.com,^
	vortex-sandbox.data.microsoft.com,settings.data.microsoft.com,^
	oca.telemetry.microsoft.com.nsatc.net,pre.footprintpredict.com,^
	spynet2.microsoft.com,spynetalt.microsoft.com,win10.ipv6.microsoft.com,^
	fe3.delivery.dsp.mp.microsoft.com.nsatc.net,cache.datamart.windows.com,^
	db3wns2011111.wns.windows.com,settings-win.data.microsoft.com,^
	v10.vortex-win.data.microsoft.com,apps.skype.com,^
	g.msn.com,bat.r.msn.com,client-s.gateway.messenger.live.com,^
	arc.msn.com,rpt.msn.com,bn1303.settings.live.net,client.wns.windows.com,^
	ieonlinews.microsoft.com,inprod.support.services.microsoft.com,^
	geover-prod.do.dsp.mp.microsoft.com,geo-prod.do.dsp.mp.microsoft.com,^
	kv201-prod.do.dsp.mp.microsoft.com,cp201-prod.do.dsp.mp.microsoft.com,^
	disc201-prod.do.dsp.mp.microsoft.com,array201-prod.do.dsp.mp.microsoft.com,^
	array202-prod.do.dsp.mp.microsoft.com,array203-prod.do.dsp.mp.microsoft.com,^
	array204-prod.do.dsp.mp.microsoft.com,tsfe.trafficshaping.dsp.mp.microsoft.com,^
	dl.delivery.mp.microsoft.com,tlu.dl.delivery.mp.microsoft.com,^
	statsfe1-df.ws.microsoft.com,statsfe2-df.ws.microsoft.com,^
	public-family.api.account.microsoft.com,dub407-m.hotmail.com,^
	www.bing.com,c.bing.com,g.bing.com,appex.bing.com,^
	urs.microsoft.com,c.urs.microsoft.com,t.urs.microsoft.com,activity.windows.com,^
	uif.microsoft.com,iecvlist.microsoft.com,ieonline.microsoft.com,c.microsoft.com,^
	nexus.officeapps.live.com,nexusrules.officeapps.live.com,c1.microsoft.com,^
	c.s-microsoft.com,apprep.smartscreen.microsoft.com,otf.msn.com,c.msn.com,^
	rr.office.microsoft.com,web.vortex.data.microsoft.com,ocsa.office.microsoft.com,^
	ocos-office365-s2s.msedge.net,odc.officeapps.live.com,uci.officeapps.live.com,^
	roaming.officeapps.live.com,urs.smartscreen.microsoft.com
set hosts=%SystemRoot%\System32\drivers\etc\hosts
for %%i in (%spy_domains%) do (
	find /c " %%i" %hosts% > nul
	if errorlevel 1 (
		echo %%i
		echo 0.0.0.0 %%i>>%hosts%
	)
)


echo disable telemetry 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f > nul

echo disable Windows CEIP
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f > nul

echo disable advertising ID
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f > nul

echo disable smartscreen
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f > nul
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f > nul

echo disable Cortana and web search 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f > nul

echo install chocolatey
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

echo SSH server
cinst -y -params '"/SSHServerFeature"' openssh

echo internet
cinst -y googlechrome firefox

echo virtualization
cinst -y virtualbox virtualbox.extensionpack

echo system tools
cinst -y sysinternals nirlauncher imdisk imdisk-toolkit 7zip hyper

echo networking
cinst -y fiddler4 winpcap wireshark

echo runtimes
cinst -y jdk8 dotnetcore dotnetcore-sdk dotnet4.7 netfx-4.7-devpack adobeair adobeshockwaveplayer silverlight

echo development
cinst -y visualstudiocode notepadplusplus dotpeek autohotkey autoit golang lua53 git jdk8 powershell nodejs nuget.commandline packer vagrant sqlite.shell sqlitebrowser

echo install Windows subsystem for Linux
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart"

echo restart Explorer... 
taskkill /f /im explorer.exe >nul & explorer.exe
schtasks /delete /tn "CreateExplorerShellUnelevatedTask" /f > nul

echo Done! You should reboot now!
pause