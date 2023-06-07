# Windows Incidence Response PlayBook

This is just another free Windows Incidence Response Playbook.

### Network & Connections
It is important to analyze the network communication betweeen the server under investigation and the whole of the other network or internet. Doing this can point you to possible C&C servers or Data exfilteration.
<details><summary><b>Check for Suspicious Network Listeners</b></summary>
  
  ```sh
  netstat -naob | more
  ```
   Autorefresh every 5 secs
  ```sh
   netstat -naob 5
  ```
</details>
  
<details><summary><b>Examine built-in firewall</b></summary>
  
  ```sh
   netsh advfirewall show currentprofile
  ```
</details>

<details><summary><b>Check the DNS Cache</b></summary>
  
  ```sh
  Get-DnsClientCache | select Entry,Name, Status, TimeToLive
  ```
</details>

<details><summary><b>Current connection profile</b></summary>

  ```sh
  Get-NetConnectionProfile | select Name, InterfaceAlias, NetworkCategory, IPV4Connectivity, IPv6Connectivity
  ```
</details>

<details><summary><b>Check all network adapters</b></summary>

  ```sh
  Get-NetAdapter | select Name, InterfaceDescription, Status, MacAddress, LinkSpeed
  ```
</details>

<details><summary><b>Check ARP Details</b></summary>

  ```sh
  Get-NetNeighbor | select InterfaceAlias, IPAddress, LinkLayerAddress
  ```
</details>

<details><summary><b>Look out for Network connections and Port</b></summary>

  ```sh
  Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process";Expression={(Get-Process -Id   $_.OwningProcess).ProcessName}}
  ```
</details>

<details><summary><b>Check ARP Details</b></summary>

  ```sh
  Get-NetNeighbor | select InterfaceAlias, IPAddress, LinkLayerAddress
  ```
</details>

<details><summary><b>Get Firewall Information</b></summary>

  ```sh
  Get-NetFirewallRule | select-object Name, DisplayName, Description, Direction, Action, EdgeTraversalPolicy, Owner, EnforcementStatus
  ```
</details>

<details><summary><b>Get WiFi Names & Passwords</b></summary>

  ```sh
  netsh.exe wlan show profiles | Select-String "\:(.+)$" | %{$wlanname=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$wlanname" key=clear)}  | Select-String 'Key Content\W+\:(.+)$' | %{$wlanpass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$wlanname;PASSWORD=$wlanpass }}
  ```
</details>

<details><summary><b>Get Active Samba shares</b></summary>

  ```sh
  Get-SMBShare | select description, path, volume
  ```
</details>

<details><summary><b>Get Active Samba sessions</b></summary>

  ```sh
  Get-SMBSession -ea silentlycontinue
  ```
</details>

<details><summary><b>IP Routes to non local destination</b></summary>

  ```sh
  Get-NetRoute | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0,6) -Ne "fe80::") }
  ```
</details>

<details><summary><b>network adapter with Routes to non local destination</b></summary>

  ```sh
  Get-NetRoute | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0,6) -Ne "fe80::") }
  ```
</details>

<details><summary><b>IP routes with infinite valid lifetime</b></summary>

  ```sh
  Get-NetRoute | Where-Object -FilterScript { $_.ValidLifetime -Eq ([TimeSpan]::MaxValue) }
  ```
</details>

### Programs
There is need to inspect installed programs

<details><summary><b>Get Installed Programs</b></summary>

  ```sh
  Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage
  ```
</details>

<details><summary><b>Installed Programs from Registry</b></summary>

  ```sh
  Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
  ```
</details>

<details><summary><b>Installed Programs from Registry</b></summary>

  ```sh
  Get-MpComputerStatus
  ```
</details>

### Running processes & Task Schedules
Some active payloads show up as running processes, scheduled tasks can be used for persistence.

<details><summary><b>Get Processes</b></summary>

  ```sh
  Get-Process | Select Handles, StartTime, PM, VM, SI, id, ProcessName, Path, Product, FileVersion
  ```
</details>

<details><summary><b>Startup Items</b></summary>

  ```sh
  Get-WmiObject Win32_StartupCommand | select Command, User, Caption
  ```
</details>

<details><summary><b>Scheduled Tasks</b></summary>

  ```sh
  Get-ScheduledTask | ? State -eq running
  ```
</details>

<details><summary><b>Running Tasks & State</b></summary>

  ```sh
  Get-ScheduledTask | ? State -eq running | Get-ScheduledTaskInfo
  ```
</details>

<details><summary><b>Services</b></summary>

  ```sh
  Get-Service | Select-Object Name, DisplayName, Status, StartType
  ```
</details>

<details><summary><b>Services</b></summary>

  ```sh
  Get-Service | Select-Object Name, DisplayName, Status, StartType
  ```
</details>

### ASEPs
Auto starts within registry...etc

<details><summary><b>Run</b></summary>

  ```sh
  Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  ```
</details>

<details><summary><b>RunOnce</b></summary>

  ```sh
  Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
  ```
</details>

<details><summary><b>RunOnceEx</b></summary>

  ```sh
  Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
  ```
</details>

<details><summary><b>RunOnceEx</b></summary>

  ```sh
  Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
  ```
</details>

### Other Checks
These are uncategorized but are worth a look...etc

<details><summary><b>Logical Drives (current session)</b></summary>

  ```sh
  get-wmiobject win32_logicaldisk | select DeviceID, DriveType, FreeSpace, Size, VolumeName
  ```
</details>

<details><summary><b>USB Devices</b></summary>

  ```sh
  Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Enum\USB*\*\* | select FriendlyName, Driver, mfg, DeviceDesc
  ```
</details>

<details><summary><b>Connected & Previously Connected webcams</b></summary>

  ```sh
  Get-WmiObject Win32_PnPEntity | where {$_.caption -match 'camera'} -EA SilentlyContinue | where caption -match 'camera'
  ```
</details>

<details><summary><b>Currently connected PNP devices</b></summary>

  ```sh
  Get-PnpDevice -PresentOnly -class 'USB', 'DiskDrive', 'Mouse', 'Keyboard', 'Net', 'Image', 'Media', 'Monitor'
  ```
</details>

<details><summary><b>Currently & Previously connected Disk drives</b></summary>

  ```sh
  Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName
  ```
</details>

<details><summary><b>Shortcuts/Link files created in the last 180 days</b></summary>

  ```sh
  Get-WmiObject Win32_ShortcutFile | select Filename, Caption, @{NAME='CreationDate';Expression={$_.ConvertToDateTime($_.CreationDate)}}, @{Name='LastAccessed';Expression={$_.ConvertToDateTime($_.LastAccessed)}}, @{Name='LastModified';Expression={$_.ConvertToDateTime($_.LastModified)}}, Target | Where-Object {$_.LastModified -gt ((Get-Date).AddDays(-180)) } | sort LastModified -Descending
  ```
</details>

<details><summary><b>100 days of powershell history</b></summary>

  ```sh
  Get-History -count 500 | select id, commandline, startexecutiontime, endexecutiontime
  ```
</details>

<details><summary><b>Executables in the downloads folder</b></summary>

  ```sh
  Get-ChildItem C:\Users\*\Downloads\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'}
  ```
</details>

<details><summary><b>Obscure locations executables might be running from</b></summary>

  ```sh
  Get-ChildItem C:\Users\*\AppData\Local\Temp\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'}
  ```
  
  ```sh
  Get-ChildItem C:\Temp\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'}
  ```
  
  ```sh
  Get-ChildItem C:\PerfLogs\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'}
  ```
  
  ```sh
  Get-ChildItem C:\Users\*\Documents\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'}
  ```
</details>
