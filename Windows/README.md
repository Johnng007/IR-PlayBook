# Windows Incidence Response PlayBook

This is just another free Windows Incidence Response Playbook.

### Network
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
  Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
  ```
</details>

<details><summary><b>Check ARP Details</b></summary>
  ```sh
  Get-NetNeighbor | select InterfaceAlias, IPAddress, LinkLayerAddress
  ```
</details>
