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
