# SemiAutomaticScanner🌍

🤔It is designed to work on an Android phone with the Termux emulator and also on Linux systems tested on Ubuntu and ParrotOS. This attempts to automate the first steps of a recognition phase in a pentest.

  ⚡️ The steps that the script follows are:

<h3> 🔭Host Discovery </h3>
It tries to ping all ip / 24 addresses by sending only one packet with the -c 1 option and also uses nmap to sweep the ping.

<h3> 🔭 ARP for Discover Host </h3>
Host discovery with arp protocol (in progress)

<h3> 🔭 Search for open ports </h3>
Try to find an open port to perform service recognition.

<h3> 🔭 Os Recon </h3>
With the ping TTL field, try to find what OS the remote host is running (automated with python)

<h3> 🔭 Service Recon </h3>
With the nmap and -sV option it tries to guess what services are running on the remote open ports.

<h3> 🔭 Vuln Scan </h3>
Using the information from the service, the version tries to scan for vulnerabilities with nmap.
