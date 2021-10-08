# SemiAutomaticScanner🌍

🤔It is designed to work on an android phone with the Termux emulator and also in Linux systems tested in Ubuntu and ParrotOS. This tries to automate the first steps of a recon phase in a pentest

 ⚡️The step that script follow are:

🔭<h3> Host Discovery </h3> 
It try to ping all the ip addres /24 sending only a packet with -c 1 option also use nmap to sweep ping.

🔭<h3> ARP for Discover Host </h3>
Host discovery with arp protocol(in process)

🔭<h3> Scan for Open Ports</h3>
Try to find open port to make recon of the services.

🔭<h3> Os Recon</h3>
With the TTL field of ping tries to find what OS is running the remote host (automated with python)

🔭<h3> Service Recon</h3>
With nmap and -sV option tries to guess waht services are running in the remote open ports.

🔭<h3> Vuln Scan with Nmap</h3>
With the information of the service vercion tries to scan for vulnerabilities.
