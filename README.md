# RedTeaming-Tools
This repository provides a comprehensive list of tools commonly used in red teaming operations, penetration testing, and offensive security exercises. The goal is to offer a centralized resource for security professionals looking to enhance their offensive capabilities

**Disclaimer**: These tools are intended exclusively for **legal and ethical security testing** on systems for which you have explicit, written authorization. Any misuse of these tools against unauthorized targets is strictly illegal, unethical, and can lead to severe legal consequences. Use responsibly.

## Table of Contents

*   [Information Gathering & Reconnaissance](#information-gathering--reconnaissance)
    *   [OSINT & Passive Recon](#osint--passive-recon)
    *   [Network Scanning & Discovery](#network-scanning--discovery)
    *   [Vulnerability Scanning & Analysis](#vulnerability-scanning--analysis)
    *   [Web Application Recon](#web-application-recon)
    *   [Cloud Recon & Enumeration](#cloud-recon--enumeration)
*   [Vulnerability Exploitation](#vulnerability-exploitation)
    *   [Exploitation Frameworks](#exploitation-frameworks)
    *   [Web Application Exploitation](#web-application-exploitation)
    *   [Network & Protocol Exploitation](#network--protocol-exploitation)
    *   [Client-Side & Social Engineering Exploitation](#client-side--social-engineering-exploitation)
    *   [Wireless & RF Exploitation](#wireless--rf-exploitation)
    *   [Container & Orchestration Exploitation](#container--orchestration-exploitation)
*   [Post-Exploitation](#post-exploitation)
    *   [Privilege Escalation](#privilege-escalation)
    *   [Credential Access & Dumping](#credential-access--dumping)
    *   [Persistence Mechanisms](#persistence-mechanisms)
    *   [Lateral Movement & Pivoting](#lateral-movement--pivoting)
    *   [Data Exfiltration & C2 Channels](#data-exfiltration--c2-channels)
    *   [Command & Control (C2) Frameworks](#command--control-c2-frameworks)
    *   [Evasion & Anti-Forensics](#evasion--anti-forensics)
*   [Payload Generation & Obfuscation](#payload-generation--obfuscation)
*   [Active Directory Specific Tools](#active-directory-specific-tools)
*   [Physical Security & Social Engineering](#physical-security--social-engineering)
*   [Hardware Hacking & IoT](#hardware-hacking--iot)
*   [Reverse Engineering & Malware Analysis](#reverse-engineering--malware-analysis)
*   [Utilities & Miscellaneous](#utilities--miscellaneous)
*   [Operating Systems & Distributions](#operating-systems--distributions)

---

## Information Gathering & Reconnaissance

### OSINT & Passive Recon

*   **[Maltego](https://www.maltego.com/downloads/)**: Link analysis and data mining.
*   **[theHarvester](https://github.com/laramies/theHarvester)**: Email, subdomain, and name harvesting.
*   **[Recon-ng](https://github.com/lanmaster53/recon-ng)**: Full-featured web reconnaissance framework.
*   **[SpiderFoot](https://github.com/smicallef/spiderfoot)**: Automated OSINT reconnaissance.
*   **[Shodan](https://www.shodan.io/)**: Search engine for internet-connected devices.
*   **[Censys](https://censys.io/)**: Internet-wide scan data platform.
*   **[Google Dorks / GHDB](https://www.exploit-db.com/google-hacking-database)**: Advanced Google search queries for sensitive information.
*   **[Have I Been Pwned?](https://haveibeenpwned.com/)**: Check for compromised email accounts.
*   **[Wayback Machine / Archive.org](https://archive.org/web/)**: Historical versions of websites.
*   **[ExifTool](https://exiftool.org/)**: Read, write, and edit metadata.
*   **[Social Mapper](https://github.com/greenplum-db/social_mapper)**: Find social media profiles by name or email.
*   **[Hunter.io](https://hunter.io/)**: Find email addresses associated with a domain.
*   **[Twint](https://github.com/twintproject/twint)**: Advanced Twitter scraping tool. (Note: Project status can fluctuate, check repo for latest)
*   **[DeHashed](https://dehashed.com/)**: Public record search engine.
*   **[Buster](https://github.com/JonnyBanana/Buster)**: Email address validation and related social accounts.
*   **[Photon](https://github.com/s0md3v/Photon)**: Incredibly fast crawler for OSINT.
*   **[GoWitness](https://github.com/sensepost/gowitness)**: Screenshot web interfaces for various web servers.
*   **[OSRFramework](https://github.com/PabloSancho/OSRFramework)**: Collection of tools for performing OSINT queries.
*   **[Dorkbot](https://github.com/utkusen/dorkbot)**: Google dorking automation.
*   **[FOCA (Fingerprinting Organizations with Collected Archives)](https://www.elevenpaths.com/labstools/foca/)**: Metadata extraction and analysis.

### Network Scanning & Discovery

*   **[Nmap](https://nmap.org/)**: Industry-standard network scanner.
*   **[Masscan](https://github.com/robertdavidgraham/masscan)**: High-performance port scanner.
*   **[UnicornScan](https://www.unicornscan.org/)**: Asynchronous stateless TCP/IP port scanner.
*   **[Netcat (nc)](http://netcat.sourceforge.net/)**: Network utility for reading/writing across network connections.
*   **[Hping3](http://www.hping.org/hping3.html)**: Network packet crafter and analyzer.
*   **[Wireshark](https://www.wireshark.org/)**: Network protocol analyzer.
*   **[Tcpdump](https://www.tcpdump.org/)**: Packet sniffer.
*   **[Fping](https://fping.org/)**: Parallelized ping utility.
*   **[RustScan](https://github.com/RustScan/RustScan)**: Modern, fast port scanner.
*   **[Angry IP Scanner](https://angryip.org/)**: Fast and friendly network scanner.
*   **[KFSensor](https://www.keyfocus.net/kfsensor/)**: Windows-based honeypot.
*   **[Zmap](https://github.com/zmap/zmap)**: Fast single packet network scanner.
*   **[Naabu](https://github.com/projectdiscovery/naabu)**: Fast port scanner with a focus on reliability and simplicity.

### Vulnerability Scanning & Analysis

*   **[Nessus](https://www.tenable.com/products/nessus)**: Comprehensive vulnerability scanner (commercial).
*   **[OpenVAS / GVM](https://www.greenbone.net/en/community-edition/)**: Open-source vulnerability management solution.
*   **[Nikto](https://github.com/sullo/nikto)**: Web server scanner.
*   **[Arachni](http://arachni-scanner.com/)**: Web application security scanner.
*   **[Wapiti](https://wapiti.sourceforge.io/)**: Web application vulnerability scanner.
*   **[Nuclei](https://github.com/projectdiscovery/nuclei)**: Fast and custom logic-based vulnerability scanner.
*   **[Vulmap](https://github.com/vulmap/vulmap)**: Local vulnerability scanner for Linux.
*   **[Lynis](https://github.com/CISOfy/lynis)**: Security auditing tool for Linux, macOS, and UNIX-based systems.
*   **[Tenable.io / Tenable.sc](https://www.tenable.com/)**: Enterprise vulnerability management platforms (commercial).
*   **[Qualys](https://www.qualys.com/)**: Cloud-based security and compliance solutions (commercial).

### Web Application Recon

*   **[Sublist3r](https://github.com/aboul3la/Sublist3r)**: Fast subdomain enumeration tool.
*   **[Amass](https://github.com/owasp-amass/amass)**: Go-based network mapping and asset discovery tool.
*   **[Assetfinder](https://github.com/tomnomnom/assetfinder)**: Find domains and subdomains related to a given domain.
*   **[Gobuster](https://github.com/OJ/gobuster)**: Directory/file, DNS, and VHost brute-forcing tool.
*   **[Findomain](https://github.com/Findomain/Findomain)**: Subdomain enumeration via various sources.
*   **[Knockpy](https://github.com/guelfoweb/knock)**: Python tool to enumerate subdomains.
*   **[OneForAll](https://github.com/shmilylty/OneForAll)**: Powerful subdomain enumeration tool.
*   **[Dirb](http://dirb.sourceforge.net/)**: Web content scanner.
*   **[Dirbuster](https://sourceforge.net/projects/dirbuster/)**: Brute-force directories and file names on web servers.
*   **[FFuF](https://github.com/ffuf/ffuf)**: Fast web fuzzer designed for speed and flexibility.
*   **[Wfuzz](https://github.com/xmendez/wfuzz)**: Web application fuzzer.
*   **[Feroxbuster](https://github.com/epi052/feroxbuster)**: Fast, simple, recursive content discovery tool.
*   **[DotDotPwn](https://github.com/wireghoul/dotdotpwn)**: Directory traversal fuzzer.
*   **[WhatWeb](https://github.com/urbanadventurer/WhatWeb)**: Website fingerprinter.
*   **[Wappalyzer](https://www.wappalyzer.com/)**: Identify technologies on websites.
*   **[Eyewitness](https://github.com/FortyNorthSecurity/EyeWitness)**: Grabs screenshots of websites, RDP, and VNC services.
*   **[Gitleaks](https://github.com/zricethezav/gitleaks)**: Scan git repos for secrets.
*   **[Subfinder](https://github.com/projectdiscovery/subfinder)**: Fast passive subdomain enumeration.
*   **[ParamSpider](https://github.com/devanshbatham/ParamSpider)**: Find parameters with arbitrary values.
*   **[Waybackurls](https://github.com/tomnomnom/waybackurls)**: Fetch known URLs from the Wayback Machine.
*   **[Gau](https://github.com/lc/gau)**: Fetch known URLs from AlienVault's Open Threat Exchange, Wayback Machine, and Common Crawl.
*   **[Katana](https://github.com/projectdiscovery/katana)**: A next-generation crawling and spidering framework.

### Cloud Recon & Enumeration

*   **[CloudMapper](https://github.com/duo-labs/cloudmapper)**: Analyze AWS environments.
*   **[Pacu](https://github.com/RhinoSecurityLabs/pacu)**: AWS exploitation framework.
*   **[ScoutSuite](https://github.com/nccgroup/ScoutSuite)**: Multi-cloud security auditing tool.
*   **[Prowler](https://github.com/prowler-cloud/prowler)**: AWS, Azure, GCP security best practices assessment.
*   **[Azucar](https://github.com/nccgroup/azucar)**: Azure security auditing.
*   **[Cloud-nuke](https://github.com/gruntwork-io/cloud-nuke)**: Permanently delete resources from an AWS account.
*   **[CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)**: "Vulnerable by design" AWS environment.
*   **[AWS CLI](https://aws.amazon.com/cli/)**: Official command-line interface for AWS.
*   **[Azure CLI](https://learn.microsoft.com/en-us/cli/azure/what-is-azure-cli)**: Official command-line interface for Azure.
*   **[GCP SDK](https://cloud.google.com/sdk)**: Official command-line interface for GCP.
*   **[Skyhawk](https://github.com/sudo-cyber/skyhawk)**: Cloud-native application security testing.
*   **[PMapper](https://github.com/nccgroup/pmapper)**: Policy Mapper for AWS Identity and Access Management (IAM).
*   **[BadSecrets](https://github.com/trufflesecurity/badsecrets)**: Scan for common secret patterns in cloud configurations.

---

## Vulnerability Exploitation

### Exploitation Frameworks

*   **[Metasploit Framework](https://www.metasploit.com/downloads/)**: The most widely used exploitation framework.
*   **[Empire / Starkiller](https://github.com/BC-SECURITY/Starkiller)**: Post-exploitation framework and C2 (Python/PowerShell).
*   **[Cobalt Strike](https://www.cobaltstrike.com/)**: Advanced threat simulation platform (commercial).
*   **[PoshC2](https://github.com/PoshC2Project/PoshC2)**: PowerShell and Python C2 framework.
*   **[Mythic](https://github.com/MythicAgents/Mythic)**: Open-source C2 framework.
*   **[Sliver](https://github.com/BishopFox/sliver)**: Adversary Emulation/Red Team Framework.
*   **[Havoc](https://github.com/HavocFramework/Havoc)**: Post-exploitation C2 framework.
*   **[Covenant](https://github.com/cobbr/Covenant)**: .NET C2 framework.
*   **[Merlin](https://github.com/Ne0nd0g/merlin)**: Cross-platform HTTP/2 C2.
*   **[Faction](https://github.com/FactionC2/Faction)**: Modern C2 framework.

### Web Application Exploitation

*   **[Burp Suite](https://portswigger.net/burp)**: Leading web vulnerability scanner and proxy (community & professional).
*   **[OWASP ZAP](https://www.zaproxy.org/)**: Open-source web application security scanner.
*   **[SQLMap](https://github.com/sqlmapproject/sqlmap)**: Automatic SQL injection and database takeover tool.
*   **[XSSer](https://github.com/epsylon/xsser)**: Cross-site scripting (XSS) exploitation tool.
*   **[Commix](https://github.com/commixproject/commix)**: Command injection exploitation tool.
*   **[Wpscan](https://wpscan.com/)**: WordPress security scanner.
*   **[Joomscan](https://github.com/rezadk/joomscan)**: Joomla! vulnerability scanner.
*   **[Droopescan](https://github.com/droope/droopescan)**: CMS scanner for Drupal, Joomla, Moodle, Silverstripe, Wordpress.
*   **[Dalfox](https://github.com/hahwul/dalfox)**: XSS scanning tool.
*   **[NoSQLMap](https://github.com/codingo/NoSQLMap)**: Automated NoSQL injection and database exploitation tool.
*   **[Dirbuster](https://sourceforge.net/projects/dirbuster/)**: Brute-force directories and file names on web servers.
*   **[DotDotPwn](https://github.com/wireghoul/dotdotpwn)**: Directory traversal fuzzer.
*   **[XSStrike](https://github.com/s0md3v/XSStrike)**: Advanced XSS detection suite.
*   **[ParamScanner](https://github.com/Raghavd3v/ParamScanner)**: Finds hidden, unlinked, and unreferenced parameters.
*   **[Interactsh](https://github.com/projectdiscovery/interactsh)**: An open-source, free server for out-of-band data interaction.

### Network & Protocol Exploitation

*   **[Responder](https://github.com/lgandx/Responder)**: LLMNR, NBT-NS, and mDNS poisoner.
*   **[Bettercap](https://github.com/bettercap/bettercap)**: Framework for Man-in-the-Middle attacks.
*   **[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)**: Post-exploitation tool for Active Directory.
*   **[Impacket](https://github.com/SecureAuthCorp/impacket)**: Collection of Python classes for network protocols.
*   **[Ettercap](https://github.com/Ettercap/ettercap)**: Comprehensive suite for MITM attacks.
*   **[MITMf](https://github.com/byt3bl33d3r/MITMf)**: Man-In-The-Middle Framework.
*   **[ARP-Spoof](https://github.com/eunyoung14/ARP-Spoofing-Tool)**: For ARP spoofing attacks (many scripts exist, linking an example).
*   **[Nmap Scripting Engine (NSE)](https://nmap.org/book/nse.html)**: Nmap scripts for various network vulns.
*   **[Metasploit Framework](https://www.metasploit.com/downloads/)**: Extensive modules for network service exploitation.
*   **[SMBExec](https://github.com/brav0hax/smbexec)**: Execute commands over SMB.
*   **[Evil-WinRM](https://github.com/Hackplayers/evil-winrm)**: WinRM shell for lateral movement.
*   **[Cain & Abel](https://www.oxid.it/cain.html)**: Password recovery, network sniffing, and more (Windows, older tool).
*   **[Dnsspoof](https://www.tcpdump.org/other/dnsspoof.html)**: For DNS spoofing attacks.
*   **[Scapy](https://scapy.net/)**: Python-based packet manipulation program.
*   **[PowerLURK](https://github.com/Evengard/PowerLURK)**: SMB Relay tool (focus on newer versions).

### Client-Side & Social Engineering Exploitation

*   **[Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit)**: Spear-phishing, credential harvesting, etc.
*   **[Browser Exploitation Framework (BeEF)](https://github.com/beefproject/beef)**: Hook browsers and launch client-side attacks.
*   **[EvilGinx2](https://github.com/kgretzky/evilginx2)**: Advanced phishing framework.
*   **[King Phisher](https://github.com/securestate/king-phisher)**: Phishing campaign toolkit.
*   **[PhishMe / Cofense PhishMe](https://cofense.com/product-services/cofense-phishme/)**: (Commercial) Phishing simulation platform.
*   **[GoPhish](https://github.com/gophish/gophish)**: Open-source phishing framework.
*   **[CredSniper](https://github.com/disenchant/CredSniper)**: Web-based credential phishing tool.
*   **[Modlishka](https://github.com/drk1wi/Modlishka)**: Flexible and powerful reverse proxy for phishing.
*   **[Browser-Pwn](https://github.com/s0md3v/Browser-Pwn)**: Tool to find browser exploits.

### Wireless & RF Exploitation

*   **[Aircrack-ng](https://www.aircrack-ng.org/)**: Suite of tools for auditing wireless networks.
*   **[Kismet](https://www.kismetwireless.net/)**: Wireless network detector, sniffer, and IDS.
*   **[Wifite2](https://github.com/derv82/wifite2)**: Automated wireless attack tool.
*   **[Fluxion](https://github.com/FluxionNetwork/fluxion)**: Social engineering WPA/WPA2 attack.
*   **[EAPHammer](https://github.com/s0lst1c3/eaphammer)**: Tool for WPA/WPA2-Enterprise attacks.
*   **[Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon)**: Multi-use bash script for wireless auditing.
*   **[Mana Toolkit](https://github.com/sensepost/mana)**: Rogue AP setup, SSL stripping, etc.
*   **[Pwnagotchi](https://pwnagotchi.ai/)**: AI-powered Wi-Fi cracking device.
*   **[WiFi Pineapple](https://hak5.org/products/wifi-pineapple)**: Wireless auditing and MITM platform.
*   **[Infernal-Twin](https://github.com/entropy1337/Infernal-Twin)**: Automated wireless hacking.

### Container & Orchestration Exploitation

*   **[Docker-Bench-Security](https://github.com/docker/docker-bench-security)**: CIS benchmark for Docker.
*   **[Kube-Hunter](https://github.com/aquasecurity/kube-hunter)**: Hunt for security weaknesses in Kubernetes clusters.
*   **[Kubeaudit](https://github.com/Shopify/kubeaudit)**: Audit Kubernetes clusters for various security concerns.
*   **[Trivy](https://github.com/aquasecurity/trivy)**: Comprehensive vulnerability scanner for containers.
*   **[Hadolint](https://github.com/hadolint/hadolint)**: Dockerfile linter.
*   **[Clair](https://github.com/quay/clair)**: Open Source Vulnerability Analysis for Containers.
*   **[Anchore Engine](https://anchore.com/opensource/)**: Container inspection and policy enforcement.
*   **[CDK (Cloud Native Hacking Toolkit)](https://github.com/cdk-team/CDK)**: CLI tool to perform security tests on cloud native environment.
*   **[Kube-bench](https://github.com/aquasecurity/kube-bench)**: Checks whether Kubernetes is deployed securely.
*   **[Deepfence ThreatMapper](https://github.com/deepfence/ThreatMapper)**: Discover, scan, and rank vulnerabilities in running containers, images, and hosts.
*   **[Aqua Security](https://www.aquasec.com/)**: (Commercial) Container security platform.

---

## Post-Exploitation

### Privilege Escalation

*   **[LinEnum](https://github.com/rebootuser/LinEnum)**: Script for Linux privilege escalation enumeration.
*   **[Privilege Escalation Awesome Scripts (PEASS) / LinPEAS / WinPEAS](https://github.com/carlospolop/PEASS-ng)**: Comprehensive local enumeration scripts.
*   **[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/PrivEsc/PowerUp.ps1)**: PowerShell script for Windows privilege escalation checks.
*   **[Watson](https://github.com/rasta-mouse/Watson)**: .NET tool for Windows privilege escalation checks.
*   **[GTFOBins](https://gtfobins.github.io/)**: Curated list of Unix executables that can be used to bypass local security restrictions.
*   **[LOLBAS (Living Off The Land Binaries And Scripts)](https://lolbas-project.github.io/)**: Windows equivalent of GTFOBins.
*   **[Seatbelt](https://github.com/GhostPack/Seatbelt)**: C# project that performs a number of security-oriented checks.
*   **[SharpUp](https://github.com/GhostPack/SharpUp)**: C# tool for enumerating common Windows privilege escalation vectors.
*   **[Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)**: Suggests potential Linux kernel exploits.
*   **[Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)**: Suggests potential Windows exploits.
*   **[Metasploit `getsystem` module](https://docs.metasploit.com/docs/using-metasploit/basic-vulnerability-exploitation/privilege-escalation.html)**: Built-in Metasploit privilege escalation.
*   **[Kernel Exploits](https://www.exploit-db.com/local-exploits)**: Various public exploits for OS kernels (link to Exploit-DB for examples).

### Credential Access & Dumping

*   **[Mimikatz](https://github.com/gentilkiwi/mimikatz)**: Extract passwords, hash, PINs, and Kerberos tickets from memory.
*   **[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)**: (Also for dumping credentials from AD)
*   **[Responder](https://github.com/lgandx/Responder)**: (Also for NTLMv1/v2 hash capturing)
*   **[Hashcat](https://hashcat.net/hashcat/)**: Advanced password recovery utility.
*   **[John the Ripper](https://www.openwall.com/john/)**: Fast password cracker.
*   **[LaZagne](https://github.com/AlessandroZ/LaZagne)**: Password recovery for many applications.
*   **[Pypykatz](https://github.com/skelsec/pypykatz)**: Python implementation of Mimikatz.
*   **[Gpp-Decrypt](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)**: Decrypt Group Policy Preferences passwords (linking to relevant script).
*   **[BloodHound](https://github.com/BloodHoundAD/BloodHound)**: Graph theory for AD relationships, pathfinding to domain admin.
*   **[Dumping LSASS](https://adsecurity.org/?p=1522)**: Techniques for extracting credentials from LSASS process (linking to a technical article).
*   **[SharpDump](https://github.com/GhostPack/SharpDump)**: C# tool for dumping credentials.
*   **[Rubeus](https://github.com/GhostPack/Rubeus)**: Kerberos abuse toolkit.
*   **[KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)**: Automated Kerberos Relay attack.
*   **[Certify](https://github.com/GhostPack/Certify)**: Active Directory Certificate Services (AD CS) abuse.
*   **[Ladon](https://github.com/schoentoon/ladon)**: Windows Active Directory penetration testing tool.

### Persistence Mechanisms

*   **[PowerShell Empire](https://github.com/BC-SECURITY/Empire)**: (Built-in persistence modules)
*   **[Cobalt Strike](https://www.cobaltstrike.com/)**: (Built-in persistence modules)
*   **[Metasploit](https://www.metasploit.com/)**: (Various persistence modules)
*   **[Scheduled Tasks](https://attack.mitre.org/techniques/T1053/005/)**: Using native OS features for persistence (linking to MITRE ATT&CK).
*   **[Startup Folders](https://attack.mitre.org/techniques/T1547/001/)**: Placing executables in startup locations (linking to MITRE ATT&CK).
*   **[Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)**: Modifying registry for automatic execution (linking to MITRE ATT&CK).
*   **[WMI Event Subscriptions](https://attack.mitre.org/techniques/T1546/003/)**: Windows Management Instrumentation for persistence (linking to MITRE ATT&CK).
*   **[DLL Sideloading](https://attack.mitre.org/techniques/T1574/002/)**: Placing malicious DLLs in legitimate application paths (linking to MITRE ATT&CK).
*   **[Netsh Persistence](https://attack.mitre.org/techniques/T1546/007/)**: Using netsh for firewall rules or helper DLLs (linking to MITRE ATT&CK).
*   **[Sticky Keys / Utilman Backdoor](https://attack.mitre.org/techniques/T1546/008/)**: Accessibility features for backdoor access (linking to MITRE ATT&CK).

### Lateral Movement & Pivoting

*   **[PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)**: Execute commands on remote Windows systems.
*   **[WMI](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)**: Windows Management Instrumentation for remote execution (linking to Microsoft documentation).
*   **[Remote Desktop Protocol (RDP)](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-clients)**: Using stolen credentials (linking to Microsoft documentation).
*   **[SSH](https://www.openssh.com/)**: Using stolen credentials (linking to OpenSSH).
*   **[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)**: (Also for lateral movement)
*   **[Impacket](https://github.com/SecureAuthCorp/impacket)**: (Various tools for lateral movement via SMB, WMI, etc.)
*   **[Evil-WinRM](https://github.com/Hackplayers/evil-winrm)**: WinRM shell for lateral movement.
*   **[wmiexec.py (Impacket)](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)**: WMI command execution.
*   **[smbexec.py (Impacket)](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)**: SMB command execution.
*   **[DCOM abuse](https://attack.mitre.org/techniques/T1021/003/)**: Distributed Component Object Model (linking to MITRE ATT&CK).
*   **[Pass-the-Hash / Pass-the-Ticket](https://attack.mitre.org/techniques/T1550/002/)**: Using stolen hashes/tickets (linking to MITRE ATT&CK).
*   **[Chisel](https://github.com/jpillora/chisel)**: Fast TCP/UDP tunnel over HTTP.
*   **[ligolo-ng](https://github.com/nicocha30/ligolo-ng)**: Advanced reverse tunneling tool.
*   **[Plink (PuTTY Link)](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)**: Command-line connection tool for SSH/Telnet.
*   **[SharpSocks](https://github.com/mdsecactivebreach/SharpSocks)**: C# port of the SOCKS5 proxy.
*   **[PivotSuite](https://github.com/optiv/PivotSuite)**: Pivot for HTTP traffic.

### Data Exfiltration & C2 Channels

*   **[Dnscat2](https://github.com/lukebaggett/dnscat2-powershell)**: C2 over DNS (linking to Powershell version).
*   **[Iodine](https://github.com/yarrick/iodine)**: Tunnel IPv4 over DNS.
*   **[PoshC2](https://github.com/PoshC2Project/PoshC2)**: (Built-in exfiltration capabilities)
*   **[Cobalt Strike](https://www.cobaltstrike.com/)**: (Built-in exfiltration capabilities)
*   **[Metasploit](https://www.metasploit.com/)**: (Various exfiltration modules)
*   **[Nishang](https://github.com/samratashok/nishang)**: Collection of PowerShell scripts, including exfiltration.
*   **[File Transfer via HTTP/HTTPS/FTP](https://attack.mitre.org/techniques/T1048/)**: Using native OS utilities (linking to MITRE ATT&CK).
*   **[Cloud Storage APIs](https://attack.mitre.org/techniques/T1537/)**: Abusing cloud storage services (linking to MITRE ATT&CK).
*   **[Stenography Tools](https://github.com/Ciphey/stegcloak)**: Hiding data within other files (linking to an example).
*   **[Exfil.py](https://github.com/ytisf/PyExfil)**: Tool for exfiltrating data over various protocols (linking to an example).
*   **[nc (Netcat)](http://netcat.sourceforge.net/)**: Simple file transfer.
*   **[Inveigh](https://github.com/Kevin-Robertson/Inveigh)**: PowerShell ADIDNS/LLMNR/NBNS/mDNS/LLMNR/mDNS/DHCPv6/HTTP/HTTPS/SMB/RDP/FTP/POP3/SMTP/SNMP/NTLMv1/NTLMv2/Kerberos Responder.
*   **[SilverC2](https://github.com/BishopFox/sliver)**: (Part of Sliver framework) for C2.
*   **[HTTPort](https://github.com/caffix/http-tunnel)**: HTTP tunneling for arbitrary TCP connections.

### Command & Control (C2) Frameworks

*   **[Cobalt Strike](https://www.cobaltstrike.com/)**: (Mentioned before, but critical for C2)
*   **[Metasploit Framework](https://www.metasploit.com/downloads/)**: (Meterpreter and other payloads)
*   **
