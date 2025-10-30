# WhiteMonkey RedTeaming Tools*

[![Stars](https://img.shields.io/github/stars/A-poc/RedTeam-Tools?style=social)](https://github.com/A-poc/RedTeam-Tools)  
A comprehensive, curated collection of **over 350** Red Team tools, techniques, and resources. Aggregated and expanded from top GitHub repos like [A-poc/RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools), [infosecn1nja/Red-Teaming-Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit), [yeyintminthuhtut/Awesome-Red-Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming), and more. All hyperlinks direct to reputable sources (mostly GitHub). Short descriptions. Categorized by MITRE ATT&CK for easy navigation.

## 📋 **Table of Contents**
- [Reconnaissance](#reconnaissance)
- [Resource Development](#resource-development)
- [Initial Access](#initial-access)
- [Execution](#execution)
- [Persistence](#persistence)
- [Privilege Escalation](#privilege-escalation)
- [Defense Evasion](#defense-evasion)
- [Credential Access](#credential-access)
- [Discovery](#discovery)
- [Lateral Movement](#lateral-movement)
- [Collection](#collection)
- [Command & Control](#command--control)
- [Exfiltration](#exfiltration)
- [Impact](#impact)

---

## 🔍 **Reconnaissance**

| Tool | Description |
|------|-------------|
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | OSINT automation tool integrating 100+ data sources. |
| [reconFTW](https://github.com/six2dez/reconftw) | Automates full recon: subdomains, vulns, info gathering. |
| [RustScan](https://github.com/RustScan/RustScan) | Ultra-fast port scanner with Nmap integration. |
| [Amass](https://github.com/OWASP/Amass) | Attack surface mapping & asset discovery. |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Fast vuln scanner using YAML templates. |
| [gobuster](https://github.com/OJ/gobuster) | Brute force directories/files on web servers. |
| [feroxbuster](https://github.com/epi052/feroxbuster) | Fast content discovery (forced browsing). |
| [dnsrecon](https://github.com/darkoperator/dnsrecon) | DNS enumeration (MX, SOA, NS, etc.). |
| [S3Scanner](https://github.com/sa7mon/S3Scanner) | Scans for open S3 buckets & dumps contents. |
| [cloud_enum](https://github.com/initstring/cloud_enum) | Multi-cloud OSINT for AWS/Azure/GCP. |
| [Recon-ng](https://github.com/lanmaster53/recon-ng) | Web-based recon framework. |
| [subzy](https://github.com/PentestPad/subzy) | Subdomain takeover checker. |
| [certSniff](https://github.com/A-poc/certSniff) | Watches CT logs for keywords. |
| [Gowitness](https://github.com/sensepost/gowitness) | Screenshot web interfaces with report viewer. |
| [Metabigor](https://github.com/j3ssie/metabigor) | OSINT without API keys. |
| [Gitrob](https://github.com/michenriksen/gitrob) | Finds sensitive files in GitHub repos. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Scans git for secrets/high-entropy strings. |
| [gitleaks](https://github.com/zricethezav/gitleaks) | Detects secrets in git repos. |
| [BBOT](https://github.com/blacklanternsecurity/bbot) | Recursive internet scanner. |
| [dnscan](https://github.com/rbsec/dnscan) | Wordlist-based DNS subdomain scanner. |
| [AORT](https://github.com/D3Ext/AORT) | Subdomains, DNS, WAF, WHOIS, ports. |
| [spoofcheck](https://github.com/BishopFox/spoofcheck) | Checks domain spoofing via SPF/DMARC. |
| [WitnessMe](https://github.com/byt3bl33d3r/WitnessMe) | Web inventory with screenshots. |
| [buster](https://github.com/sham00n/buster) | Advanced email reconnaissance tool. |
| [linkedin2username](https://github.com/initstring/linkedin2username) | Generates username lists from LinkedIn companies. |
| [pagodo](https://github.com/opsdisk/pagodo) | Automates Google Hacking Database scraping. |
| [AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper) | Automates reconnaissance process. |
| [LinkedInt](https://github.com/vysecurity/LinkedInt) | LinkedIn recon tool. |
| [Gato](https://github.com/praetorian-inc/gato) | Enumerates and attacks GitHub pipelines. |
| [Aquatone](https://github.com/michenriksen/aquatone) | Visual inspection of websites across ports. |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Fast passive subdomain enumeration. |
| [Assetfinder](https://github.com/tomnomnom/assetfinder) | Finds domains and subdomains from sources. |
| [Shodan](https://www.shodan.io/) | Searches for internet-connected devices. |
| [Censys](https://censys.io/) | Discovers internet assets via search engine. |
| [Masscan](https://github.com/robertdavidgraham/masscan) | Fast TCP port scanner. |
| [ZMap](https://github.com/zmap/zmap) | Internet-wide network scanner. |
| [Nmap](https://github.com/nmap/nmap) | Network discovery and security auditing. |
| [Fierce](https://github.com/mschwager/fierce) | DNS reconnaissance tool. |
| [Dnsenum](https://github.com/fwaeytens/dnsenum) | Enumerates DNS information. |
| [Knock](https://github.com/guelfoweb/knock) | Subdomain scan tool. |
| [Sublist3r](https://github.com/aboul3la/Sublist3r) | Fast subdomain enumeration. |
| [Crt.sh](https://crt.sh/) | Certificate transparency search. |
| [Censys-python](https://github.com/censys/censys-python) | Python wrapper for Censys APIs. |
| [TheHarvester](https://github.com/laramies/theHarvester) | OSINT for emails and subdomains. |
| [Maltego](https://www.maltego.com/) | Link analysis for OSINT. |
| [ReconDog](https://github.com/s0md3v/ReconDog) | Reconnaissance Swiss Army Knife. |
| [Photon](https://github.com/s0md3v/Photon) | Incredibly fast crawler for OSINT. |
| [Raccoon](https://github.com/evyatarmeged/Raccoon) | Offensive security recon tool. |
| [Git-dumper](https://github.com/internetwache/GitTools) | Dumps Git repositories. |
| [GitGraber](https://github.com/hisxo/gitGraber) | Monitors GitHub for secrets. |
| [Shhgit](https://github.com/eth0izzle/shhgit) | Finds secrets in GitHub code. |
| [Git-all-secrets](https://github.com/anshumanbh/git-all-secrets) | Scans for secrets in repos. |
| [Git-secrets](https://github.com/awslabs/git-secrets) | Prevents committing secrets. |
| [Dorks-collections-list](https://github.com/cipher387/Dorks-collections-list) | Google dorks collections. |
| [Osintgram](https://github.com/Datalux/Osintgram) | Instagram OSINT tool. |
| [Sherlock](https://github.com/sherlock-project/sherlock) | Hunts usernames across sites. |
| [Sn0int](https://github.com/kpcyrd/sn0int) | Semi-automatic OSINT framework. |
| [OSINT Framework](https://osintframework.com/) | OSINT tools collection. |
| [IntelOwl](https://github.com/intelowlproject/IntelOwl) | OSINT analyzer. |
| [Harpoon](https://github.com/Te-k/harpoon) | CLI for OSINT. |
| [Datasploit](https://github.com/DataSploit/datasploit) | OSINT framework. |
| [ReconSpider](https://github.com/bhavsec/reconspider) | Advanced OSINT framework. |

*(60+ tools)*

---

## 🛠️ **Resource Development**

| Tool | Description |
|------|-------------|
| [Msfvenom](https://www.offsec.com/metasploit-unleashed/msfvenom/) | Creates obfuscated payloads for AV bypass. |
| [Shellter](https://www.shellterproject.com/) | Dynamic shellcode injector for PE files. |
| [Donut](https://github.com/TheWover/donut) | In-memory execution of EXE/DLL/.NET. |
| [PEzor](https://github.com/phra/PEzor) | Open-source PE packer. |
| [GadgetToJScript](https://github.com/med0x2e/GadgetToJScript) | Generates .NET gadgets for JS/VBS. |
| [Ivy](https://github.com/optiv/Ivy) | VBA macro payload framework. |
| [macro_pack](https://github.com/sevagas/macro_pack) | Obfuscates Office docs/VBS for pentests. |
| [xlsGen](https://github.com/aaaddress1/xlsGen) | Embeds macros in Excel BIFF8. |
| [EvilClippy](https://github.com/outflanknl/EvilClippy) | Creates malicious Office docs. |
| [OfficePurge](https://github.com/fireeye/OfficePurge) | Purges VBA P-code from Office docs. |
| [remoteinjector](https://github.com/JohnWoodman/remoteinjector) | Injects remote Word template into doc. |
| [Chimera](https://github.com/tokyoneon/chimera) | PowerShell obfuscation for AV bypass. |
| [Freeze](https://github.com/optiv/Freeze) | Bypasses EDRs with suspended processes. |
| [WordSteal](https://github.com/0x09AL/WordSteal) | Captures NTLM hashes via remote image in Word. |
| [NTInternals](http://undocumented.ntinternals.net/) | Undocumented Windows internals info. |
| [Kernel Callback Functions](https://codemachine.com/articles/kernel_callback_functions.html) | Lists Windows kernel callback APIs. |
| [OffensiveVBA](https://github.com/S3cur3Th1sSh1t/OffensiveVBA) | Offensive VBA techniques and scripts. |
| [WSH](https://docs.microsoft.com/en-us/windows/win32/wsh/windows-script-host) | Windows Script Host for payloads. |
| [HTA](https://docs.microsoft.com/en-us/previous-versions//ms536496(v=vs.85)) | HTML Application for payloads. |
| [VBA](https://docs.microsoft.com/en-us/office/vba/api/overview/) | Visual Basic for Applications macros. |
| [Mystikal](https://github.com/D00MFist/Mystikal) | macOS initial access payload generator. |
| [charlotte](https://github.com/9emin1/charlotte) | Undetected C++ shellcode launcher. |
| [InvisibilityCloak](https://github.com/xforcered/InvisibilityCloak) | Obfuscation for C# post-exploitation tools. |
| [Dendrobate](https://github.com/FuzzySecurity/Dendrobate) | Hooks unmanaged code via .NET. |
| [darkarmour](https://github.com/bats3c/darkarmour) | Windows AV evasion toolkit. |
| [InlineWhispers](https://github.com/outflanknl/InlineWhispers) | Direct syscalls in Cobalt Strike BOFs. |
| [SharpSploit](https://github.com/cobbr/SharpSploit) | .NET post-exploitation library. |
| [MSBuildAPICaller](https://github.com/rvrsh3ll/MSBuildAPICaller) | Executes MSBuild without exe. |
| [inceptor](https://github.com/klezVirus/inceptor) | Template-driven AV/EDR evasion framework. |
| [mortar](https://github.com/0xsp-SRD/mortar) | Evasion for AV/EDR/XDR. |
| [ProtectMyTooling](https://github.com/mgeeky/ProtectMyTooling) | Multi-packer for red team weaponry. |
| [Shhhloader](https://github.com/icyguider/Shhhloader) | Shellcode loader bypassing AV/EDR. |
| [DllShimmer](https://github.com/Print3M/DllShimmer) | Weaponizes DLL hijacking. |
| [Veil](https://github.com/Veil-Framework/Veil) | Metasploit payload obfuscator. |
| [Shellcode Reflective DLL Injection](https://github.com/monoxgas/sRDI) | Reflective DLL injection technique. |
| [Nimcrypt](https://github.com/icyguider/nimcrypt) | Shellcode loader in Nim. |
| [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim) | Offensive security with Nim. |
| [NimlineWhispers](https://github.com/klezVirus/NimlineWhispers) | Syscalls in Nim. |
| [Cranium](https://github.com/icyguider/Cranium) | C2 framework in Nim. |
| [OffensiveRust](https://github.com/trickster0/OffensiveRust) | Offensive security with Rust. |
| [OffensiveGo](https://github.com/OffensiveGolang/OffensiveGo) | Offensive security with Go. |
| [OffensiveDLR](https://github.com/byt3bl33d3r/OffensiveDLR) | Offensive Dynamic Language Runtime. |

*(40+ tools)*

---

## 🚪 **Initial Access**

| Tool | Description |
|------|-------------|
| [Evilginx2](https://github.com/kgretzky/evilginx2) | MITM for phishing credentials/cookies. |
| [Gophish](https://github.com/gophish/gophish) | Open-source phishing toolkit. |
| [Modlishka](https://github.com/drk1wi/Modlishka) | Reverse proxy for advanced phishing. |
| [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit) | Password spraying for OWA/O365/Lync. |
| [o365recon](https://github.com/nyxgeek/o365recon) | Enumerates O365 with valid creds. |
| [Ruler](https://github.com/sensepost/ruler) | Exploits Exchange MAPI/RPC for RCE. |
| [BeEF](https://github.com/beefproject/beef) | Browser exploitation framework. |
| [CredMaster](https://github.com/knavesec/CredMaster) | Password spraying with IP rotation. |
| [TREVORspray](https://github.com/blacklanternsecurity/TREVORspray) | Modular password sprayer with proxies. |
| [EvilQR](https://github.com/kgretzky/evilqr) | QR code phishing for account takeover. |
| [CUPP](https://github.com/Mebus/cupp) | Creates personalized wordlists for brute force. |
| [Bash Bunny](https://hak5.org/products/bash-bunny) | USB attack tool for payloads. |
| [evilgophish](https://github.com/fin3ss3g0d/evilgophish) | Combines Evilginx2 and Gophish. |
| [SET](https://github.com/trustedsec/social-engineer-toolkit) | Social engineering toolkit for phishing. |
| [hydra](https://github.com/vanhauser-thc/thc-hydra) | Parallelized login cracker. |
| [SquarePhish](https://github.com/secureworks/squarephish) | Phishing via OAuth and QR codes. |
| [King Phisher](https://github.com/rsmusllp/king-phisher) | Phishing campaign toolkit. |
| [o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit) | Attacks Office365 environments. |
| [PwnAuth](https://github.com/fireeye/PwnAuth) | Framework for OAuth abuse campaigns. |
| [Phishery](https://github.com/ryhanson/phishery) | Basic auth credential harvester. |
| [ReelPhish](https://github.com/fireeye/ReelPhish) | Real-time 2FA phishing tool. |
| [Phishing Frenzy](https://github.com/pentestgeek/phishing-frenzy) | Phishing campaign manager. |
| [GoPhish](https://getgophish.com/) | Open-source phishing framework. |
| [CredSniper](https://github.com/ustayready/CredSniper) | Modular phishing framework. |
| [FiercePhish](https://github.com/Raikia/FiercePhish) | Full-fledged phishing framework. |
| [Lure](https://github.com/moloch--/Lure) | Lures for phishing campaigns. |
| [PhishingKitHunter](https://github.com/t4d/PhishingKitHunter) | Detects phishing kits. |
| [BlackPhish](https://github.com/iinc0gnit0/BlackPhish) | Super lightweight phishing server. |

*(30+ tools)*

---

## ⚡ **Execution**

| Tool | Description |
|------|-------------|
| [PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell) | Executes PS via MSBuild.exe. |
| [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter) | Retrieves/executes C# payloads. |
| [InlineWhispers](https://github.com/outflanknl/InlineWhispers) | Direct syscalls in Cobalt Strike BOFs. |
| [MSBuildAPICaller](https://github.com/rvrsh3ll/MSBuildAPICaller) | MSBuild without exe. |
| [Responder](https://github.com/lgandx/Responder) | LLMNR/NBT-NS/MDNS poisoner. |
| [secretsdump](https://github.com/SecureAuthCorp/impacket) | Dumps secrets from SAM/NTDS. |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | WinRM shell for hacking/pentesting. |
| [donut](https://github.com/TheWover/donut) | In-memory execution of scripts/EXEs. |
| [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) | Post-exploitation framework. |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Kerberos abuse toolkit. |
| [Empire](https://github.com/EmpireProject/Empire) | Post-exploitation agent. |
| [Covenant](https://github.com/cobbr/Covenant) | .NET C2 framework. |
| [Sliver](https://github.com/BishopFox/sliver) | Implant framework. |
| [Nimplant](https://github.com/chvancooten/NimPlant) | Lightweight Nim implant. |
| [Havoc](https://github.com/HavocFramework/Havoc) | Modern C2 framework. |
| [Brute Ratel](https://bruteratel.com/) | Customizable C2 framework. |
| [Merlin](https://github.com/Ne0nd0g/merlin) | Cross-platform post-exploitation HTTP/2 C2. |
| [PoshC2](https://github.com/nettitude/PoshC2) | Proxy-aware C2 framework in PowerShell. |
| [Mythic](https://github.com/its-a-feature/Mythic) | Collaborative multi-platform C2. |
| [Koadic](https://github.com/zerosum0x0/koadic) | COM C2 framework. |
| [SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY) | Post-exploitation agent in Python. |
| [Apfell](https://github.com/its-a-feature/Apfell) | macOS JavaScript for red teaming. |
| [Faction](https://github.com/FactionC2/Faction) | C2 framework. |
| [SHARP-KATZ](https://github.com/icyguider/SHARP-KATZ) | .NET port of Mimikatz. |

*(25+ tools)*

---

## 🔄 **Persistence**

| Tool | Description |
|------|-------------|
| [SharPersist](https://github.com/mandiant/SharPersist) | Windows persistence toolkit. |
| [SharpStay](https://github.com/0xthirteen/SharpStay) | .NET persistence tool. |
| [Empire Persistence](https://github.com/EmpireProject/Empire) | Persistence modules in Empire. |
| [Backdoor Factory](https://github.com/secretsquirrel/the-backdoor-factory) | Patches executables with shellcode. |
| [Regsvr32](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/) | DLL registration for persistence. |
| [Bitsadmin](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/) | BITS for scheduled tasks. |
| [Schtasks](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks) | Schedules tasks for persistence. |
| [Startup Folder](https://docs.microsoft.com/en-us/windows/win32/shell/startup-folder) | Adds to user startup. |
| [Registry Run Keys](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys) | Run keys for auto-start. |
| [AnyDesk](https://anydesk.com/) | Remote desktop for persistence. |
| [TeamViewer](https://www.teamviewer.com/) | Remote access tool. |
| [LogMeIn](https://www.logmein.com/) | Remote access software. |
| [Golden Ticket](https://github.com/GhostPack/Rubeus) | Kerberos persistence. |
| [Silver Ticket](https://github.com/GhostPack/Rubeus) | Service ticket forgery. |
| [Skeleton Key](https://github.com/GhostPack/Rubeus) | Implants key in DC. |
| [DSRM Persistence](https://adsecurity.org/?p=1714) | Directory Services Restore Mode. |
| [ACL Persistence](https://adsecurity.org/?p=1906) | Abuses ACLs for backdoors. |
| [Security Support Provider](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture) | Custom SSP for persistence. |
| [SID History Injection](https://adsecurity.org/?p=1772) | Injects SID for access. |

*(20+ tools)*

---

## 📈 **Privilege Escalation**

| Tool | Description |
|------|-------------|
| [WinPEAS](https://github.com/carlospolop/PEASS-ng) | Windows/Linux privesc enum. |
| [Sherlock](https://github.com/rasta-mouse/Sherlock) | Windows privesc checker. |
| [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) | Suggests Linux kernel exploits. |
| [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) | Windows privesc via PowerSploit. |
| [JAWS](https://github.com/411Hall/JAWS) | Just Another Windows Script for privesc. |
| [PrivescCheck](https://github.com/itm4n/PrivescCheck) | Windows privesc checker in PS. |
| [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) | Suggests Windows exploits. |
| [wesng](https://github.com/bitsadmin/wesng) | Windows Exploit Suggester Next Gen. |
| [Seatbelt](https://github.com/GhostPack/Seatbelt) | Situational awareness tool. |
| [BeRoot](https://github.com/AlessandroZ/BeRoot) | Privesc tool for Windows/Linux. |
| [SharpUp](https://github.com/GhostPack/SharpUp) | .NET port of PowerUp. |
| [PEASS-ng](https://github.com/carlospolop/PEASS-ng) | Privilege Escalation Awesome Scripts Suite. |
| [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) | Linux privesc checker. |
| [unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check) | Unix privesc auditor. |
| [LinEnum](https://github.com/rebootuser/LinEnum) | Linux enumeration & privesc. |
| [LES](https://github.com/PenturaLabs/Linux_Exploit_Suggester) | Linux Exploit Suggester. |
| [SUID3NUM](https://github.com/Anon-Exploiter/SUID3NUM) | SUID binaries enumerator. |
| [GTFOBins](https://gtfobins.github.io/) | Unix binaries for privesc. |
| [LOLBAS](https://lolbas-project.github.io/) | Living Off The Land Binaries. |
| [Windows-Privesc-Check](https://github.com/pentestmonkey/windows-privesc-check) | Windows privesc auditor. |
| [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) | Checks access permissions. |
| [PowerSploit Privesc](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) | PowerShell privesc modules. |
| [Juicy Potato](https://github.com/ohpe/juicy-potato) | Abuses SeImpersonatePrivilege. |
| [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) | WinRM backdoor exploit. |
| [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) | Abuses SeImpersonate on Win10. |
| [GodPotato](https://github.com/BeichenDream/GodPotato) | Local privesc tool. |
| [BadPotato](https://github.com/BeichenDream/BadPotato) | Windows privesc via named pipes. |

*(25+ tools)*

---

## 🛡️ **Defense Evasion**

| Tool | Description |
|------|-------------|
| [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) | PowerShell obfuscator. |
| [Veil](https://github.com/Veil-Framework/Veil) | Generates undetectable payloads. |
| [SharpBlock](https://github.com/CCob/SharpBlock) | EDR bypass via entry point prevention. |
| [Alcatraz](https://github.com/0x09AL/Alcatraz) | x64 binary obfuscator. |
| [Mangle](https://github.com/optiv/Mangle) | Manipulates compiled executables. |
| [AMSI.fail](https://amsi.fail/) | Generates AMSI bypass snippets. |
| [ScareCrow](https://github.com/optiv/ScareCrow) | Payload framework for EDR bypass. |
| [moonwalk](https://github.com/mufeedvh/moonwalk) | Clears traces on Unix systems. |
| [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m) | Kills event logging threads. |
| [DefenderCheck](https://github.com/matterpreter/DefenderCheck) | Identifies Defender detections. |
| [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell) | Hides PowerShell from AMSI. |
| [PSObfuscation](https://github.com/BC-SECURITY/PSObfuscation) | Obfuscates PowerShell scripts. |
| [Chimera](https://github.com/tokyoneon/Chimera) | PowerShell obfuscation script. |
| [Nimcrypt](https://github.com/icyguider/Nimcrypt) | PE/Shellcode crypter in Nim. |
| [ConfuserEx](https://github.com/yck1509/ConfuserEx) | .NET obfuscator. |
| [Obscure](https://github.com/mandiant/obscure) | Obfuscates strings in binaries. |
| [Gargoyle](https://github.com/JLospinoso/gargoyle) | Memory scanner evasion. |
| [AVET](https://github.com/govolution/avet) | Anti-Virus Evasion Tool. |
| [UniByAv](https://github.com/FengZiYjun/UniByAv) | Universal bypass AV tool. |
| [Shellter](https://github.com/kyREcon/shellter) | Dynamic PE injector. |
| [Donut](https://github.com/TheWover/donut) | Shellcode generator for in-memory exec. |
| [PeCloak](https://github.com/v-p-b/pecloak) | PE file obfuscator. |
| [Themida](https://www.oreans.com/Themida.php) | Advanced software protector. |
| [VMProtect](https://vmpsoft.com/) | Virtual machine-based protector. |
| [Hyperion](https://github.com/nullsecuritynet/tools/tree/master/packer/hyperion) | Runtime PE crypter. |
| [BackdoorMan](https://github.com/cr0hn/backdoor-man) | Python backdoor evasion. |
| [Ebowla](https://github.com/Genetic-Malware/Ebowla) | Genetic malware obfuscator. |

*(25+ tools)*

---

## 🔑 **Credential Access**

| Tool | Description |
|------|-------------|
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Extracts plaintexts passwords, hash, PIN code and kerberos tickets from memory. |
| [LaZagne](https://github.com/AlessandroZ/LaZagne) | Retrieves stored passwords from software. |
| [Hashcat](https://github.com/hashcat/hashcat) | Advanced password recovery utility. |
| [John the Ripper](https://github.com/openwall/john) | Fast password cracker. |
| [SCOMDecrypt](https://github.com/nccgroup/SCOMDecrypt) | Decrypts SCOM RunAs credentials. |
| [nanodump](https://github.com/helpsystems/nanodump) | Dumps LSASS minidump. |
| [eviltree](https://github.com/t3l3machus/eviltree) | Searches files for keywords/regex. |
| [SeeYouCM-Thief](https://github.com/trustedsec/SeeYouCM-Thief) | Extracts SSH creds from Cisco phones. |
| [MailSniper](https://github.com/dafthack/MailSniper) | Searches Exchange for terms. |
| [SharpChromium](https://github.com/djhohnstein/SharpChromium) | Extracts data from Chromium browsers. |
| [dploot](https://github.com/zblurx/dploot) | DPAPI loot tool. |
| [PCredz](https://github.com/lgandx/PCredz) | Extracts creds from PCAP/live interface. |
| [Kerbrute](https://github.com/ropnop/kerbrute) | Enumerates AD accounts via Kerberos. |
| [lsassy](https://github.com/Hackndo/lsassy) | Dumps LSASS remotely. |
| [Dumpert](https://github.com/outflanknl/Dumpert) | LSASS dumper using syscalls. |
| [SharpDump](https://github.com/GhostPack/SharpDump) | Creates minidump of LSASS. |
| [SafetyKatz](https://github.com/GhostPack/SafetyKatz) | Dynamically patched Mimikatz. |
| [Forkatz](https://github.com/Barbarisch/forkatz) | Credential dumper for Windows. |
| [SharpKatz](https://github.com/b4rtik/SharpKatz) | .NET port of Mimikatz features. |
| [Pypykatz](https://github.com/skelsec/pypykatz) | Mimikatz in pure Python. |
| [DonPAPI](https://github.com/login-securite/DonPAPI) | Dumps DPAPI creds remotely. |
| [DPAPick](https://github.com/kerspoon/dpapick) | Offline DPAPI decryption toolkit. |
| [Net-GPPPassword](https://github.com/obscuresec/Net-GPPPassword) | Retrieves GPP passwords. |
| [kekeo](https://github.com/gentilkiwi/kekeo) | Kerberos manipulation tool. |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | Swiss army knife for pentesting networks. |
| [Impacket](https://github.com/SecureAuthCorp/impacket) | Network protocols in Python. |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | AD attack path visualization. |

*(25+ tools)*

---

## 🔎 **Discovery**

| Tool | Description |
|------|-------------|
| [PCredz](https://github.com/lgandx/PCredz) | Credential discovery from PCAP/live. |
| [PingCastle](https://github.com/vletoux/pingcastle) | Active Directory assessor. |
| [Seatbelt](https://github.com/GhostPack/Seatbelt) | Local vulnerability scanner. |
| [ADRecon](https://github.com/sense-of-security/ADRecon) | Active Directory recon. |
| [adidnsdump](https://github.com/dirkjanm/adidnsdump) | Dumps AD Integrated DNS. |
| [scavenger](https://github.com/SpiderLabs/scavenger) | Scans for interesting files. |
| [SharpHound](https://github.com/BloodHoundAD/SharpHound) | Data collector for BloodHound. |
| [ADAPE](https://github.com/hausec/ADAPE-Script) | Active Directory assessment script. |
| [Grouper](https://github.com/l0ss/Grouper) | Finds vulns in AD group policy. |
| [ADCollector](https://github.com/dev-2null/ADCollector) | Lightweight AD info collector. |
| [Semperis DSP](https://www.semperis.com/directory-security-platform/) | AD security assessment. |
| [PurpleSharp](https://github.com/mvelazc0/PurpleSharp) | Adversary simulation for detection. |
| [PingCastle Cloud](https://www.pingcastle.com/cloud/) | Cloud AD security scanner. |
| [RiskySPN](https://github.com/GoateePFE/RiskySPNs) | Detects risky SPNs in AD. |
| [ROADtools](https://github.com/dirkjanm/ROADtools) | Azure AD exploration framework. |
| [AzureHound](https://github.com/BloodHoundAD/AzureHound) | Data collector for Azure AD. |
| [StormSpotter](https://github.com/Azure/Stormspotter) | Azure red team tool. |
| [MicroBurst](https://github.com/NetSPI/MicroBurst) | Azure security assessment. |
| [AADInternals](https://github.com/Gerenios/AADInternals) | Azure AD security toolkit. |
| [PowerZure](https://github.com/hausec/PowerZure) | PowerShell for Azure exploitation. |
| [Sparrow](https://github.com/cisagov/Sparrow) | Detects suspicious Azure behavior. |
| [Hawk](https://github.com/T0pCyber/hawk) | PowerShell for O365 intrusion. |
| [o365creeper](https://github.com/LMGsec/o365creeper) | Email address creeper for O365. |
| [TEAMSScanner](https://github.com/rvrsh3ll/TEAMSScanner) | Enumerates MS Teams info. |
| [o365enum](https://github.com/gremwell/o365enum) | Enumerates users in O365. |

*(25+ tools)*

---

## ↔️ **Lateral Movement**

| Tool | Description |
|------|-------------|
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | Swiss army knife for AD attacks. |
| [WMIOps](https://github.com/FortyNorthSecurity/WMIOps) | Performs actions via WMI. |
| [PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell) | Executes PS via MSBuild. |
| [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) | Executes processes remotely. |
| [Liquid Snake](https://github.com/RiccardoAncarani/LiquidSnake) | Lateral movement via WMI subscription. |
| [ADFSpoof](https://github.com/mandiant/ADFSpoof) | Forges AD FS security tokens. |
| [Coercer](https://github.com/p0dalirius/Coercer) | Coerces Windows auth via RPC. |
| [Impacket](https://github.com/SecureAuthCorp/impacket) | Network protocols for lateral movement. |
| [SMBExec](https://github.com/brav0hax/smbexec) | Executes via SMB. |
| [PSExec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) | Impacket PSEXEC equivalent. |
| [Kerberos](https://github.com/GhostPack/Rubeus) | Pass-the-ticket attacks. |
| [DCOM](https://github.com/Ridter/DCOM_Lateral_Movement) | Lateral via DCOM. |
| [WMIExec](https://github.com/FortyNorthSecurity/WMIOps) | Executes via WMI. |
| [Invoke-WMI](https://github.com/Kevin-Robertson/Invoke-TheHash) | WMI command execution. |
| [SMBMap](https://github.com/ShawnDEvans/smbmap) | Enumerates SMB shares. |
| [NetView](https://github.com/mubix/netview) | Enumerates domain machines. |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Maps AD for lateral paths. |
| [DeathStar](https://github.com/byt3bl33d3r/DeathStar) | Automates DA privilege gain. |
| [Empire](https://github.com/EmpireProject/Empire) | Lateral movement modules. |
| [Covenant](https://github.com/cobbr/Covenant) | .NET agent for lateral. |
| [WMIC](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic) | Command-line WMI. |
| [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting) | Remote command execution. |
| [Jenkins Script Console](https://www.jenkins.io/doc/book/managing/script-console/) | Executes Groovy scripts. |
| [RDP](https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/remote-desktop-disconnected) | Remote Desktop Protocol. |
| [WinRM](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) | Windows Remote Management. |

*(25+ tools)*

---

## 📂 **Collection**

| Tool | Description |
|------|-------------|
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Active Directory visualization. |
| [Snaffler](https://github.com/SnaffCon/Snaffler) | Active Directory credential collector. |
| [linWinPwn](https://github.com/lefayjey/linWinPwn) | AD enumeration and vuln checks. |
| [SharpHound](https://github.com/BloodHoundAD/SharpHound) | Collects data for BloodHound. |
| [AzureHound](https://github.com/BloodHoundAD/AzureHound) | Collects Azure AD data. |
| [ROADrecon](https://github.com/dirkjanm/ROADrecon) | Collects Azure AD info. |
| [Stormspotter](https://github.com/Azure/Stormspotter) | Creates Azure attack graph. |
| [Hawk](https://github.com/T0pCyber/hawk) | Collects O365 data. |
| [o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit) | Collects from Office365. |
| [MailSniper](https://github.com/dafthack/MailSniper) | Searches email for terms. |
| [DataExfiltrator](https://github.com/BC-SECURITY/DataExfiltrator) | Exfiltrates data via protocols. |
| [SharpCloud](https://github.com/chrismaddalena/SharpCloud) | Enumerates cloud services. |
| [Farm](https://github.com/mdsecresearch/FARM) | Collects hashes from domain. |
| [DCSync](https://github.com/GhostPack/Rubeus) | Replicates AD data. |
| [PyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) | Abuses GPO for collection. |
| [LDAPFragger](https://github.com/lkarlslund/LDAPFragger) | LDAP command channel. |
| [ADCollector](https://github.com/dev-2null/ADCollector) | Collects AD info. |
| [Group3r](https://github.com/Group3r/Group3r) | Finds GPO vulns. |

*(20+ tools)*

---

## 🎛️ **Command & Control**

| Tool | Description |
|------|-------------|
| [Covenant](https://github.com/cobbr/Covenant) | .NET C2 framework with web UI. |
| [Empire](https://github.com/EmpireProject/Empire) | PowerShell and Python agent C2. |
| [PoshC2](https://github.com/nettitude/PoshC2) | Proxy-aware C2 in PowerShell/C#. |
| [Merlin](https://github.com/Ne0nd0g/merlin) | Cross-platform HTTP/2 C2. |
| [Havoc](https://github.com/HavocFramework/Havoc) | Modern malleable C2 framework. |
| [Brute Ratel C4](https://bruteratel.com/) | Customizable C2 with EDR bypass. |
| [NimPlant](https://github.com/chvancooten/NimPlant) | Lightweight first-stage implant in Nim. |
| [hoaxshell](https://github.com/t3l3machus/hoaxshell) | Reverse shell via HTTP(S). |
| [Sliver](https://github.com/BishopFox/sliver) | Adversary emulation framework. |
| [Mythic](https://github.com/its-a-feature/Mythic) | Collaborative cross-platform C2. |
| [Cobalt Strike](https://www.cobaltstrike.com/) | Commercial adversary simulation. |
| [Koadic](https://github.com/zerosum0x0/koadic) | COM-based C2. |
| [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY) | Modern Python C2. |
| [Apfell](https://github.com/its-a-feature/Apfell) | macOS eBPF C2. |
| [Faction](https://github.com/FactionC2/Faction) | C2 framework in C#. |
| [Pupy](https://github.com/n1nj4sec/pupy) | Cross-platform Python C2. |
| [C2concealer](https://github.com/FortyNorthSecurity/C2concealer) | Creates randomized C2 malleable profiles. |
| [TrevorC2](https://github.com/trustedsec/trevorc2) | Client/server for tunneling. |
| [DNSCat2](https://github.com/iagox86/dnscat2) | DNS tunneling tool. |
| [Malleable C2](https://github.com/threatexpress/malleable-c2) | Cobalt Strike malleable profiles. |
| [Empire DNS](https://github.com/EmpireProject/Empire) | DNS C2 in Empire. |
| [Redirect.rules](https://github.com/0xZDH/redirect.rules) | Nginx redirector for C2. |
| [Apache2ModRewrite](https://github.com/threatexpress/domainhunter) | Apache mod_rewrite for C2. |
| [Chameleon](https://github.com/mdsecactivebreach/Chameleon) | Customizable honeypot for C2. |

*(25+ tools)*

---

## 📤 **Exfiltration**

| Tool | Description |
|------|-------------|
| [dnscat2](https://github.com/iagox86/dnscat2) | DNS tunneling for data exfil. |
| [Cloakify](https://github.com/TryCatchHCF/Cloakify) | Transforms data into harmless strings. |
| [PyExfil](https://github.com/ytisf/PyExfil) | Data exfiltration techniques in Python. |
| [Powershell-RAT](https://github.com/Viralmaniar/Powershell-RAT) | Exfils data via Gmail. |
| [GD-Thief](https://github.com/antman1p/GD-Thief) | Exfils from Google Drive via API. |
| [DET](https://github.com/PaulSec/DET) | Data Exfiltration Toolkit. |
| [Iodine](https://github.com/yarrick/iodine) | IPv4 over DNS tunnel. |
| [DNSCat](https://github.com/iagox86/dnscat2) | DNS C2 and exfil. |
| [Living Off The Cloud](https://github.com/dwmetz/LivingOffTheCloud) | Exfil via cloud services. |
| [Rclone](https://rclone.org/) | Syncs files to cloud storage. |
| [Exfil-Dropbox](https://github.com/svarona/exfil-dropbox) | Exfils via Dropbox API. |
| [Onedrive-Exfil](https://github.com/ARPSyndicate/onedrive-user-enum) | Exfils via OneDrive. |
| [Gcat](https://github.com/byt3bl33d3r/gcat) | Backdoor using Gmail. |
| [TgCat](https://github.com/EnginDemirbilek/tgcat) | Backdoor using Telegram. |
| [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator) | Exfils files over DNS. |
| [Pigeon](https://github.com/mattreduce/pigeon) | DNS request exfil tool. |
| [Living Off The Land](https://lolbas-project.github.io/) | Uses legit bins for exfil. |
| [SharpExfil](https://github.com/mdsecresearch/SharpExfiltrate) | .NET data exfil tool. |

*(20+ tools)*

---

## 💥 **Impact**

| Tool | Description |
|------|-------------|
| [Conti Pentester Guide Leak](https://github.com/ForbiddenProgrammer/conti-pentester-guide-leak) | Leaked Conti ransomware guide. |
| [Slowloris](https://github.com/gkbrk/slowloris) | Low-bandwidth DoS tool. |
| [USBkill](https://github.com/hephaest0s/usbkill) | Anti-forensic kill-switch for USB changes. |
| [Keytap](https://github.com/ggerganov/kbd-audio) | Guesses keys from audio. |
| [Lockphish](https://github.com/jaykali/lockphish) | Phishing for Android PIN. |
| [EvilUSB](https://github.com/x1mdev/EvilUSB) | USB-based attacks. |
| [Ransomwhere](https://github.com/hashtagcyber/ransomwhere) | Tracks ransomware payments. |
| [PyCryptoMiner](https://github.com/crispy-peppers/pycryptominer) | Python cryptominer. |
| [DDospot](https://github.com/alippai/DDospot) | DDoS honeypot. |
| [Torshammer](https://github.com/dotfighter/torshammer) | Slow post DoS tool. |
| [LOIC](https://github.com/NewEraCracker/LOIC) | Low Orbit Ion Cannon DoS. |
| [HOIC](https://sourceforge.net/projects/high-orbit-ion/) | High Orbit Ion Cannon. |
| [R-U-Dead-Yet](https://github.com/fygrave/r-u-dead-yet) | Slow HTTP DoS. |
| [GoldenEye](https://github.com/jseidl/GoldenEye) | HTTP/S Layer 7 DoS. |
| [HULK](https://github.com/grafov/hulk) | HTTP Unbearable Load King. |
| [PyLoris](https://github.com/JamesConway/PyLoris) | Python Slowloris variant. |
| [OWASP ZSC](https://github.com/OWASP/ZSC) | Shellcode generator. |
| [Memcrashed](https://github.com/649/Memcrashed-DDoS-Exploit) | Memcached DDoS exploit. |

*(20+ tools)*

![White Monkey RedTeaming Tools](https://raw.githubusercontent.com/byoniq/RedTeaming-Tools/main/white_monkey_hackers_compressed.jpg)

