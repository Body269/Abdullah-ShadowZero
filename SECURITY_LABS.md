# 💻 Technical Security Labs & Offensive Skills

This file contains documented evidence of my technical capabilities, penetration testing methodologies, and hands-on experience in offensive security environments.

---

## 🛠️ Core Technical Skillset
An overview of the methodologies and tools verified and deployed in my security labs:

| Category | Tools & Technologies | Focus Area |
| :--- | :--- | :--- |
| **Network Recon** | Nmap, Masscan, Advanced Google Dorking | Infrastructure mapping & port auditing |
| **Credential Auditing**| Hydra, John the Ripper, Hashcat | Password strength validation & hash cracking |
| **OSINT** | Custom Python scripts, Maltego, Recon-ng | Threat intelligence & footprinting |
| **OS / Environments** | Kali Linux, Parrot OS, Custom Android (Smali) | Penetration testing operating environments |

---

## 📟 Hardware Hacking Lab (ESP32 Wireless Auditor)
Proven capability in developing and flashing firmware for localized wireless assessments:
* **Hardware Architecture:** ESP32 (NodeMCU / D1 Mini framework).
* **Deployed Firmware:** Custom-compiled WiFi Marauder environment.
* **Tested Scenarios:** 
  - Validating Wi-Fi network resilience against 802.11 deauthentication frames.
  - Analyzing packet captures (PCAP files) using Wireshark to inspect local traffic vulnerabilities.

---

## 🎛️ Network Penetration Testing Scenario (Lab Validation)

Below is a technical layout of a standard internal assessment executed to test network posture (Simulated Red Team Environment):

### 1. Reconnaissance Phase
Using automated discovery modules to map live hosts and exposed services:
```bash
# Executing an aggressive service detection scan on the target subnet
nmap -sV -sC -O -p- 192.168.1.0/24 -oN internal_recon.txt
