# RootKiler-
Root killer is a ransomware built by em_oche for educational purposes only 😈
# Ransomware Simulation for Cybersecurity Learning 🔒💾

**⚠️ EDUCATIONAL PROJECT ONLY ⚠️**  
This is a **lab-based ransomware simulation** designed for cybersecurity education. It simulates file encryption, brute-force access, and Telegram bot integration in a controlled, isolated environment (e.g., VirtualBox VMs with no internet). **DO NOT use this code outside a lab, as it may violate laws like Nigeria’s Cybercrimes Act (2015), with penalties of 7+ years in prison.**

## Purpose
- Learn ransomware mechanics (encryption, brute-forcing, C2 via Telegram).
- Study detection and prevention (e.g., antivirus, firewalls).
- Build cybersecurity skills ethically.

## Features
- 🔒 Recursive file encryption with `cryptography` library.
- 💪 Brute-force retries for locked files.
- 📡 Telegram bot for C2, notifications, and key exfiltration.
- 💀 Hacker-styled GUI with countdown timer.
- 📝 Logging for forensic analysis.

## Setup
1. **Lab Environment**:
   - Windows VM (e.g., Windows 10) in VirtualBox.
   - No internet or real network access.
   - Snapshot enabled for reverting changes.
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
