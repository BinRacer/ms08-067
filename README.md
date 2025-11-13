<div align="center">
  <!-- Banner with negative bottom margin -->
  <a href="https://github.com/BinRacer/ms08-067">
    <img src="images/banner.svg" alt="ms08-067" style="width:100%; max-width:100%; margin-top:0; margin-bottom:-0.5rem">
  </a>
</div>

---

## 📖 Overview

This repository contains a Metasploit module implementation for the MS08-067 Windows Server Service vulnerability (CVE-2008-4250). This is a classic remote code execution vulnerability affecting older Windows systems.

## 🛠️ Installation & Usage

### Prerequisites
- Kali Linux
- Metasploit Framework installed
- Authorized testing environment


### 🤔How To Use?

First, login Kali Linux. And 	
👉 Run the following command:
```shell
git clone https://github.com/BinRacer/ms08-067.git
cd ms08-067
sudo cp -a src/ms08_067_netapi_sp1.rb /usr/share/metasploit-framework/modules/exploits/windows/smb
# must replace rc file x.x.x.x to real ip
sudo msfconsole -r src/ms08_067.rc
```

## ⚠️ Important Notes

- **Legal Compliance**: Always ensure you have proper authorization before testing any security vulnerabilities
- **Environment Isolation**: Conduct testing in controlled, isolated environments to prevent unintended system impacts
- **Educational Purpose**: This material is intended for educational and authorized security research only

For complete legal information and disclaimers, please refer to the [Disclaimer](./Disclaimer.md) document.

---

<div align="center">
  <sub>Built with ❤️ for the security research community</sub>
</div>