<div align="center">

# IHATEMYSELF

</div>

<p align="center">
  <img src="https://i.ibb.co/TctMZbX/Screenshot-1.png">
</p>

---
![python3_support](https://img.shields.io/badge/Python-3-blue.svg "Python 3.11")

## Brief Summary
* Created for fun. You can take reference from this project.

## Payloads
- It works simple:
- Bypasses UAC then restarts itself to change registry, and copy itself to C:\Windows, as well as creating a powershell script to prevent user from closing the process.
- Restarts PC.
- After the reboot, it will delete ntoskrnl.exe and hal.dll and overwrite MBR with a custom message, then create visual effects such as making your screen black.

# Registry payloads
- Disables CTRL+Alt+Delete
- Disables regedit.exe
- Swaps mouse buttons.
- Puts itself on startup (wininit, reference from Endermanch on YT!)
- Allows powershell scripts to be ran from terminal.
- Enables LUA, which runs any program with administrative privileges.

# Persistence
- Simple. It creates a powershell script that launches upon startup and monitors the malware's process. If malware process or powershell closed, it will throw BSOD.
- If tried to delete malware or powershell script from file directory, it will throw BSOD.

## DISCLAIMER
- This tool is provided for educational and research purposes only. The authors of this project are no way responsible for any misuse of this tool.
- Please credit me if you are using this in your project.

# Contributions
- All contributions are welcome!

## Credits:
* [rootm0s for winpwnage](https://github.com/rootm0s/WinPwnage)
