import os
import subprocess
import requests
import zipfile
import time
import lzma
import datetime
import json
import shutil
import random
import pyfiglet
import sys
import re
from colorama import Fore, Style, init
import xml.etree.ElementTree as ET
from tqdm import tqdm
import tempfile
from collections import Counter
import threading
import itertools

init(autoreset=True)

COLORS = [
    Fore.LIGHTBLUE_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTYELLOW_EX, Fore.LIGHTRED_EX, Fore.LIGHTMAGENTA_EX,
    Fore.LIGHTGREEN_EX, Fore.LIGHTRED_EX, Fore.LIGHTBLUE_EX,
    Fore.LIGHTMAGENTA_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTYELLOW_EX
]
FONTS = ("slant",) 
PROMPT_COLOR = Fore.LIGHTGREEN_EX
PROMPT_COLOR1 =Fore.WHITE

def print_banner():
    font = random.choice(FONTS)
    width = os.get_terminal_size().columns
    ascii_art = pyfiglet.figlet_format("APKScope", font=font)
   
    print(Fore.LIGHTCYAN_EX + ascii_art + Style.RESET_ALL)
    
    now = datetime.datetime.now().strftime("%d/%b/%Y %H:%M:%S")
    print(Fore.LIGHTGREEN_EX + f"[INFO] {now} - \n" + Style.RESET_ALL)

def print_info(msg):
    print(Fore.LIGHTCYAN_EX + "[i] " + msg + Style.RESET_ALL)

def print_success(msg):
    print(Fore.LIGHTGREEN_EX + "[✓] " + msg + Style.RESET_ALL)

def print_warning(msg):
    print(Fore.LIGHTYELLOW_EX + "[!] " + msg + Style.RESET_ALL)

def print_error(msg):
    print(Fore.LIGHTRED_EX + "[X] " + msg + Style.RESET_ALL)

def list_adb_devices():
    result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
    devices = [line.split('\t')[0] for line in result.stdout.strip().split('\n')[1:] if "\tdevice" in line]
    if not devices:
        print_error("No ADB devices connected.")
    else:
        print_info(f"{len(devices)} device(s) found.")
    return devices

def choose_device(devices):
    print_info("Device List:")
    for i, device in enumerate(devices, 1):
        print(Fore.LIGHTCYAN_EX + f"{i}. {device}" + Style.RESET_ALL)
    while True:
        try:
            idx = int(input(PROMPT_COLOR + ">>> Select device (number): " + Style.RESET_ALL)) - 1
            if 0 <= idx < len(devices):
                print_success(f"Selected device: {devices[idx]}")
                return devices[idx]
        except ValueError:
            pass
        print_error("Invalid selection, try again.")

def get_device_arch(device):
    result = subprocess.run(f'adb -s {device} shell getprop ro.product.cpu.abi', shell=True, capture_output=True, text=True)
    arch = result.stdout.strip()
    print_info(f"Device architecture: {arch}")
    if 'arm64' in arch: return 'arm64'
    if 'armeabi' in arch: return 'arm'
    if 'x86_64' in arch: return 'x86_64'
    if 'x86' in arch: return 'x86'
    print_warning("Unknown architecture.")
    return None

def get_latest_frida_versions(n=10):
    url = "https://api.github.com/repos/frida/frida/releases"
    r = requests.get(url)
    if r.status_code == 200:
        data = r.json()
        return [release["tag_name"] for release in data if release.get("assets")]
    print("Could not fetch Frida versions.")
    return []

def download_frida_server(version, arch):
    fname = f"frida-server-{version}-android-{arch}"
    url = f"https://github.com/frida/frida/releases/download/{version}/{fname}.xz"
    print(f"Downloading {url} ...")
    r = requests.get(url, stream=True)
    if r.status_code != 200:
        print("Download failed. Check version and architecture.")
        return None
    with open(f"{fname}.xz", "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)
    with lzma.open(f"{fname}.xz") as xz_file, open(fname, "wb") as out_file:
        out_file.write(xz_file.read())
    os.remove(f"{fname}.xz")
    print(f"Downloaded and extracted: {fname}")
    return fname

def install_frida_server(device):
    arch = get_device_arch(device)
    if not arch:
        print_error("Could not detect device architecture.")
        return
    try:
        frida_version_output = subprocess.run(["frida", "--version"], capture_output=True, text=True)
        if frida_version_output.returncode != 0:
            print_error("Frida CLI not found or could not be run.")
            return
        frida_version = frida_version_output.stdout.strip()
        print_success(f"Detected Frida version: {frida_version}")

        frida_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tool", "frida-server")
        os.makedirs(frida_dir, exist_ok=True)
        fname = f"frida-server-{frida_version}-android-{arch}"
        local_frida_path = os.path.join(frida_dir, fname)

        if os.path.exists(local_frida_path):
            print_info(f"Frida server binary found locally: {local_frida_path}")
        else:
            url = f"https://github.com/frida/frida/releases/download/{frida_version}/{fname}.xz"
            print_info(f"Downloading {url} ...")
            r = requests.get(url, stream=True)
            if r.status_code != 200:
                print_error("Download failed. Check version and architecture.")
                return
            with open(local_frida_path + ".xz", "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            with lzma.open(local_frida_path + ".xz") as xz_file, open(local_frida_path, "wb") as out_file:
                out_file.write(xz_file.read())
            os.remove(local_frida_path + ".xz")
            print_success(f"Downloaded and extracted: {local_frida_path}")

        os.system(f"adb -s {device} push {local_frida_path} /data/local/tmp/")
        os.system(f"adb -s {device} shell chmod 777 /data/local/tmp/{fname}")
        print_success("Frida server pushed and permissions set.")
        os.system(f"adb -s {device} shell 'pkill -f frida-server'")
        time.sleep(1)
        pid_cmd = f"adb -s {device} shell 'nohup /data/local/tmp/{fname} > /dev/null 2>&1 & echo $!'"
        pid = os.popen(pid_cmd).read().strip()
        if pid:
            print_success(f"Frida server v{frida_version} started in background. PID: {pid}")
        else:
            print_warning("Frida server started but PID could not be obtained.")
        time.sleep(2)
        test_cmd = "frida-ps"
        print_info(f"Testing connection: {test_cmd}")
        test_result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
        if test_result.returncode == 0:
            print_success("Frida server connection successful!")
        else:
            print_error("Frida server connection test failed. Error message:")
            print_error(test_result.stderr)
    except Exception as e:
        print_error(f"Error during Frida server installation: {str(e)}")

def set_proxy(device_id):
    import ipaddress
    while True:
        ip = input(PROMPT_COLOR1 + ">>> Enter Proxy IP address : " + Style.RESET_ALL).strip()
        try:
            ipaddress.IPv4Address(ip)
        except Exception:
            print(Fore.LIGHTRED_EX + "[X] Invalid IP address format! " + Style.RESET_ALL)
            continue
        while True:
            port_str = input(PROMPT_COLOR1 + ">>> Enter Proxy port (0-65535): " + Style.RESET_ALL).strip()
            if not port_str.isdigit():
                print(Fore.LIGHTRED_EX + "[X] Port must consist of digits only!" + Style.RESET_ALL)
                continue
            port = int(port_str)
            if not (0 < port < 65536):
                print(Fore.LIGHTRED_EX + "[X] Port must be between 1 and 65535!" + Style.RESET_ALL)
                continue
            break
        try:
            proxy = f"{ip}:{port}"
            subprocess.run(["adb", "-s", device_id, "shell", "settings", "put", "global", "http_proxy", proxy])
            print(Fore.LIGHTGREEN_EX + f"\n[✓] Proxy set successfully! ({proxy})" + Style.RESET_ALL)
            break
        except Exception as e:
            print(Fore.LIGHTRED_EX + f"[X] Error occurred: {str(e)}" + Style.RESET_ALL)
            continue

def install_burp_cert(device_id):
    while True:
        cer_file_path = input(PROMPT_COLOR1 + ">>> Enter the certificate file path (e.g., burp.der): " + Style.RESET_ALL).strip()
        if not os.path.exists(cer_file_path):
            print(Fore.LIGHTRED_EX + f"[X] {cer_file_path} not found." + Style.RESET_ALL)
            continue
        try:
            os.system(f"openssl x509 -inform DER -in \"{cer_file_path}\" -out burp.pem")
            hash_result = subprocess.run(
                "openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1",
                shell=True, capture_output=True, text=True
            )
            cert_hash = hash_result.stdout.strip()
            pem_filename = f"{cert_hash}.0"
            os.rename("burp.pem", pem_filename)
            os.system(f"adb -s {device_id} remount")
            os.system(f"adb -s {device_id} push {pem_filename} /system/etc/security/cacerts/")
            os.system(f"adb -s {device_id} shell chmod 644 /system/etc/security/cacerts/{pem_filename}")
            print(Fore.LIGHTGREEN_EX + f"\n[✓] Certificate installed successfully: /system/etc/security/cacerts/{pem_filename}" + Style.RESET_ALL)
            print(PROMPT_COLOR1 + "You may need to restart the device." + Style.RESET_ALL)
          
            if os.path.exists(pem_filename):
                os.remove(pem_filename)
                print(Fore.LIGHTGREEN_EX + f"[✓] Local certificate file deleted: {pem_filename}" + Style.RESET_ALL)
            break
        except Exception as e:
            print(Fore.LIGHTRED_EX + f"[X] Error occurred: {str(e)}" + Style.RESET_ALL)

def run_frida_bypass(device):
    result = subprocess.run(
        ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
        capture_output=True, text=True
    )
    packages = [line.replace("package:", "").strip() for line in result.stdout.splitlines()]
    if not packages:
        print_error("No 3rd party applications found.")
        return
    print(Fore.LIGHTMAGENTA_EX + "\nInstalled 3rd party applications:" + Style.RESET_ALL)
    for idx, pkg in enumerate(packages):
        print(Fore.LIGHTYELLOW_EX+ f"{idx+1}: {pkg}" + Style.RESET_ALL)
    while True:
        try:
            sec = int(input(PROMPT_COLOR + "Enter the number of the package you want to run: ")) - 1
            if 0 <= sec < len(packages):
                package = packages[sec]
                break
        except ValueError:
                pass
        print_error("Invalid selection.")
    
    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script")
    scripts = [f for f in os.listdir(script_dir) if f.endswith(".js")]
    if not scripts:
        print_error("No .js file found in the script folder.")
        return
    
    print("\nScript files:")
    for idx, s in enumerate(scripts):
        print(f"{idx+1}: {s}")
    while True:
        try:
            sidx = int(input(PROMPT_COLOR + "Enter the number of the script you want to run: ")) - 1
            if 0 <= sidx < len(scripts):
                script_path = os.path.join(script_dir, scripts[sidx])
                break
        except ValueError:
            pass
        print_error("Invalid selection.")
    
    cmd = f"frida -l {script_path} -U -f {package}"
    print_info(f"Running: {cmd}")
    os.system(cmd)

def dump_and_analyze_app_data(device):
    result = subprocess.run(
        ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
        capture_output=True, text=True
    )
    packages = [line.replace("package:", "").strip() for line in result.stdout.splitlines()]
    if not packages:
        print(Fore.LIGHTRED_EX + "[X] No 3rd party applications found." + Style.RESET_ALL)
        return
    print(Fore.LIGHTMAGENTA_EX + "\nInstalled 3rd party applications:" + Style.RESET_ALL)
    for idx, pkg in enumerate(packages):
        print(Fore.LIGHTYELLOW_EX+ f"{idx+1}: {pkg}" + Style.RESET_ALL)
    while True:
        try:
            sec = int(input(PROMPT_COLOR + "Enter the number of the package you want to dump and analyze: " + Style.RESET_ALL)) - 1
            if 0 <= sec < len(packages):
                package = packages[sec]
                break
        except ValueError:
            pass
        print(Fore.LIGHTRED_EX + "[X] Invalid selection." + Style.RESET_ALL)
    local_dir = os.path.join(os.getcwd(), "dumped_data", package)
    os.makedirs(local_dir, exist_ok=True)
    print(Fore.LIGHTYELLOW_EX + f"[>] Retrieving file list: /data/data/{package}" + Style.RESET_ALL)
    find_cmd = [
        "adb", "-s", device, "shell", "find", f"/data/data/{package}", "-type", "f"
    ]
    result = subprocess.run(find_cmd, capture_output=True, text=True)
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not files:
        print(Fore.LIGHTRED_EX + "[X] No files found or access denied." + Style.RESET_ALL)
        return
    print(Fore.LIGHTYELLOW_EX + f"[>] Pulling {len(files)} files..." + Style.RESET_ALL)
    dumped_files = [] 
    for f in tqdm(files, desc="Pulling", unit="file", ncols=80, colour="cyan"):
        rel_path = os.path.relpath(f, f"/data/data/{package}")
        local_path = os.path.join(local_dir, rel_path)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        pull_cmd = [
            "adb", "-s", device, "shell", "su", "-c", f"cat {f}"
        ]
        with open(local_path, "wb") as out_file:
            proc = subprocess.run(pull_cmd, capture_output=True)
            out_file.write(proc.stdout)
        dumped_files.append(local_path) 
    print(Fore.LIGHTGREEN_EX + f"[✓] Dump completed! Folder: {local_dir}" + Style.RESET_ALL)
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result", "data_data_analyze")
    os.makedirs(results_dir, exist_ok=True)
    json_path = os.path.join(results_dir, f"{package}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dumped_files, f, indent=2, ensure_ascii=False)
    print(Fore.LIGHTGREEN_EX + f"[✓] Results saved to {json_path}." + Style.RESET_ALL)

def download_drozer_agent_latest():
    apk_url = "https://github.com/ReversecLabs/drozer-agent/releases/download/3.1.0/drozer-agent.apk"
    local_dir = os.path.join("tool", "drozer_apk")
    os.makedirs(local_dir, exist_ok=True)
    local_path = os.path.join(local_dir, "drozer-agent-3.1.0.apk")
    if os.path.exists(local_path):
        print(Fore.LIGHTGREEN_EX + f"[✓] APK already downloaded: {local_path}" + Style.RESET_ALL)
        return local_path
    print(Fore.LIGHTYELLOW_EX + f"[>] Downloading: {apk_url}" + Style.RESET_ALL)
    r = requests.get(apk_url, stream=True)
    if r.status_code == 200:
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        print(Fore.LIGHTGREEN_EX + f"[✓] APK downloaded: {local_path}" + Style.RESET_ALL)
        return local_path
    print(Fore.LIGHTRED_EX + "[X] APK could not be downloaded." + Style.RESET_ALL)
    return None

def install_drozer_apk(device, apk_path):
    print(Fore.LIGHTYELLOW_EX + f"[>] Installing: {apk_path}" + Style.RESET_ALL)
    result = subprocess.run(["adb", "-s", device, "install", "-r", apk_path], capture_output=True, text=True)
    if "Success" in result.stdout:
        print(Fore.LIGHTGREEN_EX + "[✓] Drozer APK installed successfully." + Style.RESET_ALL)
    else:
        print(Fore.LIGHTRED_EX + "[X] Drozer APK could not be installed." + Style.RESET_ALL)
        print(result.stdout + result.stderr)

def forward_tcp_port(device):
    print(Fore.LIGHTYELLOW_EX + "[>] Forwarding port (31415)..." + Style.RESET_ALL)
    result = subprocess.run(["adb", "-s", device, "forward", "tcp:31415", "tcp:31415"], capture_output=True, text=True)
    if result.returncode == 0:
        print(Fore.LIGHTGREEN_EX + "[✓] TCP port forwarded: 31415" + Style.RESET_ALL)
    else:
        print(Fore.LIGHTRED_EX + "[X] TCP port could not be forwarded." + Style.RESET_ALL)

def drozer_console_connect(device):
    print(Fore.LIGHTMAGENTA_EX + "\n[>] Starting Drozer Console connection..." + Style.RESET_ALL)
    result = subprocess.run(
        ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
        capture_output=True, text=True
    )
    packages = [line.replace("package:", "").strip() for line in result.stdout.splitlines()]
    if not packages:
        print(Fore.LIGHTRED_EX + "[X] No 3rd party applications found." + Style.RESET_ALL)
        return
    print(Fore.LIGHTMAGENTA_EX  + "\nInstalled 3rd party applications:" + Style.RESET_ALL)
    for idx, pkg in enumerate(packages):
        print(Fore.LIGHTYELLOW_EX + f"{idx+1}: {pkg}" + Style.RESET_ALL)
    while True:
        try:
            sec = int(input(PROMPT_COLOR + ">>> Enter the number of the package you want information about: " + Style.RESET_ALL)) - 1
            if 0 <= sec < len(packages):
                package = packages[sec]
                break
        except ValueError:
            pass
        print(Fore.LIGHTRED_EX + "[X] Invalid selection." + Style.RESET_ALL)
    print(Fore.LIGHTYELLOW_EX + f"\n[>] Retrieving information with Drozer: {package}" + Style.RESET_ALL)
    try:
        proc = subprocess.Popen(
            ["drozer", "console", "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        command = f"run app.package.info -a {package}\nexit\n"
        out, err = proc.communicate(command, timeout=15)
        if "you probably didn't specify a valid drozer server" in out or "you probably didn't specify a valid drozer server" in err:
            print(Fore.LIGHTRED_EX + "[X] Drozer error: Please make sure the Drozer agent is running on the device and the app is started. Enable the agent's button in the app if needed." + Style.RESET_ALL)
        else:
            print(Fore.LIGHTGREEN_EX + "\n[✓] Results:\n" + Style.RESET_ALL)
            print(out)
            result_dir = os.path.join("result", "drozer_results")
            os.makedirs(result_dir, exist_ok=True)
            result_file = os.path.join(result_dir, f"app_package_info_{package}.txt")
            with open(result_file, "w", encoding="utf-8") as f:
                f.write(out)
            print(Fore.LIGHTCYAN_EX + f"\n[✓] Drozer result saved to '{result_file}'." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.LIGHTRED_EX + f"[X] Error with Drozer connection or command: {e}" + Style.RESET_ALL)

def drozer_ipc_test(device):
    print(Fore.LIGHTMAGENTA_EX + "\n[>] Starting Drozer IPC (Activity/Service/Provider/Receiver) Test..." + Style.RESET_ALL)
    result = subprocess.run(
        ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
        capture_output=True, text=True
    )
    packages = [line.replace("package:", "").strip() for line in result.stdout.splitlines()]
    if not packages:
        print(Fore.LIGHTRED_EX + "[X] No 3rd party applications found." + Style.RESET_ALL)
        return
    print(Fore.LIGHTMAGENTA_EX + "\nInstalled 3rd party applications:" + Style.RESET_ALL)
    for idx, pkg in enumerate(packages):
        print(Fore.LIGHTYELLOW_EX + f"{idx+1}: {pkg}" + Style.RESET_ALL)
    while True:
        try:
            sec = int(input(PROMPT_COLOR + ">>> Enter the number of the package you want to test IPC for: " + Style.RESET_ALL)) - 1
            if 0 <= sec < len(packages):
                package = packages[sec]
                break
        except ValueError:
            pass
        print(Fore.LIGHTRED_EX + "[X] Invalid selection." + Style.RESET_ALL)
    print(Fore.LIGHTYELLOW_EX + f"\n[>] Starting IPC tests with Drozer: {package}" + Style.RESET_ALL)
    try:
        proc = subprocess.Popen(
            ["drozer", "console", "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        commands = [
            f"run app.activity.info -a {package}",
            f"run app.service.info -a {package}",
            f"run app.provider.info -a {package}",
            f"run app.broadcast.info -a {package}",
            "exit"
        ]
        command_str = "\n".join(commands)
        out, err = proc.communicate(command_str, timeout=30)
        print(Fore.LIGHTGREEN_EX + "\n[✓] IPC Test Results:\n" + Style.RESET_ALL)
        print(out)
        result_dir = os.path.join("result", "drozer_results")
        os.makedirs(result_dir, exist_ok=True)
        result_file = os.path.join(result_dir, f"ipc_test_{package}.txt")
        with open(result_file, "w", encoding="utf-8") as f:
            f.write(out)
        print(Fore.LIGHTCYAN_EX + f"\n[✓] Drozer IPC test result saved to '{result_file}'." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.LIGHTRED_EX + f"[X] Error during Drozer IPC tests: {e}" + Style.RESET_ALL)

def drozer_attack_surface_menu(device):
    print(Fore.LIGHTMAGENTA_EX + "\n[>] Starting Drozer Attack Surface Analysis..." + Style.RESET_ALL)
    result = subprocess.run(
        ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
        capture_output=True, text=True
    )
    packages = [line.replace("package:", "").strip() for line in result.stdout.splitlines()]
    if not packages:
        print(Fore.LIGHTRED_EX + "[X] No 3rd party applications found." + Style.RESET_ALL)
        return
    print(Fore.LIGHTMAGENTA_EX  + "\nInstalled 3rd party applications:" + Style.RESET_ALL)
    for idx, pkg in enumerate(packages):
        print(Fore.LIGHTYELLOW_EX + f"{idx+1}: {pkg}" + Style.RESET_ALL)
    while True:
        try:
            sec = int(input(PROMPT_COLOR + ">>> Enter the number of the APK you want to analyze the attack surface for: " + Style.RESET_ALL)) - 1
            if 0 <= sec < len(packages):
                package = packages[sec]
                break
        except ValueError:
            pass
        print(Fore.LIGHTRED_EX + "[X] Invalid selection." + Style.RESET_ALL)
    try:
        proc = subprocess.Popen(
            ["drozer", "console", "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        commands = [
            f"run app.package.attacksurface -a {package}",
            f"run app.package.info -a {package}",
            f"run app.package.manifest -a {package}",
            f"run app.package.launchintent -a {package}",
            "exit"
        ]
        command_str = "\n".join(commands)
        out, err = proc.communicate(command_str, timeout=30)
        print(Fore.LIGHTYELLOW_EX + "\n[✓] Attack Surface Output:\n" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + out + Style.RESET_ALL)
        result_dir = os.path.join("result", "drozer_results")
        os.makedirs(result_dir, exist_ok=True)
        result_file = os.path.join(result_dir, f"attack_surface_{package}.txt")
        with open(result_file, "w", encoding="utf-8") as f:
            f.write(out)
        print(Fore.LIGHTCYAN_EX + f"\n[✓] Drozer attack surface result saved to '{result_file}'." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.LIGHTRED_EX + f"[X] Error during attack surface analysis: {e}" + Style.RESET_ALL)
        return

    try:
        proc = subprocess.Popen(
            ["drozer", "console", "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        commands = [
            f"run app.activity.info -a {package}",
            f"run app.service.info -a {package}",
            f"run app.provider.info -a {package}",
            f"run app.broadcast.info -a {package}",
            "exit"
        ]
        command_str = "\n".join(commands)
        out, err = proc.communicate(command_str, timeout=30)
        print(Fore.LIGHTCYAN_EX + "\n[✓] IPC Details:\n" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + out + Style.RESET_ALL)
        
        print(Fore.LIGHTMAGENTA_EX + "\n[✓] Exploitable ADB Commands:" + Style.RESET_ALL)
        
        activity_cmd = f"run app.activity.info -a {package} --exploits"
        proc = subprocess.Popen(
            ["drozer", "console", "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate(activity_cmd + "\nexit\n", timeout=30)
        
        activities = re.findall(r'(\S+) exported=true', out)
        if activities:
            print(Fore.LIGHTYELLOW_EX + "\n[>] Exported Activity Exploit Commands:" + Style.RESET_ALL)
            for activity in activities:
                act_name = activity.strip()
                if act_name:
                    print(PROMPT_COLOR1+ f"adb shell am start -n {package}/{act_name}" + Style.RESET_ALL)
        
        service_cmd = f"run app.service.info -a {package} --exploits"
        proc = subprocess.Popen(
            ["drozer", "console", "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate(service_cmd + "\nexit\n", timeout=30)
        
        services = re.findall(r'(\S+) exported=true', out)
        if services:
            print(Fore.LIGHTYELLOW_EX + "\n[>] Exported Service Exploit Commands:" + Style.RESET_ALL)
            for service in services:
                svc_name = service.strip()
                if svc_name:
                    print(PROMPT_COLOR1 + f"adb shell am startservice -n {package}/{svc_name}" + Style.RESET_ALL)
        
        provider_cmd = f"run app.provider.info -a {package} --exploits"
        proc = subprocess.Popen(
            ["drozer", "console", "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate(provider_cmd + "\nexit\n", timeout=30)
        
        providers = re.findall(r'(\S+) exported=true', out)
        if providers:
            print(Fore.LIGHTYELLOW_EX + "\n[>] Exported Provider Exploit Commands:" + Style.RESET_ALL)
            for provider in providers:
                prov_name = provider.strip()
                if prov_name:
                    print(Fore.LIGHTGREEN_EX + f"adb shell content query --uri content://{prov_name}" + Style.RESET_ALL)
                    print(Fore.LIGHTGREEN_EX + f"adb shell content insert --uri content://{prov_name} --bind name:s:value" + Style.RESET_ALL)
        
        broadcast_cmd = f"run app.broadcast.info -a {package} --exploits"
        proc = subprocess.Popen(
            ["drozer", "console", "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate(broadcast_cmd + "\nexit\n", timeout=30)
        
        broadcasts = re.findall(r'(\S+) exported=true', out)
        if broadcasts:
            print(Fore.LIGHTYELLOW_EX + "\n[>] Exported Broadcast Receiver Exploit Commands:" + Style.RESET_ALL)
            for broadcast in broadcasts:
                bc_name = broadcast.strip()
                if bc_name:
                    print(PROMPT_COLOR1+ f"adb shell am broadcast -n {package}/{bc_name}" + Style.RESET_ALL)
        
        browsable_cmd = f"run scanner.activity.browsable -a {package}"
        proc = subprocess.Popen(
            ["drozer", "console", "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate(browsable_cmd + "\nexit\n", timeout=30)
        
        intent_urls = re.findall(r'([\w]+://[^\s]+)', out)
        if intent_urls:
            print(Fore.LIGHTYELLOW_EX + "\n[>] Browsable Activity URL Exploit Commands:" + Style.RESET_ALL)
            for url in intent_urls:
                clean_url = url.strip()
                if clean_url:
                    print(PROMPT_COLOR1+ f"adb shell am start -a android.intent.action.VIEW -d \"{clean_url}\"" + Style.RESET_ALL)

    except Exception as e:
        print(Fore.LIGHTRED_EX + f"[X] Error while generating IPC details and exploit commands: {e}" + Style.RESET_ALL)
        return

    result_dir = os.path.join(os.getcwd(), "result")
    os.makedirs(result_dir, exist_ok=True)
    result_file = os.path.join(result_dir, f"{package}_attack_surface.txt")
    try:
        with open(result_file, "w", encoding="utf-8") as f:
            f.write(out)
        print(Fore.LIGHTCYAN_EX + f"\n[✓] Results saved to '{result_file}'." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.LIGHTRED_EX + f"[X] Error while saving results: {e}" + Style.RESET_ALL)

def print_deeplinks_and_adb(deeplinks, package):
    if deeplinks:
        print(Fore.LIGHTYELLOW_EX + "\n[✓] Deeplink/Web Intent found in Manifest:" + Style.RESET_ALL)
        for idx, d in enumerate(deeplinks, 1):
            activity = d['activity']
            for data in d['datas']:
                scheme = data.get('scheme')
                host = data.get('host')
                path = data.get('path')
                url = f"{scheme}://{host or ''}{path or ''}"
                print(Fore.LIGHTCYAN_EX + f"{idx}) {url}  -->  {activity}" + Style.RESET_ALL)
                print(Fore.LIGHTYELLOW_EX + "   For testing with ADB:")
                print(PROMPT_COLOR1+ f"   adb shell am start -a android.intent.action.VIEW -d \"{url}\" {package}/{activity}" + Style.RESET_ALL)
    else:
        print(Fore.LIGHTYELLOW_EX + "[!] No deeplink found in the manifest." + Style.RESET_ALL)
def load_blacklist(blacklist_path):
    if not os.path.exists(blacklist_path):
        return {}
    with open(blacklist_path, "r", encoding="utf-8") as f:
        return json.load(f)

def filter_blacklist(results, blacklist):
    filtered = []
    for result in results:
        regex_name = result.get("regex_name")
        match_val = result.get("match", "")
        if regex_name in blacklist:
            bl_val = blacklist[regex_name]
            if isinstance(bl_val, list):
                if any(b in match_val for b in bl_val):
                    continue
            else:
                if bl_val in match_val:
                    continue
        filtered.append(result)
    return filtered
def apk_attack_surface_analysis(device):
    print("\n" + "="*60)
    print("🔎  APK Attack Surface".center(60))
    print("="*60)
    def check_tools():
        apktool_path = shutil.which('apktool')
        if apktool_path is not None:
            return ['apktool']
        jar_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tool", "apktool", "apktool.jar")
        if os.path.exists(jar_path):
            return ['java', '-jar', jar_path]
        print("[X] apktool not found. Please install and add to PATH or ensure tool/apktool/apktool.jar exists.")
        sys.exit(1)
    def decompile_apk(apk_path, out_dir):
        print(f"[>] Decompiling APK: {apk_path}")
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        apktool_cmd = check_tools()
        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=show_spinner, args=("Decompiling, please wait...", stop_event))
        spinner_thread.start()
        result = subprocess.run(apktool_cmd + ['d', '-f', apk_path, '-o', out_dir], capture_output=True, text=True)
        stop_event.set()
        spinner_thread.join()
        if result.returncode != 0:
            print(result.stderr)
            sys.exit(1)
        print("[✓] Decompile completed.")

    def parse_manifest(manifest_path):
        print(Fore.LIGHTYELLOW_EX + f"[>] Analyzing AndroidManifest.xml: {manifest_path}" + Style.RESET_ALL)
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package = root.attrib.get('package')
        components = {'activity': [], 'service': [], 'receiver': [], 'provider': []}
        application = root.find("application")
        debug_risk = None
        backup_risk = None
        cleartext_risk = None
        network_security_config = None
        trust_anchors = False
        if application is not None:
            debuggable = application.attrib.get('{http://schemas.android.com/apk/res/android}debuggable')
            allow_backup = application.attrib.get('{http://schemas.android.com/apk/res/android}allowBackup')
            uses_cleartext = application.attrib.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
            network_security_config = application.attrib.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig')
            debug_risk = debuggable == "true"
            backup_risk = (allow_backup is None or allow_backup == "true")
            cleartext_risk = uses_cleartext == "true"
            if network_security_config:
                manifest_dir = os.path.dirname(manifest_path)
                config_path = os.path.join(manifest_dir, network_security_config)
                if os.path.exists(config_path):
                    try:
                        ns_tree = ET.parse(config_path)
                        ns_root = ns_tree.getroot()
                        for elem in ns_root.iter():
                            if elem.tag.endswith("trust-anchors"):
                                trust_anchors = True
                                break
                    except Exception:
                        pass
        permissions = []
        for perm in root.findall("uses-permission"):
            name = perm.attrib.get('{http://schemas.android.com/apk/res/android}name')
            if name:
                permissions.append(name)
        for comp in components.keys():
            for elem in root.findall(f".//{comp}"):
                name = elem.attrib.get('{http://schemas.android.com/apk/res/android}name')
                exported = elem.attrib.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                components[comp].append({'name': name, 'exported': exported})
        print(Fore.LIGHTGREEN_EX + f"[✓] Package name: {package}" + Style.RESET_ALL)
        for comp, items in components.items():
            exported_items = [c for c in items if c['exported'] == 'true']
            print(Fore.LIGHTCYAN_EX + f"\n[>] Exported {comp.capitalize()} list:" + Style.RESET_ALL)
            if exported_items:
                for c in exported_items:
                    print(Fore.LIGHTRED_EX + "    " + c['name'] + Fore.LIGHTGREEN_EX + " (exported=true)" + Style.RESET_ALL)
            else:
                print(Fore.LIGHTYELLOW_EX + "    (None)" + Style.RESET_ALL)
        print(Fore.LIGHTCYAN_EX + "\n[>] Debuggable/Backup Risk:" + Style.RESET_ALL)
        if debug_risk:
            print(Fore.LIGHTRED_EX + "      android:debuggable=\"true\" found! (Should NOT be present in production)" + Style.RESET_ALL)
        else:
            print(Fore.LIGHTGREEN_EX + "    android:debuggable=\"true\" not found." + Style.RESET_ALL)
        if backup_risk:
            print(Fore.LIGHTRED_EX + "      android:allowBackup=\"true\" (or missing, default is true)! Data can be backed up via ADB." + Style.RESET_ALL)
        else:
            print(Fore.LIGHTGREEN_EX + "    android:allowBackup=\"false\" set. (Good)" + Style.RESET_ALL)
        print(Fore.LIGHTCYAN_EX + "\n[>] Network Security Risk:" + Style.RESET_ALL)
        if cleartext_risk:
            print(Fore.LIGHTRED_EX + "      android:usesCleartextTraffic=\"true\" found! (Allows HTTP traffic)" + Style.RESET_ALL)
        else:
            print(Fore.LIGHTGREEN_EX + "    android:usesCleartextTraffic=\"true\" not found." + Style.RESET_ALL)
        if network_security_config:
            print(Fore.LIGHTYELLOW_EX + f"    networkSecurityConfig defined: {network_security_config}" + Style.RESET_ALL)
            if trust_anchors:
                print(Fore.LIGHTRED_EX + "      <trust-anchors> found in networkSecurityConfig! (Custom CA may be used)" + Style.RESET_ALL)
            else:
                print(Fore.LIGHTGREEN_EX + "    <trust-anchors> not found in networkSecurityConfig." + Style.RESET_ALL)
        else:
            print(Fore.LIGHTGREEN_EX + "    networkSecurityConfig not defined." + Style.RESET_ALL)
        print(Fore.LIGHTCYAN_EX + "\n[>] Permissions:" + Style.RESET_ALL)
        critical_permissions = {
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.CALL_PHONE",
            "android.permission.GET_ACCOUNTS",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.BODY_SENSORS",
            "android.permission.USE_SIP",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET", 
            "android.permission.NFC",
        }
        for perm in permissions:
            if perm in critical_permissions:
                print(Fore.LIGHTRED_EX + "      " + perm + Style.RESET_ALL)
            else:
                print(Fore.LIGHTGREEN_EX + "    " + perm + Style.RESET_ALL)
        if not permissions:
            print(Fore.LIGHTGREEN_EX + "    (No permissions found)" + Style.RESET_ALL)
        return package, components, debug_risk, backup_risk, permissions, cleartext_risk, network_security_config, trust_anchors

    def find_deeplinks(manifest_path):
        print("\n[>] Analyzing Deeplink/Web Intent in Manifest...")
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        deeplinks = []
        for activity in root.findall(".//activity"):
            activity_name = activity.attrib.get('{http://schemas.android.com/apk/res/android}name')
            for intent_filter in activity.findall("intent-filter"):
                datas = []
                for data in intent_filter.findall("data"):
                    scheme = data.attrib.get('{http://schemas.android.com/apk/res/android}scheme')
                    host = data.attrib.get('{http://schemas.android.com/apk/res/android}host')
                    path = data.attrib.get('{http://schemas.android.com/apk/res/android}path')
                    if scheme:
                        datas.append({'scheme': scheme, 'host': host, 'path': path})
                if datas:
                    deeplinks.append({'activity': activity_name, 'datas': datas})
        return deeplinks

    def generate_adb_commands(package, components):
        print(Fore.LIGHTYELLOW_EX + "\n[✓] Automatic ADB Exploit Commands:" + Style.RESET_ALL)
        unique_commands = set()
        for comp_type, items in components.items():
            exported_items = [c for c in items if c['exported'] == 'true']
            if exported_items:
                print(Fore.LIGHTCYAN_EX + f"\n[>] Exported {comp_type.capitalize()} Commands:" + Style.RESET_ALL)
                for c in exported_items:
                    if comp_type == 'activity':
                        cmd = f"adb shell am start -n {package}/{c['name']}"
                    elif comp_type == 'service':
                        cmd = f"adb shell am startservice -n {package}/{c['name']}"
                    elif comp_type == 'receiver':
                        cmd = f"adb shell am broadcast -n {package}/{c['name']}"
                    elif comp_type == 'provider':
                        cmd = f"adb shell content query --uri content://{c['name']}"
                    if cmd not in unique_commands:
                        unique_commands.add(cmd)
                        print(PROMPT_COLOR1 + f"   {cmd}" + Style.RESET_ALL)
        if not unique_commands:
            print(Fore.LIGHTYELLOW_EX + "   No exported components found." + Style.RESET_ALL)
    
    print(PROMPT_COLOR1 + "\n1) List and select APKs installed on the device" + Style.RESET_ALL)
    print(PROMPT_COLOR1 + "2) Enter APK path from file" + Style.RESET_ALL)
    secim = input(PROMPT_COLOR + ">>> Your choice (1/2): " + Style.RESET_ALL)
    apk_path = None
    if secim == "1":
        result = subprocess.run(
            ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
            capture_output=True, text=True
        )
        pkgs = [line.replace("package:", "").strip() for line in result.stdout.strip().splitlines()]
        if not pkgs:
            print(Fore.LIGHTRED_EX + "[X] No 3rd party applications found." + Style.RESET_ALL)
            return
        print(Fore.LIGHTMAGENTA_EX + "[i] Installed 3rd party applications:" + Style.RESET_ALL)
        for idx, pkg in enumerate(pkgs):
            print(Fore.LIGHTYELLOW_EX + f"{idx+1}: {pkg}" + Style.RESET_ALL)
        while True:
            try:
                sec = int(input(PROMPT_COLOR + "Enter the number of the APK you want to decompile: " + Style.RESET_ALL)) - 1
                if 0 <= sec < len(pkgs):
                    package_name = pkgs[sec]
                    path_result = subprocess.run(
                        ["adb", "-s", device, "shell", "pm", "path", package_name],
                        capture_output=True, text=True
                    )
                    apk_paths = [line.replace("package:", "").strip() for line in path_result.stdout.strip().splitlines()]
                    if not apk_paths:
                        print_error("APK path not found.")
                        return
                    apk_on_device = apk_paths[0]
                    local_apk = f"{package_name}.apk"
                    print_info(f"Pulling APK from device: {apk_on_device} -> {local_apk}")
                    pull_result = subprocess.run(
                        ["adb", "-s", device, "pull", apk_on_device, local_apk]
                    )
                    if pull_result.returncode != 0 or not os.path.exists(local_apk):
                        print_error("APK file could not be pulled.")
                        return
                    apk_path = local_apk
                    break
            except ValueError:
                pass
            print_error("Invalid selection.")
    elif secim == "2":
        apk_path = input(Fore.LIGHTYELLOW_EX + "Enter the APK file path: " + Style.RESET_ALL).strip()
    else:
        print(Fore.LIGHTRED_EX + "[X] Invalid selection." + Style.RESET_ALL)
        return
    if not apk_path or not os.path.exists(apk_path):
        print("[X] APK file not found.")
        return
    check_tools()
    temp_out_dir = tempfile.mkdtemp(prefix="apk_decompile_")
    if os.path.exists(temp_out_dir):
        shutil.rmtree(temp_out_dir)
    decompile_apk(apk_path, temp_out_dir)
    manifest_path = os.path.join(temp_out_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        print("[X] AndroidManifest.xml not found.")
        shutil.rmtree(temp_out_dir)
        return
    package, components, debug_risk, backup_risk, permissions, cleartext_risk, network_security_config, trust_anchors = parse_manifest(manifest_path)
    decompiled_save_dir = os.path.join("decompiled_data", package if package else "unknown_package")
    if os.path.exists(decompiled_save_dir):
        shutil.rmtree(decompiled_save_dir)
    shutil.move(temp_out_dir, decompiled_save_dir)
    manifest_path = os.path.join(decompiled_save_dir, "AndroidManifest.xml")
    deeplinks = find_deeplinks(manifest_path)
    print_deeplinks_and_adb(deeplinks, package)
    generate_adb_commands(package, components)
    summary_dir = os.path.join("result", package if package else "unknown_package")
    os.makedirs(summary_dir, exist_ok=True)
    summary_file = os.path.join(summary_dir, "apk_attack_surface.txt")
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(f"APK Attack Surface Analysis for {package}\n")
        f.write(f"Decompiled path: {decompiled_save_dir}\n")
        f.write("Exported Components:\n")
        for comp, items in components.items():
            exported_items = [c for c in items if c['exported'] == 'true']
            f.write(f"  {comp}: {[c['name'] for c in exported_items]}\n")
        f.write("\nDeeplinks:\n")
        for d in deeplinks:
            f.write(str(d) + "\n")
        f.write("\nDebuggable/Backup Risk:\n")
        if debug_risk:
            f.write("  [!] android:debuggable=\"true\" found! (Should NOT be present in production)\n")
        else:
            f.write("  android:debuggable=\"true\" not found.\n")
        if backup_risk:
            f.write("  [!] android:allowBackup=\"true\" (or missing, default is true)! Data can be backed up via ADB.\n")
        else:
            f.write("  android:allowBackup=\"false\" set. (Good)\n")
        f.write("\nNetwork Security Risk:\n")
        if cleartext_risk:
            f.write("  [!] android:usesCleartextTraffic=\"true\" found! (Allows HTTP traffic)\n")
        else:
            f.write("  android:usesCleartextTraffic=\"true\" not found.\n")
        if network_security_config:
            f.write(f"  networkSecurityConfig defined: {network_security_config}\n")
            if trust_anchors:
                f.write("  [!] <trust-anchors> found in networkSecurityConfig! (Custom CA may be used)\n")
            else:
                f.write("  <trust-anchors> not found in networkSecurityConfig.\n")
        else:
            f.write("  networkSecurityConfig not defined.\n")
        f.write("\nPermissions:\n")
        critical_permissions = {
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.CALL_PHONE",
            "android.permission.GET_ACCOUNTS",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.BODY_SENSORS",
            "android.permission.USE_SIP",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET", 
            "android.permission.NFC",
        }
        for perm in permissions:
            if perm in critical_permissions:
                f.write(f"  [CRITICAL] {perm}\n")
            else:
                f.write(f"  {perm}\n")
        if not permissions:
            f.write("  (No permissions found)\n")
    print(Fore.LIGHTGREEN_EX + f"[✓] Decompiled APK saved to '{decompiled_save_dir}'." + Style.RESET_ALL)
    print(Fore.LIGHTCYAN_EX + f"[✓] Attack surface result saved to '{summary_file}'." + Style.RESET_ALL)
    print("\n" + "="*60)
    print("Analysis completed.".center(60))
    print("="*60)

def search_with_regexes_in_dir(directory, regex_json_path):
    import json
    import re
    results = []
   
    with open(regex_json_path, "r", encoding="utf-8") as f:
        regex_rules = json.load(f)
  
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.java', '.xml', '.kt', '.smali', '.txt', '.properties')):
                file_list.append(os.path.join(root, file))
    
    for file_path in tqdm(file_list, desc="Regex search", ncols=80, colour="cyan"):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
                for name, pattern in regex_rules.items():
                    if isinstance(pattern, list):
                        for pat in pattern:
                            for match in re.finditer(pat, content, re.MULTILINE):
                                start_idx = match.start()
                                line_num = content.count('\n', 0, start_idx) + 1
                                matched_line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                                results.append({
                                    "file": file_path,
                                    "regex_name": name,
                                    "pattern": pat,
                                    "match": match.group(),
                                    "start": match.start(),
                                    "end": match.end(),
                                    "line_number": line_num,
                                    "line": matched_line
                                })
                    else:
                        for match in re.finditer(pattern, content, re.MULTILINE):
                            start_idx = match.start()
                            line_num = content.count('\n', 0, start_idx) + 1
                            matched_line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                            results.append({
                                "file": file_path,
                                "regex_name": name,
                                "pattern": pattern,
                                "match": match.group(),
                                "start": match.start(),
                                "end": match.end(),
                                "line_number": line_num,
                                "line": matched_line
                            })
        except Exception:
            continue
    return results
def install_latest_drozer_wheel():
    import sys
    import subprocess
    import tempfile
    import shutil
    import requests
    import os

    api_url = "https://api.github.com/repos/ReversecLabs/drozer/releases/latest"
    print("[>] Searching for the latest Drozer wheel file...")
    r = requests.get(api_url)
    if r.status_code != 200:
        print("[X] Could not retrieve version information from GitHub API.")
        return
    data = r.json()
    assets = data.get("assets", [])
    wheel_url = None
    wheel_name = None
    for asset in assets:
        if asset["name"].endswith(".whl"):
            wheel_url = asset["browser_download_url"]
            wheel_name = asset["name"]
            break
    if not wheel_url or not wheel_name:
        print("[X] Wheel file not found.")
        return

    print("[>] Downloading Drozer wheel: %s" % wheel_url)
    tmp_dir = tempfile.mkdtemp()
    wheel_path = os.path.join(tmp_dir, wheel_name)
    try:
        r = requests.get(wheel_url, stream=True)
        if r.status_code == 200:
            with open(wheel_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("[>] Installing...")
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", wheel_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print(Fore.LIGHTGREEN_EX + "[✓] Drozer wheel installed.")
        else:
            print(Fore.LIGHTRED_EX + "[X] Wheel file could not be downloaded." + Style.RESET_ALL)
    except Exception as e:
        print(f"[X] Error during installation: {e}")
    finally:
        shutil.rmtree(tmp_dir)

def analyze_app_data_with_regex(device):
    import tempfile

    result = subprocess.run(
        ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
        capture_output=True, text=True
    )
    packages = [line.replace("package:", "").strip() for line in result.stdout.splitlines()]
    if not packages:
        print("[X] No 3rd party applications found.")
        return
    print(Fore.LIGHTMAGENTA_EX  + "\nInstalled 3rd party applications:" + Style.RESET_ALL)
    for idx, pkg in enumerate(packages):
        print(Fore.LIGHTYELLOW_EX+ f"{idx+1}: {pkg}" + Style.RESET_ALL)
    while True:
        try:
            sec = int(input(PROMPT_COLOR + "Enter the number of the package you want to analyze: " + Style.RESET_ALL)) - 1
            if 0 <= sec < len(packages):
                package = packages[sec]
                break
        except ValueError:
            pass
        print("[X] Invalid selection.")

    temp_dir = tempfile.mkdtemp(prefix="android_analyzer_")
    local_path = os.path.join(temp_dir, package)
    remote_path = f"/data/data/{package}"
    print(Fore.LIGHTYELLOW_EX + f"\n[>] Pulling entire package: {remote_path} ..." + Style.RESET_ALL)
    subprocess.run(["adb", "-s", device, "pull", remote_path, local_path])
    print(Fore.LIGHTGREEN_EX + f"[✓] Package pulled: {local_path}\n" + Style.RESET_ALL)

    def is_sqlite_file(file_path):
        try:
            with open(file_path, "rb") as f:
                return f.read(16).startswith(b"SQLite format 3")
        except:
            return False

    def is_elf_file(file_path):
        try:
            with open(file_path, "rb") as f:
                return f.read(4) == b"\x7fELF"
        except:
            return False

    def analyze_sqlite(file_path):
        import sqlite3
        result = {"type": "sqlite", "tables": [], "file": file_path}
        try:
            conn = sqlite3.connect(file_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            for table in tables:
                table_name = table[0]
                table_data = {"table": table_name, "rows": []}
                try:
                    cursor.execute(f"SELECT * FROM {table_name}")
                    for row in cursor.fetchall():
                        table_data["rows"].append(list(row))
                except Exception as e:
                    table_data["error"] = str(e)
                result["tables"].append(table_data)
            conn.close()
        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_elf(file_path):
        result = {"type": "elf", "file": file_path}
        try:
            from elftools.elf.elffile import ELFFile
            import re
            strings = set()
            with open(file_path, "rb") as f:
                elffile = ELFFile(f)
                for section in elffile.iter_sections():
                    try:
                        data = section.data()
                    except Exception:
                        continue
                    found = re.findall(rb"[ -~]{4,}", data)
                    for s in found:
                        try:
                            strings.add(s.decode("utf-8", errors="replace"))
                        except Exception:
                            continue
            result["strings"] = sorted(strings)
        except Exception as e:
            result["error"] = str(e)
        return result

    def display_file(file_path):
        result = {"type": "text", "file": file_path}
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                result["content"] = f.read()
        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_path_json(path):
        results = []
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    results.extend(analyze_path_json(file_path))
        else:
            if is_sqlite_file(path):
                results.append(analyze_sqlite(path))
            elif is_elf_file(path):
                results.append(analyze_elf(path))
            else:
                results.append(display_file(path))
        return results

    def bytes_to_str(obj):
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")
        if isinstance(obj, dict):
            return {k: bytes_to_str(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [bytes_to_str(i) for i in obj]
        if isinstance(obj, tuple):
            return tuple(bytes_to_str(i) for i in obj)
        return obj

    print(Fore.LIGHTYELLOW_EX + "[>] Starting analysis...")
    results = analyze_path_json(local_path)
    results = bytes_to_str(results)

    print(Fore.LIGHTGREEN_EX + "[✓] Analysis completed." + Style.RESET_ALL)
    regex_json_path = os.path.join("config", "regex.json")
    try:
        with open(regex_json_path, "r", encoding="utf-8") as f:
            regex_rules = json.load(f)
    except Exception as e:
        print(f"[X] Could not read regex file: {e}")
        return
    def find_matches_in_text(text, regex_rules):
        matches = []
        lines = text.splitlines()
        for name, pattern in regex_rules.items():
            if isinstance(pattern, list):
                for pat in pattern:
                    for match in re.finditer(pat, text, re.MULTILINE):
                        start_idx = match.start()
                        line_num = text.count('\n', 0, start_idx) + 1
                        matched_line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                        matches.append({
                            "regex_name": name,
                            "pattern": pat,
                            "match": match.group(),
                            "start": match.start(),
                            "end": match.end(),
                            "line_number": line_num,
                            "line": matched_line
                        })
            else:
                for match in re.finditer(pattern, text, re.MULTILINE):
                    start_idx = match.start()
                    line_num = text.count('\n', 0, start_idx) + 1
                    matched_line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                    matches.append({
                        "regex_name": name,
                        "pattern": pattern,
                        "match": match.group(),
                        "start": match.start(),
                        "end": match.end(),
                        "line_number": line_num,
                        "line": matched_line
                    })
        return matches

    def recursive_search(obj, regex_rules, path="", file_path=None):
        results = []
        if isinstance(obj, dict):
            if "file" in obj:
                file_path = obj["file"]
            for k, v in obj.items():
                results += recursive_search(v, regex_rules, f"{path}.{k}" if path else k, file_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                results += recursive_search(item, regex_rules, f"{path}[{idx}]", file_path)
        elif isinstance(obj, str):
            found = find_matches_in_text(obj, regex_rules)
            for match in found:
                match['file'] = file_path if file_path else path
            results += found
        return results

    matches = recursive_search(results, regex_rules)
    blacklist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "blakclist.json")
    blacklist = load_blacklist(blacklist_path)
    matches = filter_blacklist(matches, blacklist)
    
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result", "data_data_analyze")
    os.makedirs(results_dir, exist_ok=True)
    regex_json_path = os.path.join(results_dir, f"regex_analysis_{package}.json")
    with open(regex_json_path, "w", encoding="utf-8") as f:
        json.dump(matches, f, ensure_ascii=False, indent=2)
    print(Fore.LIGHTGREEN_EX + f"[✓] Regex results saved to {regex_json_path}." + Style.RESET_ALL)
    group_counts = Counter([result["regex_name"] for result in matches])
    all_groups = sorted(regex_rules.keys())
    print(Fore.LIGHTCYAN_EX + "+" + "-"*32 + "+" + "-"*8 + "+" + Style.RESET_ALL)
    print(Fore.LIGHTCYAN_EX + f"| {'NAME':<30} | {'Count':<6} |" + Style.RESET_ALL)
    print(Fore.LIGHTCYAN_EX + "+" + "-"*32 + "+" + "-"*8 + "+" + Style.RESET_ALL)
    for group in all_groups:
        count = group_counts.get(group, 0)
        if count > 0:  
            print(Fore.LIGHTYELLOW_EX + f"| {group:<30} | {count:<6} |" + Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX + "+" + "-"*32 + "+" + "-"*8 + "+" + Style.RESET_ALL)
def dump_app_data_only(device):
    result = subprocess.run(
        ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
        capture_output=True, text=True
    )
    packages = [line.replace("package:", "").strip() for line in result.stdout.splitlines()]
    if not packages:
        print(Fore.LIGHTRED_EX + "[X] No 3rd party applications found." + Style.RESET_ALL)
        return
    print(Fore.LIGHTMAGENTA_EX + "\nInstalled 3rd party applications:" + Style.RESET_ALL)
    for idx, pkg in enumerate(packages):
        print(Fore.LIGHTYELLOW_EX + f"{idx+1}: {pkg}" + Style.RESET_ALL)
    while True:
        try:
            sec = int(input(PROMPT_COLOR + "Enter the number of the package you want to dump: " + Style.RESET_ALL)) - 1
            if 0 <= sec < len(packages):
                package = packages[sec]
                break
        except ValueError:
            pass
        print(Fore.LIGHTRED_EX + "[X] Invalid selection." + Style.RESET_ALL)
    local_dir = os.path.join(os.getcwd(), "dumped_data", package)
    os.makedirs(local_dir, exist_ok=True)
    print(Fore.LIGHTYELLOW_EX + f"[>] Retrieving file list: /data/data/{package}" + Style.RESET_ALL)
    find_cmd = [
        "adb", "-s", device, "shell", "find", f"/data/data/{package}", "-type", "f"
    ]
    result = subprocess.run(find_cmd, capture_output=True, text=True)
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not files:
        print(Fore.LIGHTRED_EX + "[X] No files found or access denied." + Style.RESET_ALL)
        return
    print(Fore.LIGHTYELLOW_EX + f"[>] Pulling {len(files)} files..." + Style.RESET_ALL)
    dumped_files = [] 
    for f in tqdm(files, desc="Pulling", unit="file", ncols=80, colour="cyan"):
        rel_path = os.path.relpath(f, f"/data/data/{package}")
        local_path = os.path.join(local_dir, rel_path)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        pull_cmd = [
            "adb", "-s", device, "shell", "su", "-c", f"cat {f}"
        ]
        with open(local_path, "wb") as out_file:
            proc = subprocess.run(pull_cmd, capture_output=True)
            out_file.write(proc.stdout)
        dumped_files.append(local_path)  
    print(Fore.LIGHTGREEN_EX + f"[✓] Dump completed! Folder: {local_dir}" + Style.RESET_ALL)
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result", "data_data_analyze")
    os.makedirs(results_dir, exist_ok=True)
    json_path = os.path.join(results_dir, f"file_folder_name_{package}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dumped_files, f, indent=2, ensure_ascii=False) 
    print(Fore.LIGHTGREEN_EX + f"[✓] Results saved to {json_path}." + Style.RESET_ALL)

def show_package_info(device):
    """
    Shows summary information of the selected package from dumpsys output.
    """
    pkgs = list_adb_packages(device)
    if not pkgs:
        print(Fore.LIGHTRED_EX + "No ADB devices connected." + Style.RESET_ALL)
        exit(1)
    print(Fore.LIGHTMAGENTA_EX + "\nInstalled 3rd party applications:" + Style.RESET_ALL)
    for idx, pkg in enumerate(pkgs):
        print(Fore.LIGHTYELLOW_EX + f"{idx+1}: {pkg}" + Style.RESET_ALL)
    while True:
        try:
            sec = int(input(PROMPT_COLOR + "Enter the number of the package you want to inspect: " + Style.RESET_ALL)) - 1
            if 0 <= sec < len(pkgs):
                package = pkgs[sec]
                break
            else:
                print(Fore.LIGHTRED_EX + "Invalid selection.")
        except ValueError:
            print(Fore.LIGHTRED_EX + "Invalid input.")

    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "dumpsys", "package", package]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout:
        print(Fore.LIGHTRED_EX + "Could not retrieve dumpsys output.")
        return

    out = result.stdout

    patterns = {
        "Package name": r"Package \[([^\]]+)\]",
        "Version": r"versionName=([^\s]+)",
        "VersionCode": r"versionCode=(\d+)",
        "Installer": r"installerPackageName=([^\s]+)",
        "Data Dir": r"dataDir=([^\s]+)",
        "UID": r"userId=(\d+)",
        "Enabled": r"enabled=(true|false)",
        "First Install": r"firstInstallTime=([^\n]+)",
        "Last Update": r"lastUpdateTime=([^\n]+)",
        "Target SDK": r"targetSdk=(\d+)",
        "Min SDK": r"minSdk=(\d+)",
        "Flags": r"flags=\[([^\]]+)\]",
    }
    print(Fore.LIGHTYELLOW_EX + "="*60)
    print(Fore.LIGHTCYAN_EX + f"  {package} Basic Information".center(60))
    print(Fore.LIGHTYELLOW_EX + "="*60 + Style.RESET_ALL)
    for key, pat in patterns.items():
        m = re.search(pat, out)
        if m:
            print(Fore.LIGHTGREEN_EX + f"{key:18}: " + Fore.WHITE + f"{m.group(1)}")

    declared = re.findall(r"declared permissions:\s*((?:\s+\S+:.*\n)+)", out)
    if declared:
        print(Fore.LIGHTMAGENTA_EX + "\n[Declared Permissions]" + Style.RESET_ALL)
        for line in declared[0].splitlines():
            print(Fore.WHITE + "  " + line.strip())

    perm_match = re.search(r"requested permissions:(.*?)install permissions:", out, re.DOTALL)
    permissions = []
    if perm_match:
        permissions = [p.strip() for p in perm_match.group(1).splitlines() if p.strip()]
    print(Fore.LIGHTMAGENTA_EX + "\n[Requested Permissions]" + Style.RESET_ALL)
    critical_permissions = {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.CALL_PHONE",
        "android.permission.GET_ACCOUNTS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BODY_SENSORS",
        "android.permission.USE_SIP",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.INTERNET", 
        "android.permission.NFC",      
      
    }
    if permissions:
        for p in permissions:
            perm_name = p.split(":")[0].strip()
            if perm_name in critical_permissions:
                print(Fore.LIGHTRED_EX + "  " + p + Style.RESET_ALL)
            else:
                print("  " + p + Style.RESET_ALL)
    else:
        print(Fore.LIGHTRED_EX + "  (None)")

    install_perm = re.findall(r"install permissions:\s*((?:\s+\S+:.*\n)+)", out)
    if install_perm:
        print(Fore.LIGHTMAGENTA_EX + "\n[Install Permissions]" + Style.RESET_ALL)
        for line in install_perm[0].splitlines():
            print(Fore.WHITE + "  " + line.strip())

    exported = {"activity": [], "service": [], "receiver": [], "provider": []}
    for comp in exported.keys():
        regex = rf"{comp}s:(.*?)(?:\n\S|$)"
        match = re.search(regex, out, re.DOTALL)
        if match:
            lines = match.group(1).splitlines()
            for line in lines:
                if "exported=true" in line:
                    name = line.strip().split(" ")[0]
                    exported[comp].append(name)
    if any(exported.values()):
        print(Fore.LIGHTMAGENTA_EX + "\n[Exported Components]" + Style.RESET_ALL)
        for comp, items in exported.items():
            if items:
                print(Fore.LIGHTCYAN_EX + f"  {comp.capitalize():10}:" + Style.RESET_ALL)
                for i in items:
                    if "(exported=true)" in i:
                        name_part = i.split(" (exported=true)")[0]
                        print(
                            Fore.LIGHTYELLOW_EX + "    " + name_part +
                            " " + Fore.LIGHTRED_EX + "(exported=true)" + Style.RESET_ALL
                        )
                    else:
                        print(Fore.LIGHTYELLOW_EX + "    " + i + Style.RESET_ALL)
            else:
                print(Fore.LIGHTCYAN_EX + f"  {comp.capitalize():10}: " + Fore.LIGHTRED_EX + "(None)" + Style.RESET_ALL)

    providers = re.findall(r"Registered ContentProviders:(.*?)(?:\n\S|$)", out, re.DOTALL)
    if providers:
        print(Fore.LIGHTMAGENTA_EX + "\n[Registered ContentProviders]" + Style.RESET_ALL)
        for line in providers[0].splitlines():
            if line.strip():
                print(Fore.WHITE + "  " + line.strip())

    main_activity = re.search(r"android.intent.action.MAIN:(.*?)(?:\n\S|$)", out, re.DOTALL)
    if main_activity:
        print(Fore.LIGHTMAGENTA_EX + "\n[Main Activities]" + Style.RESET_ALL)
        for line in main_activity.group(1).splitlines():
            print(Fore.WHITE + "  " + line.strip() + Style.RESET_ALL)

    receiver_table = re.search(r"Receiver Resolver Table:(.*?)(?:\n\S|$)", out, re.DOTALL)
    if receiver_table:
        print(Fore.LIGHTMAGENTA_EX + "\n[Receiver Resolver Table]" + Style.RESET_ALL)
        for line in receiver_table.group(1).splitlines():
            l = line.strip()
            if not l:
                continue
            if l.endswith(":"):
                print(Fore.LIGHTCYAN_EX + "  " + l + Style.RESET_ALL)
            elif l.startswith("Action:") or l.startswith("Category:"):
                print(Fore.WHITE + "    " + l + Style.RESET_ALL)
            else:
                print(Fore.LIGHTYELLOW_EX + "    " + l + Style.RESET_ALL)

    print(Fore.LIGHTYELLOW_EX + "="*60 + Style.RESET_ALL)

def list_adb_packages(device):
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "pm", "list", "packages", "-3"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    pkgs = [line.replace("package:", "").strip() for line in result.stdout.strip().splitlines()]
    return pkgs

def main():
    devices = list_adb_devices()
    if not devices:
        print(Fore.LIGHTRED_EX + "[X] No ADB devices connected." + Style.RESET_ALL)
        exit(1)
    selected_device = choose_device(devices)
   
    while True:
        print(Fore.LIGHTMAGENTA_EX + "\n=== MENU ===" + Style.RESET_ALL)
        print("1) Environment Config Setup (Burp Proxy,Burp Certificate)" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " Burp Proxy Settings" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " Burp Certificate Installation" + Style.RESET_ALL)
        print("2) Drozer Tools" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " Install and Configure Drozer APK" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " Connect and Recon with Drozer Console" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " Drozer IPC (Activity/Service/Provider/Receiver) Tests" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   └─" + Style.RESET_ALL + Fore.WHITE + " Drozer Attack Surface & Quick Test Menu" + Style.RESET_ALL)
        print("3) Analysis Tools" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " Pull Application Data (/data/data)" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " APK Attack Surface" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " Decompile Search and Secretkey Search" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " /data/data/<package> Regex Analysis" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   └─" + Style.RESET_ALL + Fore.WHITE + " Application Package Information (dumpsys)" + Style.RESET_ALL)
        print("4) Frida Tools " + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " Frida-Server Installation" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "   ├─" + Style.RESET_ALL + Fore.WHITE + " Run Frida Script" + Style.RESET_ALL)
        print("5) APK Build & Sign (Manual Patch) " + Style.RESET_ALL)
        print("6) Exit" + Style.RESET_ALL)
        print(PROMPT_COLOR + "For multiple steps, separate with commas (e.g., 1,2,3)" + Style.RESET_ALL)
        secim = input(PROMPT_COLOR1 + ">>> Your choice (e.g., 1 or 1,2,3): " + Style.RESET_ALL)
        adimlar = [s.strip() for s in secim.split(",") if s.strip().isdigit()]
        if not adimlar:
            print_error("Invalid selection, try again.")
            continue
        for adim in adimlar:
            if adim == "1":
                set_proxy(selected_device)
                install_burp_cert(selected_device)
            elif adim == "2":
                drozer_menu_exit = False
                while not drozer_menu_exit:
                    print(Fore.LIGHTYELLOW_EX + "\n===== Drozer Tools =====" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "1) Install and Configure Drozer APK" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "2) Connect and Recon with Drozer Console" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "3) Drozer IPC (Activity/Service/Provider/Receiver) Tests" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "4) Drozer Attack Surface & Quick Test Menu" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "5) Go Back" + Style.RESET_ALL)
                    print(Fore.LIGHTGREEN_EX + "-"*40 + Style.RESET_ALL)
                    drozer_secim = input(PROMPT_COLOR + ">>> Select Drozer step (e.g., 1 or 1,2,3): " + Style.RESET_ALL)
                    drozer_adimlar = [s.strip() for s in drozer_secim.split(",") if s.strip().isdigit()]
                    if not drozer_adimlar:
                        print_error("Invalid selection, try again.")
                        continue
                    for d_adim in drozer_adimlar:
                        if d_adim == "1":
                            install_latest_drozer_wheel()
                            apk_path = download_drozer_agent_latest()
                            if apk_path:
                                install_drozer_apk(selected_device, apk_path)
                                forward_tcp_port(selected_device)
                        elif d_adim == "2":
                            drozer_console_connect(selected_device)
                        elif d_adim == "3":
                            drozer_ipc_test(selected_device)
                        elif d_adim == "4":
                            drozer_attack_surface_menu(selected_device)
                        elif d_adim == "5":
                            drozer_menu_exit = True
                            break
                        else:
                            print_error(f"Invalid selection: {d_adim}")
                break
            elif adim == "3":
                analysis_menu_exit = False
                while not analysis_menu_exit:
                    print(Fore.LIGHTYELLOW_EX + "\n===== Analysis Tools =====" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "1) Pull Application Data (/data/data)" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "2) APK Attack Surface" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "3) Decompile Search and Secret Search" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "4) /data/data/<package> Regex Analysis" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "5) Application Package Information (dumpsys)" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "6) Go Back" + Style.RESET_ALL)
                    print(Fore.LIGHTGREEN_EX + "-"*40 + Style.RESET_ALL)
                    analiz_secim = input(PROMPT_COLOR + ">>> Select analysis step (1/2/3/4/5/6): " + Style.RESET_ALL)
                    analiz_adimlar = [s.strip() for s in analiz_secim.split(",") if s.strip().isdigit()]
                    if not analiz_adimlar:
                        print_error("Invalid selection, try again.")
                        continue
                    for a_adim in analiz_adimlar:
                        if a_adim == "1":
                            dump_app_data_only(selected_device)
                        elif a_adim == "2":
                            apk_attack_surface_analysis(selected_device)
                        elif a_adim == "3":
                            decompile_with_jadx_and_search(selected_device)
                        elif a_adim == "4":
                            analyze_app_data_with_regex(selected_device)
                        elif a_adim == "5":
                            show_package_info(selected_device)
                        elif a_adim == "6":
                            analysis_menu_exit = True
                            break
                        else:
                            print_error(f"Invalid selection: {a_adim}")
                break
            elif adim == "4":
                while True:
                    print(Fore.LIGHTYELLOW_EX + "\n===== Frida Tools =====" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "1) Frida-Server Installation" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "2) Run Frida Script" + Style.RESET_ALL)
                    print(PROMPT_COLOR1 + "3) Go Back" + Style.RESET_ALL)
                    print(Fore.LIGHTGREEN_EX + "-"*40 + Style.RESET_ALL)
                    frida_secim = input(PROMPT_COLOR + ">>> Select Frida step (1/2/3): " + Style.RESET_ALL).strip()
                    if frida_secim == "1":
                        install_frida_server(selected_device)
                    elif frida_secim == "2":
                        run_frida_bypass(selected_device)
                    elif frida_secim == "3":
                        break
                    else:
                        print_error("Invalid selection, try again.")
            elif adim == "5":
                apk_build_and_sign_menu(selected_device)
            elif adim == "6":   
                print_warning("Exiting...")
                return
            else:
                print_error(f"Invalid selection: {adim}")
def show_spinner(message, stop_event):
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    while not stop_event.is_set():
        sys.stdout.write(f"\r{message} {next(spinner)}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * (len(message) + 2) + '\r')
def decompile_with_jadx_and_search(device):
    BASE_DECOMPILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decompiled_packages")
    REGEX_JSON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "regex.json")
    TOOL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tool")

    

    print(Fore.LIGHTYELLOW_EX + "\n===== JADX Decompile and Search Tool =====" + Style.RESET_ALL)
    print(PROMPT_COLOR1 + "1) Decompile APK" + Style.RESET_ALL)
    print(PROMPT_COLOR1 + "2) Search for keyword in decompiled file" + Style.RESET_ALL)
    print(PROMPT_COLOR1 + "3) Search for secretkey with ready regex in decompiled file" + Style.RESET_ALL)
    secim = input(PROMPT_COLOR + "Your choice (1/2/3): " + Style.RESET_ALL).strip()

    if secim == "1":
        print(PROMPT_COLOR1 + "\n1) List and select APKs installed on the device" + Style.RESET_ALL)
        print(PROMPT_COLOR1 + "2) Enter APK path from file" + Style.RESET_ALL)
        apk_secim = input(PROMPT_COLOR + ">>> Your choice (1/2): " + Style.RESET_ALL)
        apk_path = None
        package_name = None
        if apk_secim == "1":
            result = subprocess.run(
                ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
                capture_output=True, text=True
            )
            pkgs = [line.replace("package:", "").strip() for line in result.stdout.strip().splitlines()]
            if not pkgs:
                print_error("No 3rd party applications found.")
                return
            print(Fore.LIGHTMAGENTA_EX + "[i] Installed 3rd party applications:" + Style.RESET_ALL)
            for idx, pkg in enumerate(pkgs):
                print(Fore.LIGHTYELLOW_EX + f"{idx+1}: {pkg}" + Style.RESET_ALL)
            while True:
                try:
                    sec = int(input(PROMPT_COLOR + "Enter the number of the APK you want to decompile: " + Style.RESET_ALL)) - 1
                    if 0 <= sec < len(pkgs):
                        package_name = pkgs[sec]
                        path_result = subprocess.run(
                            ["adb", "-s", device, "shell", "pm", "path", package_name],
                            capture_output=True, text=True
                        )
                        apk_paths = [line.replace("package:", "").strip() for line in path_result.stdout.strip().splitlines()]
                        if not apk_paths:
                            print_error("APK path not found.")
                            return
                        apk_on_device = apk_paths[0]
                        local_apk = f"{package_name}.apk"
                        print_info(f"Pulling APK from device: {apk_on_device} -> {local_apk}")
                        pull_result = subprocess.run(
                            ["adb", "-s", device, "pull", apk_on_device, local_apk]
                        )
                        if pull_result.returncode != 0 or not os.path.exists(local_apk):
                            print_error("APK file could not be pulled.")
                            return
                        apk_path = local_apk
                        break
                except ValueError:
                    pass
                print_error("Invalid selection.")
        elif apk_secim == "2":
            apk_path = input(PROMPT_COLOR + "Enter the APK file path: " + Style.RESET_ALL).strip()
            package_name = os.path.basename(apk_path).replace(".apk", "")
        else:
            print_error("Invalid selection.")
            return

        if not apk_path or not os.path.exists(apk_path):
            print_error(f"APK file not found: {apk_path}")
            return

        out_dir = os.path.join(BASE_DECOMPILE_DIR, package_name)
     
        if not jadx_path or not os.path.exists(jadx_path):
            print_error("jadx not found. Please install Jadx and set its path before using this feature.")
            return
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        os.makedirs(out_dir, exist_ok=True)
        print_info("[i] Decompiling APK...")
        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=show_spinner, args=("Decompiling, please wait...", stop_event))
        spinner_thread.start()
        apk_path = os.path.abspath(apk_path)
        result = subprocess.run([jadx_path, "-d", out_dir, apk_path], capture_output=True, text=True)
        stop_event.set()
        spinner_thread.join()

        if result.returncode == 0:
            print_success(f"Decompile completed. Results in '{out_dir}'.")
        else:
            print_error(f"Decompile failed! This error message does not mean that the decompile process has completely failed. Check logs in '{out_dir}'.\nError: {result.stderr.strip()}")
    elif secim == "2":
        decompile_data_dir = BASE_DECOMPILE_DIR
        if not os.path.exists(decompile_data_dir):
            os.makedirs(decompile_data_dir)
            print_warning("No decompiled package found.")
            return
        packages = [d for d in os.listdir(decompile_data_dir) if os.path.isdir(os.path.join(decompile_data_dir, d))]
        if not packages:
            print_warning("No previously decompiled package found.")
            return
        print_info("Decompiled packages:")
        for idx, pkg in enumerate(packages):
            print(PROMPT_COLOR1+ f"{idx+1}: {pkg}" + Style.RESET_ALL)
        while True:
            try:
                sec = int(input(PROMPT_COLOR + "Enter the number of the package you want to search in: " + Style.RESET_ALL)) - 1
                if 0 <= sec < len(packages):
                    selected_pkg = packages[sec]
                    decompiled_dir = os.path.join(decompile_data_dir, selected_pkg)
                    break
            except ValueError:
                pass
            print_error("Invalid selection.")
        if not decompiled_dir or not os.path.exists(decompiled_dir):
            print_error(f"Folder not found: {decompiled_dir}")
            return
        search_term = input(PROMPT_COLOR + "Enter the term you want to search for: " + Style.RESET_ALL).strip()
        print_info(f"Searching for '{search_term}' in '{decompiled_dir}'...")

        found_files = []

        file_list = []
        for root, dirs, files in os.walk(decompiled_dir):
            for file in files:
                if file.endswith(('.java', '.xml', '.kt', '.smali', '.txt', '.properties')):
                    file_list.append(os.path.join(root, file))
  
        for file_path in tqdm(file_list, desc="Searching files", ncols=80, colour="cyan"):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for match in re.finditer(re.escape(search_term), content, re.IGNORECASE):
                
                        start_idx = match.start()
                        line_num = content.count('\n', 0, start_idx) + 1
                        lines = content.splitlines()
                        matched_line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                        found_files.append({
                            "file": file_path,
                            "keyword": search_term,
                            "match": match.group(),
                            "start": match.start(),
                            "end": match.end(),
                            "line_number": line_num,
                            "line": matched_line
                        })
            except Exception:
                continue
        if found_files:
            results_dir = os.path.join("result", "search")
            os.makedirs(results_dir, exist_ok=True)
           
            safe_term = re.sub(r'[^a-zA-Z0-9_.-]', '_', search_term)
            safe_pkg = re.sub(r'[^a-zA-Z0-9_.-]', '_', selected_pkg)
            json_path = os.path.join(results_dir, f"{safe_term}_{safe_pkg}.json")
            with open(json_path, "w", encoding="utf-8") as jf:
                json.dump(found_files, jf, indent=2, ensure_ascii=False)
            print_success(f"Found {len(found_files)} matches. Results: {json_path}\n")
        else:
            print_warning("No matches found.")
    elif secim == "3":
        decompile_data_dir = BASE_DECOMPILE_DIR
        if not os.path.exists(decompile_data_dir):
            os.makedirs(decompile_data_dir)
            print_warning("No decompiled package found.")
            return
        packages = [d for d in os.listdir(decompile_data_dir) if os.path.isdir(os.path.join(decompile_data_dir, d))]
        if not packages:
            print_warning("No previously decompiled package found.")
            return
        print_info("Decompiled packages:")
        for idx, pkg in enumerate(packages):
            print(PROMPT_COLOR1 + f"{idx+1}: {pkg}" + Style.RESET_ALL)
        while True:
            try:
                sec = int(input(PROMPT_COLOR + "Enter the number of the package you want to search in: " + Style.RESET_ALL)) - 1
                if 0 <= sec < len(packages):
                    selected_pkg = packages[sec]
                    decompiled_dir = os.path.join(decompile_data_dir, selected_pkg)
                    break
            except ValueError:
                pass
            print_error("Invalid selection.")
        if not decompiled_dir or not os.path.exists(decompiled_dir):
            print_error(f"Folder not found: {decompiled_dir}")
            return
        print_info(f"Searching for secrets/keys with regex in '{decompiled_dir}'...")
        results = search_with_regexes_in_dir(decompiled_dir, REGEX_JSON_PATH)
        blacklist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "blakclist.json")
        blacklist = load_blacklist(blacklist_path)
        results = filter_blacklist(results, blacklist)
        results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result", "secret_analysis")
        os.makedirs(results_dir, exist_ok=True)
        json_path = os.path.join(results_dir, f"{selected_pkg}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(Fore.LIGHTGREEN_EX + f"[✓] Results saved to {json_path}." + Style.RESET_ALL)
        from collections import Counter
        if results:
            group_counts = Counter([result["regex_name"] for result in results if "regex_name" in result])
            all_groups = sorted(set([result["regex_name"] for result in results if "regex_name" in result]))
            print(Fore.LIGHTCYAN_EX + "+" + "-"*32 + "+" + "-"*8 + "+" + Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX + f"| {'NAME':<30} | {'Count':<6} |" + Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX + "+" + "-"*32 + "+" + "-"*8 + "+" + Style.RESET_ALL)
            for group in all_groups:
                count = group_counts.get(group, 0)
                print(Fore.LIGHTYELLOW_EX + f"| {group:<30} | {count:<6} |" + Style.RESET_ALL)
                print(Fore.LIGHTCYAN_EX + "+" + "-"*32 + "+" + "-"*8 + "+" + Style.RESET_ALL)
        else:
            print(Fore.LIGHTYELLOW_EX + "No regex matches found." + Style.RESET_ALL)
    else:
        print_error("Invalid selection.")

def download_file_with_retries(url, dest_path, max_retries=3, chunk_size=8192):
    import requests
    import time
    for attempt in range(max_retries):
        try:
            with requests.get(url, stream=True) as resp:
                resp.raise_for_status()
                with open(dest_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=chunk_size):
                        f.write(chunk)
            return True
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            time.sleep(2 ** attempt)
    return False
def download_file_with_retries(url, dest_path, max_retries=3, chunk_size=8192):
    for attempt in range(max_retries):
        try:
            with requests.get(url, stream=True) as resp:
                resp.raise_for_status()
                with open(dest_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=chunk_size):
                        f.write(chunk)
            return True
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            time.sleep(2 ** attempt)  
    return False

def extract_jadx_zip(zip_path, extract_to):
    if os.path.exists(extract_to):
        shutil.rmtree(extract_to)
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_to)
def apk_build_and_sign_menu(device):
    import json
    config_path = os.path.join("config", "signer.json")
    if not os.path.exists(config_path):
        print_error(f"Config file not found: {config_path}")
        return
    with open(config_path, "r") as f:
        config = json.load(f)
    decompiled_dir = config["decompiled_dir"]
    rebuilt_apk = config["rebuilt_apk"]
    signed_apk = config["signed_apk"]
    keystore = config["keystore"]
    alias = config["alias"]
    storepass = config["storepass"]
    dname = config["dname"]
    apksigner = config.get("apksigner_path", "apksigner")

    print(PROMPT_COLOR1 + "\n1) Select APK from 3rd party apps installed on the device" + Style.RESET_ALL)
    print(PROMPT_COLOR1 + "2) Enter APK file path manually" + Style.RESET_ALL)
    choice = input(PROMPT_COLOR + ">>> Your choice (1/2): " + Style.RESET_ALL)
    apk_path = None

    if choice == "1":
        result = subprocess.run(
            ["adb", "-s", device, "shell", "pm", "list", "packages", "-3"],
            capture_output=True, text=True
        )
        pkgs = [line.replace("package:", "").strip() for line in result.stdout.strip().splitlines()]
        if not pkgs:
            print_error("No 3rd party applications found on the device.")
            return
        print_info("Installed applications:")
        for idx, pkg in enumerate(pkgs):
            print(PROMPT_COLOR1 + f"{idx+1}: {pkg}" + Style.RESET_ALL)
        while True:
            try:
                sec = int(input(PROMPT_COLOR + "Enter the number of the APK you want to decompile: " + Style.RESET_ALL)) - 1
                if 0 <= sec < len(pkgs):
                    package_name = pkgs[sec]
                    path_result = subprocess.run(
                        ["adb", "-s", device, "shell", "pm", "path", package_name],
                        capture_output=True, text=True
                    )
                    apk_paths = [line.replace("package:", "").strip() for line in path_result.stdout.strip().splitlines()]
                    if not apk_paths:
                        print_error("APK path not found.")
                        return
                    apk_on_device = apk_paths[0]
                    local_apk = f"{package_name}.apk"
                    print_info(f"Pulling APK from device: {apk_on_device} -> {local_apk}")
                    pull_result = subprocess.run(
                        ["adb", "-s", device, "pull", apk_on_device, local_apk]
                    )
                    if pull_result.returncode != 0 or not os.path.exists(local_apk):
                        print_error("APK file could not be pulled.")
                        return
                    apk_path = local_apk
                    break
            except ValueError:
                pass
            print_error("Invalid selection.")
    elif choice == "2":
        apk_path = input(PROMPT_COLOR + "Enter the APK file path: " + Style.RESET_ALL).strip()
        package_name = os.path.basename(apk_path).replace(".apk", "")
    else:
        print_error("Invalid selection.")
        return

     
    print_info("Decompiling APK...")
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=show_spinner, args=("Decompiling, please wait...", stop_event))
    spinner_thread.start()
    if apktool_path and apktool_path.endswith('.jar'):
        decompile_cmd = ['java', '-jar', apktool_path, 'd', '-f', apk_path, '-o', decompiled_dir]
    else:
        decompile_cmd = [apktool_path, 'd', '-f', apk_path, '-o', decompiled_dir]
    result = subprocess.run(decompile_cmd, capture_output=True, text=True)
    stop_event.set()
    spinner_thread.join()
    if result.returncode != 0:
        print_error(f"Decompile failed: {result.stderr}")
        return
    print_success(f"Decompile completed: {decompiled_dir}")
    print_warning(f"You can make manual changes in the '{decompiled_dir}' folder.")

    choice = input(PROMPT_COLOR + "Do you want to build and sign the package? (e/E to continue): " + Style.RESET_ALL)
    if choice.lower() == "e":
        print_info("Building APK...")
        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=show_spinner, args=("Building APK, please wait...", stop_event))
        spinner_thread.start()
        
        if apktool_path and apktool_path.endswith('.jar'):
            build_cmd = ['java', '-jar', apktool_path, 'b', decompiled_dir, '-o', rebuilt_apk]
        else:
            build_cmd = [apktool_path, 'b', decompiled_dir, '-o', rebuilt_apk]
        result = subprocess.run(build_cmd, capture_output=True, text=True)
        stop_event.set()
        spinner_thread.join()
        if result.returncode != 0:
            print_error(f"Build failed: {result.stderr}")
            return
        print_success(f"Build completed: {rebuilt_apk}")

       
        if not os.path.isfile(keystore):
            print_warning("Keystore not found, creating...")
            keytool_cmd = [
                'keytool', '-genkeypair',
                '-alias', alias,
                '-keyalg', 'RSA',
                '-keysize', '2048',
                '-validity', '10000',
                '-keystore', keystore,
                '-storepass', storepass,
                '-dname', dname
            ]
            result = subprocess.run(keytool_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print_error(f"Keystore could not be created: {result.stderr}")
                return
            print_success("Keystore created.")

     
        print_info("Signing APK...")
        sign_cmd = [
            apksigner, 'sign',
            '--ks', keystore,
            '--ks-key-alias', alias,
            '--ks-pass', f'pass:{storepass}',
            '--out', signed_apk,
            rebuilt_apk
        ]
        result = subprocess.run(sign_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print_error(f"Signing failed: {result.stderr}")
            return
        print_success(f"Signing completed! Output: {signed_apk}")

        
        if os.path.exists(rebuilt_apk):
            try:
                os.remove(rebuilt_apk)
            except Exception as e:
                print_warning(f"{rebuilt_apk} could not be deleted: {e}")
    else:
        print_warning("Operation cancelled. You can make manual changes in the decompiled files.")
def download_and_extract_latest_jadx(tool_dir="tool"):
    if not os.path.exists(tool_dir):
        os.makedirs(tool_dir, exist_ok=True)   
    api_url = "https://api.github.com/repos/skylot/jadx/releases/latest"
    r = requests.get(api_url)
    r.raise_for_status()
    data = r.json()
    assets = data.get("assets", [])
    zip_asset = next((a for a in assets if a["name"].endswith(".zip")), None)
    if not zip_asset:
        print("No zip asset found in latest jadx release.")
        return
    url = zip_asset["browser_download_url"]
    filename = zip_asset["name"]
    jadx_folder = os.path.join(tool_dir, "jadx")
    zip_path = os.path.join(tool_dir, filename)
    print(f"Downloading: {url}")
    if not download_file_with_retries(url, zip_path):
        print("Download failed after multiple attempts.")
        return
    print("Extracting...")
    extract_jadx_zip(zip_path, jadx_folder)
    os.remove(zip_path)
    print(f"jadx extracted to {jadx_folder}")

    for fname in ["jadx", "jadx-gui"]:
        bin_path = os.path.join(jadx_folder, "bin", fname)
        if os.path.exists(bin_path):
            os.system(f"chmod 755 '{bin_path}' 2>/dev/null")

def download_and_setup_latest_apktool(tool_dir="tool"):
    if not os.path.exists(tool_dir):
        os.makedirs(tool_dir, exist_ok=True) 
    api_url = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"
    r = requests.get(api_url)
    r.raise_for_status()
    data = r.json()
    assets = data.get("assets", [])
    jar_asset = next((a for a in assets if a["name"].endswith(".jar")), None)
    script_asset = next((a for a in assets if a["name"] == "apktool"), None)
    if not jar_asset:
        print("No apktool jar found in latest release.")
        return
    apktool_dir = os.path.join(tool_dir, "apktool")
    os.makedirs(apktool_dir, exist_ok=True)
    jar_url = jar_asset["browser_download_url"]
    jar_path = os.path.join(apktool_dir, "apktool.jar")
    print(f"Downloading: {jar_url}")
    if not download_file_with_retries(jar_url, jar_path):
        print("Download failed after multiple attempts.")
        return
    if script_asset:
        script_url = script_asset["browser_download_url"]
        script_path = os.path.join(apktool_dir, "apktool")
        print(f"Downloading: {script_url}")
        if not download_file_with_retries(script_url, script_path):
            print("Failed to download apktool wrapper script.")
        else:
            os.system(f"chmod 755 '{script_path}' 2>/dev/null")
    print(f"apktool.jar downloaded to {jar_path}")
    print("To use: java -jar", jar_path)
def check_adb_installation():
    adb_path = shutil.which("adb")
    if adb_path:
        print(Fore.LIGHTGREEN_EX + f"[✓] adb found in PATH: {adb_path}" + Style.RESET_ALL)
        return True
    else:
        print(Fore.LIGHTRED_EX + "[X] adb not found in PATH. Please install Android Platform Tools (adb) and add to PATH!" + Style.RESET_ALL)
        return False

if __name__ == "__main__":
    print_banner()
    if not check_adb_installation():
        exit(1)
    TOOL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tool")

  
    jadx_path = shutil.which("jadx")
    if jadx_path:
        print(Fore.LIGHTGREEN_EX + f"[✓] Jadx found in PATH: {jadx_path}" + Style.RESET_ALL)
    else:
        local_jadx = os.path.join(TOOL_DIR, "jadx", "bin", "jadx")
        if os.path.exists(local_jadx):
            print(Fore.LIGHTGREEN_EX + f"[✓] Jadx found in tool: {local_jadx}" + Style.RESET_ALL)
            jadx_path = local_jadx
        else:
            print(Fore.LIGHTYELLOW_EX + "[!] Jadx not found." + Style.RESET_ALL)
            while True:
                install = input(Fore.LIGHTYELLOW_EX + "Jadx is required for decompiling APKs. Do you want to download and install Jadx now? (y/n): " + Style.RESET_ALL).strip().lower()
                if install == "y":
                    download_and_extract_latest_jadx(TOOL_DIR)
                    jadx_path = os.path.join(TOOL_DIR, "jadx", "bin", "jadx")
                    if not os.path.exists(jadx_path):
                        print(Fore.LIGHTRED_EX + "[X] Jadx could not be installed." + Style.RESET_ALL)
                    break
                elif install == "n":
                    print(Fore.LIGHTRED_EX + "[X] Jadx not installed. Some features will not work." + Style.RESET_ALL)
                    break
                else:
                    print(Fore.LIGHTRED_EX + "[X] Please answer with 'y' or 'n'." + Style.RESET_ALL)
                    


    apktool_path = shutil.which("apktool")
    if apktool_path:
        print(Fore.LIGHTGREEN_EX + f"[✓] Apktool found in PATH: {apktool_path}" + Style.RESET_ALL)
    else:
        local_apktool = os.path.join(TOOL_DIR, "apktool", "apktool.jar")
        if os.path.exists(local_apktool):
            print(Fore.LIGHTGREEN_EX + f"[✓] Apktool found in tool: {local_apktool}" + Style.RESET_ALL)
            apktool_path = local_apktool
        else:
            print(Fore.LIGHTYELLOW_EX + "[!] Apktool not found." + Style.RESET_ALL)
            while True:
                install = input(Fore.LIGHTYELLOW_EX + "Apktool is required for APK decompile/build. Do you want to download and install Apktool now? (y/n): " + Style.RESET_ALL).strip().lower()
                if install == "y":
                    download_and_setup_latest_apktool(TOOL_DIR)
                    apktool_path = os.path.join(TOOL_DIR, "apktool", "apktool.jar")
                    if not os.path.exists(apktool_path):
                        print(Fore.LIGHTRED_EX + "[X] Apktool could not be installed." + Style.RESET_ALL)
                    break
                elif install == "n":
                    print(Fore.LIGHTRED_EX + "[X] Apktool not installed. Some features will not work." + Style.RESET_ALL)
                    apktool_path = None
                    break
                else:
                    print(Fore.LIGHTRED_EX + "[X] Please answer with 'y' or 'n'." + Style.RESET_ALL)
                  

    main()