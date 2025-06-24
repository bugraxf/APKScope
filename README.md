# APKScope

APKScope is a comprehensive and automation-focused tool designed to simplify the security analysis of Android applications. It integrates with popular tools such as ADB, Frida, Drozer, Jadx, and Apktool. You can manage tasks like pulling app data, APK decompilation, attack surface analysis, regex-based key/secret search, running Frida scripts, and more from a single menu.

---

## 🚀 Features

- **Proxy and Certificate Settings:** Set up proxies (e.g., Burp) and install CA certificates on the device.
- **Frida Server Setup & Script Execution:** Downloads and starts the appropriate Frida server for your device, and runs Frida scripts.
- **Drozer Integration:** Downloads and installs Drozer and the Drozer agent APK, sets up port forwarding, and provides console access.
- **APK Attack Surface Analysis:** Decompiles APKs with Apktool, analyzes the manifest and components, lists risky permissions and exported components.
- **Jadx Decompile & Key/Secret Search:** Decompiles APKs with Jadx and searches for keywords or regex patterns.
- **/data/data Regex Analysis:** Searches for keys/secrets in app data using regex.
- **APK Build & Sign:** Automates rebuilding and signing of decompiled APKs.
- **Device Management with ADB:** Lists connected devices and allows you to select one.

---

## 🛠️ Installation

### Requirements

- ADB (Android Platform Tools)
- Jadx and Apktool (can be downloaded automatically on first run)
- Frida and Drozer (can be installed from the menu)

### Installing Dependencies


1. Clone the repository:

```sh
git clone https://github.com/bugraxf/APKScope.git
cd APKScope
```

2. Install the required Python packages:

```sh
pip3 install -r requirements.txt
```

### Running APKScope

```bash
python3 APKScope.py
```

If Jadx or Apktool are missing on first run, you will be prompted to download them automatically.

---

## 📋 Usage

When the program starts, it lists connected devices and asks you to select one. Then, you can choose from the following main menu options:
 ![Drozer](example/apkscope.png)
 
### Main Menu

- **1) Environment Config Setup:** Proxy configuration and Burp certificate installation.
- **2) Drozer Tools:** Application analysis and attack surface detection with Drozer.
- **3) Analysis Tools:** Pull app data, APK analysis, regex search, dumpsys info.
- **4) Frida Tools:** Frida server setup and script execution.
- **5) APK Build & Sign:** Rebuild and sign decompiled APKs.
- **6) Exit:** Exit the program.

Each menu contains detailed sub-steps.

---

## 📂 Directory Structure

```
APKScope/
├── APKScope.py
├── tool/
│   ├── jadx/
│   └── apktool/
|   └── frida-server/
|   └── drozer
├── config/
│   ├── regex.json
│   ├── blacklist.json
│   └── signer.json
├── result/
├── decompiled_data/
├── dumped_data/
├── app/
└── script/
```

---

## 🔍 Menu Descriptions

### 1. Environment Config Setup
Once you provide the IP address, port information, and the Burp certificate path, you will be able to view the traffic through Burp.
- Proxy configuration
- Certificate installation (e.g., Burp)
![BURP Config](example/burp.gif)
### 2. Drozer Tools
In step 1, the Drozer and Drozer Agent APKs are installed. Once the agent is activated through the interface, you can perform an attack surface analysis using Drozer.
- Install Drozer agent and set up port forwarding
- Retrieve app info via Drozer console
- IPC tests and attack surface analysis
![Drozer](example/drozer.gif)

### 3. Analysis Tools
- Pull app data (/data/data)
- APK attack surface analysis (decompile + manifest analysis)
- Jadx decompile and key/secret search
- /data/data regex analysis
- Retrieve app info with dumpsys

*Pull app data (/data/data)
-You can list the third-party applications on the device and analyze their local storage data.
![/data/data/<package-name>](example/data.data.png)
- APK attack surface analysis (decompile + manifest analysis)
  By selecting the third-party application you want to analyze from the device, you can examine security-related features such as permissions, activities, content providers, backup settings, and cleartext traffic. 
![attack surface analysis ](example/Attack%20Surface-1.png)
-Additionally, the relevant ADB commands are automatically generated for your convenience.
![attack surface analysis ](example/Attack%20Surface-2.png) 
*Jadx decompile and key/secret search
-By selecting option 1, you can list the third-party applications installed on the device, pull them from the device, and then perform secret analysis within the APK package by choosing step 2 (search) or step 3 (regex-based analysis using config/regex.json).To reduce false positives in the output, you can improve the patterns using a blacklist(config/blacklist.json).
![regex analysis](example/regex.gif)
![regex analysis](example/regex2.gif)
*You can list the third-party applications installed on the device and perform regex-based analysis on the local storage of the selected application under /data/data/<package-name> using config/regex.json. To reduce false positives in the output, you can improve the patterns using a blacklist(config/blacklist.json).
![regex analysis](example/dumpsys.gif)
*Retrieve app info with dumpsys
 Retrieve information about installed applications
 Inspect running services and activities
 View memory usage and CPU statistics
 Get detailed information from system services like battery, network, window, activity, and package
 Access application permissions, manifest details, intent filters, and more


### 4. Frida Tools
After setting up and starting the Frida server compatible with the Android device's architecture, you can execute Frida scripts.
- Frida server setup and script execution
![regex analysis](example/frida.gif)
### 5. APK Build & Sign
You need to select the package you want to decompile on the device. Once the decompilation process is complete, you can modify the desired sections under the /app directory and then re-sign the new APK package. To perform the signing process, make sure to fill in the required fields in the config/signer.json file.
- Rebuild and sign decompiled APKs

### 6. Exit
- Exit the program

---

## ⚙️ Configuration Files

- `config/regex.json`: Regex search rules
- `config/signer.json`: Settings for APK signing
- `config/blacklist.json`: Add patterns to blacklist false positives in regex results

---

## 💡 Notes

- !!! Some operations (e.g., running the Frida server) require root privileges. Ensure you have root access for smooth execution.
- The latest versions of Frida, Drozer, Apktool, and Jadx can be downloaded automatically.
- You can edit the `config/regex.json` file to customize regex searches.
- Analysis results and reports are saved as JSON and text files in the `result/` directory.

---

## 🤝 Contributing

We welcome your pull requests and issues! You can add your own regex rules or analysis modules. Contributions for new tool integrations and improvements are also appreciated.

---

**Warning:** This tool is intended for educational, analytical, and legal penetration testing purposes only. Unauthorized use is unethical and illegal.

---


