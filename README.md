# StatAnalyzr

**StatAnalyzr** is a Python-based static malware analysis tool designed to provide a quick, comprehensive static overview of suspicious executable files. It streamlines initial triage by integrating with public services like VirusTotal and leveraging powerful open-source tools such as FLOSS and UPX.

All collected analysis data is meticulously compiled into a user-friendly Microsoft Word document, making reporting and review straightforward and efficient.

---

## 🚀 Features & Outcomes

This tool automates various static analysis steps and generates a detailed Microsoft Word report containing the following key information:

### File Information:
* Filename
* File Size
* Analysis Date

### File Hashes:
* MD5
* SHA-1
* SHA-256

### VirusTotal Scan Results:
* Last Analysis Date
* Number of Detections (malicious/total)
* A **direct link to the VirusTotal report** for detailed online analysis.

### FLOSS String Extraction:
* The total number of deobfuscated strings found.
* Categorized lists of interesting strings, including:
    * URLs
    * File Paths
    * Registry Keys
    * Potential APIs/DLLs
    * Other significant printable strings

### UPX Packing Analysis:
* Indication if the file is packed with UPX.
* An attempt to unpack the file if it's UPX packed, providing:
    * Original size
    * Unpacked size
    * Compression ratio
* The raw output from UPX's information command.

### PE Structure Analysis (for Windows Executables):
* **Basic PE Information:** Machine type, number of sections, timestamp, entry point, and image base.
* **Section Analysis:** Detailed information for each PE section (name, virtual address, virtual size, raw size, characteristics), including warnings for suspicious attributes (e.g., sections with zero raw size or a virtual size much larger than raw size, often indicating obfuscation).
* **Import Analysis:** Lists all imported DLLs and the functions they provide, with a special highlight for **potentially suspicious API calls** commonly associated with malware behavior (like `CreateProcess`, `WriteProcessMemory`, `VirtualAlloc`, `CreateRemoteThread`, etc.).
* **Export Analysis:** Lists any functions exported by the executable.
* **Packer Detection (by PE Sections):** Identifies common packers based on characteristic section names (e.g., UPX, ASPack, Themida, VMProtect).
* **High Entropy Sections:** Flags sections with unusually high entropy, which can suggest packed or encrypted content.
* **Imported Libraries:** A concise list of all Dynamic Link Libraries (DLLs) that the executable imports.

---

## 📋 Prerequisites

To run this tool, you'll need the following installed on your system:

* **Python 3.x**: Download and install the latest version from [python.org](https://www.python.org/downloads/).
* **pip**: Python's package installer, which typically comes bundled with Python 3.x installations.
* **Internet Connection**: An active internet connection is essential for the tool to download its required analysis binaries (FLOSS and UPX) and to query the VirusTotal API.

The script is designed to automatically install any missing Python libraries (`python-docx`, `pefile`, `yara-python`) during its initial setup phase.

### External Tools (Automatically Downloaded)

This Python script handles the download and extraction of the following crucial external analysis binaries:

* **FLOSS (Flare-On Static String Extractor):** This tool is used for deobfuscating and extracting strings from the malware sample. The script automatically downloads the **Linux version** of the FLOSS binary from its official GitHub releases.
* **UPX (Ultimate Packer for eXecutables):** Used for detecting and, if possible, unpacking UPX-packed executables. The script automatically downloads the **Linux version** of the UPX binary from its official GitHub releases.

**Important Note for Windows Users:**
While the Python script itself is designed for cross-platform compatibility, the FLOSS and UPX binaries it downloads are specifically compiled for **Linux environments**.

If you're running this tool on **Windows**, it's strongly recommended to use a **Windows Subsystem for Linux (WSL)** environment. By installing a Linux distribution (like Ubuntu) via the Microsoft Store and then running this Python script from within your WSL terminal, the Linux FLOSS and UPX binaries will execute correctly, ensuring full functionality.

---

## 🔑 API Key Setup (VirusTotal)

To enable the VirusTotal query feature, you must provide your personal VirusTotal API Key.

1.  **Obtain your API Key:**
    * Visit the [VirusTotal website](https://www.virustotal.com/).
    * Register for a free account.
    * Once you've successfully registered and logged in, locate your API key within your profile settings (it's often labeled "API key" or "Community API key"). Copy this key to your clipboard.

2.  **Paste into the Script:**
    * Open the `Static_Analysis_Tool.py` file using a plain text editor (e.g., VS Code, Notepad++, Sublime Text).
    * Locate the line that begins with `VIRUSTOTAL_API_KEY = ` near the top of the file.
    * The provided code already has a key set. If you wish to use a different key, simply replace the existing value with your actual VirusTotal API key.

    ```python
    # --- IMPORTANT: PLACE YOUR VIRUSTOTAL API KEY HERE ---
    # Replace 'YOUR_VIRUSTOTAL_API_KEY_HERE' with your actual VirusTotal API Key.
    VIRUSTOTAL_API_KEY = '6fa8bd53cf29d967f03114ee6ff3140a2d16de8769b596dc3f465043f7546ef3'
    # -----------------------------------------------------
    ```
    * Save the changes to the `Static_Analysis_Tool.py` file.

---

## 📦 Installation & Setup

1.  **Download the Script:**
    * Save the `Static_Analysis_Tool.py` file into a dedicated directory on your local machine. A good practice is to create a new folder, for example, `MalwareAnalysis`.

2.  **Open your Terminal or Command Prompt:**
    * Navigate to the directory where you saved the script using your terminal or command prompt.
        * **On Windows (using WSL):** Open your WSL terminal (e.g., Ubuntu) and `cd /mnt/c/path/to/MalwareAnalysis` (replace `/path/to/MalwareAnalysis` with your actual path).
        * **On Linux/macOS:** Open your terminal and use `cd /home/user/path/to/MalwareAnalysis`.

3.  **Perform Initial Setup (First Run):**
    * Execute the script for the very first time. This initial run is crucial as it will automatically download the necessary FLOSS and UPX binaries into a `./tools` subdirectory created next to your script. It will also ensure all required Python libraries are installed. An active internet connection is indispensable for this step.

    ```bash
    python Static_Analysis_Tool.py
    ```
    * During this process, you will see messages printed to your console indicating the progress of tool downloads and library installations.

---

## 🚀 How to Run Analysis

1.  **Prepare your malware sample:**
    * Ensure that the malware sample you intend to analyze is readily accessible on your file system.
    * **Crucial Security Note:** It is paramount to always conduct malware analysis in a **safe, isolated environment**. This can be a dedicated virtual machine (VM) specifically configured for security analysis, or a specialized sandbox environment. **Never run this tool directly on your primary operating system with live malware samples,** as this poses a significant risk of infection or damage to your host system.

2.  **Execute the script:**
    * Open your terminal or command prompt (or WSL terminal if you are on Windows).
    * Navigate to the directory where your `Static_Analysis_Tool.py` script is located.
    * Run the script by invoking the Python interpreter:

    ```bash
    python Static_Analysis_Tool.py
    ```

3.  **Provide the file path:**
    * The script will display a prompt asking you to enter the full path to the malware sample you wish to analyze.
    * **Example (Windows file path accessible from WSL):** `/mnt/c/Users/YourUser/Desktop/suspicious_file.exe`
    * **Example (Linux/macOS or WSL native path):** `/home/user/malware_samples/sample.bin`

    ```
    Enter the full path to the malware sample you want to analyze (e.g., C:\malware\sample.exe or /home/user/malware/sample):
    File path: <Paste_Your_Malware_FilePath_Here>
    ```

4.  **Review Console Output and Generated Report:**
    * As the analysis progresses, the script will print real-time status updates and summary findings directly to your terminal.
    * Upon completion of the analysis, a comprehensive Microsoft Word document (`.docx`) report will be automatically generated and saved in the same directory as your `Static_Analysis_Tool.py` script. The filename will follow a clear pattern: `Malware_Analysis_Report_<OriginalFileName>.docx`.

5.  **Access the Report:**
    * Locate the newly generated `.docx` file (for instance, `Malware_Analysis_Report_suspicious_file.docx`) within the directory where your script resides.
    * Open this document using Microsoft Word or any other compatible word processing software to view the full, detailed, and professionally formatted static analysis report.

---
