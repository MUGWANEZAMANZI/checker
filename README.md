**Gisamagwe Miseles Cyber Attacks** 🚀💥

Welcome to Gisamagwe Miseles, a toolset designed for simulating cyber attacks and scanning vulnerabilities on various networks. This tool is intended for educational purposes to help you understand how different types of attacks can be performed and mitigated.

DISCLAIMER: This tool should only be used on networks and systems you own or have explicit permission to test. Unauthorized use of this tool is illegal and unethical.

**Features**

    Mass Scanning: Performs mass scanning to discover IPs with open ports on the internet.
    Vulnerability Scanner: Scans Windows and Linux systems for vulnerabilities using Nmap.
    Brute Force Attack: Simulates SSH and SMB brute force attacks using common usernames and passwords.
    Metasploit Integration: Create a reverse shell payload and launch a listener using Metasploit.
    Public and Private Network Attacks: Allows attacking both private (your own network) and public (internet) systems.

**Pre-requisites**

Make sure you have the following tools installed and running:

    Linux OS
    Nmap
    Masscan
    Metasploit Framework (msfconsole, msfvenom)
    Hydra
    SSH
    SMB services
**
To install these tools, run the following command:**

sudo apt install nmap masscan msfconsole msfvenom hydra ssh

Usage

**Step 1: Set Up the Environment**

When you first run the script, it will prompt you to install the necessary tools if they are not already installed. If the tools are missing, simply choose option 1 to install them.

**Step 2: Scan Networks
**
You will be prompted to choose between scanning a private network (e.g., your own local network or a virtual machine) or performing a public IP scan. The script uses nmap to scan for open ports and vulnerabilities.

    Private Network Scan: Select 1 to scan a network of your choice.
    Public Network Scan: Select 2 to scan the public internet. Be cautious as this is potentially dangerous.

**Step 3: Launch Attack**

After scanning for vulnerabilities, you can choose to launch a brute-force attack or use Metasploit to generate a payload.

    SSH Brute Force Attack: Select option 3 and provide a list of usernames and passwords to attempt SSH logins.
    SMB Brute Force Attack: Use the same procedure as the SSH attack, but targeting SMB services.
    Metasploit Payload: Select option 1 for an automatic attack or option 2 for a manual setup. This will generate a payload that can be delivered to the target system via email or a Python HTTP server.

**Step 4: Monitor and Log**

All actions are logged into output.txt and nmp.txt for tracking purposes.

Important Notes

    Use with Caution: This script is a powerful tool for learning about cyber security. Always ensure that you have the proper authorization to test any network or system.
    System Requirements: The script is designed to run on Linux-based systems and relies heavily on command-line tools.
    Legality: Unauthorized access to computer systems is illegal. Always get explicit permission before running attacks on any network or system.

License

This project is licensed under the MIT License - see the LICENSE file for details.

This README file should give users a clear understanding of how to use the tool and the precautions they need to take.
