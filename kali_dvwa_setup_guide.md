# Complete Kali Linux VM and DVWA Setup Guide

## Table of Contents
1. [VirtualBox VM Setup](#virtualbox-vm-setup)
2. [Kali Linux Installation](#kali-linux-installation)
3. [DVWA Installation and Configuration](#dvwa-installation-and-configuration)
4. [DVWA Website Setup](#dvwa-website-setup)
5. [Troubleshooting](#troubleshooting)

---

## VirtualBox VM Setup

### Prerequisites
- VirtualBox installed on your host system
- Kali Linux ISO downloaded from official website
- At least 8GB RAM on host system (4GB will be allocated to VM)
- At least 40GB free disk space

### Step 1: Create New Virtual Machine

1. **Open VirtualBox** and click **"New"**
2. **Configure VM Settings:**
   - **Name:** `Kali-Linux`
   - **Type:** `Linux`
   - **Version:** `Debian (64-bit)`
   - **Memory:** `4096 MB` (4GB minimum)
   - **Hard disk:** Create a virtual hard disk now

3. **Virtual Hard Disk Settings:**
   - **File type:** VDI (VirtualBox Disk Image)
   - **Storage:** Dynamically allocated
   - **Size:** `30 GB` minimum (50GB recommended)

### Step 2: Configure VM Settings (Critical!)

Before starting the VM, configure these essential settings:

#### System Settings
1. **Right-click VM → Settings → System → Motherboard:**
   - **Boot Order:** Optical, Hard Disk
   - **Enable I/O APIC:** ✓
   - **Hardware Clock in UTC Time:** ✓

2. **System → Processor:**
   - **Processors:** 2-4 CPUs (based on your system)
   - **Enable PAE/NX:** ✓
   - **Enable VT-x/AMD-V:** ✓ (if available)

#### Display Settings
3. **Settings → Display:**
   - **Video Memory:** `128 MB`
   - **Graphics Controller:** `VBoxVGA` (most compatible)
   - **3D Acceleration:** `DISABLED` (important!)
   - **2D Video Acceleration:** ✓

#### Storage Settings
4. **Settings → Storage:**
   - **Controller: IDE** → Click empty CD icon
   - **Optical Drive:** Choose disk file
   - **Select your Kali Linux ISO file**

#### Network Settings (Optional but Recommended)
5. **Settings → Network:**
   - **Adapter 1:** NAT (default)
   - **Advanced → Port Forwarding:** (if needed for external access)

---

## Kali Linux Installation

### Step 1: Start Installation Process

1. **Start the VM**
2. **Boot Menu Options:**
   - Choose **"Graphical Install"** (recommended)
   - Do NOT choose "Live" options

### Step 2: Installation Wizard

#### Basic Configuration
1. **Language Selection:** Choose your preferred language
2. **Location:** Select your country/region
3. **Keyboard Layout:** Choose appropriate keyboard

#### Network Configuration
4. **Hostname:** `kali` (or your preference)
5. **Domain Name:** Leave blank or use `local`

#### User Account Setup
6. **Root Password:** Create a strong password (remember this!)
7. **User Account:**
   - **Full Name:** Your name
   - **Username:** `kali` (recommended)
   - **Password:** Create a user password

#### Disk Partitioning (Important!)
8. **Partitioning Method:** 
   - Choose **"Guided - use entire disk"**
   - Select your virtual hard disk
   - **Partition Scheme:** "All files in one partition"
   - **Confirm:** "Finish partitioning and write changes to disk"
   - **Write changes to disk:** **YES** ✓

#### Software Selection
9. **Software to Install:**
   - Keep **default selections** (Desktop environment)
   - Ensure **"Debian desktop environment"** is selected
   - **"Kali Linux default"** should be selected

#### GRUB Bootloader (Critical!)
10. **Install GRUB Bootloader:**
    - **"Install GRUB boot loader to master boot record?"** → **YES** ✓
    - **"Device for boot loader installation:"** → **`/dev/sda`** ✓

### Step 3: Complete Installation
11. **Installation Complete:**
    - Click **"Continue"** to restart
    - **IMPORTANT:** Shut down VM when restart begins

### Step 4: Remove ISO and First Boot
12. **Remove Installation Media:**
    - **VM Settings → Storage**
    - **Controller: IDE** → Click ISO
    - **Remove disk from virtual drive**
    - **Should show "Empty"**

13. **Start VM:**
    - Boot should now come from hard drive
    - Login with the username/password you created

---

## DVWA Installation and Configuration

### Prerequisites Check
Ensure your Kali VM is running and you have terminal access.

### Step 1: Install DVWA Package
```bash
sudo apt update
sudo apt install dvwa
```

### Step 2: Start Required Services
```bash
sudo systemctl start apache2
sudo systemctl start mysql
sudo systemctl enable apache2
sudo systemctl enable mysql
```

**Verify services are running:**
```bash
sudo systemctl status apache2
sudo systemctl status mysql
```

### Step 3: Configure Database
```bash
sudo mysql -u root -p
```
*Press Enter for password if no password is set*

**In MySQL prompt, run these commands:**
```sql
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
exit;
```

### Step 4: Configure DVWA Settings
```bash
sudo nano /usr/share/dvwa/config/config.inc.php
```

**Find and modify these lines:**
```php
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'p@ssw0rd';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_server' ]   = '127.0.0.1';
```

**Save and exit:** `Ctrl + X`, then `Y`, then `Enter`

### Step 5: Set Permissions
```bash
sudo chown -R www-data:www-data /usr/share/dvwa
sudo chmod -R 755 /usr/share/dvwa
sudo chmod 666 /usr/share/dvwa/hackable/uploads/
sudo chmod 666 /usr/share/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt
sudo chmod 666 /usr/share/dvwa/config/config.inc.php
```

### Step 6: Create Web Access (Critical!)
```bash
sudo ln -s /usr/share/dvwa /var/www/html/dvwa
```

**Alternative if symlink fails:**
```bash
sudo cp -r /usr/share/dvwa /var/www/html/
```

---

## DVWA Website Setup

### Step 1: Access DVWA Setup Page
1. **Open Firefox** in Kali
2. **Navigate to:** `http://localhost/dvwa`
3. **You should see:** DVWA setup page with system status

### Step 2: Database Initialization
1. **Check system status:** All items should show "green" or "ok"
2. **Click:** "Create / Reset Database" button
3. **Wait for:** Database creation confirmation
4. **You should see:** "Database has been created" message

### Step 3: Login to DVWA
1. **Default credentials:**
   - **Username:** `admin`
   - **Password:** `password`

2. **After login:** You'll see the DVWA main dashboard

### Step 4: Configure Security Level
1. **Go to:** "DVWA Security" in left menu
2. **Security Level Options:**
   - **Low:** No security (beginner friendly)
   - **Medium:** Basic security measures
   - **High:** Advanced security
   - **Impossible:** Secure implementation

3. **Recommended:** Start with "Low" for learning

### Step 5: Explore Vulnerabilities
**Available modules:**
- Brute Force
- Command Injection
- CSRF (Cross-Site Request Forgery)
- File Inclusion
- File Upload
- Insecure CAPTCHA
- SQL Injection
- SQL Injection (Blind)
- Weak Session IDs
- XSS (DOM)
- XSS (Reflected)
- XSS (Stored)
- CSP Bypass
- JavaScript

---

## Troubleshooting

### Common VM Issues

#### VM Won't Boot
- **Check:** ISO is mounted in Storage settings
- **Check:** Boot order (Optical first for installation)
- **Try:** Safe graphics mode (`nomodeset` parameter)

#### Poor Performance
- **Increase:** RAM allocation (4GB minimum)
- **Disable:** 3D acceleration
- **Enable:** VT-x/AMD-V in VM settings
- **Check:** Host system resources

#### Graphics Issues
- **Change:** Graphics controller to VBoxVGA
- **Try:** Different video memory settings
- **Install:** VirtualBox Guest Additions

### Common DVWA Issues

#### 404 Not Found Error
```bash
# Check if Apache is running
sudo systemctl status apache2

# Check if symlink exists
ls -la /var/www/html/

# Recreate symlink if needed
sudo rm /var/www/html/dvwa
sudo ln -s /usr/share/dvwa /var/www/html/dvwa
```

#### Database Connection Issues
```bash
# Reset MySQL password
sudo mysql_secure_installation

# Check MySQL status
sudo systemctl status mysql

# Verify database exists
sudo mysql -u root -p -e "SHOW DATABASES;"
```

#### Permission Errors
```bash
# Reset all permissions
sudo chown -R www-data:www-data /usr/share/dvwa
sudo chmod -R 755 /usr/share/dvwa
sudo chmod 666 /usr/share/dvwa/hackable/uploads/
sudo chmod 666 /usr/share/dvwa/config/config.inc.php
```

#### PHP Errors
```bash
# Check PHP version
php --version

# Install missing PHP modules
sudo apt install php-mysql php-gd

# Restart Apache
sudo systemctl restart apache2
```

### Useful Commands

#### VM Management
```bash
# Check system resources
htop
free -h
df -h

# Network status
ip addr show
ping google.com
```

#### Service Management
```bash
# Start services
sudo systemctl start apache2 mysql

# Stop services
sudo systemctl stop apache2 mysql

# Check status
sudo systemctl status apache2
sudo systemctl status mysql

# Enable auto-start
sudo systemctl enable apache2 mysql
```

---

## Additional Security Tools in Kali

Once your VM is working, explore these pre-installed tools:

### Network Analysis
- **Nmap:** Network scanning
- **Wireshark:** Packet analysis
- **Netcat:** Network utility

### Web Application Testing
- **Burp Suite:** Web app security testing
- **OWASP ZAP:** Security testing proxy
- **Nikto:** Web server scanner

### Password Testing
- **John the Ripper:** Password cracking
- **Hashcat:** Advanced password recovery
- **Hydra:** Network login cracker

### Social Engineering
- **Social Engineering Toolkit (SET)**
- **Maltego:** Information gathering

---

## Best Practices

### VM Maintenance
1. **Regular snapshots** before major changes
2. **Keep system updated:** `sudo apt update && sudo apt upgrade`
3. **Monitor resource usage**
4. **Backup important configurations**

### Security Learning
1. **Start with Low security** in DVWA
2. **Document your findings**
3. **Practice on isolated networks only**
4. **Always get permission** before testing

### Ethical Considerations
- **Only test systems you own or have permission to test**
- **Use knowledge responsibly**
- **Follow local laws and regulations**
- **Respect others' privacy and data**

---

*This guide provides a complete setup for Kali Linux VM with DVWA for educational cybersecurity purposes. Always ensure you're using these tools ethically and legally.*