# PC Hardware Report

A **self-contained PowerShell tool** that generates a clean, professional **HTML hardware and software inventory report** for Windows PCs.

Designed for:
- Troubleshooting
- System audits
- Helping friends/family diagnose machines
- Future conversion to a standalone EXE

No external dependencies. No installers. No telemetry.

---

##  Features

###  Hardware Inventory
- Computer system (manufacturer, model, system type)
- CPU(s)
- Physical memory (DIMMs + summary)
- Motherboard (BaseBoard)
- BIOS / firmware
- GPU / video controller
- Disk drives (hardware)
- Physical disks
- Logical disks / volumes
- SMART / failure prediction (best effort)
- Monitors (EDID)
- Network adapters (physical)
- Network IP configuration
- Wi-Fi driver details
- USB devices
- Audio devices
- Active power plan
- Secure Boot status
- TPM status

> **PSU sizing checklist intentionally removed**

---

###  Installed Applications (Advanced mode)
Advanced mode includes a **superset** of what you see in *Control Panel → Programs and Features*:

- Classic desktop apps (MSI / EXE)
  - 64-bit + 32-bit
  - Per-machine and per-user
- Microsoft Store (UWP) apps

⚠️ Portable apps or software that does not register itself with Windows cannot be detected (same limitation as Control Panel).

---

###  Plug and Play Devices (Advanced mode only)
- PnP **class summary** (counts per device class)
- Full device listings intentionally omitted for readability

---

##  Modes

### **Basic**
- Core hardware
- OS and security
- Storage, networking, power, TPM
- Fast and clean

### **Advanced**
- Everything in Basic
- Installed applications (Classic + Store)
- PnP device class summary

---

##  Preflight & UX
- Clean CLI selector (Basic / Advanced)
- Preflight confirmation before collection
- User-selectable output folder (Desktop by default)
- Progress bars for:
  - Data collection
  - Report generation
- Safe for double-click execution

---

##  Output
- **HTML report only**
- Dark-mode aware (uses `prefers-color-scheme`)
- Fixed table of contents for fast navigation
- Optional CSV export per table
- Embedded raw JSON snapshot (collapsed by default)

