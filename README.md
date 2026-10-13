# Windows Port Scanner (TCP & UDP)

A lightweight, user-level port scanner built for Windows. It requires **no Administrator privileges** and runs safely in regular user space via Python standard library.

---

## 🚀 Features

- **No Administrator Rights Needed**: Uses standard user-space Winsock connections (`SOCK_STREAM` for TCP and `SOCK_DGRAM` for UDP).
- **Supports TCP & UDP**: Scan TCP, UDP, or both simultaneously.
- **Port Search & Filter**:
  - Filter results dynamically by typing port number, service name, or status (e.g., `80`, `HTTP`, `open`).
  - Search single ports (`80`), ranges (`1-100`), or lists (`80, 443, 8080, 3306`).
  - Quick Presets: Top 20 Common, Web Servers, Databases, Remote Access, and Common UDP.
- **Clear Open / Close Status**: Displays `🟢 OPEN` or `🔴 CLOSED` with service identification and latency in milliseconds.
- **Two User Interfaces**:
  1. **Desktop GUI App** (`port_scanner_gui.py`): Clean desktop window with real-time progress bar, search bar, and CSV export.
  2. **CMD Terminal Tool** (`port_scanner_cmd.py`): Interactive menu or command-line flags directly in `cmd.exe`.

---

## 📁 File Structure

```
C:\Users\PJJD\.gemini\antigravity-ide\scratch\port_scanner\
├── scanner_core.py       # Core multi-threaded socket scanning engine
├── port_scanner_gui.py   # Desktop GUI Application (Tkinter)
├── port_scanner_cmd.py   # Windows CMD / Terminal tool (Interactive + CLI)
├── run_scanner_gui.bat   # 1-click launcher for the GUI
├── run_scanner_cmd.bat   # 1-click launcher for the CMD tool
└── README.md             # Guide and examples
```

---

## 💻 How to Run in Windows CMD

Open `cmd.exe` and navigate to the directory:

```cmd
cd C:\Users\PJJD\.gemini\antigravity-ide\scratch\port_scanner
```

### 1. Launch the Desktop GUI
```cmd
python port_scanner_gui.py
```
*(Or double-click `run_scanner_gui.bat`)*

### 2. Run the Interactive CMD Tool
```cmd
python port_scanner_cmd.py
```
*(Or double-click `run_scanner_cmd.bat`)*

### 3. Run directly with Command-Line arguments in CMD

- **Scan common web ports on localhost:**
  ```cmd
  python port_scanner_cmd.py --host 127.0.0.1 --ports 80,443,3000,8080
  ```

- **Scan a port range (e.g. 20 to 100):**
  ```cmd
  python port_scanner_cmd.py --host 127.0.0.1 --ports 20-100
  ```

- **Show only OPEN ports:**
  ```cmd
  python port_scanner_cmd.py --host 127.0.0.1 --ports 1-1024 --open-only
  ```

- **Scan UDP ports:**
  ```cmd
  python port_scanner_cmd.py --host 127.0.0.1 --ports 53,123,161 --proto udp
  ```

- **Search / filter for specific service:**
  ```cmd
  python port_scanner_cmd.py --host 127.0.0.1 --ports 1-500 --search HTTP
  ```
