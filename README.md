## **Project Title**

**Real-Time Network Traffic Capture and Threat Detection**

---

## **Project Overview**

This project captures live network packets, extracts key details (IP addresses, ports, protocol, packet size), and stores them in a structured CSV file for further analysis. The goal is to detect hidden threats like port scans, DDoS attacks, and suspicious traffic patterns in real-time and visualize them using an ASCII-based dashboard.

---

## **Why This Project?**

* Manual log review is **slow and error-prone**.
* Network attacks like **stealth scans and botnets** hide in raw logs.
* **Real-time visualization + detection = faster response** by security teams.

---

## **Features Implemented**

✔ Live packet capture using **Npcap/WinPcap**
✔ Extract:

* Source IP
* Destination IP
* Protocol
* Ports (source & destination)
* Packet Size
* Timestamp
  ✔ Store captured packets in **packets.csv**
  ✔ Ready for **threat detection** and **visualization**

---

## **Project Structure**

```
/project-folder
  |-- capture.cpp         # Code for packet capture
  |-- packets.csv         # Captured packet logs
  |-- README.md           # Documentation
```

---

## **Tech Stack**

* **Language:** C++
* **Libraries:** WinPcap/Npcap (Windows) or libpcap (Linux)
* **Tools:** Visual Studio Code, MinGW Compiler

---

## **Setup Instructions**

### 1. Install Dependencies

* Install **Npcap** ([https://nmap.org/npcap/](https://nmap.org/npcap/))
* Install **WinPcap Developer Pack** (if needed)
* Install **g++ (MinGW)** for compiling C++

### 2. Clone Repo

```bash
git clone https://github.com/your-username/network-threat-monitor.git
cd network-threat-monitor
```

### 3. Compile Code

```bash
g++ capture.cpp -IC:\Path\To\Npcap\Include -LC:\Path\To\Npcap\Lib -lwpcap -o capture.exe
```

### 4. Run Code

```bash
capture.exe
```

It will capture **100 packets** and store them in `packets.csv`.

---
#**uptill this i had done for our project**

## **CSV Format**

```
timestamp,srcIP,destIP,srcPort,destPort,protocol,size
```

Example:

```
1695131234,192.168.1.10,8.8.8.8,50022,53,UDP,128
```


---

###  CSV Columns Explained:

1. **timestamp**

   * Unix time (seconds since 1970).
   * Indicates **when the packet was captured**.
   * **Why needed?**

     * Helps detect abnormal traffic bursts (DDoS, port scan).

2. **srcIP (Source IP)**

   * IP address of the sender.
   * **Why needed?**

     * Threat detection: Check if one IP is sending too many requests.

3. **destIP (Destination IP)**

   * IP address of the receiver.
   * **Why needed?**

     * Detect targeted attacks or scans toward a specific IP.

4. **srcPort (Source Port)**

   * Port number on the sender machine.
   * **Why needed?**

     * For understanding traffic patterns and identifying services.

5. **destPort (Destination Port)**

   * Port number on the receiver machine.
   * **Why needed?**

     * Detect port scanning (attacker tries many ports).

6. **protocol**

   * Example: TCP, UDP, ICMP.
   * **Why needed?**

     * Identify type of traffic (HTTP = TCP 80, DNS = UDP 53).

7. **size**

   * Packet size in bytes.
   * **Why needed?**

     * Detect anomalies (very large or small packets can indicate attacks).

---

### ✅ How Others Use This CSV:

* **Pranav (Threat Detection):**

  * Reads CSV → Detect patterns (same `srcIP` hitting multiple `destPorts` quickly = port scan).
  * High traffic frequency = DDoS.

* **Bhavik (Storage):**

  * Converts this CSV into **SQLite DB** for queries and reports.

* **Anuja (Visualization):**

  * Displays packet flow like:

    ```
    [192.168.1.5:443] ---> [8.8.8.8:53] (UDP)
    ```
  * Color code: Red for alerts, Green for normal.

---

## **Workflow for Team**

| Member     | Task                      | Input                         | Output                            |
| ---------- | ------------------------- | ----------------------------- | --------------------------------- |
| **Sumit**  | Packet Capture & Parsing  | Network packets               | `packets.csv`                     |
| **Pranav** | Threat Detection Engine   | `packets.csv`                 | Alerts in console or `alerts.csv` |
| **Bhavik** | Data Storage & Logging    | `packets.csv`                 | SQLite database                   |
| **Anuja**  | Visualization & Dashboard | `packets.csv` or `alerts.csv` | ASCII-based map                   |

---

## **Future Enhancements**

* Real-time visualization in **GUI** (Qt)
* Advanced detection using ML
* Support for IPv6

---

---

# ✅ What Each Member Does Next

### **Sumit **

✔ Done: Capturing packets and saving CSV.
Next:

* Push code & CSV to GitHub.
* Add comments in `capture.cpp` for clarity.
* Optional: Add protocol filter (TCP, UDP, ICMP).

---

### **Pranav – Threat Detection Engine**

* Read `packets.csv`.
* Implement:

  * Port scan detection (same IP hitting many ports).
  * DDoS detection (high-frequency requests from one IP).
* Output alerts in:

  * Console (`cout`)
  * `alerts.csv` with format:

    ```
    timestamp,alert_type,srcIP
    ```

---

### **Bhavik – Data Storage & Logging**

* Convert `packets.csv` → SQLite database.
* Table schema:

```sql
CREATE TABLE packets (
    timestamp INTEGER,
    srcIP TEXT,
    destIP TEXT,
    srcPort INTEGER,
    destPort INTEGER,
    protocol TEXT,
    size INTEGER
);
```

* Implement C++ code to insert rows from CSV to DB.
* Ensure **thread safety** if logging real-time data later.

---

### **Anuja – Visualization**

* Read `packets.csv` or `alerts.csv`.
* Build ASCII-based map:

```
[192.168.1.10] ---> [8.8.8.8] (TCP)
```

* Color code using ANSI escape codes:

  * Green = Normal
  * Red = Suspicious
* Show top talkers (IPs sending most packets).

---


