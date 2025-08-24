#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <set>

using namespace std;

// Struct to hold packet data from CSV
struct Packet {
    long long timestamp;
    string srcIP;
    string destIP;
    int srcPort;
    int destPort;
    string protocol;
    int size;
};

// Function to parse a single line from the CSV
Packet parsePacketLine(const string& line) {
    Packet p;
    stringstream ss(line);
    string token;

    getline(ss, token, ',');
    p.timestamp = stoll(token);
    getline(ss, p.srcIP, ',');
    getline(ss, p.destIP, ',');
    getline(ss, token, ',');
    p.srcPort = stoi(token);
    getline(ss, token, ',');
    p.destPort = stoi(token);
    getline(ss, p.protocol, ',');
    getline(ss, token, ',');
    p.size = stoi(token);

    return p;
}

int main() {
    ifstream inputFile("packets.csv");
   ofstream alertsFile("output/alerts.csv", ios::app);

    if (!inputFile.is_open()) {
        cerr << "Error: packets.csv not found!" << endl;
        return 1;
    }
    
    // Write header to alerts.csv if it's empty
    if (alertsFile.tellp() == 0) {
        alertsFile << "timestamp,alert_type,srcIP\n";
    }

    // Skip the header row of the input CSV
    string headerLine;
    getline(inputFile, headerLine);

    string line;
    // Data structures for your detection algorithms
    map<string, set<int>> port_scan_tracker;
    map<string, int> ddos_tracker; 

    cout << "Starting threat detection..." << endl;

    while (getline(inputFile, line)) {
        if (line.empty()) continue;
        Packet currentPacket = parsePacketLine(line);

        // --- Your Threat Detection Logic Goes Here ---

        // --- 1. Port Scan Detection Logic ---
        // A simple port scan detection: check if a single IP has a high number of unique destination ports
        const int PORT_SCAN_THRESHOLD = 2; // A tunable threshold. Adjust as needed.

        // Increment the count for the current packet's source IP and destination port
        port_scan_tracker[currentPacket.srcIP].insert(currentPacket.destPort);

        // Check if the number of unique destination ports exceeds the threshold
        if (port_scan_tracker[currentPacket.srcIP].size() > PORT_SCAN_THRESHOLD) {
            // Check if we have already alerted for this specific scan to avoid repeat alerts
            // We use a simple console output for now, but a more robust check would be better
            cout << "ALERT: Port Scan detected!" << endl;
            cout << "  Source IP: " << currentPacket.srcIP << endl;
            cout << "  Timestamp: " << currentPacket.timestamp << endl;
            
            // Log the alert to the alerts.csv file
            alertsFile << currentPacket.timestamp << ",Port_Scan," << currentPacket.srcIP << endl;
            
            // For this simple example, we'll reset the tracker for this IP
            // after the first alert to prevent an overwhelming number of alerts
            port_scan_tracker[currentPacket.srcIP].clear();
        }

       // --- 2. DDoS Detection Logic ---
        // A simple DDoS detection: check for a high frequency of packets from a single source IP
        const int DDOS_THRESHOLD = 5; // Another tunable threshold

        // Increment the counter for the current packet's source IP
        ddos_tracker[currentPacket.srcIP]++;

        // Check if the packet count from this IP exceeds the threshold
        if (ddos_tracker[currentPacket.srcIP] > DDOS_THRESHOLD) {
            cout << "ALERT: High traffic volume (DDoS) detected!" << endl;
            cout << "  Source IP: " << currentPacket.srcIP << endl;
            cout << "  Timestamp: " << currentPacket.timestamp << endl;

            // Log the alert
            alertsFile << currentPacket.timestamp << ",DDoS_Attack," << currentPacket.srcIP << endl;
            
            // For this simple example, reset the counter to prevent repeat alerts for the same scan
            ddos_tracker[currentPacket.srcIP] = 0;
        }
        // When you detect a threat, write to alerts.csv
        // Example: 
        // alertsFile << currentPacket.timestamp << ",Port_Scan," << currentPacket.srcIP << endl;

    }

    cout << "Threat detection complete. Alerts saved to alerts.csv" << endl;

    inputFile.close();
    alertsFile.close();

    return 0;
}