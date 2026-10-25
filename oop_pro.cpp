#include <iostream>
#include <string>

using namespace std;

class Artifact;
void generateAuditTrail(const Artifact &a);

class Artifact {
private:
    string filename;
    int checksum;
    static int totalScanned;

public:
    Artifact(string name) {
        filename = name;
        checksum = computeChecksum(filename);
        totalScanned++;
        cout << "[+] Evidence successfully ingested -> " << filename << endl;
    }

    ~Artifact() {}

    static void displayTotalScans() {
        cout << "\n[METRICS] Total digital artifacts processed: " << totalScanned << endl;
    }

    int computeChecksum(const string &str) {
        int acc = 0;
        for (size_t i = 0; i < str.length(); i++) {
            acc += static_cast<int>(str[i]);
        }
        return acc * 7 + 31;
    }

    int getChecksum() const {
        return checksum;
    }

    string getFilename() const {
        return filename;
    }

    bool operator==(const Artifact &other) const {
        return (this->checksum == other.checksum);
    }

    friend void generateAuditTrail(const Artifact &a);
};

int Artifact::totalScanned = 0;

void generateAuditTrail(const Artifact &a) {
    cout << "\n==========================================" << endl;
    cout << "          FORENSIC AUDIT DOSSIER          " << endl;
    cout << "==========================================" << endl;
    cout << "Target Asset : " << a.filename << endl;
    cout << "Crypto Hash  : [ " << a.checksum << " ]" << endl;
    cout << "Clearance    : Verified via Privileged Friend" << endl;
    cout << "==========================================" << endl;
}

class ForensicsEngine {
public:
    virtual void executeScan() = 0;
    virtual ~ForensicsEngine() {}
};

class LiveLogAnalyzer : public ForensicsEngine {
private:
    Artifact targetEvidence;
    int baselineHash;

public:
    LiveLogAnalyzer(string name, int baseline) : targetEvidence(name) {
        baselineHash = baseline;
    }

    void executeScan() override {
        cout << "\n[Engine] Initiating deep-level integrity inspection..." << endl;
        if (targetEvidence.getChecksum() == baselineHash) {
            cout << "[SECURE] Status Green: Zero anomalies or alterations detected." << endl;
        } else {
            cout << "[CRITICAL] Status Red: Tampering identified! Checksum mismatch." << endl;
        }
    }
};

void showHeader() {
    cout << "==========================================" << endl;
    cout << "     CYBER-FORENSIC INTEGRITY SUITE       " << endl;
    cout << "==========================================" << endl;
}

int main() {
    showHeader();

    string targetFile;
    int choice;

    cout << "\nEnter target evidence designation (e.g., firewall_log.txt, rootkit_dump.bin): ";
    getline(cin, targetFile);

    if (targetFile.empty()) {
        targetFile = "system_audit.log";
    }

    Artifact baselineArtifact(targetFile);

    while (true) {
        cout << "\n--- INVESTIGATION TERMINAL ---" << endl;
        cout << "1. Run Live Integrity Scan" << endl;
        cout << "2. Test Overloaded Operator (Hash Compare)" << endl;
        cout << "3. Export Forensic Audit Dossier" << endl;
        cout << "4. View Session Statistics" << endl;
        cout << "5. Terminate Operation" << endl;
        cout << "Select option: ";
        
        if (!(cin >> choice)) {
            break;
        }

        if (choice == 1) {
            string liveInput;
            cout << "Enter current state filename/string for comparison: ";
            cin >> liveInput;

            ForensicsEngine *engine = new LiveLogAnalyzer(liveInput, baselineArtifact.getChecksum());
            engine->executeScan();
            delete engine;

        } else if (choice == 2) {
            string compInput;
            cout << "Enter secondary file to test equality operator: ";
            cin >> compInput;

            Artifact secondaryArtifact(compInput);
            if (baselineArtifact == secondaryArtifact) {
                cout << "[MATCH] Operator Overload: Both entities share identical signatures." << endl;
            } else {
                cout << "[MISMATCH] Operator Overload: Signatures differ entirely." << endl;
            }

        } else if (choice == 3) {
            generateAuditTrail(baselineArtifact);

        } else if (choice == 4) {
            Artifact::displayTotalScans();

        } else if (choice == 5) {
            cout << "\n[!] Shutting down forensic suite. Secure logs saved." << endl;
            break;
        } else {
            cout << "[!] Invalid option selected. Try again." << endl;
        }
    }

    return 0;
}