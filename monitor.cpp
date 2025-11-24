#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <ctime>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "psapi.lib")
#elif __linux__
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <unistd.h>
#endif

struct ProcessInfo {
    int pid;
    std::string name;
    double cpuUsage;
    size_t memoryUsage; // in KB
    time_t timestamp;
};

class ResourceMonitor {
private:
    std::map<int, ProcessInfo> processHistory;
    double cpuThreshold;
    size_t memoryThreshold; // in MB
    
public:
    ResourceMonitor(double cpuThresh = 80.0, size_t memThresh = 500)
        : cpuThreshold(cpuThresh), memoryThreshold(memThresh) {}
    
#ifdef _WIN32
    std::vector<ProcessInfo> getProcessList() {
        std::vector<ProcessInfo> processes;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (snapshot == INVALID_HANDLE_VALUE) return processes;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &pe32)) {
            do {
                ProcessInfo info;
                info.pid = pe32.th32ProcessID;
#ifdef UNICODE
                // Convert wide-char process name (WCHAR[]) to UTF-8 std::string
                std::wstring wname(pe32.szExeFile);
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, wname.c_str(), (int)wname.size(), NULL, 0, NULL, NULL);
                if (size_needed > 0) {
                    std::string nameUtf8(size_needed, 0);
                    WideCharToMultiByte(CP_UTF8, 0, wname.c_str(), (int)wname.size(), &nameUtf8[0], size_needed, NULL, NULL);
                    info.name = nameUtf8;
                } else {
                    info.name = "";
                }
#else
                info.name = pe32.szExeFile;
#endif
                info.timestamp = time(nullptr);
                
                // Open process to get memory info
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        info.memoryUsage = pmc.WorkingSetSize / 1024; // Convert to KB
                    }
                    
                    // Get CPU usage (simplified)
                    FILETIME ftCreation, ftExit, ftKernel, ftUser;
                    if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
                        ULARGE_INTEGER kernel, user;
                        kernel.LowPart = ftKernel.dwLowDateTime;
                        kernel.HighPart = ftKernel.dwHighDateTime;
                        user.LowPart = ftUser.dwLowDateTime;
                        user.HighPart = ftUser.dwHighDateTime;
                        
                        // Simplified CPU calculation
                        info.cpuUsage = (kernel.QuadPart + user.QuadPart) / 10000.0;
                    }
                    
                    CloseHandle(hProcess);
                }
                
                processes.push_back(info);
            } while (Process32Next(snapshot, &pe32));
        }
        
        CloseHandle(snapshot);
        return processes;
    }
#elif __linux__
    std::vector<ProcessInfo> getProcessList() {
        std::vector<ProcessInfo> processes;
        DIR* dir = opendir("/proc");
        
        if (!dir) return processes;
        
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;
            
            int pid = atoi(entry->d_name);
            if (pid <= 0) continue;
            
            ProcessInfo info;
            info.pid = pid;
            info.timestamp = time(nullptr);
            
            // Read process name
            std::string statPath = "/proc/" + std::string(entry->d_name) + "/stat";
            std::ifstream statFile(statPath);
            if (statFile.is_open()) {
                std::string line;
                std::getline(statFile, line);
                
                size_t start = line.find('(') + 1;
                size_t end = line.find(')');
                if (start != std::string::npos && end != std::string::npos) {
                    info.name = line.substr(start, end - start);
                }
                
                // Parse CPU times (simplified)
                std::istringstream iss(line.substr(end + 2));
                long utime, stime;
                for (int i = 0; i < 11; ++i) iss.ignore(256, ' ');
                iss >> utime >> stime;
                info.cpuUsage = (utime + stime) / sysconf(_SC_CLK_TCK);
            }
            
            // Read memory usage
            std::string statusPath = "/proc/" + std::string(entry->d_name) + "/status";
            std::ifstream statusFile(statusPath);
            if (statusFile.is_open()) {
                std::string line;
                while (std::getline(statusFile, line)) {
                    if (line.find("VmRSS:") == 0) {
                        std::istringstream iss(line.substr(6));
                        iss >> info.memoryUsage;
                        break;
                    }
                }
            }
            
            processes.push_back(info);
        }
        
        closedir(dir);
        return processes;
    }
#endif
    
    void detectSuspiciousActivity(const std::vector<ProcessInfo>& processes) {
        std::cout << "\n=== Suspicious Activity Report ===" << std::endl;
        std::cout << "Timestamp: " << time(nullptr) << std::endl;
        bool foundSuspicious = false;
        
        for (const auto& proc : processes) {
            bool suspicious = false;
            std::string reason;
            
            // Check CPU usage
            if (proc.cpuUsage > cpuThreshold) {
                suspicious = true;
                reason += "High CPU (" + std::to_string(proc.cpuUsage) + "%) ";
            }
            
            // Check memory usage (convert KB to MB)
            size_t memoryMB = proc.memoryUsage / 1024;
            if (memoryMB > memoryThreshold) {
                suspicious = true;
                reason += "High Memory (" + std::to_string(memoryMB) + " MB) ";
            }
            
            // Check for rapid memory growth
            if (processHistory.count(proc.pid) > 0) {
                const ProcessInfo& prev = processHistory[proc.pid];
                double memGrowth = (proc.memoryUsage - prev.memoryUsage) / 1024.0; // MB
                
                if (memGrowth > 100) { // More than 100MB growth
                    suspicious = true;
                    reason += "Rapid memory growth (+" + std::to_string(memGrowth) + " MB) ";
                }
            }
            
            if (suspicious) {
                foundSuspicious = true;
                std::cout << "\n[ALERT] PID: " << proc.pid 
                         << " | Name: " << proc.name << std::endl;
                std::cout << "  Reason: " << reason << std::endl;
                std::cout << "  CPU: " << proc.cpuUsage << "% | Memory: " 
                         << (proc.memoryUsage / 1024) << " MB" << std::endl;
            }
            
            // Update history
            processHistory[proc.pid] = proc;
        }
        
        if (!foundSuspicious) {
            std::cout << "No suspicious activity detected." << std::endl;
        }
        std::cout << "==================================\n" << std::endl;
    }
    
    void monitor(int intervalSeconds = 5, int iterations = 10) {
        std::cout << "Starting Resource Monitor..." << std::endl;
        std::cout << "CPU Threshold: " << cpuThreshold << "%" << std::endl;
        std::cout << "Memory Threshold: " << memoryThreshold << " MB" << std::endl;
        
        for (int i = 0; i < iterations; ++i) {
            std::cout << "\nScan #" << (i + 1) << std::endl;
            
            auto processes = getProcessList();
            detectSuspiciousActivity(processes);
            
            if (i < iterations - 1) {
                std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
            }
        }
    }
};

int main() {
    // Create monitor with thresholds: 70% CPU, 400MB RAM
    ResourceMonitor monitor(70.0, 400);
    
    // Monitor every 5 seconds, 10 iterations
    monitor.monitor(5, 10);
    
    std::cout << "Monitoring complete." << std::endl;
    return 0;
}