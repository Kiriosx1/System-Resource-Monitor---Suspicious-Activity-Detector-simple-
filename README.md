# System Resource Monitor - Suspicious Activity Detector

A cross-platform C++ application that monitors system processes and detects suspicious activity based on CPU usage, memory consumption, and resource growth patterns.

## Features

- 🔍 **Real-time Process Monitoring** - Scans all running processes continuously
- 🚨 **Suspicious Activity Detection** - Alerts on abnormal resource usage
- 💻 **CPU Usage Tracking** - Monitors processor utilization per process
- 🧠 **Memory Monitoring** - Tracks RAM consumption and memory leaks
- 📈 **Growth Pattern Analysis** - Detects rapid memory growth (potential threats)
- 🖥️ **Cross-Platform** - Works on Windows and Linux systems
- ⚙️ **Customizable Thresholds** - Adjust detection sensitivity

## Use Cases

- Detect cryptocurrency miners consuming resources
- Identify memory leaks in applications
- Monitor system performance and resource hogs
- Security monitoring for abnormal process behavior
- System administration and troubleshooting

## Requirements

### Windows
- Windows 7 or later
- Visual Studio 2015+ or MinGW-w64
- C++11 compatible compiler

### Linux
- GCC 4.8+ or Clang 3.4+
- C++11 support
- Access to `/proc` filesystem

## Installation

### Clone the Repository

```bash
git clone https://github.com/yourusername/system-resource-monitor.git
cd system-resource-monitor
```

### Compile

**Windows (Visual Studio):**
```bash
cl /EHsc /std:c++11 monitor.cpp /Fe:monitor.exe
```

**Windows (MinGW):**
```bash
g++ -std=c++11 monitor.cpp -o monitor.exe
```

**Linux:**
```bash
g++ -std=c++11 monitor.cpp -o monitor -lpthread
```

## Usage

### Basic Usage

Run the monitor with default settings:

```bash
./monitor
```

### Default Configuration

- **CPU Threshold:** 70%
- **Memory Threshold:** 400 MB
- **Scan Interval:** 5 seconds
- **Iterations:** 10 scans

### Customization

Edit the `main()` function to adjust parameters:

```cpp
// Custom thresholds: 80% CPU, 500MB RAM
ResourceMonitor monitor(80.0, 500);

// Monitor every 10 seconds, 20 iterations
monitor.monitor(10, 20);
```

### Example Output

```
Starting Resource Monitor...
CPU Threshold: 70%
Memory Threshold: 400 MB

Scan #1

=== Suspicious Activity Report ===
Timestamp: 1732464000

[ALERT] PID: 1234 | Name: chrome.exe
  Reason: High Memory (512 MB) 
  CPU: 45.2% | Memory: 512 MB

[ALERT] PID: 5678 | Name: miner.exe
  Reason: High CPU (85.3%) Rapid memory growth (+150 MB) 
  CPU: 85.3% | Memory: 450 MB

==================================
```

## How It Works

### Detection Logic

1. **High CPU Usage** - Flags processes exceeding the CPU threshold
2. **High Memory Consumption** - Detects processes using excessive RAM
3. **Rapid Memory Growth** - Identifies processes with >100MB memory increases between scans

### Process Information Collected

- Process ID (PID)
- Process name
- CPU usage percentage
- Memory usage (Working Set/RSS)
- Timestamp of measurement

## Architecture

### Core Components

- **ResourceMonitor Class** - Main monitoring engine
- **ProcessInfo Struct** - Data structure for process information
- **Platform-Specific APIs:**
  - Windows: `CreateToolhelp32Snapshot`, `GetProcessMemoryInfo`
  - Linux: `/proc` filesystem parsing

## Permissions

### Windows
- Runs with current user privileges
- Administrator rights required for full process access

### Linux
- Regular user can monitor own processes
- Root/sudo required for system-wide monitoring:
  ```bash
  sudo ./monitor
  ```

## Configuration Options

You can modify detection behavior in the `ResourceMonitor` constructor:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cpuThreshold` | double | 70.0 | CPU usage percentage threshold |
| `memoryThreshold` | size_t | 400 | Memory usage threshold in MB |

Adjust scanning in the `monitor()` method:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `intervalSeconds` | int | 5 | Seconds between scans |
| `iterations` | int | 10 | Number of scan cycles |

## Limitations

- CPU usage calculation is simplified and may not reflect exact real-time usage
- Does not monitor network activity
- Historical data cleared between program runs
- Process names may be truncated on some systems

## Future Enhancements

- [ ] Network activity monitoring
- [ ] Process blacklist/whitelist
- [ ] Log file export (CSV/JSON)
- [ ] Email/notification alerts
- [ ] GUI interface
- [ ] Real-time graphing
- [ ] Database storage for historical analysis
- [ ] Multi-threaded scanning for better performance

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for legitimate system monitoring and security purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. Do not use this tool to monitor systems without proper authorization.

## Support

If you encounter issues or have questions:

- Open an issue on GitHub
- Check existing issues for solutions
- Provide system info and error messages when reporting bugs

## Author

[Your Name]
- GitHub: [@yourusername](https://github.com/yourusername)
- Email: your.email@example.com

## Acknowledgments

- Thanks to the open-source community for inspiration
- Built with standard C++ and platform APIs

---

⭐ If you find this project useful, please consider giving it a star!
