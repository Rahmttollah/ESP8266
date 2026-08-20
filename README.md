# ESP8266 Projects
[![Ask DeepWiki](https://devin.ai/assets/askdeepwiki.png)](https://deepwiki.com/Rahmttollah/ESP8266.git)

This repository contains a collection of projects developed for the ESP8266 microcontroller, demonstrating its capabilities in networking and security analysis.

## CurrentWatch

`CurrentWatch` is a reliable, non-blocking heartbeat client designed to run on an ESP8266. It periodically sends status updates to a remote API, making it suitable for monitoring the uptime and connectivity of a device.

### Features

*   **Reliable Heartbeats:** Sends periodic HTTP POST requests to a specified API endpoint to signal that the device is online.
*   **Non-Blocking Wi-Fi Reconnection:** Features a robust Wi-Fi manager that handles connection loss without blocking the main program loop. It continuously attempts to reconnect until successful.
*   **Immediate Failure Recovery:** On any HTTP or connection failure, the system immediately triggers a reconnection and retries the heartbeat, ensuring high availability.
*   **Optimized Network Performance:** Disables Wi-Fi modem sleep and sets the maximum transmit power (20.5f) for lower latency and a stronger signal.
*   **Forensic Logging:** Implements detailed serial logging with timestamps to provide in-depth diagnostics on Wi-Fi state, HTTP attempts, and device status.

### Project Files

*   `CurrentWatch/Current-Watch.ino`: The complete Arduino source code.
*   `CurrentWatch/Current-Watch.bin`: A pre-compiled binary for direct flashing onto an ESP8266.

## Wifi_Phishing

`Wifi_Phishing` is an advanced Wi-Fi security analysis and penetration testing tool. It hosts a sophisticated web interface that allows for network scanning, deauthentication attacks, and the deployment of an "Evil Twin" access point with a captive phishing portal.

> **Disclaimer:** This tool is intended for educational and research purposes only. Use it responsibly and only on networks you own or have explicit permission to test. Unauthorized use is illegal.

### Features

*   **Web Admin Dashboard:** A modern, responsive web UI to control all functionalities of the tool.
*   **Network Scanner:** Scans for and lists nearby Wi-Fi networks with their SSID, BSSID, vendor, and channel.
*   **Evil Twin Attack:** Creates a fake access point that mimics a selected network to capture client connection attempts.
*   **Captive Phishing Portal:** When a user connects to the Evil Twin AP, they are redirected to a captive portal disguised as a "Firmware Update Failed" page, which prompts for the Wi-Fi password.
*   **Credential Capture and Verification:** Captures submitted passwords and attempts to verify them by connecting to the original target network. Captured credentials are displayed on the admin dashboard.
*   **Deauthentication Attack:** Sends deauthentication frames to a target network to disconnect clients, encouraging them to connect to the Evil Twin AP.
*   **Beacon Spamming (Mask Manager):** Includes a "Mask Manager" to create a list of fake SSIDs and broadcast them as beacon frames, flooding the area with fake networks.

### Project Files

*   `Wifi_Phishing/Phishing.ino`: The complete Arduino source code for the tool.
*   `Wifi_Phishing/Androids/Pishi_Wifi.ino.bin`: A pre-compiled binary of the project.
