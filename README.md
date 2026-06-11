# SafeHome360 — IoT Security Dashboard

A React-based dashboard for real-time IoT device monitoring and vulnerability assessment on a local network.

## Features

- **Network Scanning** — Discovers IoT devices on the local network and displays their IP, MAC address, protocol, and port
- **Risk Classification** — Categorizes each device as Critical, High, Medium, or Low risk
- **Vulnerability Assessment** — Analyzes each device for common security weaknesses:
  - Unencrypted communication (CWE-319)
  - Default credentials in use (CWE-798)
  - Privileged port exposure (CWE-276)
  - Unencrypted video stream (CWE-522)
  - Industrial control system exposure (CWE-306)
- **Real-time Traffic Monitor** — Live table showing network traffic per device including protocol, bytes transferred, and encryption status

## Tech Stack

- React 19
- [Lucide React](https://lucide.dev/) — icons
- Create React App

## Getting Started

```bash
cd iot-security-dashboard
npm install
npm start
```

The app will run at `http://localhost:3000`.

## Usage

1. Open the dashboard in your browser
2. Click **Scan Network** to discover IoT devices
3. Click any device in the list to view its vulnerability assessment and remediation steps
4. Monitor live network traffic in the table at the bottom of the page

## Project Structure

```
iot-security-dashboard/
├── src/
│   ├── App.js          # Root component
│   ├── App.css         # Global styles
│   └── Codes.js        # IoTSecurityDashboard main component
└── public/
    └── index.html
```

## License

MIT
