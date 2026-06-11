import React, { useState, useEffect } from 'react';
import { Shield, Wifi, AlertTriangle, CheckCircle, Radio, Lock, Unlock, Activity, Search } from 'lucide-react';

const IoTSecurityDashboard = () => {
  const [scanning, setScanning] = useState(false);
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [networkTraffic, setNetworkTraffic] = useState([]);

  // Simulate IoT device discovery
  const scanNetwork = () => {
    setScanning(true);
    setTimeout(() => {
      const mockDevices = [
        {
          id: 1,
          name: 'Smart Camera',
          ip: '192.168.1.101',
          mac: '00:1A:2B:3C:4D:5E',
          type: 'Camera',
          protocol: 'RTSP',
          port: 554,
          encryption: false,
          defaultCreds: true,
          firmwareVersion: '1.2.3',
          riskLevel: 'critical'
        },
        {
          id: 2,
          name: 'Smart Thermostat',
          ip: '192.168.1.102',
          mac: '00:1A:2B:3C:4D:5F',
          type: 'Thermostat',
          protocol: 'MQTT',
          port: 1883,
          encryption: false,
          defaultCreds: false,
          firmwareVersion: '2.1.0',
          riskLevel: 'high'
        },
        {
          id: 3,
          name: 'Smart Lock',
          ip: '192.168.1.103',
          mac: '00:1A:2B:3C:4D:60',
          type: 'Lock',
          protocol: 'Zigbee',
          port: 8080,
          encryption: true,
          defaultCreds: false,
          firmwareVersion: '3.0.1',
          riskLevel: 'medium'
        },
        {
          id: 4,
          name: 'Smart Bulb',
          ip: '192.168.1.104',
          mac: '00:1A:2B:3C:4D:61',
          type: 'Light',
          protocol: 'CoAP',
          port: 5683,
          encryption: false,
          defaultCreds: true,
          firmwareVersion: '1.0.5',
          riskLevel: 'low'
        },
        {
          id: 5,
          name: 'Industrial PLC',
          ip: '192.168.1.105',
          mac: '00:1A:2B:3C:4D:62',
          type: 'PLC',
          protocol: 'Modbus',
          port: 502,
          encryption: false,
          defaultCreds: true,
          firmwareVersion: '4.2.1',
          riskLevel: 'critical'
        }
      ];
      setDevices(mockDevices);
      setScanning(false);
    }, 2000);
  };

  // Vulnerability assessment
  const assessVulnerabilities = (device) => {
    const vulns = [];
    if (!device.encryption) {
      vulns.push({
        severity: 'high',
        title: 'Unencrypted Communication',
        description: `Device uses ${device.protocol} without encryption`,
        cve: 'CWE-319',
        remediation: 'Enable TLS/SSL encryption for all communications'
      });
    }
    if (device.defaultCreds) {
      vulns.push({
        severity: 'critical',
        title: 'Default Credentials',
        description: 'Device is using factory default username/password',
        cve: 'CWE-798',
        remediation: 'Change default credentials immediately'
      });
    }
    if (device.port < 1024) {
      vulns.push({
        severity: 'medium',
        title: 'Privileged Port Exposure',
        description: `Service running on privileged port ${device.port}`,
        cve: 'CWE-276',
        remediation: 'Use non-privileged ports or implement proper access controls'
      });
    }
    if (device.type === 'Camera' && !device.encryption) {
      vulns.push({
        severity: 'critical',
        title: 'Video Stream Exposure',
        description: 'Unencrypted video feed accessible on network',
        cve: 'CWE-522',
        remediation: 'Implement SRTP or HTTPS for video streaming'
      });
    }
    if (device.type === 'PLC') {
      vulns.push({
        severity: 'critical',
        title: 'Industrial Control System Exposure',
        description: 'Critical infrastructure device accessible without authentication',
        cve: 'CWE-306',
        remediation: 'Implement network segmentation and authentication'
      });
    }
    return vulns;
  };

  // Simulate network traffic
  useEffect(() => {
    const interval = setInterval(() => {
      if (devices.length > 0) {
        const newTraffic = {
          timestamp: new Date().toLocaleTimeString(),
          device: devices[Math.floor(Math.random() * devices.length)].name,
          protocol: ['MQTT', 'HTTP', 'CoAP', 'RTSP'][Math.floor(Math.random() * 4)],
          bytes: Math.floor(Math.random() * 10000),
          encrypted: Math.random() > 0.5
        };
        setNetworkTraffic(prev => [...prev.slice(-9), newTraffic]);
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [devices]);

  // Helper for risk badge colors (uses custom CSS classes for risk levels)
  const getRiskClass = (level) => {
    switch(level) {
      case 'critical': return 'risk-badge risk-critical';
      case 'high': return 'risk-badge risk-high';
      case 'medium': return 'risk-badge risk-medium';
      case 'low': return 'risk-badge risk-low';
      default: return 'risk-badge';
    }
  };

  // Helper for vulnerability severity colors
  const getSeverityClass = (severity) => {
    switch(severity) {
      case 'critical': return 'severity-badge vuln-critical';
      case 'high': return 'severity-badge vuln-high';
      case 'medium': return 'severity-badge vuln-medium';
      case 'low': return 'severity-badge vuln-low';
      default: return 'severity-badge';
    }
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-wrapper">
        {/* Header */}
        <div className="header-card">
          <div className="header-content">
            <div className="header-left">
              <Shield className="header-icon" />
              <div>
                <h1 className="header-title">IoT Security Framework</h1>
                <p className="header-subtitle">Real-time Device Monitoring & Vulnerability Assessment</p>
              </div>
            </div>
            <button
              onClick={scanNetwork}
              disabled={scanning}
              className="scan-button"
            >
              <Search className="w-5 h-5" />
              {scanning ? 'Scanning...' : 'Scan Network'}
            </button>
          </div>
        </div>

        {/* Statistics */}
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-content">
              <div>
                <p className="stat-label">Total Devices</p>
                <p className="stat-value">{devices.length}</p>
              </div>
              <Wifi className="stat-icon" />
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-content">
              <div>
                <p className="stat-label">Critical Risks</p>
                <p className="stat-value">
                  {devices.filter(d => d.riskLevel === 'critical').length}
                </p>
              </div>
              <AlertTriangle className="stat-icon" />
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-content">
              <div>
                <p className="stat-label">Unencrypted</p>
                <p className="stat-value">
                  {devices.filter(d => !d.encryption).length}
                </p>
              </div>
              <Unlock className="stat-icon" />
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-content">
              <div>
                <p className="stat-label">Secure Devices</p>
                <p className="stat-value">
                  {devices.filter(d => d.encryption && !d.defaultCreds).length}
                </p>
              </div>
              <CheckCircle className="stat-icon" />
            </div>
          </div>
        </div>

        <div className="main-grid">
          {/* Device List */}
          <div className="content-card">
            <h2 className="card-title">
              <Radio className="stat-icon" />
              Discovered Devices
            </h2>
            <div className="device-list">
              {devices.length === 0 ? (
                <p className="empty-state">No devices found. Click "Scan Network" to discover IoT devices.</p>
              ) : (
                devices.map(device => (
                  <div
                    key={device.id}
                    onClick={() => {
                      setSelectedDevice(device);
                      setVulnerabilities(assessVulnerabilities(device));
                    }}
                    className="device-item"
                  >
                    <div className="device-header">
                      <div>
                        <span className="device-name">{device.name}</span>
                        <span className="device-info">{device.ip} • {device.type}</span>
                      </div>
                      <span className={getRiskClass(device.riskLevel)}>
                        {device.riskLevel.toUpperCase()}
                      </span>
                    </div>
                    <div className="device-details">
                      <span>{device.protocol}</span>
                      <span>Port {device.port}</span>
                      {device.encryption ? (
                        <Lock className="device-icon icon-secure" />
                      ) : (
                        <Unlock className="device-icon icon-unsecure" />
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Vulnerability Details */}
          <div className="content-card">
            <h2 className="card-title">
              <AlertTriangle className="stat-icon" />
              Vulnerability Assessment
            </h2>
            {selectedDevice ? (
              <div className="vulnerability-list">
                <div className="device-summary">
                  <h3>{selectedDevice.name}</h3>
                  <div className="summary-details">
                    <p>Firmware: v{selectedDevice.firmwareVersion}</p>
                    <p>MAC: {selectedDevice.mac}</p>
                  </div>
                </div>
                {vulnerabilities.map((vuln, idx) => (
                  <div key={idx} className={`vulnerability-item ${getSeverityClass(vuln.severity)}`}>
                    <div className="vuln-header">
                      <span className="vuln-title">{vuln.title}</span>
                      <span className="severity-badge">{vuln.severity}</span>
                    </div>
                    <p className="vuln-description">{vuln.description}</p>
                    <p className="vuln-cve">{vuln.cve}</p>
                    <div className="vuln-remediation">
                      <span className="remediation-label">Remediation:</span>
                      <span className="remediation-text">{vuln.remediation}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="empty-state">Select a device to view vulnerabilities</p>
            )}
          </div>
        </div>

        {/* Network Traffic Monitor */}
        <div className="traffic-card">
          <h2 className="card-title">
            <Activity className="stat-icon" />
            Real-time Network Traffic
          </h2>
          <div className="traffic-table-container">
            <table className="traffic-table">
              <thead>
                <tr>
                  <th className="traffic-timestamp">Timestamp</th>
                  <th className="traffic-device">Device</th>
                  <th className="traffic-protocol">Protocol</th>
                  <th className="traffic-bytes">Bytes</th>
                  <th>Encrypted</th>
                </tr>
              </thead>
              <tbody>
                {networkTraffic.map((traffic, idx) => (
                  <tr key={idx}>
                    <td className="traffic-timestamp">{traffic.timestamp}</td>
                    <td className="traffic-device">{traffic.device}</td>
                    <td className="traffic-protocol">{traffic.protocol}</td>
                    <td className="traffic-bytes">{traffic.bytes.toLocaleString()}</td>
                    <td>
                      {traffic.encrypted ? (
                        <Lock className="device-icon icon-secure" />
                      ) : (
                        <Unlock className="device-icon icon-unsecure" />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IoTSecurityDashboard;