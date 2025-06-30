# Registry Monitoring Documentation

## Overview

The Registry Detector is part of our EDR agent's comprehensive monitoring capabilities, designed specifically to track changes within the Windows Registry.

## Features

- **Real-Time Detection**: Monitors specified registry keys continuously and detects changes in real-time.
- **Security Alerts**: Generates security alerts upon detecting suspicious registry changes based on defined rules.
- **Asynchronous Processing**: Utilizes Tokio for non-blocking, efficient event handling and processing.
- **Configurable**: Easily extendable via the `config.yaml` file to support additional keys and customization.

## Configuration

To enable and configure the Registry Detector, modify the `config.yaml` file under the `registry_monitor` section:

```yaml
registry_monitor:
  enabled: true
  watched_keys:
    - HKEY_LOCAL_MACHINE\SOFTWARE\Classes
    - HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
    - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
    - HKEY_LOCAL_MACHINE\SAM
```

## Usage

Once configured, the registry monitoring will begin automatically upon starting the EDR agent. The detector actively monitors the specified registry keys and logs any modifications.

## Log Files

Registry changes and alerts are logged in the agent's log files, providing a detailed account of registry activity.

Make sure to monitor these logs for any security alerts indicating potential threats or unauthorized modifications.

For more detailed analysis, refer to additional tools and manuals within the EDR suite.
