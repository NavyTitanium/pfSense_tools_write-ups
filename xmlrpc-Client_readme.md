# pfSense XML-RPC Client

A lightweight Python client for interacting with pfSense's XML-RPC interface, providing both a library and a command-line interface for essential XML-RPC operations.

## Features

- **Core API Coverage**: Supports essential XML-RPC methods available in pfSense
- **Authentication**: Uses HTTP Basic Authentication as required by pfSense
- **SSL Support**: Configurable HTTPS with optional certificate verification
- **Timeout Control**: Configurable timeout for operations
- **Error Handling**: Detailed error reporting for HTTP, XML parsing, and XML-RPC faults
- **Command Line Interface**: Easy to use CLI for common operations

## Command Line Usage

The script provides a convenient command-line interface:

```bash
# Get help
python pfsense_xmlrpc.py --help

# Get firmware version
python pfsense_xmlrpc.py --host 192.168.1.1 --username admin --password pfsense --no-verify version

# Execute PHP code
python pfsense_xmlrpc.py --host 192.168.1.1 --username admin --password pfsense --no-verify exec_php [code]

# Execute shell command
python pfsense_xmlrpc.py --host 192.168.1.1 --username admin --password pfsense --no-verify exec_shell [code]
# Output: Shell execution result: True  (Note: Shell commands only return success status, not output)

# Get shell command output using PHP's shell_exec()
python pfsense_xmlrpc.py --host 192.168.1.1 --username admin --password pfsense --no-verify exec_php 'echo shell_exec("ls -la /tmp");'

# Reboot the system
python pfsense_xmlrpc.py --host 192.168.1.1 --username admin --password pfsense --no-verify reboot
```

## Available XML-RPC Methods

The client supports the following XML-RPC methods:

1. `host_firmware_version()` - Get host firmware version information
2. `exec_php(code)` - Execute PHP code on the pfSense server
3. `exec_shell(code)` - Execute shell commands on the pfSense server (returns only success status, not command output)
4. `reboot()` - Reboot the pfSense system

## Disclaimer

This tool is not affiliated with or endorsed by Netgate or the pfSense project. Use at your own risk.
