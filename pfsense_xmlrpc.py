#!/usr/bin/env python3
"""
PfSense XML-RPC Client

This script provides a client for interacting with pfSense's XML-RPC interface.
It supports a subset of the XML-RPC methods from the pfSense server.
"""

import argparse
import base64
import ssl
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union


class PfSenseXmlRpcClient:
    """Client for interacting with pfSense XML-RPC interface."""

    def __init__(
        self, 
        host: str, 
        username: str, 
        password: str, 
        port: int = 443, 
        https: bool = True, 
        verify_ssl: bool = True,
        timeout: int = 30
    ):
        """
        Initialize the pfSense XML-RPC client.

        Args:
            host: The hostname or IP address of the pfSense server
            username: The username for authentication
            password: The password for authentication
            port: The port number (default: 443)
            https: Whether to use HTTPS (default: True)
            verify_ssl: Whether to verify SSL certificates (default: True)
            timeout: Timeout for XML-RPC calls in seconds (default: 30)
        """
        self.host = host
        self.username = username
        self.password = password
        self.protocol = "https" if https else "http"
        self.port = port
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Set up the URL for XML-RPC requests
        self.url = f"{self.protocol}://{self.host}:{self.port}/xmlrpc.php"
        
        # Create a context for SSL verification (or lack thereof)
        self.ssl_context = None
        if not verify_ssl:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def _create_request(self, method_name: str, params: List[Any] = None) -> urllib.request.Request:
        """
        Create an XML-RPC request.

        Args:
            method_name: The name of the XML-RPC method to call
            params: A list of parameters to pass to the method

        Returns:
            An HTTP request object
        """
        # Create the XML-RPC request body
        root = ET.Element("methodCall")
        method_elem = ET.SubElement(root, "methodName")
        method_elem.text = method_name
        
        # Add parameters if provided
        if params:
            params_elem = ET.SubElement(root, "params")
            for param in params:
                param_elem = ET.SubElement(params_elem, "param")
                value_elem = ET.SubElement(param_elem, "value")
                
                # Handle different parameter types
                if isinstance(param, str):
                    string_elem = ET.SubElement(value_elem, "string")
                    string_elem.text = param
                elif isinstance(param, int):
                    int_elem = ET.SubElement(value_elem, "int")
                    int_elem.text = str(param)
                elif isinstance(param, bool):
                    boolean_elem = ET.SubElement(value_elem, "boolean")
                    boolean_elem.text = "1" if param else "0"
                elif isinstance(param, dict):
                    struct_elem = ET.SubElement(value_elem, "struct")
                    for key, val in param.items():
                        member_elem = ET.SubElement(struct_elem, "member")
                        name_elem = ET.SubElement(member_elem, "name")
                        name_elem.text = key
                        val_elem = ET.SubElement(member_elem, "value")
                        if isinstance(val, str):
                            string_elem = ET.SubElement(val_elem, "string")
                            string_elem.text = val
                        elif isinstance(val, int):
                            int_elem = ET.SubElement(val_elem, "int")
                            int_elem.text = str(val)
                        elif isinstance(val, bool):
                            boolean_elem = ET.SubElement(val_elem, "boolean")
                            boolean_elem.text = "1" if val else "0"
        
        # Convert the XML to a string
        xml_str = ET.tostring(root, encoding="utf-8", method="xml")
        
        # Create the HTTP request
        req = urllib.request.Request(self.url, data=xml_str)
        req.add_header("Content-Type", "text/xml")
        
        # Add Basic Authentication
        auth_str = f"{self.username}:{self.password}"
        auth_bytes = auth_str.encode("utf-8")
        auth_b64 = base64.b64encode(auth_bytes).decode("utf-8")
        req.add_header("Authorization", f"Basic {auth_b64}")
        
        return req

    def _send_request(self, req: urllib.request.Request) -> str:
        """
        Send the XML-RPC request and return the response.

        Args:
            req: The HTTP request object

        Returns:
            The XML-RPC response as a string
        """
        try:
            if self.ssl_context:
                response = urllib.request.urlopen(req, context=self.ssl_context, timeout=self.timeout)
            else:
                response = urllib.request.urlopen(req, timeout=self.timeout)
            
            response_data = response.read().decode("utf-8")
            return response_data
        except urllib.error.HTTPError as e:
            print(f"HTTP Error: {e.code} {e.reason}")
            print(f"Response: {e.read().decode('utf-8')}")
            raise
        except urllib.error.URLError as e:
            print(f"URL Error: {e.reason}")
            raise
        except Exception as e:
            print(f"Error: {e}")
            raise

    def _parse_response(self, response_data: str) -> Any:
        """
        Parse the XML-RPC response.

        Args:
            response_data: The XML-RPC response as a string

        Returns:
            The parsed response value
        """
        try:
            root = ET.fromstring(response_data)
            
            # Check for fault response
            fault_elem = root.find(".//fault")
            if fault_elem is not None:
                fault_value = fault_elem.find(".//value")
                if fault_value is not None:
                    struct = fault_value.find("struct")
                    if struct is not None:
                        fault_string = None
                        fault_code = None
                        for member in struct.findall("member"):
                            name = member.find("name").text
                            value = member.find("value")
                            if name == "faultString":
                                fault_string = value.find("string").text
                            elif name == "faultCode":
                                fault_code = int(value.find("int").text)
                        
                        raise Exception(f"XML-RPC Fault: {fault_code} - {fault_string}")
            
            # Parse successful response
            param_elem = root.find(".//param")
            if param_elem is not None:
                value_elem = param_elem.find("value")
                if value_elem is not None:
                    # Extract the value based on its type
                    string_elem = value_elem.find("string")
                    if string_elem is not None and string_elem.text:
                        return string_elem.text
                    
                    int_elem = value_elem.find("int")
                    if int_elem is not None and int_elem.text:
                        return int(int_elem.text)
                    
                    boolean_elem = value_elem.find("boolean")
                    if boolean_elem is not None and boolean_elem.text:
                        return boolean_elem.text == "1"
                    
                    # Handle arrays and structs if needed
                    # This is a simplified implementation
                    array_elem = value_elem.find("array")
                    if array_elem is not None:
                        data_elem = array_elem.find("data")
                        if data_elem is not None:
                            result = []
                            for value in data_elem.findall("value"):
                                # Process each value in the array
                                # This is simplified and may need expansion
                                string_in_array = value.find("string")
                                if string_in_array is not None and string_in_array.text:
                                    result.append(string_in_array.text)
                            return result
                    
                    struct_elem = value_elem.find("struct")
                    if struct_elem is not None:
                        result = {}
                        for member in struct_elem.findall("member"):
                            name_elem = member.find("name")
                            inner_value = member.find("value")
                            if name_elem is not None and inner_value is not None:
                                # Process each member in the struct
                                # This is simplified and may need expansion
                                string_in_struct = inner_value.find("string")
                                if string_in_struct is not None and string_in_struct.text:
                                    result[name_elem.text] = string_in_struct.text
                        return result
            
            # Return True for empty success responses
            return True
        except ET.ParseError as e:
            print(f"XML Parse Error: {e}")
            print(f"Response data: {response_data}")
            raise
        except Exception as e:
            print(f"Error parsing response: {e}")
            raise

    def _call_method(self, method_name: str, params: List[Any] = None) -> Any:
        """
        Call an XML-RPC method and return the result.

        Args:
            method_name: The name of the XML-RPC method to call
            params: A list of parameters to pass to the method

        Returns:
            The parsed response value
        """
        req = self._create_request(method_name, params)
        response_data = self._send_request(req)
        return self._parse_response(response_data)

    # XML-RPC method implementations

    def host_firmware_version(self) -> Dict[str, str]:
        """
        Get the host firmware version information.

        Returns:
            Dictionary containing version information
        """
        return self._call_method("pfsense.host_firmware_version", ["", self.timeout])

    def exec_php(self, code: str) -> Any:
        """
        Execute PHP code on the pfSense server.

        Args:
            code: The PHP code to execute

        Returns:
            The result of the PHP execution
        """
        return self._call_method("pfsense.exec_php", [code])

    def exec_shell(self, code: str) -> bool:
        """
        Execute shell commands on the pfSense server.
        Note: This method only returns a success status, not the command output.
        To capture command output, use exec_php with shell_exec() or similar.

        Args:
            code: The shell commands to execute

        Returns:
            True if successful, does not return command output
        """
        return self._call_method("pfsense.exec_shell", [code])

    def reboot(self) -> bool:
        """
        Reboot the pfSense system.

        Returns:
            True if successful
        """
        return self._call_method("pfsense.reboot")


def main():
    parser = argparse.ArgumentParser(description='PfSense XML-RPC Client')
    parser.add_argument('--host', required=True, help='pfSense host address')
    parser.add_argument('--port', type=int, default=443, help='Port number (default: 443)')
    parser.add_argument('--username', required=True, help='Username for authentication')
    parser.add_argument('--password', required=True, help='Password for authentication')
    parser.add_argument('--no-https', action='store_true', help='Use HTTP instead of HTTPS')
    parser.add_argument('--no-verify', action='store_true', help='Do not verify SSL certificates')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds (default: 30)')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # host_firmware_version command
    subparsers.add_parser('version', help='Get host firmware version')
    
    # exec_php command
    exec_php_parser = subparsers.add_parser('exec_php', help='Execute PHP code')
    exec_php_parser.add_argument('code', help='PHP code to execute')
    
    # exec_shell command
    exec_shell_parser = subparsers.add_parser('exec_shell', help='Execute shell commands')
    exec_shell_parser.add_argument('code', help='Shell commands to execute')
    
    # reboot command
    subparsers.add_parser('reboot', help='Reboot the system')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    client = PfSenseXmlRpcClient(
        host=args.host,
        username=args.username,
        password=args.password,
        port=args.port,
        https=not args.no_https,
        verify_ssl=not args.no_verify,
        timeout=args.timeout
    )
    
    try:
        if args.command == 'version':
            result = client.host_firmware_version()
            print(f"Firmware version: {result}")
        
        elif args.command == 'exec_php':
            result = client.exec_php(args.code)
            print(f"PHP execution result: {result}")
        
        elif args.command == 'exec_shell':
            result = client.exec_shell(args.code)
            print(f"Shell execution result: {result}")
            print("Note: Shell commands only return success status (True/False), not the actual command output")
        
        elif args.command == 'reboot':
            result = client.reboot()
            print(f"Reboot command result: {result}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
