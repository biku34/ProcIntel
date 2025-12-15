import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import winreg
import os
import sys
from datetime import datetime
import ctypes
from ctypes import wintypes
import struct
import requests
import json
import threading
import re

class USBPersistenceAnalyzer:
    def __init__(self, root):
        # Initialize app (permanent dark theme)
        ctk.set_appearance_mode("dark")  
        ctk.set_default_color_theme("blue")
        
        self.root = root
        self.root.title("ProcIntel - USB & Removable Media Analyzer")
        self.root.geometry("1600x1000")
        
        # Configure style for any remaining Tkinter components
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")
        
        # Protocol for window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize Ollama settings
        self.ollama_url = "http://localhost:11434"
        self.model_name = "gemma3:1b"  # Using lighter model for better performance
        
        # Test connection with debug output
        print("Initializing Ollama connection...")
        self.ai_analysis_enabled = self.check_ollama_connection()
        print(f"AI Analysis enabled: {self.ai_analysis_enabled}")
        
        # Store structured USB data for AI analysis
        self.usb_analysis_data = {
            "devices": [],
            "mount_points": [],
            "timestamps": [],
            "device_count": 0,
            "suspicious_indicators": []
        }
        
        # Create the header
        self.create_header()
        
        # Main content frame
        self.main_content_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_content_frame.pack(expand=True, fill="both", pady=10)
        
        # Control panel
        self.create_control_panel()
        
        # Create notebook for different USB tracking categories
        self.create_notebook()
        
        # Create footer
        self.create_footer()
        
        # Initialize tabs
        self.init_tabs()
        
    def check_ollama_connection(self):
        """Check if Ollama is running and model is available"""
        try:
            print(f"Checking Ollama connection at {self.ollama_url}")
            
            # First check if Ollama is running
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            print(f"Connection response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"Available models: {data}")
                
                models = data.get('models', [])
                print(f"Model list: {[model.get('name', 'unknown') for model in models]}")
                
                # Check for exact model name or partial match
                for model in models:
                    model_name = model.get('name', '')
                    print(f"Checking model: {model_name}")
                    if self.model_name in model_name or model_name.startswith('gemma2'):
                        print(f"Found compatible model: {model_name}")
                        # Update model name to exact match
                        self.model_name = model_name
                        return True
                
                print(f"Model '{self.model_name}' not found in available models")
                return False
            else:
                print(f"Failed to connect to Ollama: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.ConnectionError as e:
            print(f"Connection error: {e}")
            return False
        except requests.exceptions.Timeout as e:
            print(f"Timeout error: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error: {e}")
            return False
        
    def create_header(self):
        """Creates the modern header"""
        self.header_frame = ctk.CTkFrame(self.root, height=90, corner_radius=0, fg_color="#1e272e")
        self.header_frame.pack(fill="x", side="top")
        self.header_frame.pack_propagate(False)

        title = ctk.CTkLabel(self.header_frame, text="ProcIntel",
                             font=("Segoe UI", 28, "bold"), text_color="white")
        title.pack(side="left", padx=30, pady=20)

        tagline = ctk.CTkLabel(self.header_frame,
                               text="AI-Powered USB & Removable Media Analysis for Data Exfiltration Detection",
                               font=("Segoe UI", 14, "italic"), text_color="#bdc3c7")
        tagline.pack(side="left", padx=15, pady=20)
        
        # AI status indicator
        ai_status_text = "AI: ONLINE" if self.ai_analysis_enabled else "AI: OFFLINE"
        ai_color = "#27ae60" if self.ai_analysis_enabled else "#e74c3c"
        
        self.ai_status_label = ctk.CTkLabel(self.header_frame, text=ai_status_text,
                                           font=("Segoe UI", 12, "bold"), text_color=ai_color)
        self.ai_status_label.pack(side="right", padx=30, pady=20)
        
    def create_control_panel(self):
        """Creates the modern control panel"""
        control_frame = ctk.CTkFrame(self.main_content_frame, fg_color="#1e272e", height=80)
        control_frame.pack(fill="x", padx=20, pady=(10, 20))
        control_frame.pack_propagate(False)
        
        # Left side buttons
        left_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        left_frame.pack(side="left", fill="y", padx=20)
        
        self.collect_btn = ctk.CTkButton(left_frame, text="Scan USB Devices", 
                                        command=self.collect_usb_data, width=140, height=40,
                                        font=("Segoe UI", 11, "bold"), fg_color="#27ae60", 
                                        hover_color="#229954", corner_radius=10)
        self.collect_btn.pack(side="left", padx=(0, 8), pady=20)
        
        self.analyze_btn = ctk.CTkButton(left_frame, text="AI Analysis", 
                                        command=self.start_ai_analysis, width=140, height=40,
                                        font=("Segoe UI", 11, "bold"), fg_color="#9b59b6", 
                                        hover_color="#8e44ad", corner_radius=10,
                                        state="normal" if self.ai_analysis_enabled else "disabled")
        self.analyze_btn.pack(side="left", padx=(0, 8), pady=20)
        
        self.clear_btn = ctk.CTkButton(left_frame, text="Clear Results", 
                                      command=self.clear_results, width=140, height=40,
                                      font=("Segoe UI", 11, "bold"), fg_color="#e74c3c", 
                                      hover_color="#c0392b", corner_radius=10)
        self.clear_btn.pack(side="left", padx=(0, 8), pady=20)
        
        self.export_btn = ctk.CTkButton(left_frame, text="Export Report", 
                                       command=self.export_results, width=140, height=40,
                                       font=("Segoe UI", 11, "bold"), fg_color="#2980b9", 
                                       hover_color="#1e6091", corner_radius=10)
        self.export_btn.pack(side="left", padx=(0, 8), pady=20)
        
        # Right side status with admin indicator
        status_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        status_frame.pack(side="right", padx=20, pady=20)
        
        # Admin status indicator
        if is_admin():
            admin_indicator = ctk.CTkLabel(status_frame, text="ADMIN", 
                                          font=("Segoe UI", 10, "bold"), 
                                          text_color="#27ae60")
            admin_indicator.pack(side="top")
        
        self.status_label = ctk.CTkLabel(status_frame, text="Ready to scan USB devices", 
                                        font=("Segoe UI", 12, "bold"), 
                                        text_color="#3498db")
        self.status_label.pack(side="top")
        
    def create_notebook(self):
        """Creates the modern tabbed interface"""
        # Create custom tabbed frame
        self.tab_frame = ctk.CTkFrame(self.main_content_frame, fg_color="#2a2d2e")
        self.tab_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Tab buttons frame
        self.tab_buttons_frame = ctk.CTkFrame(self.tab_frame, fg_color="#1e272e", height=50)
        self.tab_buttons_frame.pack(fill="x", padx=10, pady=(10, 0))
        self.tab_buttons_frame.pack_propagate(False)
        
        # Content frame for tab content
        self.tab_content_frame = ctk.CTkFrame(self.tab_frame, fg_color="transparent")
        self.tab_content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
    def create_footer(self):
        """Creates the modern footer"""
        footer_text = "© 2025 ProcIntel | Intelligent Security for Processes and Registry"
        if not self.ai_analysis_enabled:
            footer_text += " | Start Ollama service for AI features"
            
        self.footer = ctk.CTkLabel(self.root, text=footer_text,
                                   font=("Segoe UI", 11), text_color="#7f8c8d")
        self.footer.pack(side="bottom", pady=10)
        
    def init_tabs(self):
        """Initialize tabs for different USB tracking mechanisms"""
        self.tabs = {}
        self.tab_buttons = {}
        self.current_tab = None
        
        tab_configs = [
            ("USB Storage", "usb_storage", "#27ae60"),
            ("Device History", "device_history", "#e74c3c"), 
            ("Mount Points", "mount_points", "#f39c12"),
            ("Device Classes", "device_classes", "#8e44ad"),
            ("Volume Serial", "volume_serial", "#2980b9"),
            ("AI Analysis", "ai_analysis", "#9b59b6")
        ]
        
        for i, (tab_name, tab_key, color) in enumerate(tab_configs):
            # Create tab button
            btn = ctk.CTkButton(self.tab_buttons_frame, text=tab_name, 
                               command=lambda k=tab_key: self.switch_tab(k),
                               width=110, height=35, font=("Segoe UI", 10, "bold"),
                               fg_color=color if i == 0 else "#34495e",
                               hover_color=color, corner_radius=8)
            btn.pack(side="left", padx=3, pady=7)
            self.tab_buttons[tab_key] = (btn, color)
            
            # Create content frame for this tab
            if tab_key == "ai_analysis":
                self.create_ai_analysis_tab()
            else:
                content_frame = ctk.CTkFrame(self.tab_content_frame, fg_color="transparent")
                
                # Create scrollable text widget with modern styling
                text_widget = ctk.CTkTextbox(content_frame, 
                                            font=("Consolas", 10),
                                            fg_color="#2a2d2e",
                                            text_color="#dcdde1",
                                            scrollbar_button_color="#34495e",
                                            scrollbar_button_hover_color="#4a4a4a")
                text_widget.pack(fill="both", expand=True, padx=5, pady=5)
                
                self.tabs[tab_key] = (content_frame, text_widget)
        
        # Show first tab by default
        self.switch_tab("usb_storage")
    
    def create_ai_analysis_tab(self):
        """Create enhanced AI analysis tab with better formatting and sections"""
        content_frame = ctk.CTkFrame(self.tab_content_frame, fg_color="transparent")
        
        # Create a scrollable frame for AI content
        self.ai_scroll_frame = ctk.CTkScrollableFrame(content_frame, fg_color="#1a1a1a")
        self.ai_scroll_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # AI Analysis sections will be added here dynamically
        self.ai_sections = {}
        
        self.tabs["ai_analysis"] = (content_frame, self.ai_scroll_frame)
    
    def switch_tab(self, tab_key):
        """Switch to specified tab"""
        # Hide current tab
        if self.current_tab:
            self.tabs[self.current_tab][0].pack_forget()
            # Reset previous button color
            prev_btn, prev_color = self.tab_buttons[self.current_tab]
            prev_btn.configure(fg_color="#34495e")
        
        # Show new tab
        self.tabs[tab_key][0].pack(fill="both", expand=True)
        self.current_tab = tab_key
        
        # Update button color
        btn, color = self.tab_buttons[tab_key]
        btn.configure(fg_color=color)
    
    def get_key_last_write_time(self, hkey, subkey_path):
        """Get the last write time of a registry key using Windows API"""
        try:
            # Open registry key
            key_handle = wintypes.HANDLE()
            result = ctypes.windll.advapi32.RegOpenKeyExW(
                hkey, 
                subkey_path, 
                0, 
                winreg.KEY_READ, 
                ctypes.byref(key_handle)
            )
            
            if result != 0:
                return "Access Denied"
            
            # Query key info to get last write time
            last_write_time = wintypes.FILETIME()
            result = ctypes.windll.advapi32.RegQueryInfoKeyW(
                key_handle,
                None, None, None, None, None, None, None, None, None, None,
                ctypes.byref(last_write_time)
            )
            
            ctypes.windll.advapi32.RegCloseKey(key_handle)
            
            if result == 0:
                # Convert FILETIME to datetime
                timestamp = (last_write_time.dwHighDateTime << 32) + last_write_time.dwLowDateTime
                timestamp = timestamp / 10000000.0 - 11644473600  # Convert to Unix timestamp
                return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")
            else:
                return "Unable to retrieve timestamp"
                
        except Exception as e:
            return f"Error: {str(e)}"
    
    def safe_reg_query(self, hkey, subkey_path):
        """Safely query registry values with enhanced admin access"""
        try:
            # Try with maximum access rights when running as admin
            access_rights = winreg.KEY_READ
            if is_admin():
                access_rights = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            
            with winreg.OpenKey(hkey, subkey_path, 0, access_rights) as key:
                values = []
                i = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        values.append({
                            'name': name,
                            'value': value,
                            'type': reg_type,
                            'type_name': self.get_reg_type_name(reg_type)
                        })
                        i += 1
                    except WindowsError:
                        break
                return values
        except FileNotFoundError:
            return None
        except PermissionError:
            return "ACCESS_DENIED"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def get_reg_type_name(self, reg_type):
        """Convert registry type constant to readable name"""
        type_names = {
            winreg.REG_SZ: "REG_SZ",
            winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
            winreg.REG_BINARY: "REG_BINARY",
            winreg.REG_DWORD: "REG_DWORD",
            winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
            winreg.REG_LINK: "REG_LINK",
            winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
            winreg.REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
            winreg.REG_QWORD: "REG_QWORD"
        }
        return type_names.get(reg_type, f"Type_{reg_type}")
    
    def enumerate_subkeys(self, hkey, subkey_path, max_keys=100):
        """Enumerate all subkeys under a given registry path"""
        try:
            access_rights = winreg.KEY_READ
            if is_admin():
                access_rights = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                
            with winreg.OpenKey(hkey, subkey_path, 0, access_rights) as key:
                subkeys = []
                i = 0
                while i < max_keys:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkeys.append(subkey_name)
                        i += 1
                    except WindowsError:
                        break
                return subkeys
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def extract_device_info(self, device_info):
        """Extract structured device information for AI analysis"""
        device_data = {}
        
        # Extract basic device info
        if 'DeviceDesc' in device_info:
            device_data['description'] = device_info['DeviceDesc']
        if 'FriendlyName' in device_info:
            device_data['name'] = device_info['FriendlyName']
        if 'HardwareID' in device_info:
            device_data['hardware_id'] = device_info['HardwareID']
        if 'Service' in device_info:
            device_data['service'] = device_info['Service']
        if 'Class' in device_info:
            device_data['device_class'] = device_info['Class']
        if 'Mfg' in device_info:
            device_data['manufacturer'] = device_info['Mfg']
        
        # Check for suspicious indicators
        suspicious = []
        if 'description' in device_data:
            desc = device_data['description'].lower()
            if any(word in desc for word in ['generic', 'unknown', 'mass storage']):
                suspicious.append('generic_device')
        
        if 'hardware_id' in device_data:
            hw_id = str(device_data['hardware_id']).lower()
            if 'vid_0000' in hw_id or 'pid_0000' in hw_id:
                suspicious.append('unknown_vendor')
        
        if suspicious:
            device_data['suspicious_flags'] = suspicious
        
        return device_data
    
    def collect_usb_storage_devices(self):
        """Collect USB storage device information from USBSTOR registry"""
        output = f"Registry Key: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\n"
        output += f"Last Write Time: {self.get_key_last_write_time(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\\CurrentControlSet\\Enum\\USBSTOR')}\n"
        output += f"{'='*80}\n\n"
        
        # Reset analysis data for new scan
        self.usb_analysis_data = {
            "devices": [],
            "mount_points": [],
            "timestamps": [],
            "device_count": 0,
            "suspicious_indicators": []
        }
        
        usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        
        try:
            # Get all USB storage device types
            device_types = self.enumerate_subkeys(winreg.HKEY_LOCAL_MACHINE, usbstor_path)
            
            if isinstance(device_types, str) and device_types.startswith("ERROR"):
                output += f"Status: {device_types}\n\n"
                return output
            
            total_devices = 0
            
            for device_type in device_types:
                output += f"Device Type: {device_type}\n"
                output += f"{'-'*50}\n"
                
                device_type_path = f"{usbstor_path}\\{device_type}"
                device_instances = self.enumerate_subkeys(winreg.HKEY_LOCAL_MACHINE, device_type_path)
                
                if isinstance(device_instances, str) and device_instances.startswith("ERROR"):
                    output += f"  Error reading device instances: {device_instances}\n\n"
                    continue
                
                for instance in device_instances:
                    total_devices += 1
                    output += f"  Device Instance {total_devices}: {instance}\n"
                    
                    instance_path = f"{device_type_path}\\{instance}"
                    
                    # Get device properties
                    values = self.safe_reg_query(winreg.HKEY_LOCAL_MACHINE, instance_path)
                    
                    if values is None:
                        output += f"    Status: Instance key not found\n"
                    elif values == "ACCESS_DENIED":
                        output += f"    Status: Access denied\n"
                    elif isinstance(values, str) and values.startswith("ERROR"):
                        output += f"    Status: {values}\n"
                    else:
                        # Extract key device information
                        device_info = {}
                        for entry in values:
                            device_info[entry['name']] = entry['value']
                        
                        # Store structured data for AI analysis
                        structured_device = self.extract_device_info(device_info)
                        structured_device['instance_id'] = instance
                        structured_device['device_type'] = device_type
                        
                        # Get timestamp
                        timestamp = self.get_key_last_write_time(winreg.HKEY_LOCAL_MACHINE, instance_path)
                        structured_device['last_connected'] = timestamp
                        
                        self.usb_analysis_data['devices'].append(structured_device)
                        
                        if 'suspicious_flags' in structured_device:
                            self.usb_analysis_data['suspicious_indicators'].extend(structured_device['suspicious_flags'])
                        
                        # Display important device properties
                        important_props = [
                            ('DeviceDesc', 'Device Description'),
                            ('FriendlyName', 'Friendly Name'),
                            ('HardwareID', 'Hardware ID'),
                            ('Service', 'Service'),
                            ('Class', 'Device Class'),
                            ('ClassGUID', 'Class GUID'),
                            ('Mfg', 'Manufacturer'),
                            ('FirstInstallDate', 'First Install Date'),
                            ('LocationInformation', 'Location')
                        ]
                        
                        for prop_key, prop_name in important_props:
                            if prop_key in device_info:
                                value = device_info[prop_key]
                                if isinstance(value, list):
                                    value = ', '.join(str(v) for v in value)
                                output += f"    {prop_name}: {value}\n"
                        
                        # Get timestamps
                        output += f"    Registry Key Last Write: {timestamp}\n"
                    
                    output += "\n"
                
                output += "\n"
            
            self.usb_analysis_data['device_count'] = total_devices
            output += f"Total USB Storage Devices Found: {total_devices}\n\n"
            
        except Exception as e:
            output += f"Error collecting USB storage devices: {str(e)}\n"
        
        return output
    
    def collect_device_history(self):
        """Collect device installation history"""
        output = f"Registry Key: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USB\n"
        output += f"Last Write Time: {self.get_key_last_write_time(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\\CurrentControlSet\\Enum\\USB')}\n"
        output += f"{'='*80}\n\n"
        
        usb_path = r"SYSTEM\CurrentControlSet\Enum\USB"
        
        try:
            # Get all USB device VID/PID combinations
            vid_pid_keys = self.enumerate_subkeys(winreg.HKEY_LOCAL_MACHINE, usb_path, max_keys=50)
            
            if isinstance(vid_pid_keys, str) and vid_pid_keys.startswith("ERROR"):
                output += f"Status: {vid_pid_keys}\n\n"
                return output
            
            total_devices = 0
            
            for vid_pid in vid_pid_keys:
                if "VID_" in vid_pid and "PID_" in vid_pid:  # Filter for USB devices with VID/PID
                    output += f"USB Device: {vid_pid}\n"
                    output += f"{'-'*60}\n"
                    
                    vid_pid_path = f"{usb_path}\\{vid_pid}"
                    device_instances = self.enumerate_subkeys(winreg.HKEY_LOCAL_MACHINE, vid_pid_path, max_keys=10)
                    
                    if isinstance(device_instances, str) and device_instances.startswith("ERROR"):
                        output += f"  Error reading instances: {device_instances}\n\n"
                        continue
                    
                    for instance in device_instances:
                        total_devices += 1
                        output += f"  Instance {total_devices}: {instance}\n"
                        
                        instance_path = f"{vid_pid_path}\\{instance}"
                        values = self.safe_reg_query(winreg.HKEY_LOCAL_MACHINE, instance_path)
                        
                        if values and values != "ACCESS_DENIED" and not isinstance(values, str):
                            device_info = {}
                            for entry in values:
                                device_info[entry['name']] = entry['value']
                            
                            # Display key information
                            key_props = [
                                ('DeviceDesc', 'Description'),
                                ('Service', 'Service'),
                                ('ContainerID', 'Container ID'),
                                ('ParentIdPrefix', 'Parent ID Prefix')
                            ]
                            
                            for prop_key, prop_name in key_props:
                                if prop_key in device_info:
                                    output += f"    {prop_name}: {device_info[prop_key]}\n"
                            
                            output += f"    Registry Last Write: {self.get_key_last_write_time(winreg.HKEY_LOCAL_MACHINE, instance_path)}\n"
                        
                        output += "\n"
                    
                    output += "\n"
            
            output += f"Total USB Device Instances Found: {total_devices}\n\n"
            
        except Exception as e:
            output += f"Error collecting device history: {str(e)}\n"
        
        return output
    
    def collect_mount_points(self):
        """Collect mounted volume information"""
        output = f"Registry Key: HKEY_LOCAL_MACHINE\\SYSTEM\\MountedDevices\n"
        output += f"Last Write Time: {self.get_key_last_write_time(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\\MountedDevices')}\n"
        output += f"{'='*80}\n\n"
        
        mounted_devices_path = r"SYSTEM\MountedDevices"
        
        values = self.safe_reg_query(winreg.HKEY_LOCAL_MACHINE, mounted_devices_path)
        
        if values is None:
            output += "Status: Key not found\n\n"
        elif values == "ACCESS_DENIED":
            output += "Status: Access denied\n\n"
        elif isinstance(values, str) and values.startswith("ERROR"):
            output += f"Status: {values}\n\n"
        else:
            drive_letters = []
            volume_guids = []
            
            for entry in values:
                mount_point = entry['name']
                device_id = entry['value']
                
                # Convert binary device ID to readable format
                device_id_str = ""
                if isinstance(device_id, bytes):
                    try:
                        # Try to decode as UTF-16LE for readable strings
                        device_id_str = device_id.decode('utf-16le', errors='ignore').rstrip('\x00')
                    except:
                        # If that fails, show as hex
                        device_id_str = device_id.hex().upper()
                else:
                    device_id_str = str(device_id)
                
                # Store for AI analysis
                mount_data = {
                    'mount_point': mount_point,
                    'device_id': device_id_str,
                    'is_usb': 'usb' in device_id_str.lower(),
                    'is_removable': 'removable' in device_id_str.lower()
                }
                
                if mount_point.startswith('\\DosDevices\\') and len(mount_point) == 14:
                    # Drive letter mapping
                    drive_letter = mount_point.replace('\\DosDevices\\', '')
                    mount_data['drive_letter'] = drive_letter
                    drive_letters.append((drive_letter, device_id_str, entry['type_name']))
                    self.usb_analysis_data['mount_points'].append(mount_data)
                elif mount_point.startswith('\\??\\Volume{'):
                    # Volume GUID mapping
                    mount_data['volume_guid'] = mount_point
                    volume_guids.append((mount_point, device_id_str, entry['type_name']))
                    self.usb_analysis_data['mount_points'].append(mount_data)
            
            # Display drive letter mappings
            if drive_letters:
                output += "Drive Letter Mappings:\n"
                output += f"{'-'*40}\n"
                for i, (drive, device, reg_type) in enumerate(drive_letters, 1):
                    output += f"  Entry {i}:\n"
                    output += f"    Drive Letter: {drive}\n"
                    output += f"    Device ID: {device}\n"
                    output += f"    Registry Type: {reg_type}\n"
                    
                    # Check if it looks like a USB device
                    if "usb" in device.lower() or "removable" in device.lower():
                        output += f"    *** POTENTIAL USB/REMOVABLE DEVICE ***\n"
                    
                    output += "\n"
            
            # Display volume GUID mappings
            if volume_guids:
                output += f"\nVolume GUID Mappings:\n"
                output += f"{'-'*40}\n"
                for i, (volume, device, reg_type) in enumerate(volume_guids, 1):
                    output += f"  Entry {i}:\n"
                    output += f"    Volume GUID: {volume}\n"
                    output += f"    Device ID: {device}\n"
                    output += f"    Registry Type: {reg_type}\n"
                    
                    if "usb" in device.lower() or "removable" in device.lower():
                        output += f"    *** POTENTIAL USB/REMOVABLE DEVICE ***\n"
                    
                    output += "\n"
            
            output += f"Total Mount Points: {len(values)}\n"
            output += f"Drive Letters: {len(drive_letters)}\n"
            output += f"Volume GUIDs: {len(volume_guids)}\n\n"
        
        return output
    
    def collect_device_classes(self):
        """Collect device class information for storage devices"""
        output = f"Registry Key: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\n"
        output += f"Focus: Storage and USB Device Classes\n"
        output += f"{'='*80}\n\n"
        
        class_path = r"SYSTEM\CurrentControlSet\Control\Class"
        
        # Key device class GUIDs we're interested in
        storage_classes = {
            '{4d36e967-e325-11ce-bfc1-08002be10318}': 'Disk Drives',
            '{4d36e965-e325-11ce-bfc1-08002be10318}': 'CD-ROM Drives', 
            '{53f56307-b6bf-11d0-94f2-00a0c91efb8b}': 'Battery',
            '{36fc9e60-c465-11cf-8056-444553540000}': 'USB Controllers',
            '{88bae032-5a81-49f0-bc3d-a4ff138216d6}': 'USB Devices',
            '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}': 'Volume Snapshots',
            '{71a27cdd-812a-11d0-bec7-08002be2092f}': 'Volume Devices'
        }
        
        try:
            for class_guid, class_name in storage_classes.items():
                output += f"Device Class: {class_name} ({class_guid})\n"
                output += f"{'-'*70}\n"
                
                class_guid_path = f"{class_path}\\{class_guid}"
                
                # Get class properties
                values = self.safe_reg_query(winreg.HKEY_LOCAL_MACHINE, class_guid_path)
                
                if values and values != "ACCESS_DENIED" and not isinstance(values, str):
                    for entry in values:
                        if entry['name'] in ['Class', 'ClassDesc', 'Provider', 'ClassInstall32']:
                            output += f"  {entry['name']}: {entry['value']}\n"
                
                # Get device instances under this class
                device_instances = self.enumerate_subkeys(winreg.HKEY_LOCAL_MACHINE, class_guid_path, max_keys=20)
                
                if isinstance(device_instances, list):
                    device_count = 0
                    for instance in device_instances:
                        if instance.isdigit() or len(instance) == 4:  # Device instance numbers
                            device_count += 1
                            if device_count <= 5:  # Limit output
                                instance_path = f"{class_guid_path}\\{instance}"
                                instance_values = self.safe_reg_query(winreg.HKEY_LOCAL_MACHINE, instance_path)
                                
                                if instance_values and instance_values != "ACCESS_DENIED":
                                    output += f"    Device Instance {instance}:\n"
                                    device_info = {}
                                    for entry in instance_values:
                                        device_info[entry['name']] = entry['value']
                                    
                                    # Show relevant device information
                                    relevant_props = ['DeviceDesc', 'HardwareID', 'Service', 'FriendlyName']
                                    for prop in relevant_props:
                                        if prop in device_info:
                                            value = device_info[prop]
                                            if isinstance(value, list):
                                                value = ', '.join(str(v) for v in value)
                                            output += f"      {prop}: {value}\n"
                    
                    if device_count > 5:
                        output += f"    ... and {device_count - 5} more device instances\n"
                    
                    output += f"  Total Device Instances: {device_count}\n"
                
                output += "\n"
                
        except Exception as e:
            output += f"Error collecting device classes: {str(e)}\n"
        
        return output
    
    def collect_volume_serial_numbers(self):
        """Collect volume serial numbers and drive information"""
        output = f"Registry Key: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache\n"
        output += f"Focus: Volume Serial Numbers and Drive History\n"
        output += f"{'='*80}\n\n"
        
        # Check volume info cache first
        volume_cache_path = r"SOFTWARE\Microsoft\Windows Search\VolumeInfoCache"
        
        try:
            output += "Volume Information Cache:\n"
            output += f"{'-'*40}\n"
            
            values = self.safe_reg_query(winreg.HKEY_LOCAL_MACHINE, volume_cache_path)
            
            if values and values != "ACCESS_DENIED" and not isinstance(values, str):
                for i, entry in enumerate(values, 1):
                    output += f"  Entry {i}:\n"
                    output += f"    Name: {entry['name']}\n"
                    output += f"    Value: {entry['value']}\n"
                    output += f"    Type: {entry['type_name']}\n"
                    output += "\n"
            else:
                output += f"  Status: {values if isinstance(values, str) else 'No data found'}\n\n"
            
            # Also check CurrentControlSet\Services\Disk\Enum for disk enumeration
            output += "Disk Service Enumeration:\n"
            output += f"{'-'*40}\n"
            
            disk_enum_path = r"SYSTEM\CurrentControlSet\Services\Disk\Enum"
            disk_values = self.safe_reg_query(winreg.HKEY_LOCAL_MACHINE, disk_enum_path)
            
            if disk_values and disk_values != "ACCESS_DENIED" and not isinstance(disk_values, str):
                for i, entry in enumerate(disk_values, 1):
                    output += f"  Disk {i}:\n"
                    output += f"    Name: {entry['name']}\n"
                    output += f"    Value: {entry['value']}\n"
                    
                    # Check if it's a USB device
                    if isinstance(entry['value'], str) and 'usb' in entry['value'].lower():
                        output += f"    *** USB STORAGE DEVICE DETECTED ***\n"
                    
                    output += "\n"
            else:
                output += f"  Status: {disk_values if isinstance(disk_values, str) else 'No disk enumeration found'}\n\n"
                
        except Exception as e:
            output += f"Error collecting volume serial numbers: {str(e)}\n"
        
        return output
    
    def collect_usb_data(self):
        """Main function to collect all USB and removable media data"""
        self.status_label.configure(text="Scanning USB devices...", text_color="#f39c12")
        self.root.update()
        
        # Disable buttons during collection
        self.collect_btn.configure(state="disabled")
        self.analyze_btn.configure(state="disabled")
        self.clear_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        
        try:
            # Clear existing results (except AI analysis)
            for tab_key, (content_frame, text_widget) in self.tabs.items():
                if tab_key != "ai_analysis":
                    text_widget.delete("1.0", "end")
            
            # Collect USB Storage devices
            usb_storage_result = self.collect_usb_storage_devices()
            self.tabs['usb_storage'][1].insert("end", usb_storage_result)
            
            # Collect Device History
            device_history_result = self.collect_device_history()
            self.tabs['device_history'][1].insert("end", device_history_result)
            
            # Collect Mount Points
            mount_points_result = self.collect_mount_points()
            self.tabs['mount_points'][1].insert("end", mount_points_result)
            
            # Collect Device Classes
            device_classes_result = self.collect_device_classes()
            self.tabs['device_classes'][1].insert("end", device_classes_result)
            
            # Collect Volume Serial Numbers
            volume_serial_result = self.collect_volume_serial_numbers()
            self.tabs['volume_serial'][1].insert("end", volume_serial_result)
            
            self.status_label.configure(text="USB scan completed", text_color="#27ae60")
            
            # Enable AI analysis if Ollama is available
            if self.ai_analysis_enabled:
                self.analyze_btn.configure(state="normal")
            
        except Exception as e:
            messagebox.showerror("Collection Error", f"An error occurred during USB data collection:\n{str(e)}")
            self.status_label.configure(text="USB scan failed", text_color="#e74c3c")
        
        finally:
            # Re-enable buttons
            self.collect_btn.configure(state="normal")
            self.clear_btn.configure(state="normal")
            self.export_btn.configure(state="normal")
    
    def prepare_streamlined_ai_data(self):
        """Prepare minimal, structured data for AI analysis to reduce hallucination"""
        # Create concise summary of USB activity
        summary = {
            "total_devices": self.usb_analysis_data.get('device_count', 0),
            "devices": [],
            "usb_drives": 0,
            "removable_drives": 0,
            "suspicious_count": 0,
            "recent_activity": False
        }
        
        # Process devices into minimal format
        for device in self.usb_analysis_data.get('devices', []):
            device_summary = {
                "name": device.get('name', device.get('description', 'Unknown Device')),
                "type": device.get('device_type', 'Unknown'),
                "last_seen": device.get('last_connected', 'Unknown')
            }
            
            # Check for suspicious flags
            if 'suspicious_flags' in device:
                device_summary['suspicious'] = True
                summary["suspicious_count"] += 1
            
            # Check if recently connected (within last 30 days - simplified check)
            if device.get('last_connected') and device.get('last_connected') != 'Unknown':
                try:
                    # Simple date check - if contains recent year
                    if '2024' in device.get('last_connected', '') or '2025' in device.get('last_connected', ''):
                        summary["recent_activity"] = True
                except:
                    pass
            
            summary["devices"].append(device_summary)
        
        # Count USB and removable drives from mount points
        for mount in self.usb_analysis_data.get('mount_points', []):
            if mount.get('is_usb'):
                summary["usb_drives"] += 1
            if mount.get('is_removable'):
                summary["removable_drives"] += 1
        
        return summary
    
    def query_ollama(self, prompt):
        """Query Ollama with the prepared data"""
        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,  # Lower temperature for more focused responses
                    "top_p": 0.8,
                    "num_predict": 1024  # Shorter responses to reduce hallucination
                }
            }
            
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=60  # Shorter timeout
            )
            
            if response.status_code == 200:
                return response.json().get('response', 'No response received')
            else:
                return f"Error: HTTP {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            return f"Connection Error: {str(e)}"
        except Exception as e:
            return f"Analysis Error: {str(e)}"
    
    def start_ai_analysis(self):
        """Start AI analysis in a separate thread"""
        # Re-check Ollama connection
        print("Re-checking Ollama connection before analysis...")
        self.ai_analysis_enabled = self.check_ollama_connection()
        
        if not self.ai_analysis_enabled:
            # Show detailed error dialog
            error_msg = (
                "Ollama AI service is not accessible.\n\n"
                "Troubleshooting steps:\n"
                "1. Ensure Ollama is running: Open terminal and run 'ollama serve'\n"
                "2. Check if model is downloaded: Run 'ollama list'\n"
                "3. Download model if needed: Run 'ollama pull gemma2:2b'\n"
                "4. Verify service is on localhost:11434\n"
                "5. Check Windows firewall/antivirus blocking the connection\n\n"
                f"Connection URL: {self.ollama_url}\n"
                f"Looking for model: {self.model_name}"
            )
            messagebox.showerror("AI Service Unavailable", error_msg)
            return
        
        # Update UI to show AI is now available
        self.ai_status_label.configure(text="AI: ONLINE", text_color="#27ae60")
        self.footer.configure(text="© 2025 ProcIntel | Intelligent Security for Processes and Registry")
        
        # Check if we have data to analyze
        if self.usb_analysis_data.get('device_count', 0) == 0:
            messagebox.showwarning("No Data", "Please scan USB devices first before running AI analysis.")
            return
        
        # Disable analysis button and show progress
        self.analyze_btn.configure(state="disabled")
        self.status_label.configure(text="AI analyzing USB data...", text_color="#9b59b6")
        
        # Start analysis in background thread
        analysis_thread = threading.Thread(target=self.perform_streamlined_ai_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def perform_streamlined_ai_analysis(self):
        """Perform streamlined AI analysis with focused prompts"""
        try:
            # Prepare minimal data
            summary_data = self.prepare_streamlined_ai_data()
            
            # Create single focused analysis
            analysis_result = self.run_focused_usb_analysis(summary_data)
            
            # Update UI in main thread
            self.root.after(0, self.display_streamlined_results, analysis_result)
            
        except Exception as e:
            error_msg = f"AI Analysis failed: {str(e)}"
            self.root.after(0, self.handle_ai_error, error_msg)
    
    def run_focused_usb_analysis(self, data):
        """Run a single focused AI analysis for USB security assessment"""
        
        # Create concise, focused prompt
        analysis_prompt = f"""Analyze this USB device data for security risks. Be specific and factual.

SYSTEM DATA:
- Total USB devices found: {data['total_devices']}
- USB drives detected: {data['usb_drives']}
- Removable drives: {data['removable_drives']}
- Devices with suspicious indicators: {data['suspicious_count']}
- Recent activity detected: {data['recent_activity']}

DEVICE LIST:
{json.dumps(data['devices'][:10], indent=2)}

Provide analysis in this format:

RISK ASSESSMENT:
- Overall risk level: [HIGH/MEDIUM/LOW]
- Primary concerns: [list max 3 specific issues]

SUSPICIOUS DEVICES:
[List only devices with actual suspicious indicators]

RECOMMENDATIONS:
[Provide 3-5 specific, actionable security recommendations]

Keep response under 500 words. Be factual, avoid speculation."""
        
        return self.query_ollama(analysis_prompt)
    
    def create_streamlined_section(self, parent, title, content, color):
        """Create a clean analysis section"""
        # Section frame
        section_frame = ctk.CTkFrame(parent, fg_color="#262626", corner_radius=8)
        section_frame.pack(fill="x", padx=10, pady=10)
        
        # Header frame
        header_frame = ctk.CTkFrame(section_frame, fg_color=color, corner_radius=8, height=45)
        header_frame.pack(fill="x", padx=5, pady=5)
        header_frame.pack_propagate(False)
        
        # Title label
        title_label = ctk.CTkLabel(header_frame, text=title, 
                                  font=("Segoe UI", 14, "bold"), text_color="white")
        title_label.pack(side="left", padx=15, pady=10)
        
        # Content frame
        content_frame = ctk.CTkFrame(section_frame, fg_color="#1a1a1a")
        content_frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        
        # Content text widget
        content_text = ctk.CTkTextbox(content_frame, font=("Segoe UI", 11), 
                                     fg_color="transparent", text_color="#e8e8e8",
                                     height=300, wrap="word")
        content_text.pack(fill="both", expand=True, padx=10, pady=10)
        content_text.insert("1.0", content)
        
        return section_frame
    
    def display_streamlined_results(self, analysis_result):
        """Display streamlined AI analysis results"""
        try:
            # Switch to AI analysis tab
            self.switch_tab("ai_analysis")
            
            # Clear previous results
            for widget in self.ai_scroll_frame.winfo_children():
                widget.destroy()
            self.ai_sections.clear()
            
            # Create header section
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            header_frame = ctk.CTkFrame(self.ai_scroll_frame, fg_color="#1e272e", corner_radius=10)
            header_frame.pack(fill="x", padx=10, pady=10)
            
            # Title
            title_label = ctk.CTkLabel(header_frame, text="USB SECURITY ANALYSIS",
                                      font=("Segoe UI", 16, "bold"), text_color="#3498db")
            title_label.pack(pady=10)
            
            # System info
            device_count = self.usb_analysis_data.get('device_count', 0)
            info_text = f"Analysis Time: {timestamp} | Devices Scanned: {device_count} | Model: {self.model_name}"
            info_label = ctk.CTkLabel(header_frame, text=info_text,
                                     font=("Segoe UI", 10), text_color="#bdc3c7")
            info_label.pack(pady=(0, 10))
            
            # Display analysis result
            if analysis_result and not analysis_result.startswith("Error:") and not analysis_result.startswith("Connection Error:"):
                section_widget = self.create_streamlined_section(
                    self.ai_scroll_frame, "USB SECURITY ASSESSMENT", analysis_result, "#27ae60"
                )
                self.ai_sections['security_analysis'] = section_widget
            else:
                # Show error
                error_content = f"Analysis failed: {analysis_result}"
                section_widget = self.create_streamlined_section(
                    self.ai_scroll_frame, "ANALYSIS ERROR", error_content, "#e74c3c"
                )
            
            # Add disclaimer section
            disclaimer_frame = ctk.CTkFrame(self.ai_scroll_frame, fg_color="#34495e", corner_radius=8)
            disclaimer_frame.pack(fill="x", padx=10, pady=10)
            
            disclaimer_label = ctk.CTkLabel(disclaimer_frame, 
                                          text="DISCLAIMER: This AI analysis is for informational purposes only. "
                                               "Manual verification by security professionals is recommended.",
                                          font=("Segoe UI", 10), text_color="#ecf0f1", wraplength=1400)
            disclaimer_label.pack(padx=15, pady=10)
            
            self.status_label.configure(text="USB AI analysis completed", text_color="#27ae60")
            
        except Exception as e:
            self.handle_ai_error(f"Error displaying results: {str(e)}")
        
        finally:
            # Re-enable analysis button
            if self.ai_analysis_enabled:
                self.analyze_btn.configure(state="normal")
    
    def handle_ai_error(self, error_msg):
        """Handle AI analysis errors"""
        self.status_label.configure(text="USB AI analysis failed", text_color="#e74c3c")
        
        # Display error in AI tab
        if "ai_analysis" in self.tabs:
            # Clear existing content
            for widget in self.ai_scroll_frame.winfo_children():
                widget.destroy()
            
            # Create error display
            error_frame = ctk.CTkFrame(self.ai_scroll_frame, fg_color="#e74c3c", corner_radius=10)
            error_frame.pack(fill="x", padx=10, pady=10)
            
            error_title = ctk.CTkLabel(error_frame, text="AI ANALYSIS ERROR",
                                      font=("Segoe UI", 14, "bold"), text_color="white")
            error_title.pack(pady=10)
            
            # Error details
            error_content = ctk.CTkFrame(error_frame, fg_color="#c0392b")
            error_content.pack(fill="x", padx=10, pady=(0, 10))
            
            error_text = ctk.CTkTextbox(error_content, font=("Consolas", 11), 
                                       fg_color="transparent", text_color="white", height=150)
            error_text.pack(fill="both", expand=True, padx=10, pady=10)
            
            error_details = f"""Error: {error_msg}

Troubleshooting:
1. Ensure Ollama is running: 'ollama serve'
2. Verify model: 'ollama list'
3. Download model: 'ollama pull gemma2:2b'
4. Check connection to localhost:11434

Connection Details:
- URL: {self.ollama_url}
- Model: {self.model_name}"""
            
            error_text.insert("1.0", error_details)
        
        # Re-enable analysis button
        if self.ai_analysis_enabled:
            self.analyze_btn.configure(state="normal")
    
    def clear_results(self):
        """Clear all results from tabs"""
        for tab_key, (tab_content, text_widget) in self.tabs.items():
            if tab_key == "ai_analysis":
                # Clear AI analysis sections
                for widget in self.ai_scroll_frame.winfo_children():
                    widget.destroy()
                self.ai_sections.clear()
            else:
                text_widget.delete("1.0", "end")
        
        # Reset analysis data
        self.usb_analysis_data = {
            "devices": [],
            "mount_points": [],
            "timestamps": [],
            "device_count": 0,
            "suspicious_indicators": []
        }
        
        self.status_label.configure(text="Results cleared", text_color="#3498db")
    
    def export_results(self):
        """Export USB analysis results to a text file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"procintel_usb_analysis_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
                f.write("PROCINTEL AI - USB & REMOVABLE MEDIA ANALYSIS REPORT\n")
                f.write("="*70 + "\n")
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"System: {os.environ.get('COMPUTERNAME', 'Unknown')}\n")
                f.write(f"User: {os.environ.get('USERNAME', 'Unknown')}\n")
                f.write(f"Admin Privileges: {is_admin()}\n")
                f.write(f"AI Analysis: {'Enabled' if self.ai_analysis_enabled else 'Disabled'}\n")
                f.write(f"AI Model: {self.model_name}\n")
                f.write("="*70 + "\n\n")
                
                # Export content from each tab
                tab_titles = {
                    'usb_storage': 'USB STORAGE DEVICES (USBSTOR)',
                    'device_history': 'USB DEVICE HISTORY',
                    'mount_points': 'MOUNT POINTS & DRIVE MAPPINGS',
                    'device_classes': 'DEVICE CLASSES',
                    'volume_serial': 'VOLUME SERIAL NUMBERS'
                }
                
                for tab_key, title in tab_titles.items():
                    content = self.tabs[tab_key][1].get("1.0", "end").strip()
                    if content:
                        f.write(f"{title}\n")
                        f.write("="*len(title) + "\n\n")
                        f.write(content)
                        f.write("\n\n" + "="*70 + "\n\n")
                
                # Export AI analysis if available
                if self.ai_sections and 'security_analysis' in self.ai_sections:
                    f.write("AI SECURITY ANALYSIS\n")
                    f.write("="*20 + "\n\n")
                    
                    section_widget = self.ai_sections['security_analysis']
                    # Extract text from the AI section
                    for widget in section_widget.winfo_children():
                        if isinstance(widget, ctk.CTkFrame):
                            for subwidget in widget.winfo_children():
                                if isinstance(subwidget, ctk.CTkFrame):
                                    for textwidget in subwidget.winfo_children():
                                        if isinstance(textwidget, ctk.CTkTextbox):
                                            content = textwidget.get("1.0", "end").strip()
                                            if content:
                                                f.write(content)
                                                f.write("\n\n")
                                            break
                
                f.write("END OF USB ANALYSIS REPORT\n")
            
            messagebox.showinfo("Export Complete", 
                              f"USB analysis report exported to:\n{filename}\n\n"
                              f"File location: {os.path.abspath(filename)}")
            self.status_label.configure(text="Report exported", text_color="#27ae60")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{str(e)}")
            self.status_label.configure(text="Export failed", text_color="#e74c3c")
    
    def on_closing(self):
        """Clean up and close the application"""
        self.root.destroy()

def is_admin():
    """Check if the current process has admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Re-run the current script with administrator privileges"""
    if is_admin():
        return True
    else:
        try:
            # Re-run the program with admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                f'"{__file__}"',
                None, 
                1
            )
            return False
        except Exception as e:
            messagebox.showerror("Admin Rights Required", 
                               f"Failed to request administrator privileges:\n{str(e)}\n\n"
                               f"Please run this application as Administrator for full functionality.")
            return False

def main():
    # Check if running on Windows
    if sys.platform != "win32":
        print("This tool requires Windows operating system")
        return
    
    # Check and request admin privileges
    if not is_admin():
        print("Administrator privileges required. Requesting elevation...")
        if not run_as_admin():
            return  # Exit if failed to get admin or user cancelled
        else:
            return  # Exit current instance, admin instance will start
    
    # We now have admin privileges
    root = ctk.CTk()
    
    app = USBPersistenceAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()