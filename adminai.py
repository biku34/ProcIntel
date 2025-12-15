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

class PersistenceAnalyzer:
    def __init__(self, root):
        # Initialize app (permanent dark theme)
        ctk.set_appearance_mode("dark")  
        ctk.set_default_color_theme("blue")
        
        self.root = root
        self.root.title("ProcIntel - AI-Powered Registry Persistence Analyzer")
        self.root.geometry("1600x1000")
        
        # Configure style for any remaining Tkinter components
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")
        
        # Protocol for window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize Ollama settings
        self.ollama_url = "http://localhost:11434"
        self.model_name = "gemma3:1b"  # Using more capable model
        
        # Test connection with debug output
        print("Initializing Ollama connection...")
        self.ai_analysis_enabled = self.check_ollama_connection()
        print(f"AI Analysis enabled: {self.ai_analysis_enabled}")
        
        # Create the header
        self.create_header()
        
        # Main content frame
        self.main_content_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_content_frame.pack(expand=True, fill="both", pady=10)
        
        # Control panel
        self.create_control_panel()
        
        # Create notebook for different persistence categories
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
                               text="AI-Powered Registry Persistence Analysis & Threat Detection",
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
        
        self.collect_btn = ctk.CTkButton(left_frame, text="Collect Data", 
                                        command=self.collect_data, width=140, height=40,
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
            admin_indicator = ctk.CTkLabel(status_frame, text="🔒 ADMIN", 
                                          font=("Segoe UI", 10, "bold"), 
                                          text_color="#27ae60")
            admin_indicator.pack(side="top")
        
        self.status_label = ctk.CTkLabel(status_frame, text="Ready", 
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
        """Initialize tabs for different persistence mechanisms"""
        self.tabs = {}
        self.tab_buttons = {}
        self.current_tab = None
        
        tab_configs = [
            ("HKCU Run", "hkcu_run", "#27ae60"),
            ("HKLM Run", "hklm_run", "#e74c3c"), 
            ("HKLM RunOnce", "hklm_runonce", "#f39c12"),
            ("Services", "services", "#8e44ad"),
            ("Shell Folders", "shell_folders", "#2980b9"),
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
        self.switch_tab("hkcu_run")
    
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
    
    # [Previous methods remain the same: get_key_last_write_time, safe_reg_query, get_reg_type_name, 
    #  collect_run_keys, collect_services, get_service_details, collect_shell_folders, collect_data]
    
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
    
    def collect_run_keys(self, hkey, subkey_path, hkey_name):
        """Collect Run/RunOnce registry key data"""
        output = f"Registry Key: {hkey_name}\\{subkey_path}\n"
        output += f"Last Write Time: {self.get_key_last_write_time(hkey, subkey_path)}\n"
        output += f"{'='*80}\n\n"
        
        # Get values
        values = self.safe_reg_query(hkey, subkey_path)
        
        if values is None:
            output += "Status: Key not found\n\n"
        elif values == "ACCESS_DENIED":
            output += "Status: Access denied\n\n"
        elif isinstance(values, str) and values.startswith("ERROR"):
            output += f"Status: {values}\n\n"
        elif len(values) == 0:
            output += "Status: Key exists but no values found\n\n"
        else:
            output += f"Total Entries: {len(values)}\n\n"
            
            for i, entry in enumerate(values, 1):
                output += f"Entry {i}:\n"
                output += f"  Name: {entry['name']}\n"
                output += f"  Value: {entry['value']}\n"
                output += f"  Type: {entry['type_name']}\n"
                output += f"  Raw Type: {entry['type']}\n"
                
                # Check if file exists
                if entry['value']:
                    try:
                        # Handle quoted paths
                        command_str = str(entry['value']).strip()
                        if command_str.startswith('"'):
                            end_quote = command_str.find('"', 1)
                            if end_quote != -1:
                                exe_path = command_str[1:end_quote]
                            else:
                                exe_path = command_str[1:]
                        else:
                            exe_path = command_str.split(' ', 1)[0]
                        
                        expanded_path = os.path.expandvars(exe_path)
                        if os.path.exists(expanded_path):
                            file_stat = os.stat(expanded_path)
                            output += f"  File Status: EXISTS\n"
                            output += f"  File Size: {file_stat.st_size} bytes\n"
                            output += f"  File Modified: {datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}\n"
                        else:
                            output += f"  File Status: NOT FOUND\n"
                    except Exception as e:
                        output += f"  File Check: Error - {str(e)}\n"
                
                output += "\n"
        
        return output
    
    def collect_services(self):
        """Collect Windows Services data"""
        output = f"Registry Key: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\n"
        output += f"Last Write Time: {self.get_key_last_write_time(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\\CurrentControlSet\\Services')}\n"
        output += f"{'='*80}\n\n"
        
        try:
            services_collected = 0
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as services_key:
                i = 0
                while services_collected < 100:  # Collect first 100 services
                    try:
                        service_name = winreg.EnumKey(services_key, i)
                        service_path = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
                        
                        # Get service details
                        service_info = self.get_service_details(service_name, service_path)
                        
                        if service_info:
                            services_collected += 1
                            output += f"Service {services_collected}:\n"
                            output += f"  Name: {service_name}\n"
                            output += f"  Display Name: {service_info.get('display_name', 'N/A')}\n"
                            output += f"  Image Path: {service_info.get('image_path', 'N/A')}\n"
                            output += f"  Start Type: {service_info.get('start_type', 'N/A')}\n"
                            output += f"  Start Type Value: {service_info.get('start_type_raw', 'N/A')}\n"
                            output += f"  Service Type: {service_info.get('service_type_raw', 'N/A')}\n"
                            output += f"  Description: {service_info.get('description', 'N/A')}\n"
                            
                            # File existence check
                            if service_info.get('image_path'):
                                try:
                                    image_path = str(service_info['image_path'])
                                    if image_path.startswith('"'):
                                        end_quote = image_path.find('"', 1)
                                        if end_quote != -1:
                                            exe_path = image_path[1:end_quote]
                                        else:
                                            exe_path = image_path[1:]
                                    else:
                                        exe_path = image_path.split(' ', 1)[0]
                                    
                                    expanded_path = os.path.expandvars(exe_path)
                                    if os.path.exists(expanded_path):
                                        file_stat = os.stat(expanded_path)
                                        output += f"  File Status: EXISTS\n"
                                        output += f"  File Size: {file_stat.st_size} bytes\n"
                                        output += f"  File Modified: {datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}\n"
                                    else:
                                        output += f"  File Status: NOT FOUND\n"
                                except Exception as e:
                                    output += f"  File Check: Error - {str(e)}\n"
                            
                            output += "\n"
                        
                        i += 1
                        
                    except WindowsError:
                        break
                    except Exception as e:
                        i += 1
                        continue
            
            output += f"Total Services Collected: {services_collected}\n\n"
        
        except Exception as e:
            output += f"Error collecting services: {str(e)}\n"
        
        return output
    
    def get_service_details(self, service_name, service_path):
        """Get detailed information about a Windows service with admin access"""
        try:
            # Use enhanced access rights when running as admin
            access_rights = winreg.KEY_READ
            if is_admin():
                access_rights = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, service_path, 0, access_rights) as key:
                service_info = {}
                
                # Common service values to check
                values_to_check = [
                    ('ImagePath', 'image_path'),
                    ('DisplayName', 'display_name'),
                    ('Description', 'description'),
                    ('Start', 'start_type_raw'),
                    ('Type', 'service_type_raw')
                ]
                
                for reg_value, info_key in values_to_check:
                    try:
                        value, _ = winreg.QueryValueEx(key, reg_value)
                        service_info[info_key] = value
                    except FileNotFoundError:
                        service_info[info_key] = None
                
                # Convert start type to readable format
                start_types = {
                    0: "Boot Start",
                    1: "System Start", 
                    2: "Auto Start",
                    3: "Manual Start",
                    4: "Disabled"
                }
                start_type_raw = service_info.get('start_type_raw')
                service_info['start_type'] = start_types.get(start_type_raw, f"Unknown_{start_type_raw}")
                
                return service_info
                
        except Exception:
            return None
    
    def collect_shell_folders(self):
        """Collect Shell Folders data"""
        shell_folders_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        
        output = f"Registry Key: HKEY_CURRENT_USER\\{shell_folders_path}\n"
        output += f"Last Write Time: {self.get_key_last_write_time(winreg.HKEY_CURRENT_USER, shell_folders_path)}\n"
        output += f"{'='*80}\n\n"
        
        values = self.safe_reg_query(winreg.HKEY_CURRENT_USER, shell_folders_path)
        
        if values is None:
            output += "Status: Key not found\n\n"
        elif values == "ACCESS_DENIED":
            output += "Status: Access denied\n\n"
        elif isinstance(values, str) and values.startswith("ERROR"):
            output += f"Status: {values}\n\n"
        elif len(values) == 0:
            output += "Status: Key exists but no values found\n\n"
        else:
            output += f"Total Entries: {len(values)}\n\n"
            
            for i, entry in enumerate(values, 1):
                output += f"Entry {i}:\n"
                output += f"  Name: {entry['name']}\n"
                output += f"  Value: {entry['value']}\n"
                output += f"  Type: {entry['type_name']}\n"
                output += f"  Raw Type: {entry['type']}\n"
                
                # Check if path exists
                if entry['value']:
                    try:
                        expanded_path = os.path.expandvars(str(entry['value']))
                        if os.path.exists(expanded_path):
                            output += f"  Path Status: EXISTS\n"
                            if os.path.isdir(expanded_path):
                                try:
                                    file_count = len(os.listdir(expanded_path))
                                    output += f"  Directory Contents: {file_count} items\n"
                                except:
                                    output += f"  Directory Contents: Cannot list\n"
                            else:
                                output += f"  Path Type: File\n"
                        else:
                            output += f"  Path Status: NOT FOUND\n"
                    except Exception as e:
                        output += f"  Path Check: Error - {str(e)}\n"
                
                output += "\n"
        
        return output
    
    def collect_data(self):
        """Main function to collect all persistence data"""
        self.status_label.configure(text="Collecting data...", text_color="#f39c12")
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
            
            # Registry keys to collect
            persistence_keys = [
                {
                    'hkey': winreg.HKEY_CURRENT_USER,
                    'path': r"Software\Microsoft\Windows\CurrentVersion\Run",
                    'name': "HKEY_CURRENT_USER",
                    'tab': 'hkcu_run'
                },
                {
                    'hkey': winreg.HKEY_LOCAL_MACHINE,
                    'path': r"Software\Microsoft\Windows\CurrentVersion\Run", 
                    'name': "HKEY_LOCAL_MACHINE",
                    'tab': 'hklm_run'
                },
                {
                    'hkey': winreg.HKEY_LOCAL_MACHINE,
                    'path': r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    'name': "HKEY_LOCAL_MACHINE", 
                    'tab': 'hklm_runonce'
                }
            ]
            
            # Collect Run/RunOnce keys
            for key_info in persistence_keys:
                result = self.collect_run_keys(
                    key_info['hkey'],
                    key_info['path'], 
                    key_info['name']
                )
                self.tabs[key_info['tab']][1].insert("end", result)
            
            # Collect Services
            services_result = self.collect_services()
            self.tabs['services'][1].insert("end", services_result)
            
            # Collect Shell Folders
            shell_folders_result = self.collect_shell_folders()
            self.tabs['shell_folders'][1].insert("end", shell_folders_result)
            
            self.status_label.configure(text="Data collection completed", text_color="#27ae60")
            
            # Enable AI analysis if Ollama is available
            if self.ai_analysis_enabled:
                self.analyze_btn.configure(state="normal")
            
        except Exception as e:
            messagebox.showerror("Collection Error", f"An error occurred during data collection:\n{str(e)}")
            self.status_label.configure(text="Data collection failed", text_color="#e74c3c")
        
        finally:
            # Re-enable buttons
            self.collect_btn.configure(state="normal")
            self.clear_btn.configure(state="normal")
            self.export_btn.configure(state="normal")
    
    def prepare_data_for_ai(self):
        """Prepare collected data for AI analysis with structured format"""
        analysis_data = {
            "system_info": {
                "computer_name": os.environ.get('COMPUTERNAME', 'Unknown'),
                "username": os.environ.get('USERNAME', 'Unknown'),
                "analysis_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "admin_privileges": is_admin()
            },
            "persistence_entries": []
        }
        
        # Extract structured data from each tab
        tab_mapping = {
            'hkcu_run': 'HKCU\\Run',
            'hklm_run': 'HKLM\\Run',
            'hklm_runonce': 'HKLM\\RunOnce',
            'services': 'Services',
            'shell_folders': 'Shell Folders'
        }
        
        for tab_key, location_type in tab_mapping.items():
            content = self.tabs[tab_key][1].get("1.0", "end").strip()
            if content:
                # Parse the content to extract individual entries
                entries = self.parse_tab_content(content, location_type)
                analysis_data["persistence_entries"].extend(entries)
        
        return analysis_data
    
    def parse_tab_content(self, content, location_type):
        """Parse tab content to extract structured persistence entries"""
        entries = []
        
        if location_type in ['HKCU\\Run', 'HKLM\\Run', 'HKLM\\RunOnce']:
            # Parse registry run entries
            entry_blocks = re.split(r'Entry \d+:', content)
            for block in entry_blocks[1:]:  # Skip first empty block
                lines = block.strip().split('\n')
                entry = {"location_type": location_type}
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Name:'):
                        entry['name'] = line.replace('Name:', '').strip()
                    elif line.startswith('Value:'):
                        entry['value'] = line.replace('Value:', '').strip()
                    elif line.startswith('File Status:'):
                        entry['file_status'] = line.replace('File Status:', '').strip()
                    elif line.startswith('File Size:'):
                        entry['file_size'] = line.replace('File Size:', '').strip()
                
                if 'name' in entry and 'value' in entry:
                    entries.append(entry)
                    
        elif location_type == 'Services':
            # Parse service entries
            service_blocks = re.split(r'Service \d+:', content)
            for block in service_blocks[1:]:  # Skip first empty block
                lines = block.strip().split('\n')
                entry = {"location_type": "Windows Service"}
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Name:'):
                        entry['name'] = line.replace('Name:', '').strip()
                    elif line.startswith('Image Path:'):
                        entry['image_path'] = line.replace('Image Path:', '').strip()
                    elif line.startswith('Start Type:') and not line.startswith('Start Type Value:'):
                        entry['start_type'] = line.replace('Start Type:', '').strip()
                    elif line.startswith('File Status:'):
                        entry['file_status'] = line.replace('File Status:', '').strip()
                
                if 'name' in entry:
                    entries.append(entry)
        
        return entries
    
    def query_ollama(self, prompt):
        """Query Ollama with the prepared data"""
        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9,
                    "num_predict": 3072
                }
            }
            
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=90
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
        self.footer.configure(text="© 2025 ProcIntel AI | Advanced Registry Persistence Analysis with Machine Learning")
        
        # Check if we have data to analyze
        has_data = False
        for tab_key in ['hkcu_run', 'hklm_run', 'hklm_runonce', 'services', 'shell_folders']:
            content = self.tabs[tab_key][1].get("1.0", "end").strip()
            if content:
                has_data = True
                break
        
        if not has_data:
            messagebox.showwarning("No Data", "Please collect persistence data first before running AI analysis.")
            return
        
        # Disable analysis button and show progress
        self.analyze_btn.configure(state="disabled")
        self.status_label.configure(text="AI analyzing data...", text_color="#9b59b6")
        
        # Start analysis in background thread
        analysis_thread = threading.Thread(target=self.perform_ai_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def perform_ai_analysis(self):
        """Perform AI analysis in background thread"""
        try:
            # Prepare data for analysis
            analysis_data = self.prepare_data_for_ai()
            
            # Create specialized prompts for different analysis types
            analyses = self.run_multiple_analyses(analysis_data)
            
            # Update UI in main thread
            self.root.after(0, self.display_ai_results, analyses)
            
        except Exception as e:
            error_msg = f"AI Analysis failed: {str(e)}"
            self.root.after(0, self.handle_ai_error, error_msg)
    
    def run_multiple_analyses(self, data):
        """Run multiple specialized AI analyses with specific, detailed prompts"""
        analyses = {}
        
        # 1. Enhanced Threat Detection Analysis
        threat_prompt = f"""You are an expert cybersecurity analyst specializing in Windows persistence mechanisms and malware detection. Analyze the following persistence data and provide a comprehensive threat assessment.

ANALYSIS REQUIREMENTS:
- Identify specific indicators of compromise (IOCs)
- Flag entries pointing to non-standard Windows directories
- Check for common malware file naming patterns
- Identify suspicious command-line arguments
- Look for entries with missing executables (potential cleanup artifacts)
- Flag services with unusual start types or descriptions

SYSTEM CONTEXT:
Computer: {data['system_info']['computer_name']}
User: {data['system_info']['username']}
Admin Rights: {data['system_info']['admin_privileges']}
Analysis Time: {data['system_info']['analysis_time']}

PERSISTENCE ENTRIES TO ANALYZE:
{json.dumps(data['persistence_entries'], indent=2)}

PROVIDE YOUR ANALYSIS IN THIS EXACT FORMAT:

🚨 CRITICAL THREATS (Immediate Action Required):
[List any entries that are definitely malicious or highly suspicious]
- Entry name: [name]
- Location: [registry location]
- Threat indicators: [specific red flags]
- Recommended action: [specific steps]

⚠️ SUSPICIOUS ENTRIES (Investigation Required):
[List entries that need further investigation]
- Entry name: [name]
- Location: [registry location]  
- Suspicious indicators: [what makes it suspicious]
- Investigation steps: [how to verify]

ℹ️ UNUSUAL BUT LIKELY BENIGN:
[List entries that are unusual but probably legitimate]
- Entry name: [name]
- Reason for flagging: [why it appeared suspicious]
- Likely explanation: [probable legitimate reason]

📊 THREAT SUMMARY:
- Total entries analyzed: [number]
- Critical threats found: [number]
- Suspicious entries: [number]
- Overall risk level: [HIGH/MEDIUM/LOW]

🛡️ IMMEDIATE RECOMMENDATIONS:
[Provide 3-5 specific actionable recommendations]"""
        
        analyses['threat_detection'] = self.query_ollama(threat_prompt)
        

        
        # 3. Enhanced System Security Analysis
        security_prompt = f"""You are a Windows security expert analyzing system persistence configurations for security vulnerabilities and policy violations.

SECURITY ANALYSIS REQUIREMENTS:
- Identify deviations from Windows security best practices
- Flag entries that bypass standard security controls
- Check for privilege escalation indicators
- Identify configuration weaknesses
- Assess overall security posture

SYSTEM CONTEXT:
Computer: {data['system_info']['computer_name']}
User: {data['system_info']['username']}
Admin Rights: {data['system_info']['admin_privileges']}

PERSISTENCE ENTRIES:
{json.dumps(data['persistence_entries'], indent=2)}

PROVIDE SECURITY ANALYSIS IN THIS FORMAT:

🔐 SECURITY VIOLATIONS:
[List entries that violate Windows security best practices]
- Entry: [name and location]
- Violation type: [specific security issue]
- Risk level: [HIGH/MEDIUM/LOW]
- Remediation: [how to fix]

⚡ PRIVILEGE ESCALATION RISKS:
[Identify entries that could be used for privilege escalation]
- Entry: [name]
- Escalation vector: [how it could be exploited]
- Mitigation: [prevention measures]

🛡️ SECURITY POSTURE ASSESSMENT:
- Overall security level: [assessment]
- Key vulnerabilities: [main weaknesses]
- Compliance issues: [policy violations]

🎯 HARDENING RECOMMENDATIONS:
[Provide 5-7 specific security hardening steps]
1. [Specific recommendation]
2. [Specific recommendation]
3. [Continue...]

📝 MONITORING RECOMMENDATIONS:
[Suggest what to monitor going forward]"""
        
        analyses['security_analysis'] = self.query_ollama(security_prompt)
        
        return analyses
    
    def create_analysis_section(self, parent, title, content, icon, color):
        """Create a formatted analysis section in the AI tab"""
        # Section frame
        section_frame = ctk.CTkFrame(parent, fg_color="#262626", corner_radius=8)
        section_frame.pack(fill="x", padx=10, pady=10)
        
        # Header frame
        header_frame = ctk.CTkFrame(section_frame, fg_color=color, corner_radius=8, height=50)
        header_frame.pack(fill="x", padx=5, pady=5)
        header_frame.pack_propagate(False)
        
        # Title label
        title_label = ctk.CTkLabel(header_frame, text=f"{icon} {title}", 
                                  font=("Segoe UI", 16, "bold"), text_color="white")
        title_label.pack(side="left", padx=15, pady=12)
        
        # Content frame
        content_frame = ctk.CTkFrame(section_frame, fg_color="#1a1a1a")
        content_frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        
        # Content text widget
        content_text = ctk.CTkTextbox(content_frame, font=("Segoe UI", 11), 
                                     fg_color="transparent", text_color="#e8e8e8",
                                     height=200, wrap="word")
        content_text.pack(fill="both", expand=True, padx=10, pady=10)
        content_text.insert("1.0", content)
        
        return section_frame
    
    def display_ai_results(self, analyses):
        """Display AI analysis results with enhanced formatting"""
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
            title_label = ctk.CTkLabel(header_frame, text="AI-POWERED PERSISTENCE ANALYSIS REPORT",
                                      font=("Segoe UI", 18, "bold"), text_color="#3498db")
            title_label.pack(pady=10)
            
            # System info
            info_text = f"Analysis Time: {timestamp} | Model: {self.model_name} | System: {os.environ.get('COMPUTERNAME', 'Unknown')}"
            info_label = ctk.CTkLabel(header_frame, text=info_text,
                                     font=("Segoe UI", 11), text_color="#bdc3c7")
            info_label.pack(pady=(0, 10))
            
            # Display each analysis section with enhanced formatting
            sections = [
                ("THREAT DETECTION ANALYSIS", "threat_detection", "", "#e74c3c"),
                ("FORENSIC INVESTIGATION ANALYSIS", "forensic_analysis", "", "#f39c12"),
                ("SECURITY POSTURE ANALYSIS", "security_analysis", "", "#27ae60")
            ]
            
            for section_title, analysis_key, icon, color in sections:
                if analysis_key in analyses:
                    content = analyses[analysis_key]
                    if content and not content.startswith("Error:") and not content.startswith("Connection Error:"):
                        section_widget = self.create_analysis_section(
                            self.ai_scroll_frame, section_title, content, icon, color
                        )
                        self.ai_sections[analysis_key] = section_widget
                    else:
                        # Show error for this section
                        error_content = f"Analysis failed: {content}"
                        section_widget = self.create_analysis_section(
                            self.ai_scroll_frame, f"{section_title} (ERROR)", error_content, "❌", "#95a5a6"
                        )
            
            # Add disclaimer section
            disclaimer_frame = ctk.CTkFrame(self.ai_scroll_frame, fg_color="#34495e", corner_radius=8)
            disclaimer_frame.pack(fill="x", padx=10, pady=10)
            
            disclaimer_label = ctk.CTkLabel(disclaimer_frame, 
                                          text="⚠️ DISCLAIMER: This AI analysis is for informational purposes only. "
                                               "Manual verification by cybersecurity professionals is recommended for security decisions.",
                                          font=("Segoe UI", 10), text_color="#ecf0f1", wraplength=1400)
            disclaimer_label.pack(padx=15, pady=10)
            
            self.status_label.configure(text="AI analysis completed", text_color="#27ae60")
            
        except Exception as e:
            self.handle_ai_error(f"Error displaying results: {str(e)}")
        
        finally:
            # Re-enable analysis button
            if self.ai_analysis_enabled:
                self.analyze_btn.configure(state="normal")
    
    def handle_ai_error(self, error_msg):
        """Handle AI analysis errors with better formatting"""
        self.status_label.configure(text="AI analysis failed", text_color="#e74c3c")
        
        # Display error in AI tab
        if "ai_analysis" in self.tabs:
            # Clear existing content
            for widget in self.ai_scroll_frame.winfo_children():
                widget.destroy()
            
            # Create error display
            error_frame = ctk.CTkFrame(self.ai_scroll_frame, fg_color="#e74c3c", corner_radius=10)
            error_frame.pack(fill="x", padx=10, pady=10)
            
            error_title = ctk.CTkLabel(error_frame, text="❌ AI ANALYSIS ERROR",
                                      font=("Segoe UI", 16, "bold"), text_color="white")
            error_title.pack(pady=10)
            
            # Error details
            error_content = ctk.CTkFrame(error_frame, fg_color="#c0392b")
            error_content.pack(fill="x", padx=10, pady=(0, 10))
            
            error_text = ctk.CTkTextbox(error_content, font=("Consolas", 11), 
                                       fg_color="transparent", text_color="white", height=150)
            error_text.pack(fill="both", expand=True, padx=10, pady=10)
            
            error_details = f"""Error: {error_msg}

Troubleshooting Steps:
1. Ensure Ollama is running: Open terminal and run 'ollama serve'
2. Verify model is available: Run 'ollama list'
3. Download model if needed: Run 'ollama pull gemma2:2b'
4. Check Ollama is accessible on localhost:11434
5. Verify Windows firewall is not blocking the connection
6. Ensure sufficient system memory for AI model

Connection Details:
- URL: {self.ollama_url}
- Model: {self.model_name}
- Timeout: 90 seconds"""
            
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
        self.status_label.configure(text="Results cleared", text_color="#3498db")
    
    def export_results(self):
        """Export all results including enhanced AI analysis to a text file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"procintel_ai_analysis_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
                f.write("PROCINTEL AI - ENHANCED WINDOWS PERSISTENCE ANALYSIS REPORT\n")
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
                    'hkcu_run': 'HKEY_CURRENT_USER RUN KEYS',
                    'hklm_run': 'HKEY_LOCAL_MACHINE RUN KEYS',
                    'hklm_runonce': 'HKEY_LOCAL_MACHINE RUNONCE KEYS',
                    'services': 'WINDOWS SERVICES',
                    'shell_folders': 'SHELL FOLDERS'
                }
                
                for tab_key, title in tab_titles.items():
                    content = self.tabs[tab_key][1].get("1.0", "end").strip()
                    if content:
                        f.write(f"{title}\n")
                        f.write("="*len(title) + "\n\n")
                        f.write(content)
                        f.write("\n\n" + "="*70 + "\n\n")
                
                # Export AI analysis if available
                if self.ai_sections:
                    f.write("AI ANALYSIS RESULTS\n")
                    f.write("="*19 + "\n\n")
                    
                    section_titles = {
                        'threat_detection': 'THREAT DETECTION ANALYSIS',
                        'forensic_analysis': 'FORENSIC INVESTIGATION ANALYSIS',
                        'security_analysis': 'SECURITY POSTURE ANALYSIS'
                    }
                    
                    for section_key, title in section_titles.items():
                        if section_key in self.ai_sections:
                            f.write(f"{title}\n")
                            f.write("-" * len(title) + "\n\n")
                            
                            # Extract text from the AI section
                            section_widget = self.ai_sections[section_key]
                            # Find the textbox widget within the section
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
                            f.write("-" * 50 + "\n\n")
                
                f.write("END OF PROCINTEL AI ANALYSIS REPORT\n")
            
            messagebox.showinfo("Export Complete", 
                              f"Enhanced analysis report exported to:\n{filename}\n\n"
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
    
    app = PersistenceAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()