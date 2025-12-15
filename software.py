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
from pathlib import Path
import requests
import json

class PersistenceAnalyzer:
    def __init__(self, root):
        # Initialize app (permanent dark theme)
        ctk.set_appearance_mode("dark")  
        ctk.set_default_color_theme("blue")
        
        self.root = root
        self.root.title("ProcIntel - Enterprise Registry & System Analyzer")
        self.root.geometry("1800x1100")
        
        # Configure style for any remaining Tkinter components
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")
        
        # Protocol for window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
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
        
    def create_header(self):
        """Creates the modern header"""
        self.header_frame = ctk.CTkFrame(self.root, height=90, corner_radius=0, fg_color="#1e272e")
        self.header_frame.pack(fill="x", side="top")
        self.header_frame.pack_propagate(False)

        title = ctk.CTkLabel(self.header_frame, text="ProcIntel Enterprise",
                             font=("Segoe UI", 28, "bold"), text_color="white")
        title.pack(side="left", padx=30, pady=20)

        tagline = ctk.CTkLabel(self.header_frame,
                               text="Advanced Registry & System Analysis • Enterprise Threat Detection",
                               font=("Segoe UI", 14, "italic"), text_color="#bdc3c7")
        tagline.pack(side="left", padx=15, pady=20)
        
    def create_control_panel(self):
        """Creates the modern control panel"""
        control_frame = ctk.CTkFrame(self.main_content_frame, fg_color="#1e272e", height=80)
        control_frame.pack(fill="x", padx=20, pady=(10, 20))
        control_frame.pack_propagate(False)
        
        # Left side buttons
        left_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        left_frame.pack(side="left", fill="y", padx=20)
        
        self.collect_btn = ctk.CTkButton(left_frame, text="Full Scan", 
                                        command=self.collect_data, width=130, height=40,
                                        font=("Segoe UI", 11, "bold"), fg_color="#27ae60", 
                                        hover_color="#229954", corner_radius=10)
        self.collect_btn.pack(side="left", padx=(0, 8), pady=20)
        
        self.clear_btn = ctk.CTkButton(left_frame, text="Clear Results", 
                                      command=self.clear_results, width=130, height=40,
                                      font=("Segoe UI", 11, "bold"), fg_color="#e74c3c", 
                                      hover_color="#c0392b", corner_radius=10)
        self.clear_btn.pack(side="left", padx=(0, 8), pady=20)
        
        self.export_btn = ctk.CTkButton(left_frame, text="Export Report", 
                                       command=self.export_results, width=130, height=40,
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
        
        self.status_label = ctk.CTkLabel(status_frame, text="Ready for Enterprise Scan", 
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
        footer_text = "© 2025 ProcIntel Enterprise | Advanced System Analysis & Threat Intelligence"
            
        self.footer = ctk.CTkLabel(self.root, text=footer_text,
                                   font=("Segoe UI", 11), text_color="#7f8c8d")
        self.footer.pack(side="bottom", pady=10)
        
    def init_tabs(self):
        """Initialize tabs for different analysis categories"""
        self.tabs = {}
        self.tab_buttons = {}
        self.current_tab = None
        
        tab_configs = [
            ("Installed Software", "installed_software", "#16a085"),
            ("System Policies", "system_policies", "#d35400"),
            ("AI Analysis", "ai_analysis", "#8e44ad")
        ]
        
        for i, (tab_name, tab_key, color) in enumerate(tab_configs):
            # Create tab button
            btn = ctk.CTkButton(self.tab_buttons_frame, text=tab_name, 
                               command=lambda k=tab_key: self.switch_tab(k),
                               width=100, height=35, font=("Segoe UI", 9, "bold"),
                               fg_color=color if i == 0 else "#34495e",
                               hover_color=color, corner_radius=8)
            btn.pack(side="left", padx=3, pady=7)
            self.tab_buttons[tab_key] = (btn, color)
            
            # Create content frame for this tab
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
        self.switch_tab("installed_software")
    
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
    
    def safe_reg_enumerate_subkeys(self, hkey, subkey_path):
        """Safely enumerate registry subkeys"""
        try:
            access_rights = winreg.KEY_READ
            if is_admin():
                access_rights = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            
            with winreg.OpenKey(hkey, subkey_path, 0, access_rights) as key:
                subkeys = []
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkeys.append(subkey_name)
                        i += 1
                    except WindowsError:
                        break
                return subkeys
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
    
    def collect_data(self):
        """Main function to collect all persistence and system data"""
        self.status_label.configure(text="Running enterprise scan...", text_color="#f39c12")
        self.root.update()
        
        # Disable buttons during collection
        self.collect_btn.configure(state="disabled")
        self.clear_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        
        try:
            # Clear existing results
            for tab_key, (content_frame, text_widget) in self.tabs.items():
                text_widget.delete("1.0", "end")
            
            # Update status
            self.status_label.configure(text="Enumerating installed software...", text_color="#f39c12")
            self.root.update()
            
            # Collect Installed Software
            software_data = self.collect_installed_software()
            self.tabs['installed_software'][1].insert("end", software_data['output'])
            
            # Update status
            self.status_label.configure(text="Analyzing system policies...", text_color="#f39c12")
            self.root.update()
            
            # Collect System Policies  
            policies_result = self.collect_system_policies()
            self.tabs['system_policies'][1].insert("end", policies_result)

            # Update status
            self.status_label.configure(text="Sending data to local LLM for analysis...", text_color="#3498db")
            self.root.update()

            # Perform AI Analysis
            ai_analysis_result = self.analyze_with_ollama(software_data['list'], policies_result)
            self.tabs['ai_analysis'][1].insert("end", ai_analysis_result)
            
            self.status_label.configure(text="Enterprise scan completed", text_color="#27ae60")
            
        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred during data collection:\n{str(e)}")
            self.status_label.configure(text="Enterprise scan failed", text_color="#e74c3c")
        
        finally:
            # Re-enable buttons
            self.collect_btn.configure(state="normal")
            self.clear_btn.configure(state="normal")
            self.export_btn.configure(state="normal")

    def analyze_with_ollama(self, software_list, policies_data):
        """Sends data to local Ollama instance for AI analysis."""
        combined_analysis = ""
        
        # Take only the first 10 software entries for the group analysis
        software_chunk = software_list[:10]
        
        if not software_chunk:
            combined_analysis += "No software found to analyze.\n\n"
        else:
            # Construct a detailed prompt for the group of software entries
            software_block = ""
            for i, software in enumerate(software_chunk, 1):
                software_block += f"Software {i}:\n"
                for key, value in software.items():
                    software_block += f"  {key.replace('_', ' ').capitalize()}: {value}\n"
                software_block += "\n"

            self.status_label.configure(text="Analyzing first 10 software entries with AI...", text_color="#3498db")
            self.root.update()

            prompt_text = f"""
You are a highly skilled security analyst. Your task is to analyze the following group of software from a system, identify any potential malicious activity, and provide actionable threat intelligence and security recommendations.

Software to analyze:
---
{software_block}

Your analysis should include:
1.  **Threat Analysis**: Identify any software entries that look suspicious. For example, a missing publisher, an unusual install location, or an uninstall string pointing to a non-standard path.
2.  **Threat Intelligence**: Provide context on any identified threats. Mention common attack vectors, malware families, or known vulnerabilities associated with similar findings.
3.  **Security Recommendations**: Provide a numbered list of practical, actionable steps to mitigate the identified risks.
4.  **Conclusion**: A brief summary of the security status for this group of software.

If the software appears to be legitimate and poses no obvious risk, state that clearly.
"""

            url = 'http://localhost:11434/api/generate'
            payload = {
                "model": "gemma3:1b",
                "prompt": prompt_text,
                "stream": False
            }
            
            try:
                response = requests.post(url, json=payload, timeout=120)
                response.raise_for_status()
                
                result = response.json()
                analysis_report = result.get('response', 'Error: No response from Ollama.')
                combined_analysis += f"--- AI ANALYSIS FOR FIRST 10 SOFTWARE ENTRIES ---\n{analysis_report}\n\n"

            except requests.exceptions.RequestException as e:
                error_message = f"Failed to connect to Ollama server.\n"
                error_message += f"Please ensure Ollama is running at {url} and the 'gemma3:1b' model is installed.\n\n"
                error_message += f"Connection Error: {e}"
                messagebox.showerror("Ollama Connection Error", error_message)
                return "AI analysis failed. Please check your Ollama setup."
            except json.JSONDecodeError:
                return "Error: Invalid JSON response from Ollama."
            except Exception as e:
                return f"An unexpected error occurred during AI analysis: {e}"

        # Now, analyze system policies in one final block
        self.status_label.configure(text="Analyzing system policies with AI...", text_color="#3498db")
        self.root.update()

        policy_prompt = f"""
You are a highly skilled security analyst. Your task is to analyze the following system policy data and provide a report on potential security risks and recommendations.

System Policy Data:
---
{policies_data}
---

Your analysis should include:
1.  **Threat Analysis**: Identify any policies that weaken the system's security posture or could be used for malicious purposes. Be specific and provide reasons for your concerns.
2.  **Threat Intelligence**: Provide context on how these policy misconfigurations could be exploited.
3.  **Security Recommendations**: Provide a numbered list of practical, actionable steps to mitigate the identified risks and improve the overall security posture of the system.
4.  **Overall Conclusion**: A brief summary of the system's security status based on the provided policies.

If no concerning policies are found, state that the policies appear to be secure based on the provided data.
"""
        try:
            response = requests.post(url, json={"model": "gemma3:1b", "prompt": policy_prompt, "stream": False}, timeout=120)
            response.raise_for_status()
            result = response.json()
            policy_report = result.get('response', 'Error: No response from Ollama.')
            combined_analysis += f"--- AI ANALYSIS FOR SYSTEM POLICIES ---\n{policy_report}\n\n"
        except requests.exceptions.RequestException as e:
            combined_analysis += f"Error: Could not analyze policies with AI. Connection to Ollama failed: {e}\n"
        
        return combined_analysis

    def collect_installed_software(self):
        """Collect installed software from both HKLM and HKCU uninstall keys"""
        output = "INSTALLED SOFTWARE ANALYSIS\n"
        output += "="*80 + "\n\n"
        software_list = []
        
        # Define uninstall registry paths
        uninstall_paths = [
            {
                'hkey': winreg.HKEY_LOCAL_MACHINE,
                'path': r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                'name': "HKEY_LOCAL_MACHINE (System-wide Software)"
            },
            {
                'hkey': winreg.HKEY_CURRENT_USER,
                'path': r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 
                'name': "HKEY_CURRENT_USER (User Software)"
            },
            {
                'hkey': winreg.HKEY_LOCAL_MACHINE,
                'path': r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                'name': "HKEY_LOCAL_MACHINE (32-bit on 64-bit System)"
            }
        ]
        
        total_software = 0
        
        for uninstall_info in uninstall_paths:
            output += f"Location: {uninstall_info['name']}\n"
            output += f"Registry Key: {uninstall_info['name'].split(' ')[0]}\\{uninstall_info['path']}\n"
            output += f"Last Write Time: {self.get_key_last_write_time(uninstall_info['hkey'], uninstall_info['path'])}\n"
            output += "-" * 80 + "\n\n"
            
            # Get software entries
            subkeys = self.safe_reg_enumerate_subkeys(uninstall_info['hkey'], uninstall_info['path'])
            
            if subkeys is None:
                output += "Status: Key not found\n\n"
                continue
            elif subkeys == "ACCESS_DENIED":
                output += "Status: Access denied\n\n"
                continue
            elif isinstance(subkeys, str) and subkeys.startswith("ERROR"):
                output += f"Status: {subkeys}\n\n"
                continue
            
            software_count = 0
            for subkey in subkeys:
                try:
                    software_path = f"{uninstall_info['path']}\\{subkey}"
                    software_info = self.get_software_details(uninstall_info['hkey'], software_path, subkey)
                    
                    if software_info and software_info.get('display_name'):
                        software_count += 1
                        total_software += 1
                        
                        output += f"Software {software_count}:\n"
                        output += f"  Registry Key: {subkey}\n"
                        output += f"  Display Name: {software_info.get('display_name', 'N/A')}\n"
                        output += f"  Publisher: {software_info.get('publisher', 'N/A')}\n"
                        output += f"  Version: {software_info.get('version', 'N/A')}\n"
                        output += f"  Install Date: {software_info.get('install_date', 'N/A')}\n"
                        output += f"  Install Location: {software_info.get('install_location', 'N/A')}\n"
                        output += f"  Uninstall String: {software_info.get('uninstall_string', 'N/A')}\n"
                        output += f"  Size (MB): {software_info.get('size_mb', 'N/A')}\n"
                        output += f"  System Component: {software_info.get('system_component', 'No')}\n"
                        
                        # Check if install location exists
                        install_location = software_info.get('install_location')
                        if install_location and install_location != 'N/A':
                            try:
                                expanded_path = os.path.expandvars(str(install_location))
                                if os.path.exists(expanded_path):
                                    output += f"  Install Path Status: EXISTS\n"
                                    try:
                                        file_count = len(os.listdir(expanded_path))
                                        output += f"  Directory Contents: {file_count} items\n"
                                    except:
                                        output += f"  Directory Contents: Cannot list\n"
                                else:
                                    output += f"  Install Path Status: NOT FOUND\n"
                            except Exception as e:
                                output += f"  Install Path Check: Error - {str(e)}\n"
                        
                        output += "\n"
                        software_list.append(software_info)
                        
                        # Limit per location to avoid overwhelming output
                        if software_count >= 50:
                            output += f"  ... (Limited to first 50 entries from this location)\n\n"
                            break
                            
                except Exception as e:
                    continue
            
            output += f"Software found in this location: {software_count}\n"
            output += "="*80 + "\n\n"
        
        output += f"TOTAL SOFTWARE ENTRIES ANALYZED: {total_software}\n\n"
        return {'output': output, 'list': software_list}
    
    def get_software_details(self, hkey, software_path, subkey):
        """Get detailed information about installed software"""
        try:
            access_rights = winreg.KEY_READ
            if is_admin():
                access_rights = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                
            with winreg.OpenKey(hkey, software_path, 0, access_rights) as key:
                software_info = {'subkey': subkey}
                
                # Common software values to check
                values_to_check = [
                    ('DisplayName', 'display_name'),
                    ('Publisher', 'publisher'),
                    ('DisplayVersion', 'version'),
                    ('InstallDate', 'install_date'),
                    ('InstallLocation', 'install_location'),
                    ('UninstallString', 'uninstall_string'),
                    ('EstimatedSize', 'size_kb'),
                    ('SystemComponent', 'system_component_raw'),
                    ('WindowsInstaller', 'windows_installer'),
                    ('URLInfoAbout', 'url_info'),
                    ('HelpLink', 'help_link')
                ]
                
                for reg_value, info_key in values_to_check:
                    try:
                        value, _ = winreg.QueryValueEx(key, reg_value)
                        software_info[info_key] = value
                    except FileNotFoundError:
                        software_info[info_key] = None
                
                # Convert size from KB to MB
                if software_info.get('size_kb'):
                    try:
                        size_mb = round(int(software_info['size_kb']) / 1024, 2)
                        software_info['size_mb'] = size_mb
                    except:
                        software_info['size_mb'] = None
                
                # Convert system component flag
                if software_info.get('system_component_raw') == 1:
                    software_info['system_component'] = 'Yes'
                else:
                    software_info['system_component'] = 'No'
                
                # Format install date
                install_date = software_info.get('install_date')
                if install_date and len(str(install_date)) == 8:
                    try:
                        date_str = str(install_date)
                        formatted_date = f"{date_str[0:4]}-{date_str[4:6]}-{date_str[6:8]}"
                        software_info['install_date'] = formatted_date
                    except:
                        pass
                
                return software_info
                
        except Exception:
            return None
    
    def collect_system_policies(self):
        """Collect system policies from various registry locations"""
        output = "SYSTEM POLICIES ANALYSIS\n"
        output += "="*80 + "\n\n"
        
        # Define policy registry paths to analyze
        policy_paths = [
            {
                'hkey': winreg.HKEY_LOCAL_MACHINE,
                'path': r"SOFTWARE\Policies\Microsoft\Windows",
                'name': "HKLM System-Wide Windows Policies"
            },
            {
                'hkey': winreg.HKEY_CURRENT_USER,
                'path': r"SOFTWARE\Policies\Microsoft\Windows", 
                'name': "HKCU User Windows Policies"
            },
            {
                'hkey': winreg.HKEY_LOCAL_MACHINE,
                'path': r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
                'name': "HKLM Legacy System Policies"
            },
            {
                'hkey': winreg.HKEY_CURRENT_USER,
                'path': r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
                'name': "HKCU Legacy User Policies"
            },
            {
                'hkey': winreg.HKEY_LOCAL_MACHINE,
                'path': r"SOFTWARE\Policies\Microsoft\WindowsFirewall",
                'name': "HKLM Windows Firewall Policies"
            },
            {
                'hkey': winreg.HKEY_LOCAL_MACHINE,
                'path': r"SOFTWARE\Policies\Microsoft\Windows Defender",
                'name': "HKLM Windows Defender Policies"
            }
        ]
        
        total_policies = 0
        
        for policy_info in policy_paths:
            output += f"Policy Location: {policy_info['name']}\n"
            output += f"Registry Key: {policy_info['name'].split(' ')[0]}\\{policy_info['path']}\n"
            output += f"Last Write Time: {self.get_key_last_write_time(policy_info['hkey'], policy_info['path'])}\n"
            output += "-" * 80 + "\n\n"
            
            # Recursively analyze policy subkeys
            policy_count = self.analyze_policy_tree(policy_info['hkey'], policy_info['path'], output, 0)
            total_policies += policy_count
            
            output += f"Policies found in this location: {policy_count}\n"
            output += "="*80 + "\n\n"
        
        output += f"TOTAL POLICY ENTRIES ANALYZED: {total_policies}\n\n"
        return output
    
    def analyze_policy_tree(self, hkey, base_path, output_ref, depth, max_depth=3):
        """Recursively analyze policy registry tree"""
        if depth > max_depth:
            return 0
        
        policy_count = 0
        indent = "  " * depth
        
        # Get direct values in this key
        values = self.safe_reg_query(hkey, base_path)
        if values and isinstance(values, list) and len(values) > 0:
            hkey_name = "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
            output_ref += f"{indent}Policy Key: {hkey_name}\\{base_path}\n"
            
            for value in values:
                policy_count += 1
                output_ref += f"{indent}  Policy: {value['name']}\n"
                output_ref += f"{indent}  Value: {value['value']}\n"
                output_ref += f"{indent}  Type: {value['type_name']}\n"
                
                # Interpret common policy values
                policy_meaning = self.interpret_policy_value(value['name'], value['value'])
                if policy_meaning:
                    output_ref += f"{indent}  Meaning: {policy_meaning}\n"
                
                output_ref += "\n"
        
        # Get subkeys and recurse
        subkeys = self.safe_reg_enumerate_subkeys(hkey, base_path)
        if subkeys and isinstance(subkeys, list):
            for subkey in subkeys[:20]:  # Limit subkeys to avoid excessive output
                try:
                    subkey_path = f"{base_path}\\{subkey}"
                    sub_count = self.analyze_policy_tree(hkey, subkey_path, output_ref, depth + 1, max_depth)
                    policy_count += sub_count
                except Exception:
                    continue
        
        return policy_count
    
    def interpret_policy_value(self, policy_name, policy_value):
        """Interpret common policy values for better understanding"""
        interpretations = {
            # Security policies
            'DisableAntiSpyware': lambda v: "Windows Defender disabled" if v == 1 else "Windows Defender enabled",
            'DisableRealtimeMonitoring': lambda v: "Real-time protection disabled" if v == 1 else "Real-time protection enabled",
            'NoAutoReboot': lambda v: "Automatic reboot disabled" if v == 1 else "Automatic reboot enabled",
            'EnableScriptBlockLogging': lambda v: "PowerShell script logging enabled" if v == 1 else "PowerShell script logging disabled",
            
            # Network policies  
            'EnableFirewall': lambda v: "Firewall enabled" if v == 1 else "Firewall disabled",
            'DisableNotifications': lambda v: "Firewall notifications disabled" if v == 1 else "Firewall notifications enabled",
            
            # User policies
            'DisableTaskMgr': lambda v: "Task Manager disabled" if v == 1 else "Task Manager enabled",
            'DisableRegistryTools': lambda v: "Registry editing disabled" if v == 1 else "Registry editing enabled",
            'RestrictRun': lambda v: "Application execution restricted" if v == 1 else "No application restrictions",
            
            # System policies
            'DisableSystemRestore': lambda v: "System Restore disabled" if v == 1 else "System Restore enabled",
            'DisableSR': lambda v: "System Restore disabled" if v == 1 else "System Restore enabled",
            'NoControlPanel': lambda v: "Control Panel access disabled" if v == 1 else "Control Panel access enabled"
        }
        
        if policy_name in interpretations:
            try:
                return interpretations[policy_name](policy_value)
            except:
                return None
        return None
    
    def clear_results(self):
        """Clear all analysis results"""
        for tab_key, (content_frame, widget) in self.tabs.items():
            widget.delete("1.0", "end")
        
        self.status_label.configure(text="Results cleared", text_color="#95a5a6")
    
    def export_results(self):
        """Export analysis results to file"""
        try:
            from tkinter import filedialog
            
            # Ask user for save location
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Analysis Results"
            )
            
            if not filename:
                return
            
            # Compile all results
            export_content = f"ProcIntel Enterprise Analysis Report\n"
            export_content += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            export_content += f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}\n"
            export_content += f"User: {os.environ.get('USERNAME', 'Unknown')}\n"
            export_content += f"Admin Rights: {is_admin()}\n"
            export_content += "="*80 + "\n\n"
            
            # Export each tab's content
            tab_names = {
                'installed_software': 'Installed Software',
                'system_policies': 'System Policies',
                'ai_analysis': 'AI Analysis'
            }
            
            for tab_key, tab_name in tab_names.items():
                content = self.tabs[tab_key][1].get("1.0", "end").strip()
                if content:
                    export_content += f"\n{tab_name}\n"
                    export_content += "="*80 + "\n"
                    export_content += content + "\n\n"
            
            # Write to file
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(export_content)
            
            messagebox.showinfo("Export Complete", f"Analysis results exported to:\n{filename}")
            self.status_label.configure(text="Results exported successfully", text_color="#27ae60")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
            self.status_label.configure(text="Export failed", text_color="#e74c3c")
    
    def on_closing(self):
        """Handle application closing"""
        self.root.quit()
        self.root.destroy()

def is_admin():
    """Check if the script is running with administrative privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Relaunches the script with administrator privileges."""
    try:
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([f'"{p}"' for p in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, script, None, 1)
        sys.exit(0)
    except Exception as e:
        messagebox.showerror("Admin Error", f"Failed to acquire administrator privileges:\n{str(e)}")
        sys.exit(1)

def main():
    """Main function to run the application"""
    # Check if running on Windows
    if os.name != 'nt':
        messagebox.showerror("Platform Error", "This application is designed for Windows systems only.")
        sys.exit(1)
    
    # Relaunch as admin if not already
    if not is_admin():
        run_as_admin()
            
    # Create main window
    root = ctk.CTk()
    app = PersistenceAnalyzer(root)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()
