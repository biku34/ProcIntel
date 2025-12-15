import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
from datetime import datetime
import psutil
import time
import threading
import subprocess
import sys

class ProcIntelHome:
    def __init__(self):
        # Initialize app (permanent dark theme)
        ctk.set_appearance_mode("dark")  
        ctk.set_default_color_theme("blue")  

        self.root = ctk.CTk()
        self.root.title("ProcIntel - Home")
        self.root.geometry("1000x650")
        
        # Configure Ttk style for process table (dark theme)
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")
        self.style.configure("Treeview", 
                             background="#2a2d2e", 
                             foreground="#dcdde1", 
                             fieldbackground="#2a2d2e",
                             bordercolor="#1e272e",
                             rowheight=25)
        self.style.map('Treeview', background=[('selected', '#27ae60')])
        self.style.configure("Treeview.Heading", 
                             background="#1e272e", 
                             foreground="white", 
                             font=("Segoe UI", 12, "bold"))
        
        # Protocol for window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Create the header (persistent across views)
        self.create_header()
        
        # Main content frame that will switch between views
        self.main_content_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_content_frame.pack(expand=True, fill="both", pady=40)
        
        # Create footer (persistent across views)
        self.create_footer()
        
        # State management
        self.is_monitoring = False
        self.update_job = None
        self.clock_job = None
        
        # Show initial welcome screen
        self.show_welcome_screen()

    def create_header(self):
        """Creates the persistent header"""
        self.header_frame = ctk.CTkFrame(self.root, height=80, corner_radius=0, fg_color="#1e272e")
        self.header_frame.pack(fill="x", side="top")

        title = ctk.CTkLabel(self.header_frame, text="ProcIntel",
                             font=("Segoe UI", 30, "bold"), text_color="white")
        title.pack(side="left", padx=30, pady=20)

        tagline = ctk.CTkLabel(self.header_frame,
                               text="Intelligent Process Monitoring & Registry Analysis",
                               font=("Segoe UI", 14, "italic"), text_color="#bdc3c7")
        tagline.pack(side="left", padx=15, pady=20)

    def create_footer(self):
        """Creates the persistent footer"""
        self.footer = ctk.CTkLabel(self.root,
                                   text="© 2025 ProcIntel | Intelligent Security for Processes and Registry",
                                   font=("Segoe UI", 11), text_color="#7f8c8d")
        self.footer.pack(side="bottom", pady=10)

    def show_welcome_screen(self):
        """Creates and displays the initial welcome screen"""
        self.is_monitoring = False
        self.root.title("ProcIntel - Home")
        
        # Clear existing content
        for widget in self.main_content_frame.winfo_children():
            widget.destroy()

        # Create welcome content
        welcome_frame = ctk.CTkFrame(self.main_content_frame, fg_color="transparent")
        welcome_frame.pack(expand=True, fill="both")

        welcome_label = ctk.CTkLabel(welcome_frame, text="Monitor, Detect, Defend",
                                     font=("Segoe UI", 28, "bold"), text_color="#ffffff")
        welcome_label.pack(pady=(10, 20))

        desc_label = ctk.CTkLabel(welcome_frame,
                                  text="AI-powered scanning for real-time\nprocess monitoring, registry analysis, and alerts.",
                                  font=("Segoe UI", 15), text_color="#dcdde1")
        desc_label.pack(pady=(0, 30))

        # Dynamic clock
        self.clock_label = ctk.CTkLabel(welcome_frame, font=("Segoe UI", 12), text_color="#95a5a6")
        self.clock_label.pack(pady=(0, 10))
        self.update_clock()

        # Buttons
        button_frame = ctk.CTkFrame(welcome_frame, fg_color="transparent")
        button_frame.pack(pady=30)

        self.create_button(button_frame, "Start Monitoring", "#27ae60", 0, 0, self.start_monitoring)
        self.create_button(button_frame, "View Reports", "#2980b9", 0, 1, self.view_reports)
        self.create_button(button_frame, "Registry Analysis", "#8e44ad", 1, 0, self.open_settings)
        self.create_button(button_frame, "Exit", "#c0392b", 1, 1, self.root.quit)

    def show_monitoring_screen(self):
        """Creates and displays the process monitoring screen"""
        self.is_monitoring = True
        self.root.title("ProcIntel - Process Monitor")
        
        # Clear existing content
        for widget in self.main_content_frame.winfo_children():
            widget.destroy()

        # Create monitoring content
        monitoring_frame = ctk.CTkFrame(self.main_content_frame, fg_color="transparent")
        monitoring_frame.pack(fill="both", expand=True)

        # Status and controls section
        status_frame = ctk.CTkFrame(monitoring_frame, fg_color="#1e272e", height=60)
        status_frame.pack(fill="x", padx=20, pady=(0, 10))
        status_frame.pack_propagate(False)

        # Back button with same styling as main buttons but smaller
        back_button = ctk.CTkButton(status_frame, text="← Back to Home", width=150, height=35,
                                    font=("Segoe UI", 12, "bold"), command=self.show_welcome_screen,
                                    fg_color="#8e44ad", hover_color="#7f8c8d", corner_radius=10)
        back_button.pack(side="left", padx=20, pady=12)



        # Search and controls
        controls_frame = ctk.CTkFrame(monitoring_frame, fg_color="transparent")
        controls_frame.pack(fill="x", padx=20, pady=(0, 10))

        search_label = ctk.CTkLabel(controls_frame, text="Search Processes:",
                                    font=("Segoe UI", 12), text_color="#bdc3c7")
        search_label.pack(side="left", padx=(0, 10))

        self.search_entry = ctk.CTkEntry(controls_frame, placeholder_text="Enter process name...", 
                                         width=300, height=35, font=("Segoe UI", 12))
        self.search_entry.pack(side="left", padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", self.filter_table)

        refresh_button = ctk.CTkButton(controls_frame, text="🔄 Refresh", width=120, height=35,
                                       font=("Segoe UI", 12, "bold"), command=self.manual_refresh,
                                       fg_color="#2980b9", hover_color="#1e6091", corner_radius=10)
        refresh_button.pack(side="left", padx=(0, 10))

        # Process table frame with border styling
        table_frame = ctk.CTkFrame(monitoring_frame, fg_color="#1e272e", corner_radius=15)
        table_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Table title
        table_title = ctk.CTkLabel(table_frame, text="Active Processes",
                                   font=("Segoe UI", 16, "bold"), text_color="white")
        table_title.pack(pady=(15, 10))

        # Create the process table
        columns = ["Process Name", "PID", "User", "CPU %", "Memory", "Disk Read", "Disk Write", "Network"]
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)

        # Configure columns
        column_widths = [150, 80, 100, 80, 100, 100, 100, 100]
        for i, (col, width) in enumerate(zip(columns, column_widths)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center")
            
        self.tree.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # Start the monitoring loop
        self.update_table_loop()

    def start_monitoring(self):
        """Switches to monitoring view and starts the process monitoring"""
        self.show_monitoring_screen()

    def view_reports(self):
        """Placeholder for view reports functionality"""
        # Create a simple dialog or new window for reports
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Reports")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        
        label = ctk.CTkLabel(dialog, text="Reports Feature Coming Soon!",
                             font=("Segoe UI", 16, "bold"))
        label.pack(pady=50)
        
        close_btn = ctk.CTkButton(dialog, text="Close", command=dialog.destroy,
                                  fg_color="#2980b9", hover_color="#1e6091")
        close_btn.pack(pady=20)

    def open_settings(self):
        python_exe = sys.executable  # gets path of current python interpreter
        subprocess.Popen([python_exe, "per.py"])

    def create_button(self, parent, text, color, row, col, cmd=None):
        """Helper method to create and grid buttons with consistent styling"""
        btn = ctk.CTkButton(parent, text=text, width=220, height=60,
                            font=("Segoe UI", 14, "bold"),
                            fg_color=color, hover_color="#2c3e50",
                            corner_radius=15, command=cmd)
        btn.grid(row=row, column=col, padx=30, pady=20)

    def update_clock(self):
        """Updates the dynamic clock label on welcome screen"""
        if not self.is_monitoring and hasattr(self, 'clock_label'):
            try:
                now = datetime.now().strftime("%A, %d %B %Y | %H:%M:%S")
                self.clock_label.configure(text=f"🕒 {now}")
                self.clock_job = self.root.after(1000, self.update_clock)
            except:
                pass  # Widget may have been destroyed

    def manual_refresh(self):
        """Manually refresh the process table"""
        if self.is_monitoring:
            self.update_table_loop(manual=True)

    def filter_table(self, event=None):
        """Filter processes based on search term"""
        if self.is_monitoring:
            self.update_table_loop(manual=True)

    def bytes_to_mb(self, bytes_val):
        """Convert bytes to MB with proper formatting"""
        if bytes_val is None:
            return "0.0"
        return f"{round(bytes_val / (1024 * 1024), 1)}"

    def get_processes(self, search_term=""):
        """Fetch current process information with filtering"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'io_counters']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'] or "Unknown"
                    user = proc.info.get('username') or "System"
                    
                    # Get CPU percentage
                    try:
                        cpu = proc.cpu_percent(interval=None)
                    except:
                        cpu = 0.0
                    
                    # Get memory info
                    try:
                        mem_mb = self.bytes_to_mb(proc.info['memory_info'].rss)
                    except:
                        mem_mb = "0.0"

                    # Get disk I/O info
                    try:
                        io = proc.info['io_counters']
                        read_mb = self.bytes_to_mb(io.read_bytes) if io else "0.0"
                        write_mb = self.bytes_to_mb(io.write_bytes) if io else "0.0"
                    except:
                        read_mb = write_mb = "0.0"

                    # Get network connections
                    try:
                        net_conns = len(proc.net_connections(kind='inet'))
                    except:
                        net_conns = 0
                    
                    # Apply search filter
                    if not search_term or search_term.lower() in name.lower():
                        processes.append([
                            name[:25] + "..." if len(name) > 25 else name,
                            str(pid),
                            user[:15] + "..." if len(user) > 15 else user,
                            f"{cpu:.1f}%",
                            f"{mem_mb} MB",
                            f"{read_mb} MB",
                            f"{write_mb} MB",
                            f"{net_conns}"
                        ])
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            print(f"Error getting processes: {e}")
            
        return processes

    def update_table_loop(self, manual=False):
        """Update the process table with current data"""
        if not self.is_monitoring:
            return
            
        # Cancel previous scheduled update
        if self.update_job is not None:
            self.root.after_cancel(self.update_job)

        try:
            # Clear existing rows
            for row in self.tree.get_children():
                self.tree.delete(row)

            # Get search term
            search_term = ""
            if hasattr(self, 'search_entry'):
                search_term = self.search_entry.get().strip()

            # Get and sort processes by CPU usage
            processes = self.get_processes(search_term)
            processes.sort(key=lambda x: float(x[3].replace("%", "")), reverse=True)

            # Insert top processes (limit to prevent performance issues)
            for process in processes[:100]:  # Show top 100 processes
                self.tree.insert("", "end", values=process)
                
        except Exception as e:
            print(f"Error updating table: {e}")
            
        # Schedule next update if monitoring is active and not manual
        if self.is_monitoring and not manual:
            self.update_job = self.root.after(3000, self.update_table_loop)  # Update every 3 seconds

    def on_closing(self):
        """Clean up and close the application"""
        self.is_monitoring = False
        
        # Cancel any scheduled jobs
        if self.update_job:
            self.root.after_cancel(self.update_job)
        if self.clock_job:
            self.root.after_cancel(self.clock_job)
            
        self.root.destroy()

    def run(self):
        """Start the application"""
        self.root.mainloop()


if __name__ == "__main__":
    app = ProcIntelHome()
    app.run()