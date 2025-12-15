import customtkinter as ctk
from datetime import datetime
import subprocess
import os

class ProcIntelDashboard:
    def __init__(self):
        # Initialize app with dark theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("ProcIntel - Dashboard")
        self.root.geometry("1000x650")

        # ------------- HEADER -------------
        self.create_header()

        # ------------- DASHBOARD CONTENT -------------
        self.main_content_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_content_frame.pack(expand=True, fill="both", pady=40)
        
        # Display the main dashboard view
        self.show_dashboard_view()

        # ------------- FOOTER -------------
        self.create_footer()

        # State management for clock
        self.clock_job = None
        self.update_clock()

    def create_header(self):
        """Creates the persistent header frame."""
        header_frame = ctk.CTkFrame(self.root, height=80, corner_radius=0, fg_color="#1e272e")
        header_frame.pack(fill="x", side="top")

        title = ctk.CTkLabel(header_frame, text="ProcIntel Dashboard",
                             font=("Segoe UI", 30, "bold"), text_color="white")
        title.pack(side="left", padx=30, pady=20)

        tagline = ctk.CTkLabel(header_frame,
                               text="AI powered Registry Analysis",
                               font=("Segoe UI", 14, "italic"), text_color="#bdc3c7")
        tagline.pack(side="left", padx=15, pady=20)

        # Add a clock label to the header
        self.clock_label = ctk.CTkLabel(header_frame, text="",
                                        font=("Segoe UI", 14), text_color="#bdc3c7")
        self.clock_label.pack(side="right", padx=30, pady=20)

    def create_footer(self):
        """Creates the persistent footer label."""
        footer = ctk.CTkLabel(self.root,
                              text="© 2025 ProcIntel | Intelligent Security for Processes and Registry",
                              font=("Segoe UI", 11), text_color="#7f8c8d")
        footer.pack(side="bottom", pady=10)

    def show_dashboard_view(self):
        """Creates and displays the dashboard content with a welcome message and buttons."""
        self.clear_content_frame()
        
        # Button section
        button_frame = ctk.CTkFrame(self.main_content_frame, fg_color="transparent")
        button_frame.pack(pady=30)
        
        # Connect the "Analyse Persistence Mechanisms" button to the new function
        self.create_button(button_frame, "Analyse Persistence Mechanisms", "#2980b9", 0, 0, self.run_adminai_script)
        self.create_button(button_frame, "Analyze USB / Removable Media", "#8e44ad", 0, 1, self.run_usb_script)
        self.create_button(button_frame, "View Reports", "#27ae60", 1, 0)
        self.create_button(button_frame, "Exit", "#c0392b", 1, 1, self.root.quit)

    def create_button(self, parent, text, color, row, col, cmd=None):
        """Creates a button with consistent styling and grids it."""
        btn = ctk.CTkButton(parent, text=text, width=220, height=60,
                            font=("Segoe UI", 14, "bold"),
                            fg_color=color, hover_color="#2c3e50",
                            corner_radius=15, command=cmd)
        btn.grid(row=row, column=col, padx=30, pady=20)

    def clear_content_frame(self):
        """Destroys all widgets in the main content frame."""
        for widget in self.main_content_frame.winfo_children():
            widget.destroy()
    
    def run_adminai_script(self):
        """
        Executes the 'adminai.py' script using subprocess.
        Note: This assumes adminai.py is in the same directory.
        """
        script_path = "adminai.py"
        if os.path.exists(script_path):
            try:
                # Use Popen to run the script in a new process without blocking the GUI
                subprocess.Popen(["python", script_path])
                print(f"Successfully launched {script_path}")
            except Exception as e:
                print(f"Failed to launch script: {e}")
                # Optional: Show a message box to the user
                ctk.CTkMessagebox(title="Error", message=f"Failed to launch script: {e}", icon="cancel")
        else:
            print(f"Error: {script_path} not found.")
            # Optional: Show a message box to the user
            ctk.CTkMessagebox(title="Error", message=f"The script '{script_path}' was not found. Please ensure it is in the same directory.", icon="warning")
            
    def run_usb_script(self):
        """
        Executes the 'adminai.py' script using subprocess.
        Note: This assumes adminai.py is in the same directory.
        """
        script_path = "usb.py"
        if os.path.exists(script_path):
            try:
                # Use Popen to run the script in a new process without blocking the GUI
                subprocess.Popen(["python", script_path])
                print(f"Successfully launched {script_path}")
            except Exception as e:
                print(f"Failed to launch script: {e}")
                # Optional: Show a message box to the user
                ctk.CTkMessagebox(title="Error", message=f"Failed to launch script: {e}", icon="cancel")
        else:
            print(f"Error: {script_path} not found.")
            # Optional: Show a message box to the user
            ctk.CTkMessagebox(title="Error", message=f"The script '{script_path}' was not found. Please ensure it is in the same directory.", icon="warning")
    
    def update_clock(self):
        """Updates the dynamic clock label in the header."""
        current_time = datetime.now().strftime("%I:%M:%S %p")
        self.clock_label.configure(text=current_time)
        # Schedule the next update after 1000 milliseconds (1 second)
        self.root.after(1000, self.update_clock)

    def run(self):
        """Starts the application's main loop."""
        self.root.mainloop()

if __name__ == "__main__":
    app = ProcIntelDashboard()
    app.run()
