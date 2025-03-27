import wx
import wx.adv
import wx.grid
import nmap
import threading
import ipaddress
import socket
import subprocess

class RootAccessDialog(wx.Dialog):
    def __init__(self, parent):
        super(RootAccessDialog, self).__init__(parent, title="Root Access", size=(300, 200))
        
        panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        
        # Password input
        password_label = wx.StaticText(panel, label="Enter Root Password:")
        self.password_entry = wx.TextCtrl(panel, style=wx.TE_PASSWORD)
        
        # Status message
        self.status_text = wx.StaticText(panel, label="")
        
        # Buttons
        button_sizer = wx.StdDialogButtonSizer()
        self.ok_button = wx.Button(panel, wx.ID_OK, label="Authenticate")
        self.cancel_button = wx.Button(panel, wx.ID_CANCEL, label="Cancel")
        
        button_sizer.AddButton(self.ok_button)
        button_sizer.AddButton(self.cancel_button)
        button_sizer.Realize()
        
        # Add to main sizer
        sizer.Add(password_label, 0, wx.ALL | wx.CENTER, 10)
        sizer.Add(self.password_entry, 0, wx.ALL | wx.EXPAND, 10)
        sizer.Add(self.status_text, 0, wx.ALL | wx.CENTER, 10)
        sizer.Add(button_sizer, 0, wx.ALL | wx.CENTER, 10)
        
        panel.SetSizer(sizer)
        
        # Bind events
        self.ok_button.Bind(wx.EVT_BUTTON, self.OnAuthenticate)
        
    def OnAuthenticate(self, event):
        password = self.password_entry.GetValue()
        
        try:
            # Attempt to verify root password
            subprocess.run(['sudo', '-S', 'ls'], input=password.encode(), capture_output=True, check=True)
            self.EndModal(wx.ID_OK)
        except subprocess.CalledProcessError:
            self.status_text.SetLabel("Invalid Password")
            self.status_text.SetForegroundColour(wx.RED)
            self.Layout()

class NmapScannerFrame(wx.Frame):
    def __init__(self, parent, title):
        super(NmapScannerFrame, self).__init__(parent, title=title, size=(1000, 800))
        
        # Dark theme styling
        self.SetBackgroundColour(wx.Colour(50, 50, 50))
        
        self.scanner = nmap.PortScanner()
        self.scanning = False
        self.scan_thread = None
        self.is_root = False
        
        self.InitUI()
        self.Centre()
        # Remove self.Show() from here since we'll control it from the App class
    
    def InitUI(self):
        panel = wx.Panel(self)
        panel.SetBackgroundColour(wx.Colour(50, 50, 50))
        
        # Main vertical sizer
        main_sizer = wx.BoxSizer(wx.VERTICAL)
        
        # Target input section
        target_box = wx.StaticBox(panel, label="Target Selection")
        target_sizer = wx.StaticBoxSizer(target_box, wx.VERTICAL)
        
        target_hsizer = wx.BoxSizer(wx.HORIZONTAL)
        target_label = wx.StaticText(panel, label="Target IP/Hostname:")
        self.target_entry = wx.TextCtrl(panel)
        self.target_entry.SetValue("127.0.0.1")
        
        target_hsizer.Add(target_label, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        target_hsizer.Add(self.target_entry, 1, wx.ALL | wx.EXPAND, 5)
        target_sizer.Add(target_hsizer, 0, wx.EXPAND)
        
        main_sizer.Add(target_sizer, 0, wx.ALL | wx.EXPAND, 10)
        
        # Scan options section
        options_box = wx.StaticBox(panel, label="Scan Options")
        options_sizer = wx.StaticBoxSizer(options_box, wx.VERTICAL)
        
        # Port range
        port_hsizer = wx.BoxSizer(wx.HORIZONTAL)
        port_label = wx.StaticText(panel, label="Port Range:")
        self.port_entry = wx.TextCtrl(panel)
        self.port_entry.SetValue("1-1024")
        
        port_hsizer.Add(port_label, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        port_hsizer.Add(self.port_entry, 1, wx.ALL | wx.EXPAND, 5)
        options_sizer.Add(port_hsizer, 0, wx.EXPAND)
        
        # Scan type
        scan_hsizer = wx.BoxSizer(wx.HORIZONTAL)
        scan_label = wx.StaticText(panel, label="Scan Type:")
        scan_types = ["SYN Scan (-sS)", "TCP Connect (-sT)", "UDP Scan (-sU)", "Service Detection (-sV)"]
        self.scan_type = wx.Choice(panel, choices=scan_types)
        self.scan_type.SetSelection(3)  # Default to service detection
        
        scan_hsizer.Add(scan_label, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        scan_hsizer.Add(self.scan_type, 1, wx.ALL, 5)
        options_sizer.Add(scan_hsizer, 0, wx.EXPAND)
        
        # Timing template
        timing_hsizer = wx.BoxSizer(wx.HORIZONTAL)
        timing_label = wx.StaticText(panel, label="Timing Template:")
        self.timing_choices = ["T0", "T1", "T2", "T3", "T4", "T5"]
        self.timing_radio = wx.RadioBox(panel, choices=self.timing_choices, style=wx.RA_HORIZONTAL)
        self.timing_radio.SetSelection(3)  # Default to T3
        
        timing_hsizer.Add(timing_label, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        timing_hsizer.Add(self.timing_radio, 1, wx.ALL, 5)
        options_sizer.Add(timing_hsizer, 0, wx.EXPAND)
        
        main_sizer.Add(options_sizer, 0, wx.ALL | wx.EXPAND, 10)
        
        # Control buttons
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        self.scan_button = wx.Button(panel, label="Start Scan")
        self.scan_button.Bind(wx.EVT_BUTTON, self.OnStartScan)
        
        self.stop_button = wx.Button(panel, label="Stop Scan")
        self.stop_button.Bind(wx.EVT_BUTTON, self.OnStopScan)
        self.stop_button.Disable()
        
        self.clear_button = wx.Button(panel, label="Clear Results")
        self.clear_button.Bind(wx.EVT_BUTTON, self.OnClearResults)
        
        button_sizer.Add(self.scan_button, 0, wx.ALL, 5)
        button_sizer.Add(self.stop_button, 0, wx.ALL, 5)
        button_sizer.Add(self.clear_button, 0, wx.ALL, 5)
        
        main_sizer.Add(button_sizer, 0, wx.ALL | wx.CENTER, 5)
        
        # Root Access button
        self.root_button = wx.Button(panel, label="Authenticate Root Access")
        self.root_button.Bind(wx.EVT_BUTTON, self.OnRootAuthentication)
        main_sizer.Add(self.root_button, 0, wx.ALL | wx.CENTER, 10)
        
        # Progress bar
        self.progress = wx.Gauge(panel, range=100)
        main_sizer.Add(self.progress, 0, wx.ALL | wx.EXPAND, 10)
        
        # Status bar
        self.statusbar = self.CreateStatusBar()
        self.statusbar.SetStatusText("Ready")
        
        # Results notebook
        self.notebook = wx.Notebook(panel)
        
        # Raw output tab
        self.raw_panel = wx.Panel(self.notebook)
        raw_sizer = wx.BoxSizer(wx.VERTICAL)
        self.raw_output = wx.TextCtrl(self.raw_panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.HSCROLL)
        raw_sizer.Add(self.raw_output, 1, wx.EXPAND | wx.ALL, 5)
        self.raw_panel.SetSizer(raw_sizer)
        
        # Services tab
        self.services_panel = wx.Panel(self.notebook)
        services_sizer = wx.BoxSizer(wx.VERTICAL)
        
        # Create grid for services
        self.services_grid = wx.grid.Grid(self.services_panel)
        self.services_grid.CreateGrid(0, 6)
        
        # Set column headers
        self.services_grid.SetColLabelValue(0, "Port")
        self.services_grid.SetColLabelValue(1, "Protocol")
        self.services_grid.SetColLabelValue(2, "State")
        self.services_grid.SetColLabelValue(3, "Service")
        self.services_grid.SetColLabelValue(4, "Version")
        self.services_grid.SetColLabelValue(5, "Additional Info")
        
        # Set column widths
        self.services_grid.SetColSize(0, 60)
        self.services_grid.SetColSize(1, 60)
        self.services_grid.SetColSize(2, 80)
        self.services_grid.SetColSize(3, 100)
        self.services_grid.SetColSize(4, 150)
        self.services_grid.SetColSize(5, 250)
        
        services_sizer.Add(self.services_grid, 1, wx.EXPAND | wx.ALL, 5)
        self.services_panel.SetSizer(services_sizer)
        
        # Host info tab
        self.host_panel = wx.Panel(self.notebook)
        host_sizer = wx.BoxSizer(wx.VERTICAL)
        self.host_info = wx.TextCtrl(self.host_panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        host_sizer.Add(self.host_info, 1, wx.EXPAND | wx.ALL, 5)
        self.host_panel.SetSizer(host_sizer)
        
        # Add tabs to notebook
        self.notebook.AddPage(self.raw_panel, "Raw Output")
        self.notebook.AddPage(self.services_panel, "Services")
        self.notebook.AddPage(self.host_panel, "Host Info")
        
        main_sizer.Add(self.notebook, 1, wx.ALL | wx.EXPAND, 10)
        
        # Customize colors and fonts for a more professional look
        font = wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
        
        # Apply custom styling to various widgets
        for child in panel.GetChildren():
            if isinstance(child, wx.StaticText):
                child.SetForegroundColour(wx.WHITE)
                child.SetFont(font)
            elif isinstance(child, wx.Button):
                child.SetBackgroundColour(wx.Colour(70, 70, 70))
                child.SetForegroundColour(wx.WHITE)
        
        panel.SetSizer(main_sizer)
    
    def OnRootAuthentication(self, event):
        root_dialog = RootAccessDialog(self)
        if root_dialog.ShowModal() == wx.ID_OK:
            self.is_root = True
            self.statusbar.SetStatusText("Root Access Granted")
            self.root_button.Disable()
        root_dialog.Destroy()
    
    def ValidateInput(self):
        # Validate target
        target = self.target_entry.GetValue().strip()
        if not target:
            wx.MessageBox("Please enter a target IP or hostname", "Error", wx.OK | wx.ICON_ERROR)
            return False
        
        # Try to validate IP or resolve hostname
        try:
            try:
                # Check if valid IP address
                ipaddress.ip_address(target)
            except ValueError:
                # If not valid IP, try to resolve hostname
                socket.gethostbyname(target)
        except:
            wx.MessageBox(f"Invalid IP address or hostname: {target}", "Error", wx.OK | wx.ICON_ERROR)
            return False
            
        # Validate port range
        port_range = self.port_entry.GetValue().strip()
        if not port_range:
            wx.MessageBox("Please enter a port range", "Error", wx.OK | wx.ICON_ERROR)
            return False
            
        # Basic validation of port format
        if not all(part.strip().isdigit() or '-' in part for part in port_range.split(',')):
            if not port_range.lower() in ['all', 'common']:
                wx.MessageBox("Invalid port range format. Use comma-separated values or ranges (e.g., '80,443,8000-8100')", 
                              "Error", wx.OK | wx.ICON_ERROR)
                return False
        
        return True
    
    def GetScanArguments(self):
        arguments = ""
        
        # Add scan type
        scan_type = self.scan_type.GetString(self.scan_type.GetSelection())
        if "SYN Scan" in scan_type:
            arguments += " -sS"
        elif "TCP Connect" in scan_type:
            arguments += " -sT"
        elif "UDP Scan" in scan_type:
            arguments += " -sU"
        elif "Service Detection" in scan_type:
            arguments += " -sV"
        
        # Add timing template
        timing = self.timing_choices[self.timing_radio.GetSelection()]
        arguments += f" -{timing}"
        
        # Add root-level scanning capabilities if authenticated
        if self.is_root:
            arguments += " -O"  # OS detection
        
        return arguments.strip()
    
    def OnStartScan(self, event):
        if not self.ValidateInput():
            return
            
        if self.scan_thread and self.scan_thread.is_alive():
            wx.MessageBox("A scan is already running", "Info", wx.OK | wx.ICON_INFORMATION)
            return
            
        self.ClearResults()
        self.scan_button.Disable()
        self.stop_button.Enable()
        self.statusbar.SetStatusText("Scanning...")
        self.progress.SetValue(0)
        
        # Get scan parameters
        self.target = self.target_entry.GetValue().strip()
        self.ports = self.port_entry.GetValue().strip()
        self.args = self.GetScanArguments()
        
        # Start scan in a separate thread
        self.scanning = True
        self.scan_thread = threading.Thread(target=self.RunScan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Start progress updater
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.UpdateProgress, self.timer)
        self.timer.Start(100)
    
    def RunScan(self):
        try:
            # Update raw output with scan configuration
            wx.CallAfter(self.UpdateRawOutput, f"Starting NMAP scan\n")
            wx.CallAfter(self.UpdateRawOutput, f"Target: {self.target}\n")
            wx.CallAfter(self.UpdateRawOutput, f"Ports: {self.ports}\n")
            wx.CallAfter(self.UpdateRawOutput, f"Arguments: {self.args}\n")
            wx.CallAfter(self.UpdateRawOutput, "Scanning in progress...\n\n")
            
            # Run the scan
            self.scanner.scan(self.target, self.ports, arguments=self.args)
            
            if not self.scanning:  # Check if scan was stopped
                return
                
            # Process results
            wx.CallAfter(self.ProcessResults)
            
        except nmap.PortScannerError as e:
            wx.CallAfter(self.UpdateRawOutput, f"Error during scan: {str(e)}\n")
            wx.CallAfter(wx.MessageBox, f"Error during scan: {str(e)}", "Scan Error", wx.OK | wx.ICON_ERROR)
        except Exception as e:
            wx.CallAfter(self.UpdateRawOutput, f"Unexpected error: {str(e)}\n")
            wx.CallAfter(wx.MessageBox, f"Unexpected error: {str(e)}", "Error", wx.OK | wx.ICON_ERROR)
        finally:
            self.scanning = False
            wx.CallAfter(self.scan_button.Enable)
            wx.CallAfter(self.stop_button.Disable)
            wx.CallAfter(self.statusbar.SetStatusText, "Scan completed")
            wx.CallAfter(self.progress.SetValue, 100)
            if hasattr(self, 'timer') and self.timer.IsRunning():
                wx.CallAfter(self.timer.Stop)
    
    def ProcessResults(self):
        if not self.scanner.all_hosts():
            self.UpdateRawOutput("No hosts were found or responded to the scan.\n")
            return
            
        for host in self.scanner.all_hosts():
            self.UpdateRawOutput(f"Host: {host} ({self.scanner[host].hostname()})\n")
            self.UpdateRawOutput(f"State: {self.scanner[host].state()}\n\n")
            
            # Update host info tab
            host_info = f"Host: {host}\n"
            if self.scanner[host].hostname():
                host_info += f"Hostname: {self.scanner[host].hostname()}\n"
            host_info += f"State: {self.scanner[host].state()}\n"
            
            if 'osmatch' in self.scanner[host]:
                host_info += "\nOS Detection:\n"
                for osmatch in self.scanner[host]['osmatch']:
                    host_info += f"OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)\n"
            
            self.UpdateHostInfo(host_info)
            
            for proto in self.scanner[host].all_protocols():
                self.UpdateRawOutput(f"Protocol: {proto}\n")
                
                ports = sorted(self.scanner[host][proto].keys())
                for port in ports:
                    port_info = self.scanner[host][proto][port]
                    service = port_info.get('name', 'unknown')
                    state = port_info.get('state', 'unknown')
                    
                    # Add to services grid
                    version = port_info.get('product', '') + ' ' + port_info.get('version', '')
                    version = version.strip()
                    extra_info = port_info.get('extrainfo', '')
                    
                    self.AddServiceToGrid(port, proto, state, service, version, extra_info)
                    
                    # Add to raw output
                    service_detail = f"Port: {port}/{proto} \tState: {state} \tService: {service}"
                    if version:
                        service_detail += f" \tVersion: {version}"
                    if extra_info:
                        service_detail += f" ({extra_info})"
                    self.UpdateRawOutput(service_detail + "\n")
                
                self.UpdateRawOutput("\n")
    
    def UpdateProgress(self, event):
        if self.scanning:
            # In a real application, you might query the scanner for progress
            # Here we'll just increment the progress bar until it reaches 90%
            current = self.progress.GetValue()
            if current < 90:
                self.progress.SetValue(current + 1)
        else:
            self.timer.Stop()
    
    def OnStopScan(self, event):
        if self.scanning:
            self.scanning = False
            self.statusbar.SetStatusText("Scan stopped by user")
            self.scan_button.Enable()
            self.stop_button.Disable()
            self.UpdateRawOutput("Scan stopped by user\n")
            if hasattr(self, 'timer') and self.timer.IsRunning():
                self.timer.Stop()
    
    def OnClearResults(self, event):
        self.ClearResults()
    
    def ClearResults(self):
        self.raw_output.SetValue("")
        self.host_info.SetValue("")
        
        # Clear services grid
        if self.services_grid.GetNumberRows() > 0:
            self.services_grid.DeleteRows(0, self.services_grid.GetNumberRows())
    
    def UpdateRawOutput(self, text):
        current_text = self.raw_output.GetValue()
        self.raw_output.SetValue(current_text + text)
    
    def UpdateHostInfo(self, text):
        self.host_info.SetValue(text)
    
    def AddServiceToGrid(self, port, protocol, state, service, version, extra_info):
        # Add a new row
        row = self.services_grid.GetNumberRows()
        self.services_grid.AppendRows(1)
        
        # Populate the cells
        self.services_grid.SetCellValue(row, 0, str(port))
        self.services_grid.SetCellValue(row, 1, protocol)
        self.services_grid.SetCellValue(row, 2, state)
        self.services_grid.SetCellValue(row, 3, service)
        self.services_grid.SetCellValue(row, 4, version)
        self.services_grid.SetCellValue(row, 5, extra_info)

class NmapScannerApp(wx.App):
    def OnInit(self):
        frame = NmapScannerFrame(None, "Professional NMAP Service Scanner")
        self.SetTopWindow(frame)
        
        # Initialize frame but don't show it yet
        frame.Centre()
        
        # Show authentication dialog
        root_dialog = RootAccessDialog(frame)
        if root_dialog.ShowModal() == wx.ID_OK:
            frame.is_root = True
            frame.root_button.Disable()
            frame.Show()
            frame.statusbar.SetStatusText("Root Access Granted")
            root_dialog.Destroy()
            return True
        else:
            root_dialog.Destroy()
            frame.Destroy()
            return False

def main():
    app = NmapScannerApp()
    app.MainLoop()

if __name__ == "__main__":
    main()