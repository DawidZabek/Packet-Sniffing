import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, get_if_list, get_working_ifaces
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.running = False
        self.packet_count = 0
        self.packets = []
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0,
                        "TLS": 0, "HTTP": 0, "DNS": 0}
        self.chart_updating = False

        filter_frame = tk.Frame(root)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(filter_frame, text="Protocol:").pack(side=tk.LEFT)
        self.protocol_var = tk.StringVar(value="ALL")
        self.protocol_menu = ttk.Combobox(
        filter_frame,
        textvariable=self.protocol_var,
        values=["ALL", "TCP", "UDP", "ICMP", "TLS", "HTTP", "DNS"],
        width=8
        )
        self.protocol_menu.pack(side=tk.LEFT, padx=5)

        tk.Label(filter_frame, text="Filter IP:").pack(side=tk.LEFT)
        self.ip_filter_entry = tk.Entry(filter_frame, width=20)
        self.ip_filter_entry.pack(side=tk.LEFT, padx=5)

        tk.Label(filter_frame, text="Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_map = {"All Interfaces": None}
        display_names = []
        for iface in get_working_ifaces():
            name = iface.name
            desc = iface.description
            label = desc if desc else name
            self.interface_map[label] = name
            display_names.append(label)
        self.iface_var = tk.StringVar(value="All Interfaces")
        self.iface_menu = ttk.Combobox(
            filter_frame,
            textvariable=self.iface_var,
            values=["All Interfaces"] + display_names,
            width=25,
            state="readonly"
        )
        self.iface_menu.pack(side=tk.LEFT, padx=5)

        button_frame = tk.Frame(root)
        button_frame.pack()

        self.start_button = tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(button_frame, text="Stop", command=self.stop_sniffing)
        self.stop_button.pack(side=tk.LEFT)

        self.chart_button = tk.Button(button_frame, text="Show Chart", command=self.open_chart_window)
        self.chart_button.pack(side=tk.LEFT, padx=10)

        self.tree = ttk.Treeview(root, columns=("Source", "Destination", "Protocol", "Port"))
        self.tree.heading("#0", text="ID")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Port", text="Port")
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.show_packet_details)

        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def packet_callback(self, packet):
        if not packet.haslayer("IP"):
            return

        ip_layer = packet["IP"]
        proto_label = "Other"
        port = ""
        is_tls = is_http = is_dns = False

        if packet.haslayer("TCP"):
            sport = packet["TCP"].sport
            dport = packet["TCP"].dport

            proto_label = "TCP"

            if 443 in (sport, dport):
                is_tls = True
            elif 80 in (sport, dport) or 8080 in (sport, dport):
                is_http = True

        elif packet.haslayer("UDP"):
            sport = packet["UDP"].sport
            dport = packet["UDP"].dport
            proto_label = "UDP"

            if 53 in (sport, dport):
                is_dns = True

        elif packet.haslayer("ICMP"):
            proto_label = "ICMP"

        # Protocol filter logic
        selected_filter = self.protocol_var.get()
        if selected_filter != "ALL":
            if selected_filter == "TCP" and proto_label != "TCP":
                return
            elif selected_filter == "UDP" and proto_label != "UDP":
                return
            elif selected_filter == "ICMP" and proto_label != "ICMP":
                return
            elif selected_filter == "TLS" and not is_tls:
                return
            elif selected_filter == "HTTP" and not is_http:
                return
            elif selected_filter == "DNS" and not is_dns:
                return

        # IP filter
        ip_filter = self.ip_filter_entry.get()
        if ip_filter and ip_filter not in (ip_layer.src, ip_layer.dst):
            return

        self.protocol_counts[proto_label] = self.protocol_counts.get(proto_label, 0) + 1
        self.packet_count += 1
        self.packets.append(packet)
        self.tree.insert("", "end", text=str(self.packet_count),
                        values=(ip_layer.src, ip_layer.dst, proto_label, f"{sport}->{dport}" if 'sport' in locals() and 'dport' in locals() else ""))




    def get_bpf_filter(self):
        proto = self.protocol_var.get()
        if proto in ["TCP", "TLS", "HTTP"]:
            return "tcp"
        elif proto in ["UDP", "DNS"]:
            return "udp"
        elif proto == "ICMP":
            return "icmp"
        return ""


    def sniff_packets(self):
        selected_label = self.iface_var.get()
        iface_real = self.interface_map.get(selected_label)

        sniff_kwargs = {
            "filter": self.get_bpf_filter(),
            "prn": self.packet_callback,
            "stop_filter": lambda x: not self.running
        }

        if iface_real:
            sniff_kwargs["iface"] = iface_real
        sniff(**sniff_kwargs)

    def start_sniffing(self):
        self.running = True
        self.packet_count = 0
        for item in self.tree.get_children():
            self.tree.delete(item)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.running = False

    def show_packet_details(self, event):
        selected_item = self.tree.focus()
        if not selected_item:
            return

        index = int(self.tree.item(selected_item, "text")) - 1
        if index < 0 or index >= len(self.packets):
            return

        packet = self.packets[index]

        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Packet #{index + 1} Details")
        detail_window.geometry("600x400")

        text_widget = tk.Text(detail_window, wrap=tk.NONE)
        text_widget.insert(tk.END, packet.show(dump=True))
        text_widget.pack(fill=tk.BOTH, expand=True)

        y_scroll = tk.Scrollbar(detail_window, command=text_widget.yview)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.config(yscrollcommand=y_scroll.set)

    def setup_chart(self):
        self.fig, self.ax = plt.subplots(figsize=(3, 3))
        self.pie_canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.pie_canvas.get_tk_widget().pack(side=tk.RIGHT, fill=tk.BOTH, expand=False)

    def update_chart_loop(self):
        if not getattr(self, 'chart_updating', False):
            return

        if not hasattr(self, 'chart_window') or not self.chart_window.winfo_exists():
            self.chart_updating = False
            return

        self.ax.clear()
        labels = list(self.protocol_counts.keys())
        sizes = list(self.protocol_counts.values())
        if sum(sizes) == 0:
            sizes = [1]
            labels = ["Waiting..."]
        chart_type = self.chart_type.get()
        if chart_type == "Pie":
            self.ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
            self.ax.axis("equal")
        else:
            self.ax.bar(labels, sizes)
            self.ax.set_ylabel("Packet Count")
            self.ax.set_title("Protocol Distribution")
        self.pie_canvas.draw()
        if self.chart_updating:
            self.chart_window.after(2000, self.update_chart_loop)
            
    def open_chart_window(self):
        if getattr(self, 'chart_window', None) and self.chart_window.winfo_exists():
            self.chart_window.lift()
            return

        self.chart_updating = True

        self.chart_window = tk.Toplevel(self.root)
        self.chart_window.title("Live Protocol Chart")
        self.chart_window.geometry("500x500")
        option_frame = tk.Frame(self.chart_window)
        option_frame.pack(pady=5)

        tk.Label(option_frame, text="Chart Type:").pack(side=tk.LEFT, padx=5)

        self.chart_type = tk.StringVar(value="Pie")
        chart_selector = ttk.Combobox(
            option_frame,
            textvariable=self.chart_type,
            values=["Pie", "Bar"],
            state="readonly",
            width=10
        )
        chart_selector.pack(side=tk.LEFT)
        chart_selector.bind("<<ComboboxSelected>>", lambda e: self.update_chart_loop())
        self.fig, self.ax = plt.subplots(figsize=(4, 4))
        self.pie_canvas = FigureCanvasTkAgg(self.fig, master=self.chart_window)
        self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.chart_window.protocol("WM_DELETE_WINDOW", self.on_close_chart_window)
        self.update_chart_loop()


    def on_close_chart_window(self):
        self.chart_updating = False
        if hasattr(self, 'chart_window'):
            try:
                self.chart_window.destroy()
            except:
                pass
            self.chart_window = None


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()
