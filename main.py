# 24.04.2025
# Застосунок збору та аналізу статистичних показників мережевого трафіку

# Імпорт необхідних модулей.
import os
import threading
import tkinter as tk
from threading import Thread, Event
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
from tkinter import ttk, Menu, messagebox, Checkbutton, BooleanVar, OptionMenu, StringVar, scrolledtext, filedialog, Toplevel

# Створення головного класу застосунку.
class Application:
    def __init__(self, root):
        self.root = root
        # Налаштування вікна та зовнішнього вигляду застосунку.
        self.root.title("colandant")
        self.root.minsize(1280, 720)
        # Відмальовування елементу відображення результатів роботи застосунку.
        self.create_widgets()
        # Створюємо флаг для контролю процесу захоплення пакетів.
        self.sniffing = False
        self.packet_logs = []
        # Створюємо лічильники для протоколів
        self.packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Total": 0}

    def create_widgets(self):
        # Створення меню.
        self.menubar = Menu(self.root)
        self.root.config(menu=self.menubar)
        # Створення вкладки меню.
        file_menu = Menu(self.menubar, tearoff = 0)
        file_menu.add_command(label="Відкрити")
        file_menu.add_command(label="Зберегти")
        file_menu.add_separator()
        file_menu.add_command(label="Вихід", command=self.on_exit)
        # Сгруповування елементів меню до розділу з назвою Файл.
        self.menubar.add_cascade(label="File", menu=file_menu)
        # Створення вкладки меню для захоплення.
        capture_menu = Menu(self.menubar, tearoff = 0)
        capture_menu.add_command(label="Розпочати", command=self.start_sniffing)
        capture_menu.add_command(label="Зупинитись", command=self.stop_sniffing)
        # Сгруповування елементів меню до розділу з назвою Захоплення.
        self.menubar.add_cascade(label="Захоплення", menu=capture_menu)
        # Сгруповування елементів меню до розділу з назвою Інше.
        self.menubar.add_cascade(label="Інше")
        # Призначаємо створене меню до головного вікна.
        self.root.config(menu=self.menubar)

        # Створення 
        toolbar_frame = tk.Frame(self.root)
        toolbar_frame.grid(row=0, column=0)

        # Створення та розміщення лічильників захоплення пакетів за протоколами
        self.stats_frame = tk.Frame(self.root)
        self.stats_frame.grid(row=0, column=0, columnspan=5)
        self.tcp_count_label = tk.Label(self.stats_frame, text="TCP: 0")
        self.tcp_count_label.grid(row=0, column=2, sticky=tk.W)
        self.udp_count_label = tk.Label(self.stats_frame, text="UDP: 0")
        self.udp_count_label.grid(row=0, column=3, sticky=tk.W)
        self.icmp_count_label = tk.Label(self.stats_frame, text="ICMP: 0")
        self.icmp_count_label.grid(row=0, column=4, sticky=tk.W)
        self.total_count_label = tk.Label(self.stats_frame, text="Всього: 0")
        self.total_count_label.grid(row=0, column=5, sticky=tk.W)

        # Створення та розміщення вибору інтерфейсу для захоплення трафіку
        tk.Label(toolbar_frame, text="Інтерфейси:").grid(row=1, column=0, sticky=tk.W)
        self.interface_var = StringVar()
        self.interface_menu = ttk.Combobox(toolbar_frame, textvariable=self.interface_var)
        self.interface_menu['values'] = get_if_list()
        self.interface_menu.grid(row=1, column=1, sticky=tk.W)
        self.interface_menu.current(0)

        # Створення та розміщення вибору протоколу для захоплення трафіку
        tk.Label(toolbar_frame, text="Protocol:").grid(row=0, column=0, sticky=tk.W)
        self.protocol_var = StringVar(value="ALL")
        self.protocol_menu = ttk.Combobox(toolbar_frame, textvariable=self.protocol_var)
        self.protocol_menu['values'] = ["ALL", "TCP", "UDP", "ICMP"]
        self.protocol_menu.grid(row=0, column=1, sticky=tk.W)
        self.protocol_menu.current(0)

        tk.Label(toolbar_frame, text="Filter:").grid(row=2, column=0, sticky=tk.W)
        self.filter_entry = ttk.Entry(toolbar_frame, width=50)
        self.filter_entry.grid(row=2, column=1, sticky=tk.W)

        # Створення таблиці для виводу інформації про пакети, їх призначення, протоколи 
        self.packet_table = ttk.Treeview(self.root, columns=("No", "Source", "Destination", "Protocol", "Info"), show="headings")
        self.packet_table.grid(row=2, column=0, columnspan=3, sticky=tk.W)
        self.packet_table.heading("No", text="№")
        self.packet_table.heading("Source", text="Джерело")
        self.packet_table.heading("Destination", text="Призначення")
        self.packet_table.heading("Protocol", text="Протокол")
        self.packet_table.heading("Info", text="Інформація")
        self.packet_table.bind("<Double-1>", self.on_packet_select)

        # Створення вікна для відображення отриманих пакетів
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=120, height=15)
        self.text_area.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            log_entry = f"IP {ip_src} -> {ip_dst} [{proto}]"

            protocol = "Total"
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                protocol = "TCP"
                self.packet_count["TCP"] += 1
                self.packet_count["Total"] += 1
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                protocol = "UDP"
                self.packet_count["UDP"] += 1
                self.packet_count["Total"] += 1
            elif ICMP in packet:
                protocol = "ICMP"
                self.packet_count["ICMP"] += 1
                self.packet_count["Total"] += 1
            else:
                self.packet_count["Total"] += 1

            # Вивід до вікна відображення
            self.text_area.insert(tk.END, log_entry + "\n")
            self.text_area.yview(tk.END)

            # Вставлення до таблиці з виводом інформації
            self.packet_table.insert("", "end", values=(len(self.packet_logs), ip_src, ip_dst, protocol, log_entry))

            # Оновлення інформації лічильників
            self.update_stats()

    # Реалізація функції початку захоплення пакетів
    def start_sniffing(self):
        self.sniffing = True
        self.text_area.insert(tk.END, "Розпочато захоплення пакетів.\n")
        self.packet_logs.clear()

        filter_exp = self.filter_entry.get()
        interface = self.interface_var.get()
        protocol = self.protocol_var.get()

        if protocol != "ALL":
            filter_exp += f" {protocol.lower()}"

        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(filter_exp, interface))
        self.sniffer_thread.start()

    # Реалізація функції зупинки захоплення пакетів
    def stop_sniffing(self):
        self.sniffing = False
        self.text_area.insert(tk.END, "Завершено захоплення пакетів.\n")

    # Реалізація функція захоплення пакетів
    def sniff_packets(self, filter_exp, interface):
        try:
            sniff(prn=self.packet_callback, filter=filter_exp, iface=interface, store=0, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            self.stop_sniffing()

    # Реалізація функції відображення оновленної інформації лічильніків
    def update_stats(self):
        self.tcp_count_label.config(text=f"TCP: {self.packet_count['TCP']}")
        self.udp_count_label.config(text=f"UDP: {self.packet_count['UDP']}")
        self.icmp_count_label.config(text=f"ICMP: {self.packet_count['ICMP']}")
        self.total_count_label.config(text=f"Всього: {self.packet_count['Total']}")


    def on_packet_select(self, event):
        selected_item = self.packet_table.selection()[0]
        packet_info = self.packet_table.item(selected_item, "values")
        self.text_area.insert(tk.END, f"Selected Packet: {packet_info}\n")
        self.text_area.yview(tk.END)

    # Реалізація функції виходу з програми
    def on_exit(self):
        if messagebox.askyesno():
            self.root.quit()
            self.root.destroy()
            
if __name__ == "__main__":
    root = tk.Tk()
    app = Application(root)
    # Включення циклу оновлення програми   
    root.mainloop()

   
