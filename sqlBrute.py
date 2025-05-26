import argparse
import requests
import time
import threading
from jinja2 import Template
import html
from urllib.parse import urlparse, quote
import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from webbrowser import open as open_browser
from rich.console import Console
from rich.table import Table
from rich.live import Live
import operator
from datetime import datetime
from queue import Queue
import sys
import base64

# Global variables
gui_root = None
gui_tree = None
gui_details_text = None
gui_results = []
gui_wordlist = []
gui_sort_column = ""
gui_sort_reverse = False
gui_update_lock = threading.Lock()

console_table = None
console_live = None
title_by = '''
   \033[31mSSSSSSSSSSSSSSS      QQQQQQQQQ     LLLLLLLLLLL             \033[0mBBBBBBBBBBBBBBBBB                                               tttt                              
 \033[31mSS:::::::::::::::S   QQ:::::::::QQ   L:::::::::L             \033[0mB::::::::::::::::B                                           ttt:::t                              
\033[31mS:::::SSSSSS::::::S QQ:::::::::::::QQ L:::::::::L             \033[0mB::::::BBBBBB:::::B                                          t:::::t                              
\033[31mS:::::S     SSSSSSSQ:::::::QQQ:::::::QLL:::::::LL             \033[0mBB:::::B     B:::::B                                         t:::::t                              
\033[31mS:::::S            Q::::::O   Q::::::Q  L:::::L                 \033[0mB::::B     B:::::Brrrrr   rrrrrrrrr   uuuuuu    uuuuuuttttttt:::::ttttttt        eeeeeeeeeeee    
\033[31mS:::::S            Q:::::O     Q:::::Q  L:::::L                 \033[0mB::::B     B:::::Br::::rrr:::::::::r  u::::u    u::::ut:::::::::::::::::t      ee::::::::::::ee  
\033[31m S::::SSSS         Q:::::O     Q:::::Q  L:::::L                 \033[0mB::::BBBBBB:::::B r:::::::::::::::::r u::::u    u::::ut:::::::::::::::::t     e::::::eeeee:::::ee
\033[31m  SS::::::SSSSS    Q:::::O     Q:::::Q  L:::::L                 \033[0mB:::::::::::::BB  rr::::::rrrrr::::::ru::::u    u::::utttttt:::::::tttttt    e::::::e     e:::::e
\033[31m    SSS::::::::SS  Q:::::O     Q:::::Q  L:::::L                 \033[0mB::::BBBBBB:::::B  r:::::r     r:::::ru::::u    u::::u     t:::::t          e:::::::eeeee::::::e
\033[31m       SSSSSS::::S Q:::::O     Q:::::Q  L:::::L                 \033[0mB::::B     B:::::B r:::::r     rrrrrrru::::u    u::::u     t:::::t          e:::::::::::::::::e 
\033[31m            S:::::SQ:::::O  QQQQ:::::Q  L:::::L                 \033[0mB::::B     B:::::B r:::::r            u::::u    u::::u     t:::::t          e::::::eeeeeeeeeee  
\033[31m            S:::::SQ::::::O Q::::::::Q  L:::::L         LLLLLL  \033[0mB::::B     B:::::B r:::::r            u:::::uuuu:::::u     t:::::t    tttttte:::::::e           
\033[31mSSSSSSS     S:::::SQ:::::::QQ::::::::QLL:::::::LLLLLLLLL:::::L\033[0mBB:::::BBBBBB::::::B r:::::r            u:::::::::::::::uu   t::::::tttt:::::te::::::::e          
\033[31mS::::::SSSSSS:::::S QQ::::::::::::::Q L::::::::::::::::::::::L\033[0mB:::::::::::::::::B  r:::::r             u:::::::::::::::u   tt::::::::::::::t e::::::::eeeeeeee  
\033[31mS:::::::::::::::SS    QQ:::::::::::Q  L::::::::::::::::::::::L\033[0mB::::::::::::::::B   r:::::r              uu::::::::uu:::u     tt:::::::::::tt  ee:::::::::::::e  
\033[31m SSSSSSSSSSSSSSS        QQQQQQQQ::::QQLLLLLLLLLLLLLLLLLLLLLLLL\033[0mBBBBBBBBBBBBBBBBB    rrrrrrr                uuuuuuuu  uuuu       ttttttttttt      eeeeeeeeeeeeee  
\033[31m                                Q:::::Q                                                                                                                           
\033[31m                                 QQQQQQ                                                                                                                                                                                                    '''

author_by = '''\033[92m                                         _                          _                             _                                              (_)      
                                        | |__  _   _         __ _  | |__  _   _ _ __  _   _  __ _| |_ _____   __     _ __ _ __  _   _ _ ____   ___ _ __  
                                        | '_ \| | | |       / _` | | '_ \| | | | '_ \| | | |/ _` | __/ _ \ \ / /    | '__| '_ \| | | | '__\ \ / / | '_ \ 
                                        | |_) | |_| |      | (_| |_| |_) | |_| | | | | |_| | (_| | || (_) \ V /     | |  | | | | |_| | |   \ V /| | | | |
                                        |_.__/ \__, |       \__,_(_)_.__/ \__,_|_| |_|\__, |\__,_|\__\___/ \_/      |_|  |_| |_|\__,_|_|    \_/ |_|_| |_|
                                               |___/                           |___/                                            \033[0m'''

DESCRIPTION = """
SQL Fuzzing Aləti - Brute Force Test Aləti

Bu alət veb tətbiqlərdə SQL injeksiya zəifliklərini aşkar etmək üçün istifadə olunur.
Aşağıdakı xüsusiyyətləri dəstəkləyir:
- GET və POST sorğuları ilə işləyə bilmə
- Çoxsaylı threadlərlə sürətli fuzzinq
- Konsol, GUI və HTML hesabat modları
- Dinamik çeşidləmə və filtrləmə

Nümunə istifadə:
1. GET sorğusu: 
   python3 sqlfuzz.py --url "https://example.com/search?q=NAN" --fuzzfile fuzz.txt --threads 10

2. POST sorğusu:
   python3 sqlfuzz.py --request request.txt --fuzzfile fuzz.txt --gui

3. Çoxmodlu iş:
   python3 sqlfuzz.py --request request.txt --fuzzfile fuzz.txt --console "status desc" --report hesabat.html
"""


def truncate_payload(payload, max_length=50):
    if len(payload) > max_length:
        return payload[:max_length] + "..."
    return payload


def detect_scheme(host):
    try:
        requests.get(f"https://{host}", timeout=10, verify=False)
        return "https"
    except:
        try:
            requests.get(f"http://{host}", timeout=10)
            return "http"
        except:
            return "https"


def parse_request_file(file_path):
    """Parse request file with support for all HTTP methods and headers"""
    with open(file_path, 'r') as f:
        lines = f.read().splitlines()

    if not lines:
        raise ValueError("Empty request file")

    first_line = lines[0].strip().split()
    if len(first_line) < 2:
        raise ValueError("Invalid request format")

    method = first_line[0].upper()
    supported_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
    if method not in supported_methods:
        raise ValueError(f"Unsupported method. Supported methods: {', '.join(supported_methods)}")

    path = first_line[1]
    headers = {}
    body_lines = []
    in_body = False

    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
            elif ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        else:
            body_lines.append(line)

    body = "\n".join(body_lines).strip()

    host = headers.get('Host', '')
    if not host.startswith(('http://', 'https://')):
        scheme = detect_scheme(host)
        host = f"{scheme}://{host}"

    url = f"{host}{path}"

    return method, url, headers, body


def encode_payload(payload, encoding_type):
    """Encode payload based on specified encoding type"""
    if encoding_type == "url":
        return quote(payload)
    elif encoding_type == "b64":
        return base64.b64encode(payload.encode()).decode()
    else:
        return payload  # No encoding


def send_request(method, url, data, payload, headers, result_list, request_count, encoding=None):
    """Send HTTP request with optional payload encoding"""
    # Create a copy of headers to modify
    request_headers = headers.copy()

    # Encode payload if specified
    encoded_payload = encode_payload(payload, encoding)

    # Replace NAN in all headers with encoded payload
    for key, value in request_headers.items():
        if "NAN" in value:
            request_headers[key] = value.replace("NAN", encoded_payload)

    # Handle URL and body data replacement
    replaced_url = url.replace("NAN", encode_payload(payload, "url" if encoding != "b64" else None))
    replaced_data = data.replace("NAN", encoded_payload) if data else None

    try:
        start_time = time.time()

        # Handle different HTTP methods
        if method == "GET":
            r = requests.get(replaced_url, headers=request_headers, timeout=60, verify=False)
        elif method == "POST":
            r = requests.post(replaced_url, data=replaced_data, headers=request_headers, timeout=60, verify=False)
        elif method == "PUT":
            r = requests.put(replaced_url, data=replaced_data, headers=request_headers, timeout=60, verify=False)
        elif method == "PATCH":
            r = requests.patch(replaced_url, data=replaced_data, headers=request_headers, timeout=60, verify=False)
        elif method == "DELETE":
            r = requests.delete(replaced_url, headers=request_headers, timeout=60, verify=False)
        elif method == "HEAD":
            r = requests.head(replaced_url, headers=request_headers, timeout=60, verify=False)
        elif method == "OPTIONS":
            r = requests.options(replaced_url, headers=request_headers, timeout=60, verify=False)
        else:
            raise ValueError(f"Unsupported method: {method}")

        response_time = time.time() - start_time

        result = {
            'request_number': request_count,
            'payload': payload,
            'encoded_payload': encoded_payload,
            'status_code': r.status_code,
            'response_length': len(r.text) if method != "HEAD" else 0,
            'response_time': response_time,
            'request': f"{r.request.method} {r.request.url} HTTP/1.1\n" + "\n".join(
                [f"{k}: {v}" for k, v in r.request.headers.items()]) + (
                           f"\n\n{r.request.body}" if r.request.body else ""),
            'response': f"HTTP/1.1 {r.status_code} {r.reason}\n" + "\n".join(
                [f"{k}: {v}" for k, v in r.headers.items()]) + f"\n\n{r.text if method != 'HEAD' else ''}"
        }

        with gui_update_lock:
            result_list.append(result)
        return True

    except Exception as e:
        result = {
            'request_number': request_count,
            'payload': payload,
            'encoded_payload': encoded_payload,
            'status_code': "ERROR",
            'response_length': str(e),
            'response_time': 0,
            'request': None,
            'response': str(e)
        }

        with gui_update_lock:
            result_list.append(result)
        return True


def init_gui():
    global gui_root, gui_tree, gui_details_text, progress_bar, sent_label, received_label

    gui_root = tk.Tk()
    gui_root.title("SQL Fuzzing Aləti - GUI Modu")
    gui_root.geometry("1200x800")

    main_frame = ttk.Frame(gui_root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Status bar frame at bottom
    status_frame = ttk.Frame(main_frame)
    status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=5)

    # Progress bar
    progress_bar = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL, mode='determinate')
    progress_bar.pack(fill=tk.X, expand=True, side=tk.LEFT, padx=5)

    # Sent requests counter
    sent_label = ttk.Label(status_frame, text="Göndərilən: 0")
    sent_label.pack(side=tk.LEFT, padx=5)

    # Received responses counter
    received_label = ttk.Label(status_frame, text="Alınan: 0")
    received_label.pack(side=tk.LEFT, padx=5)

    table_frame = ttk.Frame(main_frame)
    table_frame.pack(fill=tk.BOTH, expand=True)

    details_frame = ttk.Frame(main_frame)
    details_frame.pack(fill=tk.BOTH, expand=True)

    gui_tree = ttk.Treeview(table_frame, columns=('Request', 'Payload', 'Status', 'Length', 'Time'), show='headings')

    for col in ('Request', 'Payload', 'Status', 'Length', 'Time'):
        gui_tree.heading(col, text=col, command=lambda c=col: sort_gui_tree(c))

    gui_tree.column('Request', width=80, anchor=tk.CENTER)
    gui_tree.column('Payload', width=200, anchor=tk.CENTER)
    gui_tree.column('Status', width=80, anchor=tk.CENTER)
    gui_tree.column('Length', width=80, anchor=tk.CENTER)
    gui_tree.column('Time', width=80, anchor=tk.CENTER)

    scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=gui_tree.yview)
    gui_tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    gui_tree.pack(fill=tk.BOTH, expand=True)

    details_label = ttk.Label(details_frame, text="Sorğu/Cavab Detalları:")
    details_label.pack(anchor=tk.W)

    gui_details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD)
    gui_details_text.pack(fill=tk.BOTH, expand=True)

    gui_tree.bind('<<TreeviewSelect>>', show_details)

    # Initialize counters
    update_counters()

    # Auto-update GUI
    auto_update_gui()


def update_counters():
    """Update the sent/received counters and progress bar"""
    global gui_results, gui_wordlist, sent_label, received_label, progress_bar

    if gui_root:
        total = len(gui_wordlist)
        received = len([r for r in gui_results if r['status_code'] != "PENDING"])
        sent = len([r for r in gui_results if r.get('sent', False)])

        # Update counters
        sent_label.config(text=f"Göndərilən: {sent}/{total}")
        received_label.config(text=f"Alınan: {received}/{total}")

        # Update progress bar
        if total > 0:
            progress_bar['value'] = (received / total) * 100

        # Schedule next update
        gui_root.after(500, update_counters)


def auto_update_gui():
    global gui_root, gui_results, gui_tree, gui_sort_column, gui_sort_reverse

    if gui_root:
        with gui_update_lock:
            current_items = gui_tree.get_children()
            current_item_count = len(current_items)
            results_count = len(gui_results)

            # Only update if the number of results has changed
            if current_item_count != results_count:
                # Remember selected item to restore after update
                selected = gui_tree.selection()

                # Apply the current sort to all results
                apply_sort()

                # Restore selection if possible
                if selected:
                    try:
                        gui_tree.selection_set(selected)
                    except:
                        pass

        gui_root.after(500, auto_update_gui)
def sort_gui_tree(col):
    """Sort tree with persistent sorting that maintains when new data arrives"""
    global gui_tree, gui_results, gui_sort_column, gui_sort_reverse

    if col == gui_sort_column:
        gui_sort_reverse = not gui_sort_reverse
    else:
        gui_sort_column = col
        gui_sort_reverse = False

    # Apply the sort to existing data
    apply_sort()

def update_gui_result(result, add_to_tree=False):
    global gui_tree, gui_results

    def _update():
        status = result['status_code']
        status_color = ""

        if status == "ERROR":
            status_color = "red"
        elif isinstance(status, int):
            if 200 <= status < 300:
                status_color = "green"
            elif 300 <= status < 400:
                status_color = "orange"
            elif 400 <= status < 500:
                status_color = "red"
            elif status >= 500:
                status_color = "purple"

        item = gui_tree.insert("", tk.END, values=(
            result['request_number'],
            truncate_payload(result['payload']),
            status,
            result['response_length'],
            f"{result['response_time']:.4f}"
        ))

        if status_color:
            gui_tree.tag_configure(status_color, foreground=status_color)
            gui_tree.item(item, tags=(status_color,))

    if gui_root:
        gui_root.after(0, _update)


def apply_sort():
    """Apply current sort to the treeview while maintaining existing items"""
    global gui_tree, gui_results, gui_sort_column, gui_sort_reverse

    if not gui_sort_column:  # No sort applied yet
        return

    key_map = {
        'Request': 'request_number',
        'Payload': 'payload',
        'Status': 'status_code',
        'Length': 'response_length',
        'Time': 'response_time'
    }

    key = key_map.get(gui_sort_column, 'request_number')

    # Get all results
    all_results = gui_results.copy()

    try:
        if key == 'status_code':
            sorted_results = sorted(
                all_results,
                key=lambda x: (0 if x[key] == "ERROR" else x[key]),
                reverse=gui_sort_reverse
            )
        else:
            sorted_results = sorted(
                all_results,
                key=lambda x: (int(x[key]) if isinstance(x.get(key), str) and x.get(key).isdigit() else x.get(key, 0)),
                reverse=gui_sort_reverse
            )
    except:
        sorted_results = all_results

    # Clear and repopulate treeview while maintaining selection
    selected = gui_tree.selection()
    gui_tree.delete(*gui_tree.get_children())

    for result in sorted_results:
        status = result['status_code']

        # Default text color
        tags = ()

        # Set tag only if status column needs color
        if status == "ERROR":
            status_color = "red"
            tag_name = "status_red"
        elif isinstance(status, int):
            if 200 <= status < 300:
                status_color = "green"
                tag_name = "status_green"
            elif 300 <= status < 400:
                status_color = "orange"
                tag_name = "status_orange"
            elif 400 <= status < 500:
                status_color = "red"
                tag_name = "status_red"
            elif status >= 500:
                status_color = "purple"
                tag_name = "status_purple"
            else:
                status_color = "black"
                tag_name = "status_black"
        else:
            status_color = "black"
            tag_name = "status_black"

        # Create tag for status color (only once per color)
        if not gui_tree.tag_has(tag_name):
            gui_tree.tag_configure(tag_name, foreground=status_color)

        tags = (tag_name,)  # only tag affecting status

        # Insert item with the tag (yes, it colors whole row, but we'll fix it below)
        item = gui_tree.insert("", tk.END, values=(
            result['request_number'],  # black
            truncate_payload(result['payload']),  # black
            status,  # colored
            result['response_length'],  # black
            f"{result['response_time']:.4f}"  # we’ll override to blue
        ), tags=tags)

        # Set time column manually to blue (overriding color)
        gui_tree.tag_configure("time_column", foreground="blue")
        gui_tree.set(item, "Time", f"{result['response_time']:.4f}")


    # Update column header to show sort direction
    for column in gui_tree['columns']:
        gui_tree.heading(column, text=column)

    sort_symbol = " ↓" if gui_sort_reverse else " ↑"
    gui_tree.heading(gui_sort_column, text=gui_sort_column + sort_symbol)


def show_details(event):
    global gui_tree, gui_details_text, gui_results

    selected_item = gui_tree.selection()
    if not selected_item:
        return

    item = gui_tree.item(selected_item)
    request_num = item['values'][0]

    result = next((r for r in gui_results if r['request_number'] == request_num), None)
    if not result:
        return

    details = f"=== SORĞU ===\n{result.get('request', 'N/A')}\n\n"
    details += f"=== CAVAB ===\n{result.get('response', 'N/A')}"

    gui_details_text.delete(1.0, tk.END)
    gui_details_text.insert(tk.END, details)


def generate_console_table(results, sort_key=None, sort_reverse=False):
    table = Table(show_header=True, header_style="bold magenta", width=min(120, os.get_terminal_size().columns))
    table.add_column("Request #", style="cyan", justify="right", width=10)
    table.add_column("Payload", style="green", width=30)
    table.add_column("Status", style="bold red", justify="center", width=10)
    table.add_column("Length", style="blue", justify="right", width=10)
    table.add_column("Time (ms)", style="yellow", justify="right", width=12)

    # Sort results by request number first to maintain sequence
    sorted_results = sorted(results, key=lambda x: x['request_number'])

    if sort_key:
        key_map = {
            'request': 'request_number',
            'payload': 'payload',
            'status': 'status_code',
            'length': 'response_length',
            'time': 'response_time'
        }

        key = key_map.get(sort_key.lower(), 'request_number')

        try:
            if key == 'status_code':
                sorted_results = sorted(
                    sorted_results,
                    key=lambda x: (0 if x[key] == "ERROR" else x[key]),
                    reverse=sort_reverse
                )
            else:
                sorted_results = sorted(
                    sorted_results,
                    key=lambda x: (
                        int(x[key]) if isinstance(x.get(key), str) and x.get(key).isdigit() else x.get(key, 0)),
                    reverse=sort_reverse
                )
        except:
            pass

    for result in sorted_results:
        status = result['status_code']
        status_style = "green" if str(status).startswith('2') else "red"
        if str(status).startswith('3'):
            status_style = "yellow"
        if status == "ERROR":
            status_style = "bold red"

        table.add_row(
            str(result['request_number']),
            truncate_payload(result['payload']),
            f"[{status_style}]{status}[/]",
            str(result['response_length']),
            f"{result['response_time']:.4f}"
        )

    return table


def worker(request_queue, method, url, data, headers, result_list, encoding=None):
    while not request_queue.empty():
        try:
            request_num, payload = request_queue.get_nowait()
            send_request(method, url, data, payload, headers, result_list, request_num, encoding)
            request_queue.task_done()
        except:
            break

def generate_report_filename(report_arg):
    if not report_arg:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"report_{timestamp}.html"
    if not report_arg.lower().endswith('.html'):
        return f"{report_arg}.html"
    return report_arg


def fuzz(method, url, data, wordlist, threads, user_headers, post_file_headers,
         report_name=None, console_mode=False, gui_mode=False,
         sort_key=None, sort_reverse=False, encoding=None):  # Added encoding parameter
    global gui_results, gui_wordlist, console_table, console_live

    headers = {
        'User-Agent': 'SQLFuzz/1.0',
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }

    if post_file_headers:
        headers.update(post_file_headers)

    if user_headers:
        try:
            for h in user_headers.split('|'):
                key, value = h.strip().split(':', 1)
                headers[key.strip()] = value.strip()
        except ValueError:
            print("⚠️  Xəta: Header formatı yalnışdır! Format: 'Açar: Dəyər|Açar2: Dəyər2'")
            return

    if gui_mode:
        init_gui()
        gui_wordlist = wordlist.copy()

    results = []
    request_queue = Queue()

    for i, payload in enumerate(wordlist, 1):
        request_queue.put((i, payload))

    if console_mode:
        console = Console()
        with Live(console=console, refresh_per_second=4) as live:
            console_live = live
            worker_threads = []

            for _ in range(threads):
                t = threading.Thread(target=worker, args=(request_queue, method, url, data, headers, results, encoding))  # Added encoding
                worker_threads.append(t)
                t.start()

            while any(t.is_alive() for t in worker_threads):
                console_table = generate_console_table(results, sort_key, sort_reverse)
                live.update(console_table)
                time.sleep(0.1)

            console_table = generate_console_table(results, sort_key, sort_reverse)
            live.update(console_table)
    elif gui_mode:
        worker_threads = []

        for _ in range(threads):
            t = threading.Thread(target=worker, args=(request_queue, method, url, data, headers, gui_results, encoding))  # Added encoding
            worker_threads.append(t)
            t.start()

        gui_root.mainloop()
    else:
        worker_threads = []

        for _ in range(threads):
            t = threading.Thread(target=worker, args=(request_queue, method, url, data, headers, results, encoding))  # Added encoding
            worker_threads.append(t)
            t.start()

        for t in worker_threads:
            t.join()

    if report_name is not None:
        final_report_name = generate_report_filename(report_name)
        generate_html_report(results if not gui_mode else gui_results, final_report_name)
def generate_html_report(results, report_name):
    html_template = """
<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Fuzzing Results</title>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        <style>
            .table th, .table td {
                text-align: center;
                vertical-align: middle;
            }
            .modal-dialog {
                max-width: 90%;
            }
            .modal-content {
                padding: 20px;
                background-color: #ffffff;
            }
            .section-title {
                font-size: 1.2rem;
                font-weight: bold;
                margin-top: 20px;
                color: #343a40;
            }
            .code-block {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                padding: 15px;
                border-radius: 8px;
                font-family: monospace;
                white-space: pre-wrap;
                word-wrap: break-word;
                color: #212529;
            }
            .code-header {
                background-color: #e9ecef;
                padding: 8px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: bold;
                color: #495057;
            }
            .header-section {
                background-color: #e2f0ff;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 10px;
            }
            .body-section {
                background-color: #fff3cd;
                padding: 10px;
                border-radius: 5px;
            }
            body::before {
                content: "";
                background-image: url('https://dia.edu.az/wp-content/uploads/2021/03/cropped-DIA-gerb-fon-png.png');
                background-size: contain;
                background-repeat: no-repeat;
                background-position: center;
                opacity: 0.1;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -1;
            }
        </style>
    </head>
    <body>
        <div class="container col-md-12">
            <div class="text-center mt-4">
                <h2>Fuzzing Results</h2>
                <p class="text-muted">Generated on: {{ timestamp }}</p>
            </div>

            <table class="table table-striped mt-4" id="resultsTable">
                <thead class="thead-dark">
                    <tr>
                        <th onclick="sortTable(0)">Request # ↕</th>
                        <th onclick="sortTable(1)">Payload ↕</th>
                        <th onclick="sortTable(2)">Status Code ↕</th>
                        <th onclick="sortTable(3)">Response Length ↕</th>
                        <th onclick="sortTable(4)">Response Time (s) ↕</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for result in results %}
                        <tr>
                            <td>{{ result['request_number'] }}</td>
                            <td>{{ result['payload'][:50] ~ ("..." if result['payload']|length > 50 else "") }}</td>
                            <td>{{ result['status_code'] }}</td>
                            <td>{{ result['response_length'] }}</td>
                            <td>{{ result['response_time'] }}</td>
                            <td><button class="btn btn-info btn-sm" data-toggle="modal" data-target="#modal{{ result['request_number'] }}">👁️ View</button></td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        {% for result in results %}
        <div class="modal fade" id="modal{{ result['request_number'] }}" tabindex="-1" role="dialog">
            <div class="modal-dialog modal-lg" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Request {{ result['request_number'] }} - Details</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="section-title">Request</div>
                        <pre class="code-block"><xmp>{{ result['request'] }}</xmp></pre>

                        <div class="section-title">Response</div>
                        <div class="header-section">
                            <strong>Headers:</strong>
                            <pre class="code-block"><xmp>{{ result['response'].split('\\n\\n')[0] }}</xmp></pre>
                        </div>
                        <div class="body-section">
                            <strong>Body:</strong>
                            <pre class="code-block"><xmp>{{ result['response'].split('\\n\\n', 1)[1] if '\\n\\n' in result['response'] else '' }}</xmp></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        {% endfor %}

        <script>
            function sortTable(n) {
                var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
                table = document.getElementById("resultsTable");
                switching = true;
                dir = "asc";
                while (switching) {
                    switching = false;
                    rows = table.rows;
                    for (i = 1; i < (rows.length - 1); i++) {
                        shouldSwitch = false;
                        x = rows[i].getElementsByTagName("TD")[n];
                        y = rows[i + 1].getElementsByTagName("TD")[n];
                        if (dir == "asc") {
                            if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                                shouldSwitch = true;
                                break;
                            }
                        } else if (dir == "desc") {
                            if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                                shouldSwitch = true;
                                break;
                            }
                        }
                    }
                    if (shouldSwitch) {
                        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                        switching = true;
                        switchcount++;
                    } else {
                        if (switchcount == 0 && dir == "asc") {
                            dir = "desc";
                            switching = true;
                        }
                    }
                }
            }
        </script>
    </body>
    </html>
    """

    template = Template(html_template)
    html_content = template.render(results=results, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    with open(report_name, "w", encoding='utf-8') as f:
        f.write(html_content)

    print(f"✅ HTML hesabat yaradıldı: {report_name}")


def parse_sort_argument(sort_arg):
    if not sort_arg:
        return None, False

    if ' ' in sort_arg:
        parts = sort_arg.split()
        if len(parts) == 2:
            key = parts[0].lower()
            direction = parts[1].lower()
            reverse = direction in ['desc', 'azalan', '-', 'down']
            return key, reverse
        else:
            return sort_arg.lower(), False
    else:
        if sort_arg.endswith('+'):
            return sort_arg[:-1].lower(), False
        elif sort_arg.endswith('-'):
            return sort_arg[:-1].lower(), True
        else:
            return sort_arg.lower(), False


def main():
    parser = argparse.ArgumentParser(
        description="SQL Fuzzing Aləti - Brute Force Test Aləti",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        help="Kömək mesajını göstər"
    )

    parser.add_argument(
        "--url",
        help="Hədəf URL ünvanı (NAN payload üçün işarədir)\n"
             "Nümunə: https://example.com/search?q=NAN"
    )
    parser.add_argument(
        "--request",
        help="Sorğu faylı (GET/POST avtomatik aşkar ediləcək)\n"
             "Fayl formatı:\n"
             "GET /path?param=NAN HTTP/1.1\n"
             "Host: example.com\n"
             "...\n"
             "\n"
             "post_data (əgər POST sorğusu olarsa)"
    )
    parser.add_argument(
        "--fuzzfile",
        required=False,
        help="Payloadların olduğu fayl (hər sətirdə bir payload)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="İşlədiləcək thread sayı (standart: 10)"
    )
    parser.add_argument(
        "--header",
        help="Əlavə HTTP başlıqları 'Açar: Dəyər' formatında\n"
             "Çoxlu başlıqlar üçün '|' işarəsindən istifadə edin\n"
             "Nümunə: 'Authorization: Bearer token|X-Header: dəyər'"
    )
    parser.add_argument(
        "--report",
        nargs='?',
        const="",
        help="HTML hesabat faylının adı (boş buraxılsa avtomatik adlandırılır)"
    )
    parser.add_argument(
        "--console",
        nargs='?',
        const="sorğu",
        help="Konsol çıxışı (çeşidləmə üçün 'sütun istiqamət' formatında)\n"
             "Nümunələr:\n"
             "  'length-' və ya 'status+'\n"
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Qrafik istifadəçi interfeysini başlat"
    )
    parser.add_argument(
        "--encode",
        choices=["url", "b64"],
        help="Payload encoding type (optional):\n"
             "  url - URL encoding\n"
             "  b64 - Base64 encoding"
    )

    args = parser.parse_args()

    if args.help:
        print(title_by)
        print(author_by)
        print(DESCRIPTION)
        parser.print_help()
        return

    if not args.fuzzfile:
        parser.error("Parametr tələb olunur: --fuzzfile")
    if not args.request and not args.url:
        parser.error("Ya --request ya da --url parametri tələb olunur")

    if args.request and args.url:
        parser.error("Yalnız birini seçin: --request VƏ ya --url")


    try:
        with open(args.fuzzfile, "r") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        parser.error(f"Payload faylı tapılmadı: {args.fuzzfile}")

    method, url, headers, post_data = None, None, {}, None

    if args.request:
        try:
            method, url, headers, post_data = parse_request_file(args.request)
        except FileNotFoundError:
            parser.error(f"Sorğu faylı tapılmadı: {args.request}")
        except ValueError as e:
            parser.error(f"Sorğu faylında xəta: {str(e)}")
    else:
        method = "GET"
        url = args.url

    sort_key, sort_reverse = parse_sort_argument(args.console) if args.console else (None, False)

    # Determine output mode - default to console if none specified
    console_mode = bool(args.console)
    gui_mode = args.gui
    report_mode = args.report is not None

    # If no output mode specified, default to console
    if not any([console_mode, gui_mode, report_mode]):
        console_mode = True

    fuzz(
        method=method,
        url=url,
        data=post_data,
        wordlist=wordlist,
        threads=args.threads,
        user_headers=args.header,
        post_file_headers=headers,
        report_name=args.report if args.report is not None else None,
        console_mode=console_mode,
        gui_mode=gui_mode,
        sort_key=sort_key,
        sort_reverse=sort_reverse,
        encoding=args.encode
    )

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main() 
