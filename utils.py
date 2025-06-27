import csv
import queue
import time
import threading
from .vt_api import check_ip_virustotal, RATE_LIMIT

def read_ip_list(filename, verbose=False):
    ip_list = []
    if filename.endswith('.csv'):
        with open(filename, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get('IP Address') or row.get('ip') or row.get('ip_address')
                if ip:
                    ip_list.append(ip.strip())
    else:
        with open(filename, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip:
                    ip_list.append(ip)
    if verbose:
        print(f"[VERBOSE] Loaded {len(ip_list)} IPs from {filename}")
    return ip_list

def worker(q, api_key, result_list, lock, thread_idx, verbose=False):
    while True:
        try:
            ip = q.get_nowait()
        except queue.Empty:
            break
        if verbose:
            print(f"[VERBOSE][Thread-{thread_idx}] Checking {ip}")
        else:
            print(f"[Thread-{thread_idx}] Checking {ip}")
        result = check_ip_virustotal(ip, api_key, verbose)
        with lock:
            result_list.append(result)
        time.sleep(60 / RATE_LIMIT)
        q.task_done()
