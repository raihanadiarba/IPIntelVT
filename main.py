# main.py
import argparse
import threading
import queue

from vt_api import check_ip_virustotal, RATE_LIMIT
from utils import read_ip_list, worker
from output import print_cli, generate_csv, generate_html

def parse_args():
    parser = argparse.ArgumentParser(
        description="Advanced VirusTotal Bulk IP Reputation Checker with Community Score"
    )
    parser.add_argument("-k", "--api-key", required=True, help="VirusTotal API key")
    parser.add_argument("-i", "--ip-list", help="File IP (txt/csv, satu IP/kolom 'IP Address')")
    parser.add_argument("-s", "--single-ip", help="Cek satu IP saja")
    parser.add_argument("-o", "--output-html", help="Output HTML (opsional)")
    parser.add_argument("-c", "--output-csv", help="Output CSV (opsional)")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Jumlah thread (max 4 public API)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Tampilkan log detail proses")
    return parser.parse_args()

def main():
    args = parse_args()
    result_list = []
    lock = threading.Lock()

    if args.single_ip:
        if args.verbose:
            print(f"[VERBOSE] Checking single IP: {args.single_ip}")
        result = check_ip_virustotal(args.single_ip, args.api_key, args.verbose)
        result_list.append(result)
    elif args.ip_list:
        ip_list = read_ip_list(args.ip_list, args.verbose)
        print(f"[+] Total IPs to check: {len(ip_list)}")
        q = queue.Queue()
        for ip in ip_list:
            q.put(ip)
        threads = []
        for i in range(min(args.threads, RATE_LIMIT)):
            t = threading.Thread(target=worker, args=(q, args.api_key, result_list, lock, i+1, args.verbose))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
    else:
        print("[-] Please specify --single-ip or --ip-list")
        return

    print_cli(result_list)

    if args.output_csv:
        generate_csv(result_list, args.output_csv)
        print(f"[+] CSV report saved: {args.output_csv}")
    if args.output_html:
        generate_html(result_list, args.output_html)
        print(f"[+] HTML report saved: {args.output_html}")

if __name__ == '__main__':
    main()
