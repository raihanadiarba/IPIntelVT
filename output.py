# output.py
import csv
from datetime import datetime
from html import escape

def print_cli(results):
    for r in results:
        print(f"ip           : {r.get('ip', '')}")
        print(f"country      : {r.get('country', '')}")
        print(f"owner        : {r.get('owner', '')}")
        print(f"malicious    : {r.get('malicious', '')}")
        print(f"suspicious   : {r.get('suspicious', '')}")
        print(f"undetected   : {r.get('undetected', '')}")
        print(f"harmless     : {r.get('harmless', '')}")
        print(f"community_harmless  : {r.get('community_harmless', '')}")
        print(f"community_malicious : {r.get('community_malicious', '')}")
        print(f"reputation   : {r.get('reputation', '')}")
        print(f"last_modification   : {r.get('last_modification', '')}")
        print(f"vt_link      : {r.get('vt_link', '')}")
        print(f"error        : {r.get('error', '')}")
        print("------")

def generate_csv(results, filename):
    fieldnames = [
        'ip', 'country', 'owner', 'malicious', 'suspicious', 'undetected', 'harmless',
        'community_harmless', 'community_malicious', 'reputation', 'last_modification', 'vt_link', 'error'
    ]
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

def generate_html(results, filename):
    html = []
    html.append('<html><head><meta charset="utf-8"><title>VirusTotal IP Report</title>')
    html.append('<style>table{border-collapse:collapse;}td,th{border:1px solid #ccc;padding:5px;}</style>')
    html.append('</head><body>')
    html.append(f'<h2>VirusTotal Bulk IP Report ({datetime.now().strftime("%Y-%m-%d %H:%M")})</h2>')
    html.append('<table>')
    html.append(
        '<tr><th>No</th><th>IP Address</th><th>Country</th><th>Owner</th>'
        '<th>Malicious</th><th>Suspicious</th><th>Undetected</th><th>Harmless</th>'
        '<th>Community Harmless</th><th>Community Malicious</th><th>Reputation</th>'
        '<th>Last Modified</th><th>VT Link</th><th>Error</th></tr>'
    )
    for idx, r in enumerate(results, 1):
        html.append(
            f'<tr><td>{idx}</td>'
            f'<td>{escape(r.get("ip",""))}</td>'
            f'<td>{escape(str(r.get("country","")))}</td>'
            f'<td>{escape(str(r.get("owner","")))}</td>'
            f'<td>{escape(str(r.get("malicious","")))}</td>'
            f'<td>{escape(str(r.get("suspicious","")))}</td>'
            f'<td>{escape(str(r.get("undetected","")))}</td>'
            f'<td>{escape(str(r.get("harmless","")))}</td>'
            f'<td>{escape(str(r.get("community_harmless","")))}</td>'
            f'<td>{escape(str(r.get("community_malicious","")))}</td>'
            f'<td>{escape(str(r.get("reputation","")))}</td>'
            f'<td>{escape(str(r.get("last_modification","")))}</td>'
            f'<td><a href="{escape(r.get("vt_link",""))}" target="_blank">View</a></td>'
            f'<td>{escape(str(r.get("error","")))}</td>'
            '</tr>'
        )
    html.append('</table></body></html>')
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))
