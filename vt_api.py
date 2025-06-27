import requests
import time
from datetime import datetime

RATE_LIMIT = 4  # VirusTotal public API: 4 req/min

def check_ip_virustotal(ip, api_key, verbose=False):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {"x-apikey": api_key}
    try:
        if verbose:
            print(f"[VERBOSE] Requesting {url}")
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 429:
            print(f"[!] Rate limit hit for IP {ip}, sleeping 60s...")
            time.sleep(60)
            response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            if verbose:
                print(f"[VERBOSE] API error {response.status_code} for {ip}")
            return {'ip': ip, 'error': f"API error {response.status_code}"}
        data = response.json().get('data', {}).get('attributes', {})
        stats = data.get('last_analysis_stats', {})
        votes = data.get('total_votes', {})
        reputation = data.get('reputation', '')
        last_mod = data.get('last_modification_date', '')
        if last_mod:
            last_mod = datetime.utcfromtimestamp(last_mod).strftime('%Y-%m-%d %H:%M:%S UTC')
        if verbose:
            print(f"[VERBOSE] Parsed result for {ip}: {stats}, votes={votes}, reputation={reputation}")
        return {
            'ip': ip,
            'country': data.get('country', ''),
            'owner': data.get('as_owner', ''),
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'community_harmless': votes.get('harmless', 0),
            'community_malicious': votes.get('malicious', 0),
            'reputation': reputation,
            'last_modification': last_mod,
            'vt_link': f'https://www.virustotal.com/gui/ip-address/{ip}',
            'error': ''
        }
    except Exception as e:
        if verbose:
            print(f"[VERBOSE] Exception for {ip}: {e}")
        return {'ip': ip, 'error': str(e)}
