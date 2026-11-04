import asyncio
import aiohttp
import time
import json
import socket

# قائمة المصادر (10 مصادر)
SOURCES = [
    "https://proxmint.com/api/free-proxies?protocol=socks5&limit=200",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/xyzs996/free-proxy-health-list/main/socks5.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt",
    "https://cdn.jsdelivr.net/gh/officialputuid/KangProxy@main/socks5/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt"
]

TIMEOUT = 5 # مهلة فتح الاتصال (TCP) فقط

async def fetch_proxies():
    proxies = set()
    async with aiohttp.ClientSession() as session:
        for url in SOURCES:
            try:
                print(f"Fetching from {url}...")
                async with session.get(url, timeout=15) as response:
                    if response.status == 200:
                        text = await response.text()
                        if "proxmint.com" in url and text.strip().startswith('{'):
                            data = json.loads(text)
                            for row in data.get("rows", []):
                                proxies.add(f"{row['ip']}:{row['port']}")
                        else:
                            for line in text.splitlines():
                                line = line.strip()
                                if line and ":" in line and not line.startswith("#"):
                                    proxies.add(line)
            except Exception as e:
                print(f"Error fetching {url}: {e}")
    return list(proxies)

async def test_proxy(proxy):
    # الفلتر البسيط: فحص فتح المنفذ (TCP) فقط دون طلب بيانات
    try:
        host, port = proxy.split(":")
        port = int(port)
        start_time = time.time()
        
        # محاولة فتح اتصال سريع
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), 
            timeout=TIMEOUT
        )
        
        latency = int((time.time() - start_time) * 1000)
        writer.close()
        await writer.wait_closed()
        return (proxy, latency)
        
    except Exception:
        return None

async def main():
    print("Starting Proxy Fetcher (Simple TCP Filter)...")
    all_proxies = await fetch_proxies()
    print(f"Fetched {len(all_proxies)} proxies. Starting simple TCP tests...")

    # تقسيم الفحص على دفعات لتجنب انهيار الشبكة
    tasks = [test_proxy(p) for p in all_proxies]
    results = await asyncio.gather(*tasks)

    working_proxies = [res for res in results if res is not None]
    # ترتيب البروكسيات حسب الأسرع في فتح الاتصال
    working_proxies.sort(key=lambda x: x[1])

    print(f"Found {len(working_proxies)} working proxies (TCP only)!")
    
    with open("proxies.txt", "w") as f:
        for proxy, latency in working_proxies[:200]: # حفظ أفضل 200 بروكسي
            f.write(f"socks5://{proxy}\n")
            
    print("Done. 'proxies.txt' is ready.")

if __name__ == "__main__":
    asyncio.run(main())