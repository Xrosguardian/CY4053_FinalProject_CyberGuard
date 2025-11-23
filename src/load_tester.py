import aiohttp
import asyncio
import time
import pandas as pd

async def fetch(session, url, results):
    start_time = time.time()
    try:
        async with session.get(url, timeout=5) as response:
            latency = (time.time() - start_time) * 1000 # ms
            status = response.status
            results.append({"Status": status, "Latency (ms)": latency, "Timestamp": time.time()})
    except Exception as e:
        results.append({"Status": "Error", "Latency (ms)": 0, "Timestamp": time.time()})

async def run_load_test(target_url, request_count=200):
    results = []
    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(request_count):
            task = asyncio.ensure_future(fetch(session, target_url, results))
            tasks.append(task)
        
        await asyncio.gather(*tasks)
    
    return pd.DataFrame(results)

def trigger_load_test(url, count):
    # Wrapper to run async in streamlit
    return asyncio.run(run_load_test(url, count))