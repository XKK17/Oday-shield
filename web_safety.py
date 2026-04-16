import requests, sys, re

# مفتاح API الخاص بك - VirusTotal
VT_API_KEY = "5b176265980710b1e04458851d38ef38a153f34b4833ba8e20ef23103b509692"

# دالة بسيطة لإرجاع النص كما هو لتجنب أخطاء المكتبات الخارجية
def ar(text):
    return text

def get_server_intel(domain):
    try:
        res = requests.get(f"http://ip-api.com/json/{domain}", timeout=5).json()
        if res['status'] == 'success':
            return {
                "ip": res.get('query'),
                "isp": res.get('isp'),
                "loc": f"{res.get('city')}, {res.get('country')}"
            }
    except: pass
    return None

def oday_final_shield(url):
    # الواجهة العربية ستظهر في المتصفح بشكل صحيح تلقائياً
    print(f"\n--- القيادة ابوخالد المزهري عدي ---")
    
    if not url.startswith('http'): url = 'https://
