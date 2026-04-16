import requests, sys, re

# مفتاح API الخاص بك - VirusTotal
VT_API_KEY = "5b176265980710b1e04458851d38ef38a153f34b4833ba8e20ef23103b509692"

def ar(text):
    return text

def get_server_intel(domain):
    try:
        res = requests.get(f"http://ip-api.com/json/{domain}", timeout=5).json()
        if res.get('status') == 'success':
            return {
                "ip": res.get('query'),
                "isp": res.get('isp'),
                "loc": f"{res.get('city')}, {res.get('country')}"
            }
    except: pass
    return None

def oday_final_shield(url):
    print("--- القيادة ابوخالد المزهري عدي ---")
    if not url.startswith('http'): url = 'https://' + url
    domain = url.split("//")[-1].split("/")[0]
    intel = get_server_intel(domain)
    if intel:
        print(f"\n🌍 معلومات الخادم: \n IP: {intel['ip']} \n ISP: {intel['isp']} \n Loc: {intel['loc']}")
    print("-" * 40)
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        print("📡 فحص التجسس والحساسات:")
        if 'getUserMedia' in response.text or 'mediaDevices' in response.text:
            print("🚨 خطر: كود لسحب الكاميرا أو الميكروفون!")
        elif 'geolocation' in response.text:
            print("📍 تنبيه: كود لطلب الموقع الجغرافي (GPS)")
        else:
            print("✅ الكود سليم من طلبات التجسس")
        print("-" * 40)
        print("🔍 نتائج تحليل الفيروسات:")
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY})
        if vt_res.status_code == 200:
            stats = vt_res.json()['data']['attributes']['last_analysis_stats']
            print(f"● ملغم: {stats['malicious']} \n● آمن: {stats['harmless']}")
        else:
            print("⚠️ تعذر الاتصال بقاعدة بيانات الفيروسات")
    except:
        print("❌ فشل في فحص محتوى الرابط")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        oday_final_shield(sys.argv[1])
