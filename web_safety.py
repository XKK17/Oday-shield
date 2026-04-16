import requests, sys, re
import arabic_reshaper
from bidi.algorithm import get_display
from colorama import Fore, Style

# مفتاح API الخاص بك - VirusTotal
VT_API_KEY = "5b176265980710b1e04458851d38ef38a153f34b4833ba8e20ef23103b509692"

def ar(text):
    try: return get_display(arabic_reshaper.reshape(text))
    except: return text

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
    title = ar("القيادة ابوخالد المزهري عدي")
    print(f"\n{Fore.CYAN}╔═════════════════════════════════════════════╗")
    print(f"║ {Fore.YELLOW}{title.center(43)} {Fore.CYAN}║")
    print(f"╚═════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    if not url.startswith('http'): url = 'https://' + url
    domain = url.split("//")[-1].split("/")[0]
    
    # 1. قناة معلومات الخادم (Intel)
    intel = get_server_intel(domain)
    if intel:
        print(f"\n🌍 {Fore.WHITE}{ar('معلومات الخادم (الاستخبارات)')}:")
        print(f"   {Fore.BLUE}● {ar('عنوان الـ IP')}: {Fore.YELLOW}{intel['ip']}")
        print(f"   {Fore.BLUE}● {ar('مزود الخدمة')}: {Fore.YELLOW}{intel['isp']}")
        print(f"   {Fore.BLUE}● {ar('الموقع الجغرافي')}: {Fore.YELLOW}{intel['loc']}")

    print(f"{Fore.CYAN}{'━'*45}{Style.RESET_ALL}")
    
    try:
        # محاكاة متصفح حقيقي لكشف الكود المخفي
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=10)
        
        # 2. قناة تحليل التجسس والحساسات (الرادار)
        print(f"📡 {Fore.WHITE}{ar('قناة تحليل التجسس والحساسات')}:")
        spy_findings = []
        if 'getUserMedia' in response.text or 'mediaDevices' in response.text:
            spy_findings.append(ar("🚨 خطر: كود لسحب الكاميرا أو الميكروفون!"))
        if 'geolocation' in response.text:
            spy_findings.append(ar("📍 تنبيه: كود لطلب الموقع الجغرافي (GPS)"))
        
        if spy_findings:
            for s in spy_findings: print(f"   {Fore.RED}● {s}")
        else:
            print(f"   {Fore.GREEN}● {ar('✅ الكود سليم من طلبات التجسس المباشرة')}")

        print(f"{Fore.CYAN}{'━'*45}{Style.RESET_ALL}")

        # 3. قناة فحص الفيروسات العالمية
        print(f"🔍 {Fore.WHITE}{ar('نتائج قناة تحليل الفيروسات العالمية')}:")
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": VT_API_KEY})
        m_count = 0
        if vt_res.status_code == 200:
            stats = vt_res.json()['data']['attributes']['last_analysis_stats']
            m_count = stats['malicious']
            print(f"   {Fore.RED}● {ar('ملغم / فيروسات')}: {m_count}")
            print(f"   {Fore.GREEN}● {ar('آمن / نظيف')}: {stats['harmless']}")
            
            print(f"\n{Fore.CYAN}{'━'*45}{Style.RESET_ALL}")
            if m_count > 0 or spy_findings:
                print(f"{Fore.RED}💀 {ar('النتيجة النهائية: الرابط ملغم أو تجسسي، احذر!')}")
            else:
                print(f"{Fore.GREEN}🛡️ {ar('النتيجة النهائية: الموقع آمن تماماً.')}")
    except:
        print(f"{Fore.RED}❌ {ar('فشل في فحص محتوى الرابط حياً')}")

    print(f"{Fore.CYAN}{'═'*47}\n{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1: oday_final_shield(sys.argv[1])
    else: print(f"{Fore.YELLOW}{ar('الاستخدام')}: oday [URL]{Style.RESET_ALL}")

