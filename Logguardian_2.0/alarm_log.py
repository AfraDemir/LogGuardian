import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

def log_oku(dosya_adi):
    with open(dosya_adi, "r", encoding="utf-8") as f:
        return f.readlines()

def log_parcala(line):
    line = line.strip().replace('\r', '')
    line = re.sub(r'\x1b\[[0-9;]*m', '', line)  # ANSI kodları temizle

    if line.startswith("<") and "date=" in line:
        line = line.split(">", 1)[1].strip()

    if line.startswith("date="):
        parts = line.split()
        data = {}
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                data[key] = value.strip('"')

        msg_match = re.search(r'msg="(.*?)"', line)
        if msg_match:
            data["msg"] = msg_match.group(1)

        if all(k in data for k in ('date', 'time', 'srcip', 'dstip')):
            try:
                zaman = f"{data['date']} {data['time']}"
                datetime.strptime(zaman, "%Y-%m-%d %H:%M:%S")
            except:
                zaman = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return {
                "zaman": zaman,
                "ip": data["srcip"],
                "tur": "FortiGate",
                "olay": data.get("msg", ""),
                "dstport": data.get("dstport", "")
            }

    if "Source Network Address:" in line and "Account Name:" in line:
        try:
            timestamp, event_id, *rest = line.split(",")
            ip = ""
            for part in rest:
                if "Source Network Address:" in part:
                    ip = part.split("Source Network Address:")[1].strip()
            if ip:
                olay = "Başarısız giriş denemesi" if event_id.strip() == "4625" else "Başarılı giriş"
                return {
                    "zaman": timestamp.strip(),
                    "ip": ip,
                    "tur": "Windows",
                    "olay": olay
                }
        except:
            return None

    apache_match = re.match(r'.*?(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] ".*?" (\d{3})', line)
    if apache_match:
        ip = apache_match.group(1)
        zaman_raw = apache_match.group(2)
        status = apache_match.group(3)
        try:
            zaman = datetime.strptime(zaman_raw.split()[0], "%d/%b/%Y:%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
        except:
            zaman = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "zaman": zaman,
            "ip": ip,
            "tur": "Apache",
            "olay": f"HTTP {status} yanıtı",
            "status": status
        }

    if "alarm_handler:" in line:
        match_ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        ip = match_ip.group(1) if match_ip else "localhost"

        match_time = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        zaman = match_time.group(1) if match_time else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "{set,{system_memory_high_watermark" in line:
            olay = "Bellek sınırı AŞILDI"
        elif "{clear,system_memory_high_watermark" in line:
            olay = "Bellek sınırı normale döndü"
        else:
            olay = "Sistem alarmı"

        return {
            "zaman": zaman,
            "ip": ip,
            "tur": "Sistem",
            "olay": olay
        }

    return None

def loglari_analiz_et(loglar):
    brute_force_ips = defaultdict(list)
    dns_ips = {}
    port_aktivitesi = defaultdict(list)
    zararlilar = set()
    alarmlar = []
    id_sayac = 1

    for log in loglar:
        ip = log["ip"]
        tur = log["tur"]
        olay = log["olay"].lower()

        if (tur == "Windows" and "başarısız" in olay) or \
           (tur == "FortiGate" and "login failed" in olay) or \
           (tur == "Apache" and log.get("status") == "401"):
            brute_force_ips[ip].append(log["zaman"])

        if tur == "FortiGate" and "dns tunneling" in olay:
            dns_ips[ip] = log["zaman"]

        if tur == "FortiGate" and log.get("dstport"):
            try:
                ts = datetime.strptime(log["zaman"], "%Y-%m-%d %H:%M:%S")
                port_aktivitesi[ip].append((ts, log["dstport"]))
            except:
                continue

        if tur == "FortiGate" and "malicious website" in olay:
            zararlilar.add((ip, log["zaman"]))

    for ip, zamanlar in brute_force_ips.items():
        if len(zamanlar) >= 5:
            alarmlar.append({
                "id": id_sayac,
                "zaman": zamanlar[0],
                "ip": ip,
                "tur": "Brute Force"
            })
            id_sayac += 1

    for ip, zaman in dns_ips.items():
        alarmlar.append({
            "id": id_sayac,
            "zaman": zaman,
            "ip": ip,
            "tur": "DNS Tunneling"
        })
        id_sayac += 1

    for ip, kayitlar in port_aktivitesi.items():
        kayitlar.sort()
        for i in range(len(kayitlar)):
            bas_zaman = kayitlar[i][0]
            portlar = {kayitlar[i][1]}
            for j in range(i+1, len(kayitlar)):
                if kayitlar[j][0] - bas_zaman <= timedelta(minutes=2):
                    portlar.add(kayitlar[j][1])
                else:
                    break
            if len(portlar) >= 5:
                alarmlar.append({
                    "id": id_sayac,
                    "zaman": bas_zaman.strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": ip,
                    "tur": "Port Scan"
                })
                id_sayac += 1
                break

    for ip, zaman in zararlilar:
        alarmlar.append({
            "id": id_sayac,
            "zaman": zaman,
            "ip": ip,
            "tur": "Zararlı Web Sitesi"
        })
        id_sayac += 1

    return alarmlar

def json_ozetle(alarmlar):
    grup = {}
    for a in alarmlar:
        tur = a["tur"]
        aciklama = {
            "Brute Force": "5 başarısız deneme. Brute force saldırısı olabilir.",
            "DNS Tunneling": "Olağandışı DNS trafiği. Tunneling girişimi olabilir.",
            "Port Scan": "2 dakika içinde birden fazla porta erişim tespit edildi.",
            "Zararlı Web Sitesi": "Web filtreleme tarafından engellenen zararlı site erişimi."
        }.get(tur, "")

        if tur not in grup:
            grup[tur] = {
                "alarm_turu": tur,
                "aciklama": aciklama,
                "ip_adresleri": []
            }
        grup[tur]["ip_adresleri"].append(a["ip"])
    return list(grup.values())

def rapor_olustur(loglar, alarmlar):
    log_kayitlari = [{
        "id": l["id"],
        "zaman": l["zaman"],
        "ip": l["ip"],
        "tur": l["tur"],
        "olay": l["olay"]
    } for l in loglar]

    rapor = {
        "toplam_log_sayisi": len(loglar),
        "alarm_kayitlari": alarmlar,
        "ozet": json_ozetle(alarmlar),
        "log_kayitlari": log_kayitlari
    }

    zaman_damgasi = datetime.now().strftime("%Y-%m-%d_%H-%M")
    dosya_adi = f"rapor_{zaman_damgasi}.json"

    with open(dosya_adi, "w", encoding="utf-8") as f:
        json.dump(rapor, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Rapor oluşturuldu: {dosya_adi}")

from collections import Counter

def konsol_baslat(loglar, alarmlar):
    while True:
        print("\n=== LogGuardian Güvenlik Konsolu ===")
        print("1. Alarm Kayıtlarını Görüntüle")
        print("2. Tüm Logları Görüntüle")
        print("3. Çıkış")
        print("4. En Çok Saldıran IP'yi Göster")
        secim = input("Seçiminizi girin (1-4): ")

        if secim == "1":
            print("\n--- Alarm Türleri ---")
            print("1. Brute Force IP'leri")
            print("2. Port Scan IP'leri")
            print("3. DNS Tunneling IP'leri")
            print("4. Zararlı Web Siteleri IP'leri")
            print("5. Ana Menüye Dön")
            alt = input("Seçiminizi girin (1-5): ")

            if alt == "1":
                print("\nBrute Force Alarmı:")
                for a in alarmlar:
                    if a["tur"] == "Brute Force":
                        print(f"[{a['id']:03}] {a['zaman']} | IP: {a['ip']} | Tür: {a['tur']}")
            elif alt == "2":
                print("\nPort Scan Alarmı:")
                for a in alarmlar:
                    if a["tur"] == "Port Scan":
                        print(f"[{a['id']:03}] {a['zaman']} | IP: {a['ip']} | Tür: {a['tur']}")
            elif alt == "3":
                print("\nDNS Tunneling Alarmı:")
                for a in alarmlar:
                    if a["tur"] == "DNS Tunneling":
                        print(f"[{a['id']:03}] {a['zaman']} | IP: {a['ip']} | Tür: {a['tur']}")
            elif alt == "4":
                print("\nZararlı Web Sitesi Alarmı:")
                for a in alarmlar:
                    if a["tur"] == "Zararlı Web Sitesi":
                        print(f"[{a['id']:03}] {a['zaman']} | IP: {a['ip']} | Tür: {a['tur']}")
            elif alt == "5":
                continue
            else:
                print("Geçersiz seçim. Tekrar deneyin.")

        elif secim == "2":
            print("\nTüm Log Kayıtları:")
            for log in loglar:
                print(f"[{log['id']:03}] {log['zaman']} | IP: {log['ip']} | Tür: {log['tur']} | Olay: {log['olay']}")
        elif secim == "3":
            print("\nÇıkış yapılıyor... Görüşmek üzere!")
            break
        elif secim == "4":
            ip_sayilari = Counter([a["ip"] for a in alarmlar])
            if ip_sayilari:
                en_cok = ip_sayilari.most_common(1)[0]
                print(f"\n🔎 En Çok Saldıran IP: {en_cok[0]} ({en_cok[1]} alarm)")
            else:
                print("\n🔎 Henüz tespit edilen bir saldırgan IP yok.")
        else:
            print("Geçersiz seçim. Tekrar deneyin.")

def main():
    ham = log_oku("örneklog.txt")
    parsed = [log_parcala(l) for l in ham]
    loglar = [l for l in parsed if l and "zaman" in l]

    for idx, l in enumerate(loglar, start=1):
        l["id"] = idx

    alarmlar = loglari_analiz_et(loglar)
    rapor_olustur(loglar, alarmlar)
    konsol_baslat(loglar, alarmlar)

if __name__ == "__main__":
    main()


