# 🦅 PROJE BÜRKÜT: Otonom Purple Team ve DevSecOps Laboratuvarı

## 📌 Proje Hakkında
BÜRKÜT, geleneksel "bayrağı kap" (CTF) mantığının ötesine geçerek, modern kurumsal mimarilere uygun bir "Purple Team" laboratuvarını sıfırdan inşa etme projesidir. 

Bu laboratuvarın temel amacı; izole bir ağda zafiyetli sistemlere sızmak, saldırı anındaki logları merkezi bir SIEM (Wazuh) üzerinde analiz etmek ve ardından tespit edilen zafiyetleri başta manuel olarak, sonrasında ise "Infrastructure as Code" (IaC) felsefesiyle otomatize edilmiş scriptler yazarak konfigürasyon seviyesinde kapatmaktır.

Ayrıca bu proje, modern siber güvenliğin geleceği olan Yapay Zeka (MCP) ajanlarını operasyonel süreçlere entegre ederek; insan zekası ile AI yeteneklerini saldırı, "Active Response" (Otonom Savunma), Hatalı Alarm (False-Positive) Yönetimi ve Kalite Kontrol (QA) dinamikleri altında kıyaslamayı hedefler.

## 🛠️ Teknik Altyapı ve Mimari
Sistem, karmaşık çift-bacaklı (Dual-NIC) yapılardan arındırılarak, ağın merkezine donanımsal izolasyon ve kurumsal DMZ mantığı sağlayan bir **pfSense Firewall** yerleştirilerek VMware Workstation Pro üzerinde kurgulanmıştır.

* **Ağ Geçidi (pfSense Firewall):** Laboratuvar trafiğini denetleyen, AI ajanının bulut API'lerine çıkışını kontrollü sağlarken fiziksel ağlara sızmasını L3/L4 seviyesinde engelleyen ana güvenlik katmanıdır.
* **Gözetleme Kulesi (SIEM):** Logları toplayan ve Active Response ile otonom savunma kararları alan Wazuh Manager.
* **Kurban (Target):** Sadece izole (Host-Only) ağa bağlı, pfSense üzerinden dış dünyaya (WAN) çıkışı kesinlikle kısıtlanmış (Strict Egress) modern Ubuntu Server. Zafiyetli uygulamalar doğrudan işletim sistemine değil, Vulhub reposu üzerinden Docker konteynerleri şeklinde ayağa kaldırılmaktadır.
* **Saldırgan (Attacker) & AI Host:** Kali Linux. Üzerinde hem manuel sızma araçları hem de bulut tabanlı zekayı kullanan MCP ajanları çalışır. AI ajanının "halüsinasyon" görüp izole ağ dışına çıkmasını önlemek için Python (Middleware), iptables (Hard Kill Switch) ve pfSense tabanlı üç katmanlı Güvenlik Kilitleri (Guardrails) uygulanmıştır.

## 🗺️ Yol Haritası (5 Seviyeli Operasyon Modeli)
Proje, sıfırdan otomasyona doğru giden 5 aşamalı bir metodoloji ile yürütülmektedir:

* **Seviye 0 (İnşaat Alanı):** pfSense tabanlı Kurumsal DMZ Mimarisinin, sanal ağların ve katı izolasyon kurallarının kurulması.
* **Seviye 1 (Zanaatkar):** Zafiyetlerin manuel olarak sömürülmesi, SIEM üzerinden izlenmesi ve el yordamıyla yamalanması.
* **Seviye 2 (Siber Çırak):** Saldırı yetkisinin, "Fail-Safe" mekanizmalarıyla sınırlandırılmış Yapay Zeka ajanlarına devredilmesi.
* **Seviye 3 (Kalkan):** Wazuh Active Response otonom savunma mekanizmasının çalıştırılması ve başarısının 3 farklı metrikle (Wazuh Logları, Firewall State Değişimi, Servis Sağlığı) çapraz doğrulanması.
* **Seviye 4 (Mühendis):** DevSecOps yaklaşımıyla; zafiyetlerin Bash/Ansible scriptleri (IaC) aracılığıyla tek tuşla kapatılması, yama önerilerinin AI'dan alınması ve meşru trafiğin kesilmediğini kanıtlayan "Masum Trafik Testi" (Noise Injection) yapılması.
* **Seviye 5 (Doğrulama):** AI ajanlarının Kalite Kontrol (QA) için kullanılması; "Eminlik Derecesi" (Confidence Scoring) mekanizması ile AI'ın False-Positive (Hatalı Alarm) tuzaklarına düşmeden güvenilir karar verebilme yeteneğinin test edilmesi.

## 📂 Dosyalar
Laboratuvarın kavramsal mimarisini, altyapı detaylarını ve adım adım kurulum rotasını içeren dokümanlara bu repodaki PDF dosyalarından ulaşabilirsiniz:
1. `BÜRKÜT-Proje Amacı.pdf`
2. `BÜRKÜT-Teknik Altyapı ve Hedefimiz.pdf`
3. `BÜRKÜT-Yol Haritası.pdf`

---
*Bu proje, akademik teoriyi operasyonel saha gerçekliğiyle birleştirmek amacıyla geliştirilmektedir. Tüm hakları ve kodlar Apache 2.0 Lisansı ile korunmaktadır.*
