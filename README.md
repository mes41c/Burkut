# 🦅 PROJE BÜRKÜT: Otonom Purple Team ve DevSecOps Laboratuvarı

## 📌 Proje Hakkında
BÜRKÜT, geleneksel "bayrağı kap" (CTF) mantığının ötesine geçerek, modern kurumsal mimarilere uygun bir "Purple Team" laboratuvarını sıfırdan inşa etme projesidir. 

Bu laboratuvarın temel amacı; izole bir ağda zafiyetli sistemlere sızmak, saldırı anındaki logları merkezi bir SIEM (Wazuh) üzerinde analiz etmek ve ardından tespit edilen zafiyetleri başta manuel olarak sonrasında ise "Infrastructure as Code" (IaC) felsefesiyle otomatize edilmiş scriptler yazarak konfigürasyon seviyesinde kapatmaktır.

Ayrıca bu proje, modern siber güvenliğin geleceği olan Yapay Zeka (MCP) ajanlarını operasyonel süreçlere entegre ederek; insan zekası ile AI yeteneklerini saldırı, "Active Response" (Otonom Savunma) ve Kalite Kontrol (QA) dinamikleri altında kıyaslamayı hedefler.

## 🛠️ Teknik Altyapı ve Mimari
Proje, kararlılık ve ağ izolasyonu sağlamak amacıyla "Çift Bacaklı" (Dual-NIC) hibrit bir topoloji kullanılarak VMware Workstation Pro üzerinde kurgulanmıştır.

* **Gözetleme Kulesi (SIEM):** Logları toplayan ve Active Response ile otonom savunma yapan Wazuh Manager.
* **Kurban (Target):** Dış dünyadan tamamen izole edilmiş (Host-Only) modern Ubuntu Server. Zafiyetli uygulamalar doğrudan işletim sistemine değil, Vulhub reposu üzerinden Docker konteynerleri (Örn: Log4j, DVWA) şeklinde ayağa kaldırılmaktadır.
* **Saldırgan (Attacker) & AI Host:** Kali Linux. Üzerinde hem manuel sızma araçları hem de bulut tabanlı zekayı kullanan MCP ajanları (Open Interpreter vb.) çalışır. AI ajanının kontrolden çıkmasını önlemek için Python ve iptables tabanlı güvenlik kilitleri (Guardrails) uygulanmıştır.

## 🗺️ Yol Haritası (5 Seviyeli Operasyon Modeli)
Proje, sıfırdan otomasyona doğru giden 5 aşamalı bir metodoloji ile yürütülmektedir:

* **Seviye 0 (İnşaat Alanı):** Sanal veri merkezinin, hibrit ağ topolojisinin ve izolasyonun kurulması.
* **Seviye 1 (Zanaatkar):** Zafiyetlerin manuel olarak sömürülmesi, SIEM üzerinden izlenmesi ve el yordamıyla yamalanması.
* **Seviye 2 (Siber Çırak):** Saldırı yetkisinin, "Fail-Safe" mekanizmalarıyla sınırlandırılmış Yapay Zeka ajanlarına devredilmesi.
* **Seviye 3 (Kalkan):** Wazuh Active Response ile saldırgan IP'lerin otonom bir şekilde sistemden banlanması.
* **Seviye 4 (Mühendis):** DevSecOps yaklaşımıyla; zafiyetlerin Bash/Ansible scriptleri (IaC) aracılığıyla tek tuşla kapatılması ve AI ajanından yama önerileri alınması.
* **Seviye 5 (Doğrulama):** Kapatılan zafiyetlerin AI ajanları tarafından tekrar test edilerek "Kalite Kontrol" (QA) süreçlerinin tamamlanması.

## 📂 Dosyalar
Laboratuvarın kavramsal mimarisini, altyapı detaylarını ve adım adım kurulum rotasını içeren dokümanlara bu repodaki PDF dosyalarından ulaşabilirsiniz:
1. `BÜRKÜT-Proje Amacı.pdf`
2. `BÜRKÜT-Teknik Altyapı ve Hedefimiz.pdf`
3. `BÜRKÜT-Yol Haritası.pdf`

---
*Bu proje, akademik teoriyi operasyonel saha gerçekliğiyle birleştirmek amacıyla geliştirilmektedir.*
