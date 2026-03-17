# 🦅 PROJE BÜRKÜT: Otonom Purple Team ve DevSecOps Laboratuvarı

## 📌 Proje Hakkında
BÜRKÜT, geleneksel "bayrağı kap" (CTF) mantığının ötesine geçerek, modern kurumsal mimarilere uygun bir "Purple Team" laboratuvarını sıfırdan inşa etme projesidir. 

Bu laboratuvarın temel amacı; izole bir ağda zafiyetli sistemlere sızmak, saldırı anındaki logları merkezi bir SIEM (Wazuh) üzerinde analiz etmek ve ardından tespit edilen zafiyetleri "Infrastructure as Code" (IaC) felsefesiyle otomatize edilmiş scriptler yazarak konfigürasyon seviyesinde kapatmaktır.

Proje, modern siber güvenliğin geleceği olan Yapay Zeka (MCP) ajanlarını operasyonel süreçlere entegre eder. AI ajanının yetenekleri; **"İki Fazlı AI Doktrini" (Otonom ve Human-in-the-Loop)**, "Active Response", "Deception" (Aldatmaca) ve "MITRE ATT&CK" haritalandırması gibi ileri düzey savunma dinamikleri altında test edilmektedir.

## 🛠️ Teknik Altyapı ve Mimari
Sistem, ağın merkezine donanımsal izolasyon ve kurumsal DMZ mantığı sağlayan bir **pfSense Firewall** yerleştirilerek VMware Workstation üzerinde kurgulanmıştır.

* **Ağ Geçidi (pfSense):** Kurumsal DMZ mimarisini sağlar. Strict Egress (Beyaz Liste) ve Derin Paket İncelemesi (SSL/TLS Inspection) ile AI ajanının fiziksel ağlara veya zararlı internet sitelerine çıkışını engeller.
* **Gözetleme Kulesi (SIEM):** Logları toplayan ve Active Response ile otonom savunma kararları alan Wazuh Manager.
* **Kurban (Target):** Zafiyetli uygulamaların doğrudan işletim sistemine değil, Vulhub reposu üzerinden Docker konteynerleri şeklinde ayağa kaldırıldığı izole Ubuntu Server.
* **Saldırgan (Attacker) & AI Host (Kali Linux):** Bulut tabanlı zekayı kullanan MCP ajanlarının çalıştığı merkez. AI ajanının "halüsinasyon" görüp izole ağ dışına çıkmasını önlemek için **HMAC-SHA256 Mührü**, **Unix Socket (IPC) İzolasyonu** ve **Middleware (Deli Gömleği)** kilitleri uygulanmıştır.

## 🗺️ Yol Haritası (Kısa Bakış)
Proje, sıfırdan otomasyona doğru giden, saldırganı aldatmayı ve otonom tepkiyi merkeze alan 6 aşamalı bir metodoloji ile yürütülmektedir. **Tüm teknik detaylar, komutlar ve konfigürasyonlar ana yol haritası dosyasında mevcuttur.**

* **Seviye 0 (İnşaat Alanı):** pfSense tabanlı Kurumsal DMZ Mimarisi ve katı ağ izolasyonunun kurulması.
* **Seviye 1 (Zanaatkar):** Zafiyetlerin manuel olarak sömürülmesi ve el yordamıyla yamalanması.
* **Seviye 2 (Siber Çırak):** Saldırı yetkisinin, "Fail-Safe" mekanizmaları ve **İki Fazlı AI Doktrini (Otonom & HITL)** ile sınırlandırılmış Yapay Zeka ajanlarına devredilmesi.
* **Seviye 3 (Kalkan):** Wazuh Active Response ile otonom savunma ve L2 Katmanında **Statik ARP Zırhı** ile MITM engellemesi.
* **Seviye 3.5 (Gölge ve Zeka):** Savunmayı pasiflikten çıkarıp; **Deception (Ağ Yemi/Honeytoken)**, Process Lineage ve UEBA (Kullanıcı Davranış Analizi) ile saldırganı tuzağa düşüren aktif mimari.
* **Seviye 4 (Mühendis):** DevSecOps yaklaşımıyla; State Management (Rollback) planlanması, zafiyetlerin Bash/Ansible (IaC) aracılığıyla tek tuşla kapatılması ve "Masum Trafik Testi" (Noise Injection).
* **Seviye 5 (Bürküt - Büyük Final):** Adversary Emulation (Atomic Red Team) ile Kırmızı-Mavi düellosunun gerçekleştirilmesi. Sonuçların **MTTD/MTTR** metrikleriyle ölçülmesi ve **MITRE ATT&CK** framework'üne haritalandırılması.

## 🚀 Başlangıç ve Detaylı Dokümantasyon
Laboratuvarın kavramsal mimarisini, güvenlik kilitlerinin (Guardrails) çalışma mantığını ve adım adım kurulum rotasını içeren **TAM KAPSAMLI UYGULAMA REHBERİ'ne** aşağıdaki bağlantıdan ulaşabilirsiniz:

👉 **[BÜRKÜT Yol Haritası ve Mimari Dokümantasyon](./BURKUT-Yol-Haritasi.md)**

---
*Bu proje, akademik teoriyi operasyonel saha gerçekliğiyle birleştirmek amacıyla geliştirilmektedir. Kodlar ve mimari tasarımlar Apache 2.0 Lisansı ile korunmaktadır.*
