# 🦅 BÜRKÜT: TEKNİK ALTYAPI VE HEDEFLENEN MİMARİ (v3.0)

**Mimari Vizyon** BÜRKÜT; geleneksel zafiyet tarama laboratuvarlarının ötesine geçerek, Yapay Zeka (MCP) ajanlarının otonom saldırı ve savunma yeteneklerini Kurumsal DMZ standartlarında test eden, "Aldatma (Deception)" ve "Davranışsal Zeka (UEBA)" konseptlerini barındıran, DevSecOps kaslarını geliştiren ve "Infrastructure as Code" (IaC) felsefesiyle yaşayan yeni nesil bir Purple Team ekosistemidir.

### 🏗️ 1. AĞ TOPOLOJİSİ VE İZOLASYON

Proje, VMware Workstation Pro üzerinde, dış dünyadan tamamen izole edilmiş ancak kendi içinde kurumsal bir hiyerarşiye sahip hibrit bir ağ yapısında çalışır.

**Ağ Katmanları**

- **WAN (Dış Dünya):** VMnet0 (Bridged/NAT). Sadece OPNsense'in dış bacağı buraya bağlıdır.
    
- **LAN (BÜRKÜT Lab - Kurumsal DMZ):** VMnet2 (Host-Only).
    
    - **Subnet:** `192.168.100.0/24`
        
    - **DHCP:** KAPALI (Statik IP Yönetimi).
        
    - **Erişim Kuralı:** Bu ağdaki hiçbir makine, OPNsense izni olmadan birbirine veya dışarıya (İnternet) erişemez. Çekirdek seviyesinde Statik ARP zırhı ile L2 manipülasyonları engellenir.
        

### 💻 2. SİSTEM BİLEŞENLERİ VE ROLLER

Laboratuvar 4 ana aktör (Sanal Makine) üzerine inşa edilmiştir:

**A. KALE KOMUTANI (Gateway & Firewall)**

- **İşletim Sistemi:** OPNsense (HardenedBSD)
    
- **IP Adresi:** `192.168.100.1` (LAN Gateway)
    
- **Görevi:** Ağın tek giriş-çıkış kapısıdır. L3/L4/L7 seviyesinde trafik denetimi yapar. AI ajanının "halüsinasyon" görüp internete veya ev ağına sızmasını engelleyen donanımsal kill-switch görevi görür. TLS Inspection ve Strict Egress kurallarını yönetir.
    

**B. GÖZETLEME KULESİ (SIEM & Defense)**

- **İşletim Sistemi:** Ubuntu Server (Wazuh Server)
    
- **IP Adresi:** `192.168.100.10`
    
- **Görevi:** Tüm ajanlardan logları toplar, MAC adresi değişimlerini (ARP Bekçiliği) izler. Saldırı veya anomali tespit edildiğinde OPNsense API'si üzerinden saldırganı otonom olarak banlar (Active Response).
    

**C. SALDIRGAN VE AI OPERATÖRÜ (Red Team)**

- **İşletim Sistemi:** Kali Linux
    
- **IP Adresi:** `192.168.100.5`
    
- **İçindeki Araçlar:** * **AI Agent (MCP):** Claude/OpenAI tabanlı otonom sızma testi ajanı.
    
    - **Python Middleware:** İstemci ile Ajan arasında HMAC-SHA256 imzalaması yaparak prompt manipülasyonunu (Hijacking) önleyen güvenlik katmanı.
        
    - **Least Privilege:** AI ajanı, sistemde `sudo` yetkisi olmayan izole bir `ai_agent` kullanıcısı ile kısıtlı çalışır.
        

**D. KURBAN VE TEST SAHASI (Target)**

- **İşletim Sistemi:** Ubuntu Server
    
- **IP Adresi:** `192.168.100.20`
    
- **Mimari:** Doğrudan OS üzerinde zafiyet barındırmaz. DVWA, Juice Shop, Log4j gibi uygulamalar Vulhub üzerinden izole Docker konteynerleri içinde ayağa kaldırılır.
    

### 🛡️ 3. İLERİ GÜVENLİK DOKTRİNLERİ

BÜRKÜT, toolları çalıştırmanın ötesinde, modern siber güvenlik tehditlerine karşı kapsamlı bir "Mühendislik Felsefesi" sunar:

**1. Aldatma Mimarisi (Deception & Honeypot)** Savunma, sadece bloklamak yerine saldırganı oyalamak üzerine kuruludur. Ağda gerçekte olmayan sahte IP'ler (Network Decoys) ve yapılandırma dosyalarına gizlenmiş sahte şifreler (Honeytokens) barındırır. Bu tuzaklara dokunulması, saldırganı anında ifşa eder.

**2. Davranışsal Zeka ve Anti-Zehirlenme (UEBA)** Sistem; operatörün komut sözlüğünü, kullanım saatlerini ve klavye dinamiklerini öğrenerek bir "Risk Skoru" oluşturur. Yapay zeka modellerinin veya öğrenme sistemlerinin manipüle edilmesini (Poisoning) önlemek için, tuzaklara düşüldüğü an öğrenme modu kapatılır ve sistem "İnfaz Modu"na (Trap-Triggered Freeze) geçer.

**3. Üçlü Doğrulama Prensibi (The Trilogy) & Masum Trafik** Bir savunma hamlesinin (Active Response) başarılı sayılması için 3 şart aranır:

- **SIEM Alert:** Wazuh "Tehdit engellendi" logunu üretmeli.
    
- **State Change:** OPNsense veya iptables kurallarında IP'nin banlandığı görülmeli.
    
- **Innocent Traffic Test (Noise Injection):** Saldırgan engellenirken, meşru HTTP istekleri sisteme kesintisiz ulaşmaya devam etmeli (Granüler engelleme).
    

**4. Kurumsal Metrikler ve MITRE ATT&CK** Proje, yapılan her saldırı ve savunma testini rastgelelikten çıkarır. Gelişen olaylar **MTTD** (Tespit Süresi) ve **MTTR** (Müdahale Süresi) metrikleriyle saniye bazında ölçülür. Yapılan tüm ataklar ve defansif kilitler **MITRE ATT&CK** matrisindeki Taktik ve Teknik ID'leri (Örn: T1059, T1556) ile haritalandırılarak küresel standartlara uygun raporlanır.

**5. IaC ve Kalıcı İyileştirme (DevSecOps)** Zafiyetler önce manuel analizle sömürülür. Çözüm bulunduğunda bu işlem bir Bash/Ansible scriptine (Hardening) dönüştürülür. Sistem, API ve CLI otomasyonları ile "Tek Tuşla İyileştirme" ve gerektiğinde "Tek Tuşla Geri Alma (Rollback)" yeteneğine sahiptir.

**Sonuç:** Bu altyapı; bir mühendis adayının sadece bir sistemi kıran değil, sistemin mimarisini, davranışsal anormalliklerini ve otonom savunma reflekslerini derinlemesine anlayan bir **"Güvenlik Mimarı"** seviyesine evrilmesi için tasarlanmıştır.
