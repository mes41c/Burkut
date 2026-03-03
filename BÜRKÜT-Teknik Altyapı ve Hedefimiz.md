# 🦅 BÜRKÜT: TEKNİK ALTYAPI VE HEDEFLENEN MİMARİ (v2.0)

> [!abstract] Mimari Vizyon BÜRKÜT; geleneksel zafiyet tarama laboratuvarlarının ötesine geçerek, **Yapay Zeka (MCP)** ajanlarının otonom saldırı ve savunma yeteneklerini **Kurumsal DMZ** standartlarında test eden, **DevSecOps** kaslarını geliştiren ve "Infrastructure as Code" (IaC) felsefesiyle yaşayan bir **Purple Team** ekosistemidir.

---

## 🏗️ 1. AĞ TOPOLOJİSİ VE İZOLASYON

Proje, **VMware Workstation Pro** üzerinde, dış dünyadan tamamen izole edilmiş ancak kendi içinde kurumsal bir hiyerarşiye sahip hibrit bir ağ yapısında çalışır.

### **Ağ Katmanları**

- **WAN (Dış Dünya):** `VMnet0` (Bridged/NAT). Sadece pfSense'in dış bacağı buraya bağlıdır.
    
- **LAN (BÜRKÜT Lab - Kurumsal DMZ):** `VMnet2` (Host-Only).
    
    - **Subnet:** `192.168.100.0/24`
        
    - **DHCP:** KAPALI (Statik IP Yönetimi).
        
    - **Erişim Kuralı:** Bu ağdaki hiçbir makine, pfSense izni olmadan birbirine veya dışarıya (İnternet) erişemez.
        

---

## 💻 2. SİSTEM BİLEŞENLERİ VE ROLLER

Laboratuvar 4 ana aktör (Sanal Makine) üzerine inşa edilmiştir:

### **A. KALE KOMUTANI (Gateway & Firewall)**

- **İşletim Sistemi:** pfSense (FreeBSD)
    
- **IP Adresi:** `192.168.100.1` (LAN Gateway)
    
- **Görevi:**
    
    - Ağın tek giriş-çıkış kapısıdır.
        
    - L3/L4 seviyesinde trafik denetimi yapar.
        
    - AI ajanının "halüsinasyon" görüp internete veya ev ağına sızmasını engelleyen donanımsal kill-switch görevi görür.
        

### **B. GÖZETLEME KULESİ (SIEM & Defense)**

- **İşletim Sistemi:** Ubuntu Server (Wazuh Server)
    
- **IP Adresi:** `192.168.100.50`
    
- **Görevi:**
    
    - Tüm ajanlardan (Kali ve Ubuntu) logları toplar.
        
    - **Active Response:** Saldırı tespit edildiğinde (örn: Brute Force, Web Attack) saldırganı otomatik olarak banlar.
        
    - **The Trilogy (3'lü Doğrulama):** Savunma başarısını sadece "Alert" ile değil; 1) Log, 2) Firewall State, 3) Servis Sağlığı metrikleriyle kanıtlar.
        

### **C. SALDIRGAN VE AI OPERATÖRÜ (Red Team)**

- **İşletim Sistemi:** Kali Linux
    
- **IP Adresi:** `192.168.100.20`
    
- **İçindeki Araçlar:**
    
    - **AI Agent (MCP):** Claude/OpenAI tabanlı otonom sızma testi ajanı.
        
    - **Python Middleware:** AI ile işletim sistemi arasında duran, komutları filtreleyen "Güvenlik Katmanı".
        
    - **Strict Egress (iptables):** Makinenin sadece `192.168.100.10` (Hedef) ve API uç noktalarıyla konuşmasına izin veren sıkı ağ kuralları.
        

### **D. KURBAN VE TEST SAHASI (Target)**

- **İşletim Sistemi:** Ubuntu Server
    
- **IP Adresi:** `192.168.100.10`
    
- **Mimari:**
    
    - Doğrudan OS üzerinde zafiyet barındırmaz.
        
    - **Docker Konteynerleri:** DVWA, Juice Shop, Log4j gibi zafiyetli uygulamalar izole konteynerler içinde ayağa kaldırılır.
        
    - Wazuh Agent ile sürekli izlenir (FIM - Dosya Bütünlüğü Takibi).
        

---

## 🛡️ 3. TEMEL GÜVENLİK DOKTRİNLERİ

BÜRKÜT, sadece toolları çalıştırmak değil, bir "Mühendislik Felsefesi" oturtmak üzerine kuruludur:

### **1. The Trilogy (Üçlü Doğrulama Prensibi)**

Bir savunma hamlesinin (Active Response) başarılı sayılması için 3 şart aranır:

1. **SIEM Alert:** Wazuh "Tehdit engellendi" logunu üretmeli.
    
2. **State Change:** Firewall veya iptables kurallarında IP'nin banlandığı görülmeli.
    
3. **Innocent Traffic Test:** Saldırgan engellenirken, masum kullanıcının (Noise Traffic) erişimi kesintisiz devam etmeli (Servis sürekliliği).
    

### **2. Guardrails (AI Güvenlik Kilitleri)**

Yapay zekanın kontrolden çıkmasını önlemek için 2 katmanlı kilit sistemi uygulanır:

- **Yazılımsal Kilit (Middleware):** AI'ın ürettiği komutlar önce Python scripti tarafından taranır. "rm -rf", "shutdown" gibi yıkıcı komutlar reddedilir.
    
- **Ağ Kilidi (pfSense & iptables):** AI ajanı istese bile `192.168.1.x` (Ev Ağı) bloğuna paket gönderemez; paketler Gateway seviyesinde düşürülür (DROP).
    

### **3. IaC ve Kalıcı İyileştirme**

Zafiyet bulunduğunda süreç şöyle işler:

- **Manuel Analiz:** Önce elle sömürülür ve analiz edilir.
    
- **Otomasyon:** Çözüm, bir Bash veya Ansible scriptine (Hardening Script) dönüştürülür.
    
- **Self-Correction:** Sistem bir sonraki kurulumda bu script ile "Doğuştan Güvenli" (Secure by Design) olarak ayağa kalkar.
    

---

> [!check] Sonuç Bu altyapı; bir siber güvenlik öğrencisinin "Script Kiddie" seviyesinden, sistemin mimarisini ve ruhunu anlayan bir **"Güvenlik Mimarı"** seviyesine evrilmesi için tasarlanmıştır.
