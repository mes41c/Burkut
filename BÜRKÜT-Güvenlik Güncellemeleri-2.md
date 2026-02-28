
### **BÜRKÜT PROJESİ: GÜVENLİK MİMARİSİ GÜNCELLEME PAKETİ (v3.0)**

#### **5. Aldatma Mimarisi: Gölge ve Yem (Deception & Honeypot)**

> **🗣️ İlhan Hoca:** * "Bir şey diyim mi tuzak kurmak aslında çok daha mantıklı." * "Tuzak kurup orada alarm verdirip yakalayacak bir sistem :)" * "Diğer türlü her seferinde bir şey çıkacaktır çünkü ve kisitlamalara gidecek olay"

- **Mimari Karar:** Savunma, sürekli engelleme (Block) yerine saldırganı yanlış hedeflere yönlendirme üzerine kuruldu.
    
- **Teknik Aksiyon (Katmanlı Tuzak):**
    
    1. **Network Decoy (Ağ Yemi):** Ağda aslında var olmayan IP adresleri (Hayalet Varlıklar) için ARP cevapları üreten bir script çalıştırılacak. Tarama yapan saldırgan, gerçek AI sunucusu yerine bu sahte servislerle vakit kaybedecek ve o IP'lere herhangi saldırı girişimi tespit edilirse saldırgan IP'si banlanacak.
        
    2. **Embedded Honeytoken (Gömülü Dosya Yemi):** Projenin gerçek `config.yaml` dosyası içine, sanki unutulmuş eski bir AWS/API anahtarıymış gibi sahte bir "Secret Key" gömülecek. Bu anahtar kullanıldığı an alarm çalacak.
        
- **Kazanım:** Saldırganın keşif süreci sabote edilir ve gerçek sisteme dokunmadan ifşa olması sağlanır.
    

#### **6. Protokol ve Trafik Anomalisi Tespiti (Anti-Tunneling)**

> **🗣️ İlhan Hoca:** * "3337 neden hatirliyorum bilmiyorum :) ... 3337 neden aklımda böyle bir seneryo da onu çözemedim" * "Gerçi port önemli mi şimdilik önemli değil" * "Proje de iç agi komple kontrol edecek bir şey lazım"

- **Mimari Karar:** Savunma sadece port numaralarına (Statik) değil, trafiğin karakteristiğine (Dinamik) odaklanacak.
    
- **Teknik Aksiyon:**
    
    1. **Honeyport (Tuzak Port):** 3337 gibi standart dışı portlar kapatılmayacak, "Tuzaklı" olarak açık bırakılacak. Bu portlara gelen her bağlantı (SYN), kaynağı otomatik banlayacak.
        
    2. **Whitelist Koruması:** Kendi yönetim IP'miz (`192.168.100.5`) ve Gateway (`192.168.100.1`) **Beyaz Liste**'ye alınarak, operatörün yanlışlıkla kendini kilitlemesi engellenecek.
        
    3. **Beaconing Analizi:** HTTPS/DNS üzerinden tünel açılsa bile, paketlerin "Kalp Atış Ritmi" (Low Jitter Frequency) analiz edilerek makine davranışı tespit edilecek.
        
- **Kazanım:** Tünelleme girişimleri porttan bağımsız olarak yakalanır.
    

#### **7. Davranışsal Zeka (UEBA & Quantum Intelligence)**

> **🗣️ İlhan Hoca:** * "Merkezi ama quantum intelligence." * "Kendi kendine de ogrenmeli sistem" * "Kullaniciyi da öğrenmeli extension desteği de olabilir"

- **Mimari Karar:** "Statik Şifre Doğrulama" yerine "Risk Skorlaması"na geçilecek.
    
- **Teknik Aksiyon:**
    
    - **Kullanıcı Profilleme:** Operatörün çalışma saatleri, klavye vuruş hızı (Keystroke Dynamics) ve kullandığı komut sözlüğü (Vocabulary), semantiği(komut parametreleri) baz alınarak bir "Normal" (Baseline) oluşturulacak.
        
    - **Anomali Tepkisi:** Şifre doğru olsa bile; anormal saat, aşırı hızlı komut girişi (Script/Paste) tespit edildiğinde oturum kilitlenecek.
        
- **Kazanım:** Şifre çalınsa (Credential Theft) bile, saldırganın "davranışsal parmak izi" taklit edilemeyeceği için sistem korunur.
    

#### **8. Anti-Zehirlenme ve Soy Ağacı (Process Lineage)**

> **🗣️ İlhan Hoca:** * "Kendi kendine de ogrenmeli sistem" _(Risk: Model Zehirlenmesi)_ * "Diğer türlü her seferinde bir şey çıkacaktır" _(İhtiyaç: Kararlılık)_

- **Mimari Karar:** Dinamik öğrenme süreci, manipülasyonu engellemek için "Frozen Core" (Kilitli Çekirdek) mantığıyla sınırlandırılacak.
    
- **Teknik Aksiyon:**
    
    1. **Process Lineage (Soy Ağacı):** Web servislerinden (Apache/Tomcat) doğan Shell (`/bin/bash`) veya Derleyici (`python`) işlemleri, skorlamaya bakılmaksızın **DERHAL** engellenecek.
        
    2. **Frozen Baseline:** Sistemin ilk kurulumundaki güvenli durum kilitlenecek. Saldırganın zamana yaydığı yavaş değişiklikler (Low and Slow) "Yeni Normal" olarak kabul edilmeyecek.

    3. **Tuzak-Tetiklemeli Öğrenme Durdurma (Trap-Triggered Freeze):** **Bölüm 5**'te tanımlanan "Honeytoken" (Yem Dosyalar) veya "Network Decoy" erişimi tespit edildiği anda, UEBA sisteminin "Öğrenme Modu" (Adaptive Learning) **derhal ve kalıcı olarak** devre dışı bırakılır.
    
- Sistem, "Mayına basan" bir varlığın davranışlarını analiz etmeyi bırakır ve doğrudan "İnfaz Modu"na (Isolation) geçer. Bu sayede saldırganın tuzağa düştükten sonra ürettiği gürültü ile sistemi zehirleme ihtimali matematiksel olarak sıfırlanır.
        
- **Kazanım:** Saldırgan sistemi yavaşça manipüle etmeye çalışsa bile, "Kırmızı Çizgi" ihlallerinde sistemin tolerans göstermesi (Haşlanmış Kurbağa Sendromu) engellenir.