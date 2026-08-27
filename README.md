# NGFW Lab

NGFW Lab, Linux ve nftables üzerinde çalışan web tabanlı bir firewall yönetim prototipidir. Projenin amacı, yöneticinin panelden oluşturduğu kuralları doğrulamak, nftables kurallarına dönüştürmek ve NGFW sanal makinesinde güvenli biçimde uygulamaktır.

Bu sürüm tam kapsamlı bir NGFW ürünü değildir. Stateful firewall, NAT ve politika yönetimi için çalışan bir MVP/laboratuvar ortamıdır.

## Mimari

```text
Yönetici
   |
   v
Django paneli
   |
   | JSON / HTTP API
   v
Go config-agent
   |
   | doğrulama, render, kontrol ve uygulama
   v
nftables / Linux kernel
   |
   v
LAN ve WAN trafiği
```

Django paneli kuralları ve uygulama geçmişini veritabanında tutar. Go config-agent gelen politikayı yeniden doğrular, nftables biçimine çevirir, `nft -c` ile kontrol eder ve ardından çalışan ruleset'e uygular. Gerçek ağ trafiğini Django veya Go değil, Linux kernelindeki nftables yönetir.

## Mevcut özellikler

- Stateful paket filtreleme
- LAN ve WAN zone'larına göre kural oluşturma
- Kaynak ve hedef CIDR kontrolü
- TCP, UDP, ICMP ve ANY protokol desteği
- TCP/UDP hedef portu desteği
- İzin verme ve engelleme kuralları
- Kural önceliği, aktiflik ve log seçenekleri
- Varsayılan `forward drop` politikası
- `established,related` bağlantıların takibi
- Geçersiz bağlantıların düşürülmesi
- LAN'dan WAN'a masquerade NAT
- Django ve Go tarafında ayrı doğrulama
- Candidate nftables ruleset üretimi
- `nft -c` ile uygulama öncesi kontrol
- Policy uygulama, geçmiş ve rollback işlemleri
- Firewall loglarını panelden görüntüleme
- API tokeni ile config-agent erişim kontrolü
- systemd ile config-agent ve nftables servislerinin otomatik başlaması

## Laboratuvar topolojisi

Projede üç Rocky Linux sanal makinesi bulunur:

| Makine | Rol | Adresler |
|---|---|---|
| `ngfw` | Firewall ve router | Management: `192.168.60.10`, WAN: `10.10.10.1`, LAN: `192.168.50.1` |
| `internet-sim` | WAN tarafındaki test sunucusu | `10.10.10.10` |
| `lan-client` | Korunan LAN istemcisi | `192.168.50.10` |

NGFW arayüzleri:

| Arayüz | Görev |
|---|---|
| `eth0` | VirtualBox NAT ve Vagrant SSH |
| `eth1` | Management ağı |
| `eth2` | WAN ağı |
| `eth3` | LAN ağı |

LAN'dan WAN'a örnek trafik yolu:

```text
lan-client 192.168.50.10
→ ngfw eth3
→ nftables forward zinciri
→ masquerade
→ ngfw eth2
→ internet-sim 10.10.10.10
```

## Policy uygulama akışı

1. Yönetici Django panelinde kuralları oluşturur veya düzenler.
2. Kurallar Django veritabanına kaydedilir.
3. Yönetici `Policy'yi uygula` düğmesine basar.
4. Django aktif kuralları öncelik sırasına göre JSON olarak hazırlar.
5. JSON, management ağı üzerinden Go config-agent'a gönderilir.
6. Config-agent policy'yi doğrular.
7. `render.go` candidate nftables ruleset'ini üretir.
8. Candidate `nft -c` ile kontrol edilir.
9. Geçerli ruleset yedeklenir ve candidate uygulanır.
10. Sonuç ve policy geçmişi panelde gösterilir.

## Proje yapısı

```text
ngfw-lab/
├── Vagrantfile
├── backend/
│   ├── manage.py
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── Django proje ayarları
│   └── policies/
│       ├── models.py
│       ├── forms.py
│       ├── views.py
│       ├── urls.py
│       ├── migrations/
│       ├── templates/
│       └── static/
└── config-agent/
    ├── go.mod
    ├── main.go
    ├── validation.go
    ├── render.go
    ├── apply.go
    ├── server.go
    ├── logs.go
    ├── policy.json
    └── ngfw-candidate.nft
```

## Kullanılan teknolojiler

- Rocky Linux 9
- Vagrant
- VirtualBox
- nftables
- Go
- Django
- Docker
- systemd

## Laboratuvarı başlatma

Gerekli araçlar kurulduktan sonra proje dizininde:

```bash
vagrant up --provider=virtualbox
vagrant status
```

Sanal makinelere erişmek için:

```bash
vagrant ssh ngfw
vagrant ssh internet-sim
vagrant ssh lan-client
```

Config-agent sağlık kontrolü:

```bash
curl http://192.168.60.10:8080/health
```

Django paneli çalışırken tarayıcıdan şu adres kullanılır:

```text
http://127.0.0.1:8000
```

## Durum ve sınırlar

Proje geliştirme ve öğrenme amaçlı bir laboratuvar prototipidir. Mevcut sürümde ağ adresleri, zone-arayüz eşleştirmeleri ve masquerade NAT laboratuvar topolojisine bağlıdır. HTTP tabanlı management API de üretim ortamına taşınmadan önce TLS ile korunmalıdır.

Planlanan temel geliştirmeler arasında güvenli policy onayı ve otomatik rollback, kural sayaçları, aktif bağlantı görünürlüğü, DNAT/port forwarding, dinamik arayüz-zone yönetimi ve Suricata IDS/IPS entegrasyonu bulunmaktadır.
