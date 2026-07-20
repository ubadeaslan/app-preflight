# Backlog — Nokturn lansman dersleri (B1–B37)

Kaynak: `c:/Users/ubade/app-factory/apps/nokturn/lansman-dersleri-2026-07.md` §BÖLÜM B
(2026-07 Nokturn App Store lansmanında yaşanan gerçek olaylardan türetilen kural seti).
Takip defteri: app-factory `FLYWHEEL.md`.

Durumlar: **yazıldı** (check ID'siyle canlı) · **açık** (yapılacak) ·
**manuel** (otomatikleştirilemez, /magaza-hazirlik checklist'inde kalır).

## Statik katman (proje / .ipa / fastlane metadata)

| B | Kural | Durum |
|---|-------|-------|
| B1 | Purpose string ↔ SDK/API eşlemesi | **yazıldı — IOS-BIN-008** (binary sembol taraması; ITMS-90683) |
| B3 | Reddedilen build numarası yakılır → otomatik +n | açık (ASC build listesiyle karşılaştırma ister — ASC katmanına) |
| B4 | Deployment target ↔ SDK gereksinimi | **kısmen yazıldı — IOS-CONFIG-011** (pbxproj tutarlılık; SDK-gereksinim eşlemesi açık) |
| B5 | Release binary'de ENV assert'i (dart-define prod doğrulaması) | açık (Flutter'a özgü; Generated.xcconfig DART_DEFINES base64 decode) |
| B6 | Cihaz ailesi ↔ ekran görüntüsü seti | **yazıldı — IOS-BIN-009** (UIDeviceFamily; ASC screenshot çapraz kontrolü ASC katmanına) |
| B7 | Yön kilidi (landscape test edilmediyse portrait-only) | açık (Info.plist UISupportedInterfaceOrientations — info seviyesi) |
| B8 | Görünür sürüm etiketi == mağaza sürümü | manuel (kaynak kodda hardcode sürüm avı güvenilir değil) |
| B9 | İstemci timeout > sunucu timeout | manuel (iki ayrı repo/dil; kod incelemesi işi) |
| B10 | Subtitle keyword listesi olmasın (2.3.7) | **yazıldı — IOS-STORE-002** |
| B11 | Metadata'da olmayan özellik vaadi (2.3.1) | manuel (anlam analizi ister) |
| B12 | Alakasız/yasaklı kategori kelimesi | açık (yapılandırılabilir kelime listesi — düşük öncelik) |
| B13 | Sayısal iddialar gerçekle eşleşsin ("N dil" ↔ ARB sayısı) | açık (Flutter'a özgü) |
| B14 | Karakter limitleri (subtitle 30 / keywords 100 / promo 170) | **yazıldı — IOS-STORE-001** (fastlane dosyaları; ASC tarafı IOS-META-006) |
| — | "iPhone Developer" CODE_SIGN_IDENTITY pini (imza savaşı A1.6) | **yazıldı — IOS-CONFIG-012** |

## ASC API katmanı (metadata client genişletmesi)

| B | Kural | Durum |
|---|-------|-------|
| B2 | buildUploads'tan işleme reddi izleme | açık |
| B19 | Abonelik metadata tam seti (locale ad+açıklama 45kr + screenshot + fiyat) | açık |
| B20 | Fiyat: baz ülke yetmez — manualPrices + equalizations kontrolü | açık |
| B21 | Intro offer ülke başına | açık |
| B22 | Age rating appInfos alanları | açık |
| B23 | App Privacy API'de yok | **manuel** (tek doğrulayıcı submit'in kendisi) |
| B24 | appStoreReviewDetail zorunlu (ad+telefon+e-posta) | açık (mevcut ReviewDetail modeline yakın — kolay) |
| B25 | Demo hesap + içerik tohumu | manuel (IOS-META-003 varlığını kontrol ediyor; tohum manuel) |
| B26 | TestFlight internal betaGroup + tester akışı | manuel/prosedür |
| B27 | Build listesi sorgusu filter[app] ile | (implementasyon notu — B2 yazılırken uygulanır) |
| B28 | deliver metadata/screenshot lane ayrımı | prosedür (playbook-05 §16.3) |
| B35 | appAvailabilityV2 set edilmiş mi | açık — **yüksek öncelik (submit blokeri)** |
| B36 | appPriceSchedule manualPrices dolu mu | açık — **yüksek öncelik (submit blokeri)** |
| B37 | Submit-simülasyonu (reviewSubmissionItems → associatedErrors → geri al) | açık — en değerli tek check adayı |

## Çalışma zamanı (yalnız macOS)

| B | Kural | Durum |
|---|-------|-------|
| B32 | simctl boot duman testi + screenshot | açık (ayrı komut/lane; Windows'ta koşmaz) |
| B33 | Bildirim kanıtı (usernotificationsd log) | açık (aynı) |
| B34 | Mac "Designed for iPhone" sandbox IAP testi | manuel/prosedür |

## Paywall/gizlilik kaynak taramaları (düşük güven — heuristik)

| B | Kural | Durum |
|---|-------|-------|
| B15 | Deneme şart cümlesi her trial'lı kartta | manuel (l10n metin analizi; playbook-11 §5.1 checklist) |
| B16 | "Hazır değiliz" dili yasak | manuel (aynı) |
| B17 | Paywall vaatleri ↔ sunucu teslimi | manuel |
| B29 | Privacy label ↔ gerçek toplama (FCM token vb.) | manuel (denetim-gizlilik skill'i kapsıyor) |
| B30 | deleteAccount hata yutmasın | manuel (code review konusu) |
| B31 | Email girişi varsa şifre sıfırlama yolu | açık (heuristik: FirebaseAuth + sendPasswordReset yokluğu — düşük öncelik) |
