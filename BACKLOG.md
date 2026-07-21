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
| B3 | Reddedilen build numarası yakılır → otomatik +n | **yazıldı — IOS-META-011** (2026-07-21; builds + buildUploads max'ı ↔ CFBundleVersion; Flutter'ın `$(FLUTTER_BUILD_NUMBER)` değişkeninde sessiz kalır) |
| B4 | Deployment target ↔ SDK gereksinimi | **kısmen yazıldı — IOS-CONFIG-011** (pbxproj tutarlılık; SDK-gereksinim eşlemesi açık) |
| B5 | Release binary'de ENV assert'i (dart-define prod doğrulaması) | **yazıldı — IOS-CONFIG-014** (2026-07-21; Generated.xcconfig DART_DEFINES base64 decode, ENV/APP_ENV/ENVIRONMENT ≠ prod → uyarı; dosya gitignore'lu olduğundan tam arşiv makinesinde ateşler. `kReleaseMode` assert yarısı kod tarafı — starter main şablonunda) |
| B6 | Cihaz ailesi ↔ ekran görüntüsü seti | **yazıldı — IOS-BIN-009** (UIDeviceFamily; ASC screenshot çapraz kontrolü ASC katmanına) |
| B7 | Yön kilidi (landscape test edilmediyse portrait-only) | **yazıldı — IOS-CONFIG-013** (2026-07-21; portrait+landscape birlikte = info; salt-landscape bilinçli sayılır, sessiz) |
| B8 | Görünür sürüm etiketi == mağaza sürümü | manuel (kaynak kodda hardcode sürüm avı güvenilir değil) |
| B9 | İstemci timeout > sunucu timeout | manuel (iki ayrı repo/dil; kod incelemesi işi) |
| B10 | Subtitle keyword listesi olmasın (2.3.7) | **yazıldı — IOS-STORE-002** |
| B11 | Metadata'da olmayan özellik vaadi (2.3.1) | manuel (anlam analizi ister) |
| B12 | Alakasız/yasaklı kategori kelimesi | açık (yapılandırılabilir kelime listesi — düşük öncelik) |
| B13 | Sayısal iddialar gerçekle eşleşsin ("N dil" ↔ ARB sayısı) | **yazıldı — IOS-STORE-003** (2026-07-21; 19 dilde "N language" kelime eşleme + benzersiz ARB dil sayımı, bölgesel varyantlar tekilleştirilir. İlk canlı koşuda gerçek bulgu: Nokturn metadata "16 dil" ↔ 30 ARB dili) |
| B14 | Karakter limitleri (subtitle 30 / keywords 100 / promo 170) | **yazıldı — IOS-STORE-001** (fastlane dosyaları; ASC tarafı IOS-META-006) |
| — | "iPhone Developer" CODE_SIGN_IDENTITY pini (imza savaşı A1.6) | **yazıldı — IOS-CONFIG-012** |

## ASC API katmanı (metadata client genişletmesi)

| B | Kural | Durum |
|---|-------|-------|
| B2 | buildUploads'tan işleme reddi izleme | **yazıldı — IOS-META-010** (2026-07-21; en son upload'ın `state.errors[]`'u; canlı doğrulama sıradaki build'de) |
| B19 | Abonelik metadata tam seti (locale ad+açıklama 45kr + screenshot + fiyat) | **yazıldı — IOS-META-012** (2026-07-21; ASC'nin kendi `MISSING_METADATA` durumu üzerinden — tek tek saymak yerine ASC'nin hükmü) |
| B20 | Fiyat: baz ülke yetmez — equalizations kontrolü | **yazıldı — IOS-META-013** (2026-07-21; tek territory fiyatı = uyarı) |
| B21 | Intro offer ülke başına | **yazıldı — IOS-META-014** (2026-07-21; kısmi kapsam uyarısı; 0 offer = trial yok, sessiz) |
| B22 | Age rating appInfos alanları | **yazıldı — IOS-META-015** (2026-07-21; tüm alanlar null = hiç doldurulmamış) |
| B23 | App Privacy API'de yok | **manuel** (tek doğrulayıcı submit'in kendisi) |
| B24 | appStoreReviewDetail zorunlu (ad+telefon+e-posta) | **yazıldı — IOS-META-009** (2026-07-21; kaynak yoksa VEYA ad/telefon/e-posta boşsa) |
| B25 | Demo hesap + içerik tohumu | manuel (IOS-META-003 varlığını kontrol ediyor; tohum manuel) |
| B26 | TestFlight internal betaGroup + tester akışı | manuel/prosedür |
| B27 | Build listesi sorgusu filter[app] ile | **uygulandı** (IOS-META-010/011 fetch'i `/v1/builds?filter[app]` kullanır — relationship path sort ile 400 verdiğinden) |
| B28 | deliver metadata/screenshot lane ayrımı | prosedür (playbook-05 §16.3) |
| B35 | appAvailabilityV2 set edilmiş mi | **yazıldı — IOS-META-007** (2026-07-21; 404/boş data = hiç kurulmamış) |
| B36 | appPriceSchedule manualPrices dolu mu | **yazıldı — IOS-META-008** (2026-07-21; schedule 200 yanıltır, manualPrices satırı şart) |
| B37 | Submit-simülasyonu (reviewSubmissionItems → associatedErrors → geri al) | **yazıldı — `preflight submit-sim` komutu** (2026-07-21; yazma içerdiğinden check değil ayrı komut; bitmemiş submission varsa dokunmadan çekilir. Canlı test bekliyor: guard yolu Nokturn incelemedeyken, blocked/clean yolları bir sonraki uygulamada) |

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
