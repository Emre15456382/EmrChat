# EmrChat v3.0
Telefon numarasız mesajlaşma: kullanıcı adı + şifre, arkadaşlar, gruplar, arama, sesli mesaj, sesli/görüntülü arama, profil kozmetikleri, ban/şikayet.

## Dosyalar (hepsi ana dizinde, klasör yok)
`server.js`, `index.html`, `package.json`, `LICENSE`, `README.md`

## Render ayarları
- Build Command: `npm install`  · Start Command: `npm start` · Instance: Free
- Ortam değişkenleri: `JWT_SECRET`, `OWNER_PASSWORD` (Emre15456382), `OWNER2_PASSWORD` (Eren1545_0), `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`
- İsteğe bağlı (farklı ağlarda arama): `METERED_APP` + `METERED_KEY`

## Kontrol
`https://SITEN.onrender.com/api/status` adresini aç: sürüm `3.0`, db `bulut`, ok `true` olmalı. Giriş ekranının altında da aynı durum yazar.

## Kurucular
`emre15456382` ve `eren1545_0` ayrılmıştır, etiketleri DEV'dir. Her biri kendi şifresiyle (OWNER_PASSWORD / OWNER2_PASSWORD) kayıt olur. Ban, şikayet ve özel kozmetik yetkisi sadece kurucularda (⚙ → Kurucu paneli).

## Lisans
MIT. © 2026 Emre Yıldız.
