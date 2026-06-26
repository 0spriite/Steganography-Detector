# Steganography Detector 🔍

> Tool digital forensics untuk mendeteksi pesan tersembunyi dalam gambar menggunakan analisis statistik multi-metode.

---

## Fitur

- **LSB Randomness Analysis** — mendeteksi tingkat keacakan tidak wajar pada Least Significant Bit setiap channel warna
- **Chi-Square Test** — uji distribusi pasangan nilai pixel untuk mendeteksi LSB embedding
- **Histogram Anomaly Detection** — mendeteksi *comb effect* pada histogram akibat manipulasi bit
- **RS (Regular-Singular) Analysis** — estimasi keberadaan payload berdasarkan asimetri kelompok pixel
- **LSB Message Extractor** — percobaan ekstraksi pesan tersembunyi secara otomatis
- **Multi-format Report** — output laporan dalam format TXT, JSON, dan HTML interaktif

---

## Instalasi

```bash
git clone https://github.com/username/stego-detector.git
cd stego-detector
pip install -r requirements.txt
```

**Persyaratan:** Python 3.9+

---

## Penggunaan

### Jalankan Demo

```bash
python main.py demo
```

Membuat gambar sample, menyematkan pesan, lalu mendeteksinya secara otomatis.

### Analisis Gambar

```bash
# Satu file
python main.py analyze foto_bukti.png

# Seluruh folder
python main.py analyze ./folder_bukti/

# Dengan laporan tersimpan
python main.py analyze ./folder_bukti/ --output laporan_kasus1
```

Output laporan: `laporan_kasus1.txt`, `laporan_kasus1.json`, `laporan_kasus1.html`

### Sembunyikan Pesan (Testing)

```bash
python main.py embed gambar_asli.png "pesan rahasia" gambar_output.png
```

### Ekstrak Pesan

```bash
python main.py extract gambar_output.png
```

---

## Format yang Didukung

| Format | Ekstensi | Catatan |
|--------|----------|---------|
| PNG    | `.png`   | Direkomendasikan, lossless |
| BMP    | `.bmp`   | Lossless |
| TIFF   | `.tiff`, `.tif` | Lossless |
| JPEG   | `.jpg`, `.jpeg` | Deteksi terbatas (lossy compression) |
| WebP   | `.webp`  | Dukungan terbatas |

> **Catatan:** Steganografi LSB paling efektif pada format lossless (PNG, BMP). Format lossy seperti JPEG merusak LSB saat kompresi.

---

## Contoh Output

```
=================================================================
       STEGANOGRAPHY DETECTION REPORT — DIGITAL FORENSICS
=================================================================
  Tanggal Analisis : 2024-11-15 14:32:07
  Total File       : 2
  File Mencurigakan: 1
=================================================================

[1] clean_photo.png  [✓ BERSIH]
    Ukuran      : 245,120 bytes
    Dimensi     : 512x512 px  Mode: RGB
    Confidence  : Clean

    Hasil Analisis:
    Test                      Status           Score/p-value
    -------------------------------------------------------
    LSB Randomness            Normal           0.3821
    Chi-Square Test           Normal           p=0.843200
    Histogram Anomaly         Normal           0.0512
    RS Analysis               Normal           0.0031

[2] suspicious.png  [⚠ MENCURIGAKAN]
    Ukuran      : 245,122 bytes
    Dimensi     : 512x512 px  Mode: RGB
    Confidence  : High

    Hasil Analisis:
    Test                      Status           Score/p-value
    -------------------------------------------------------
    LSB Randomness            MENCURIGAKAN     0.4987
    Chi-Square Test           MENCURIGAKAN     p=0.000023
    Histogram Anomaly         MENCURIGAKAN     0.2341
    RS Analysis               MENCURIGAKAN     0.0892

    *** PESAN DITEMUKAN: "DATA RAHASIA KASUS #2024"
```

---

## Cara Kerja

### 1. LSB Randomness Analysis
Gambar normal memiliki LSB yang berkorelasi dengan pixel tetangga (tidak acak). Saat pesan disembunyikan menggunakan LSB embedding, bit-bit ini menjadi hampir acak sempurna dengan skor mendekati **0.5**.

### 2. Chi-Square Test
Teknik LSB standar membuat frekuensi pasangan nilai `(2n, 2n+1)` menjadi hampir identik. Chi-square test mendeteksi penyimpangan distribusi ini. **p-value < 0.05** mengindikasikan anomali.

### 3. Histogram Anomaly
LSB embedding menghasilkan *comb effect* — grafik histogram bergerigi tidak wajar karena pasangan nilai saling bertukar frekuensi. Skor tinggi menunjukkan pola ini terdeteksi.

### 4. RS Analysis
Regular-Singular analysis mengklasifikasikan kelompok pixel menjadi Regular (R), Singular (S), dan Unusable (U). Rasio R dan S berubah secara prediktif saat steganografi diterapkan, menghasilkan asimetri yang dapat diukur.

### Verdict
| Jumlah Test Positif | Confidence |
|---------------------|-----------|
| 0 | Clean |
| 1 | Low |
| 2 | Medium |
| 3 | High |
| 4 | Very High |

File dinyatakan **mencurigakan** jika minimal 2 dari 4 test positif.

---

## Struktur Proyek

```
stego-detector/
├── main.py              # CLI entrypoint
├── requirements.txt
├── src/
│   ├── detector.py      # Core analysis engine (4 metode)
│   ├── embedder.py      # LSB embedder untuk testing
│   └── reporter.py      # Generator laporan TXT/JSON/HTML
├── samples/             # Gambar uji (dibuat saat demo)
└── reports/             # Output laporan
```

---

## Keterbatasan

- Deteksi optimal untuk **steganografi LSB pada format lossless**
- Format JPEG mengurangi akurasi deteksi karena kompresi lossy merusak LSB
- Bukan pengganti tool forensik profesional (Steghide, StegExpose, dll)
- Tidak mendeteksi metode steganografi non-LSB (DCT, palette-based, dll)

---

## Disclaimer

> Tool ini dibuat untuk keperluan **pendidikan dan forensik digital**. Penggunaan untuk tujuan ilegal adalah tanggung jawab pengguna sepenuhnya. Selalu patuhi hukum yang berlaku dan dapatkan izin yang diperlukan sebelum menganalisis perangkat atau file milik orang lain.

---

## Lisensi

MIT License — bebas digunakan untuk keperluan edukasi dan riset.
