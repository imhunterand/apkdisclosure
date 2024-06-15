# APK Disclosure Scanner Tool

## Deskripsi
Alat ini dikembangkan untuk memindai file APK (Android Package) guna mendeteksi URIs, endpoints, dan secrets yang tersembunyi di dalam kode sumber. Kebocoran informasi sensitif seperti ini, yang dikenal sebagai "APK Sensitive Leaks," dapat menjadi celah keamanan yang serius. Alat ini membantu pengembang aplikasi Android untuk melakukan audit keamanan dan mengidentifikasi potensi kerentanan sebelum aplikasi dipublikasikan.

## Fitur yang Ditambahkan
1. Ekstraksi Email: Mendeteksi alamat email dalam file APK.
2. Ekstraksi Alamat IP: Mendeteksi alamat IP dalam file APK.
3. Pembuatan Hash (MD5, SHA-1, SHA-256): Menghasilkan hash dari file APK untuk tujuan keamanan.
4. Integrasi VirusTotal: Memeriksa hash file di VirusTotal menggunakan API untuk mendapatkan laporan deteksi malware.

## Tata Cara Penggunaan
1. **Persiapan**: Pastikan Python telah terinstal di lingkungan Anda. Install library yang diperlukan dengan menjalankan `pip install -r requirements.txt`.
2. **Menjalankan Alat**: Buka terminal atau command prompt, lalu jalankan alat dengan perintah:
   ```bash
   python apk_scanner.py
```
3. **Input:** Masukkan path lengkap ke file APK yang ingin Anda pindai.
4. **Output:** Hasil pemindaian akan ditampilkan di terminal dan disimpan dalam file JSON.

### Contoh Output di Terminal
```
Scanning APK: /path/to/your/app.apk

Found URIs/Endpoints:
https://example.com/api/v1/resource
http://anotherexample.com/login

Found Secrets:
api_key_12345
password_example

Found Emails:
user@example.com

Found IP Addresses:
192.168.1.1

Hashes:
md5: d41d8cd98f00b204e9800998ecf8427e
sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709
sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Results saved to /path/to/your/results.json

Checking MD5 hash on VirusTotal...
{
    "scans": {
        ...
    }
}

Checking SHA1 hash on VirusTotal...
{
    "scans": {
        ...
    }
}

Checking SHA256 hash on VirusTotal...
{
    "scans": {
        ...
    }
}
```
### Contoh Output JSON
```
{
    "uris": [
        "https://example.com/api/v1/resource",
        "http://anotherexample.com/login"
    ],
    "secrets": [
        "api_key_12345",
        "password_example"
    ],
    "emails": [
        "user@example.com"
    ],
    "ip_addresses": [
        "192.168.1.1"
    ],
    "urls": [
        "https://example.com/api/v1/resource",
        "http://anotherexample.com/login"
    ],
    "hashes": {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "virustotal_md5": {
        "scans": {
            ...
        }
    },
    "virustotal_sha1": {
        "scans": {
            ...
        }
    },
    "virustotal_sha256": {
        "scans": {
            ...
        }
    }
}
```
## Kesimpulan
Alat ini memberikan solusi komprehensif untuk mengidentifikasi kebocoran informasi sensitif dalam file APK. Dengan fitur seperti deteksi URIs, endpoints, secrets, email, dan alamat IP, serta pembuatan hash dan integrasi dengan VirusTotal, pengembang dapat secara proaktif meningkatkan keamanan aplikasi Android mereka. File hasil JSON memungkinkan analisis lebih lanjut terhadap informasi yang ditemukan dan laporan deteksi malware dari VirusTotal. Alat ini direkomendasikan untuk digunakan dalam proses pengembangan dan pengujian aplikasi Android untuk mengurangi risiko keamanan.



### Tools Preview
|    main.py    |
| ------------- |
|![Index](assets/test.png)|





  ### Author

- [@Imhunterand](https://www.github.com/imhunterand)
- [@PWN0SEC](https://www.github.com/pwn0sec)
