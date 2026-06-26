#!/usr/bin/env python3
"""
Steganography Detector — CLI
Digital Forensics Tool untuk mendeteksi pesan tersembunyi dalam gambar

Penggunaan:
  python main.py analyze  <gambar_atau_folder> [--output laporan]
  python main.py embed    <gambar> <pesan> <output>
  python main.py extract  <gambar>
  python main.py demo
"""

import sys
import os
import argparse
import time

sys.path.insert(0, os.path.dirname(__file__))

from src.detector import SteganographyDetector
from src.embedder import embed_message, extract_message
from src.reporter import generate_text_report, generate_json_report, generate_html_report


SUPPORTED_FORMATS = {'.png', '.bmp', '.tiff', '.tif', '.jpg', '.jpeg', '.webp'}

BANNER = r"""
  ███████╗████████╗███████╗ ██████╗  ██████╗ 
  ██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗
  ███████╗   ██║   █████╗  ██║  ███╗██║   ██║
  ╚════██║   ██║   ██╔══╝  ██║   ██║██║   ██║
  ███████║   ██║   ███████╗╚██████╔╝╚██████╔╝
  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ 
  Steganography Detector v1.0 | Digital Forensics
"""


def collect_images(path: str) -> list:
    """Kumpulkan semua file gambar dari path (file atau folder)."""
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        if ext in SUPPORTED_FORMATS:
            return [path]
        print(f"[!] Format tidak didukung: {ext}")
        return []

    images = []
    for root, _, files in os.walk(path):
        for f in sorted(files):
            if os.path.splitext(f)[1].lower() in SUPPORTED_FORMATS:
                images.append(os.path.join(root, f))
    return images


def cmd_analyze(args):
    """Analisis satu atau banyak gambar."""
    images = collect_images(args.target)
    if not images:
        print(f"[!] Tidak ada gambar ditemukan di: {args.target}")
        return 1

    detector = SteganographyDetector()
    results = []

    print(f"\n[+] Memulai analisis {len(images)} file...\n")
    for i, path in enumerate(images, 1):
        print(f"  [{i}/{len(images)}] Menganalisis: {os.path.basename(path)}", end=" ", flush=True)
        t0 = time.time()
        try:
            result = detector.analyze(path)
            results.append(result)
            elapsed = time.time() - t0
            verdict = "⚠ MENCURIGAKAN" if result.overall_suspicious else "✓ bersih"
            print(f"→ {verdict}  [{elapsed:.2f}s]")
        except Exception as e:
            print(f"→ ERROR: {e}")

    print()
    report_txt = generate_text_report(results)
    print(report_txt)

    # Simpan laporan jika diminta
    if args.output:
        base = args.output
        generate_text_report(results, f"{base}.txt")
        generate_json_report(results, f"{base}.json")
        generate_html_report(results, f"{base}.html")
        print(f"\n[+] Laporan disimpan:")
        print(f"    {base}.txt")
        print(f"    {base}.json")
        print(f"    {base}.html")

    return 0


def cmd_embed(args):
    """Sembunyikan pesan dalam gambar."""
    print(f"\n[+] Menyembunyikan pesan dalam: {args.image}")
    try:
        bits = embed_message(args.image, args.message, args.output)
        print(f"[+] Berhasil! {bits} bit ({bits//8} byte) disematkan")
        print(f"[+] Output: {args.output}")
    except Exception as e:
        print(f"[!] Gagal: {e}")
        return 1
    return 0


def cmd_extract(args):
    """Coba ekstrak pesan dari gambar."""
    print(f"\n[+] Mencoba ekstrak pesan dari: {args.image}")
    msg = extract_message(args.image)
    if msg:
        print(f"[+] Pesan ditemukan: \"{msg}\"")
    else:
        print("[-] Tidak ada pesan teks yang dapat diekstrak (metode LSB standar)")
    return 0


def cmd_demo(args):
    """Demo lengkap: buat gambar sample, embed pesan, lalu deteksi."""
    import numpy as np
    from PIL import Image

    os.makedirs("samples", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    print("\n[DEMO] Membuat gambar uji...")

    # Buat gambar bersih (gradien natural)
    arr = np.zeros((256, 256, 3), dtype=np.uint8)
    for y in range(256):
        for x in range(256):
            arr[y, x] = [x, y, (x + y) // 2]
    Image.fromarray(arr).save("samples/clean_image.png")
    print("  → samples/clean_image.png (gambar bersih)")

    # Buat gambar dengan pesan tersembunyi
    secret = "INI PESAN RAHASIA - DIGITAL FORENSICS DEMO 2024"
    embed_message("samples/clean_image.png", secret, "samples/stego_image.png")
    print(f"  → samples/stego_image.png (pesan: \"{secret}\")")

    # Analisis keduanya
    print("\n[DEMO] Menjalankan analisis...\n")
    detector = SteganographyDetector()
    results = []
    for name in ["samples/clean_image.png", "samples/stego_image.png"]:
        print(f"  Menganalisis: {name}")
        r = detector.analyze(name)
        results.append(r)

    print()
    print(generate_text_report(results))

    generate_html_report(results, "reports/demo_report.html")
    generate_json_report(results, "reports/demo_report.json")
    print("\n[DEMO] Laporan HTML: reports/demo_report.html")
    print("[DEMO] Laporan JSON: reports/demo_report.json")
    return 0


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Steganography Detector — Digital Forensics Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python main.py demo
  python main.py analyze foto.png
  python main.py analyze ./folder_bukti --output laporan_kasus1
  python main.py embed  asli.png "pesan rahasia" output.png
  python main.py extract output.png
        """
    )

    sub = parser.add_subparsers(dest='command', required=True)

    # analyze
    p_analyze = sub.add_parser('analyze', help='Analisis gambar untuk steganografi')
    p_analyze.add_argument('target', help='File gambar atau folder')
    p_analyze.add_argument('--output', '-o', help='Nama dasar file laporan (tanpa ekstensi)')

    # embed
    p_embed = sub.add_parser('embed', help='Sembunyikan pesan dalam gambar (untuk testing)')
    p_embed.add_argument('image', help='Gambar sumber')
    p_embed.add_argument('message', help='Pesan yang akan disembunyikan')
    p_embed.add_argument('output', help='Path output gambar')

    # extract
    p_extract = sub.add_parser('extract', help='Ekstrak pesan dari gambar')
    p_extract.add_argument('image', help='Gambar yang akan diperiksa')

    # demo
    sub.add_parser('demo', help='Jalankan demo lengkap dengan sample gambar')

    args = parser.parse_args()
    cmd_map = {
        'analyze': cmd_analyze,
        'embed':   cmd_embed,
        'extract': cmd_extract,
        'demo':    cmd_demo,
    }
    sys.exit(cmd_map[args.command](args))


if __name__ == '__main__':
    main()
