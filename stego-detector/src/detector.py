"""
Steganography Detector - Core Analysis Engine
Digital Forensics Tool untuk mendeteksi pesan tersembunyi dalam gambar
"""

import os
import struct
import numpy as np
from PIL import Image
from scipy.stats import chisquare
from dataclasses import dataclass, field
from typing import Optional
import warnings
warnings.filterwarnings('ignore')


@dataclass
class AnalysisResult:
    filename: str
    filesize: int
    image_mode: str
    image_size: tuple
    lsb_suspicious: bool = False
    lsb_score: float = 0.0
    chi_square_suspicious: bool = False
    chi_square_pvalue: float = 1.0
    histogram_suspicious: bool = False
    histogram_score: float = 0.0
    rs_suspicious: bool = False
    rs_score: float = 0.0
    overall_suspicious: bool = False
    confidence: str = "Low"
    details: dict = field(default_factory=dict)
    embedded_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file": self.filename,
            "filesize_bytes": self.filesize,
            "image_mode": self.image_mode,
            "image_size": f"{self.image_size[0]}x{self.image_size[1]}",
            "overall_suspicious": self.overall_suspicious,
            "confidence": self.confidence,
            "tests": {
                "lsb_analysis": {
                    "suspicious": self.lsb_suspicious,
                    "score": round(self.lsb_score, 4)
                },
                "chi_square": {
                    "suspicious": self.chi_square_suspicious,
                    "p_value": round(self.chi_square_pvalue, 6)
                },
                "histogram_analysis": {
                    "suspicious": self.histogram_suspicious,
                    "score": round(self.histogram_score, 4)
                },
                "rs_analysis": {
                    "suspicious": self.rs_suspicious,
                    "score": round(self.rs_score, 4)
                }
            },
            "details": self.details,
            "extracted_message": self.embedded_message
        }


class SteganographyDetector:
    """
    Detektor steganografi menggunakan multiple teknik analisis statistik:
    - LSB (Least Significant Bit) Analysis
    - Chi-Square Test
    - Histogram Anomaly Detection
    - RS (Regular-Singular) Analysis
    """

    CHI_SQUARE_THRESHOLD = 0.05
    LSB_RANDOMNESS_THRESHOLD = 0.45
    HISTOGRAM_SPIKE_THRESHOLD = 0.15
    RS_THRESHOLD = 0.05

    def analyze(self, image_path: str) -> AnalysisResult:
        """Jalankan semua analisis pada satu gambar."""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"File tidak ditemukan: {image_path}")

        img = Image.open(image_path)
        if img.mode not in ('RGB', 'RGBA', 'L'):
            img = img.convert('RGB')

        result = AnalysisResult(
            filename=os.path.basename(image_path),
            filesize=os.path.getsize(image_path),
            image_mode=img.mode,
            image_size=img.size
        )

        # Jalankan semua tes
        self._lsb_analysis(img, result)
        self._chi_square_test(img, result)
        self._histogram_analysis(img, result)
        self._rs_analysis(img, result)

        # Coba ekstrak pesan tersembunyi
        result.embedded_message = self._try_extract_lsb(img)

        # Tentukan verdict keseluruhan
        self._calculate_verdict(result)

        return result

    # ------------------------------------------------------------------ #
    #  1. LSB ANALYSIS                                                     #
    # ------------------------------------------------------------------ #
    def _lsb_analysis(self, img: Image.Image, result: AnalysisResult) -> None:
        """
        Analisis bit paling tidak signifikan (LSB).
        Gambar biasa memiliki distribusi LSB yang tidak acak (berkorelasi
        dengan nilai pixel tetangga). Jika LSB diacak untuk menyembunyikan
        data, randomness-nya meningkat mendekati 0.5.
        """
        pixels = np.array(img)

        if len(pixels.shape) == 3:
            channels = [pixels[:, :, i] for i in range(pixels.shape[2])]
        else:
            channels = [pixels]

        channel_scores = []
        for ch in channels:
            lsb_plane = ch & 1  # ambil bit LSB saja
            # Hitung transisi antara pixel bertetangga
            h_transitions = np.sum(np.abs(np.diff(lsb_plane.astype(int), axis=1)))
            v_transitions = np.sum(np.abs(np.diff(lsb_plane.astype(int), axis=0)))
            total_pairs = lsb_plane.size
            score = (h_transitions + v_transitions) / (2 * total_pairs)
            channel_scores.append(score)

        avg_score = float(np.mean(channel_scores))
        result.lsb_score = avg_score
        result.lsb_suspicious = avg_score > self.LSB_RANDOMNESS_THRESHOLD
        result.details['lsb'] = {
            "description": "Mengukur tingkat keacakan pada bit LSB setiap channel",
            "channel_scores": [round(s, 4) for s in channel_scores],
            "average_score": round(avg_score, 4),
            "threshold": self.LSB_RANDOMNESS_THRESHOLD,
            "interpretation": (
                "LSB sangat acak — kemungkinan data tersembunyi" if result.lsb_suspicious
                else "LSB normal — tidak ada indikasi steganografi"
            )
        }

    # ------------------------------------------------------------------ #
    #  2. CHI-SQUARE TEST                                                  #
    # ------------------------------------------------------------------ #
    def _chi_square_test(self, img: Image.Image, result: AnalysisResult) -> None:
        """
        Chi-Square Test terhadap distribusi nilai pixel.
        Steganografi LSB membuat pasangan nilai pixel (2n, 2n+1) menjadi
        hampir sama frekuensinya — ini yang diuji.
        """
        pixels = np.array(img).flatten()
        min_pval = 1.0

        for start in range(0, min(len(pixels) - 512, 1024), 256):
            sample = pixels[start:start + 512]
            hist = np.bincount(sample, minlength=256)

            # Gabungkan pasangan (0,1), (2,3), ..., (254,255)
            pairs = [(hist[i] + hist[i + 1]) / 2 for i in range(0, 256, 2)]
            observed = np.array([hist[i] for i in range(0, 256, 2)])
            expected = np.array(pairs)

            mask = expected > 0
            if mask.sum() < 2:
                continue
            try:
                _, pval = chisquare(observed[mask], expected[mask])
                min_pval = min(min_pval, float(pval))
            except Exception:
                continue

        result.chi_square_pvalue = min_pval
        result.chi_square_suspicious = min_pval < self.CHI_SQUARE_THRESHOLD
        result.details['chi_square'] = {
            "description": "Uji distribusi pasangan nilai pixel untuk deteksi LSB embedding",
            "p_value": round(min_pval, 6),
            "threshold": self.CHI_SQUARE_THRESHOLD,
            "interpretation": (
                f"p-value={min_pval:.4f} < {self.CHI_SQUARE_THRESHOLD} — distribusi mencurigakan"
                if result.chi_square_suspicious
                else f"p-value={min_pval:.4f} — distribusi normal"
            )
        }

    # ------------------------------------------------------------------ #
    #  3. HISTOGRAM ANALYSIS                                               #
    # ------------------------------------------------------------------ #
    def _histogram_analysis(self, img: Image.Image, result: AnalysisResult) -> None:
        """
        Analisis histogram untuk mendeteksi anomali.
        Steganografi menyebabkan "comb effect" — pasangan nilai berdekatan
        menjadi saling menukar frekuensi secara bergantian.
        """
        pixels = np.array(img)
        if len(pixels.shape) == 3:
            grey = pixels.mean(axis=2).astype(np.uint8)
        else:
            grey = pixels

        hist, _ = np.histogram(grey.flatten(), bins=256, range=(0, 256))
        hist = hist.astype(float)
        hist_norm = hist / hist.sum() if hist.sum() > 0 else hist

        # Hitung perbedaan relatif antar pasangan nilai
        anomaly_scores = []
        for i in range(0, 254, 2):
            a, b = hist_norm[i], hist_norm[i + 1]
            if (a + b) > 1e-6:
                diff = abs(a - b) / (a + b)
                anomaly_scores.append(diff)

        avg_anomaly = float(np.mean(anomaly_scores)) if anomaly_scores else 0.0
        result.histogram_score = avg_anomaly
        result.histogram_suspicious = avg_anomaly > self.HISTOGRAM_SPIKE_THRESHOLD
        result.details['histogram'] = {
            "description": "Mendeteksi comb-effect pada histogram akibat LSB embedding",
            "anomaly_score": round(avg_anomaly, 4),
            "threshold": self.HISTOGRAM_SPIKE_THRESHOLD,
            "interpretation": (
                "Terdeteksi comb-effect — kemungkinan steganografi aktif"
                if result.histogram_suspicious
                else "Histogram normal"
            )
        }

    # ------------------------------------------------------------------ #
    #  4. RS ANALYSIS                                                      #
    # ------------------------------------------------------------------ #
    def _rs_analysis(self, img: Image.Image, result: AnalysisResult) -> None:
        """
        Regular-Singular (RS) Analysis.
        Membagi gambar menjadi grup pixel, lalu hitung kelompok Regular (R),
        Singular (S), dan Unusable (U). Rasio R-S berubah secara prediktif
        saat steganografi diterapkan.
        """
        pixels = np.array(img)
        if len(pixels.shape) == 3:
            grey = pixels[:, :, 0].astype(float)
        else:
            grey = pixels.astype(float)

        mask_pos = np.array([1, -1, 1, -1])
        mask_neg = np.array([-1, 1, -1, 1])

        def flip(x, mask):
            """Flip LSB sesuai mask."""
            result = x.copy().astype(np.int32)
            for i, m in enumerate(mask):
                if m == 1:
                    result[i] = int(result[i]) ^ 1
                elif m == -1:
                    if int(result[i]) % 2 == 0:
                        result[i] = result[i] - 1
                    else:
                        result[i] = result[i] + 1
            return np.clip(result, 0, 255).astype(np.float64)

        def discriminant(group):
            """Hitung diskriminan smoothness."""
            return np.sum(np.abs(np.diff(group)))

        h, w = grey.shape
        r_pos = s_pos = r_neg = s_neg = total = 0

        for y in range(h):
            for x in range(0, w - 3, 4):
                group = grey[y, x:x + 4]
                if len(group) < 4:
                    continue
                total += 1

                d_orig = discriminant(group)
                d_flip_pos = discriminant(flip(group.copy(), mask_pos))
                d_flip_neg = discriminant(flip(group.copy(), mask_neg))

                if d_flip_pos > d_orig:
                    r_pos += 1
                elif d_flip_pos < d_orig:
                    s_pos += 1

                if d_flip_neg > d_orig:
                    r_neg += 1
                elif d_flip_neg < d_orig:
                    s_neg += 1

        if total == 0:
            result.rs_score = 0.0
            result.rs_suspicious = False
            return

        r_pos_r = r_pos / total
        s_pos_r = s_pos / total
        r_neg_r = r_neg / total
        s_neg_r = s_neg / total

        rs_score = abs((r_pos_r - r_neg_r) + (s_neg_r - s_pos_r))
        result.rs_score = rs_score
        result.rs_suspicious = rs_score > self.RS_THRESHOLD
        result.details['rs_analysis'] = {
            "description": "Regular-Singular analysis untuk estimasi jumlah bit tersembunyi",
            "R_pos": round(r_pos_r, 4),
            "S_pos": round(s_pos_r, 4),
            "R_neg": round(r_neg_r, 4),
            "S_neg": round(s_neg_r, 4),
            "rs_score": round(rs_score, 4),
            "threshold": self.RS_THRESHOLD,
            "interpretation": (
                f"RS asymmetry={rs_score:.4f} — ada indikasi payload tersembunyi"
                if result.rs_suspicious
                else "RS simetris — tidak ada indikasi steganografi"
            )
        }

    # ------------------------------------------------------------------ #
    #  5. LSB EXTRACTION (percobaan)                                       #
    # ------------------------------------------------------------------ #
    def _try_extract_lsb(self, img: Image.Image, max_bytes: int = 256) -> Optional[str]:
        """
        Coba ekstrak pesan tersembunyi menggunakan metode LSB standar.
        Hanya berhasil jika gambar menggunakan teknik LSB embedding biasa.
        """
        try:
            pixels = np.array(img).flatten()
            bits = pixels[:max_bytes * 8] & 1

            chars = []
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                if byte == 0:
                    break
                if 32 <= byte <= 126:
                    chars.append(chr(byte))
                else:
                    chars = []
                    break

            if len(chars) >= 4:
                return ''.join(chars)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    #  VERDICT                                                             #
    # ------------------------------------------------------------------ #
    def _calculate_verdict(self, result: AnalysisResult) -> None:
        """Tentukan verdict akhir berdasarkan semua tes."""
        flags = [
            result.lsb_suspicious,
            result.chi_square_suspicious,
            result.histogram_suspicious,
            result.rs_suspicious
        ]
        count = sum(flags)

        result.overall_suspicious = count >= 2

        if count == 0:
            result.confidence = "Clean"
        elif count == 1:
            result.confidence = "Low"
        elif count == 2:
            result.confidence = "Medium"
        elif count == 3:
            result.confidence = "High"
        else:
            result.confidence = "Very High"
