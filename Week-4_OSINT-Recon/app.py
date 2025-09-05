
import io
import json
import base64
import hashlib
from datetime import datetime
from typing import List, Tuple
from flask import Flask, request, send_file, render_template_string, redirect, url_for, flash
from PIL import Image
import PIL

app = Flask(__name__)
app.secret_key = "dev-secret-key"  # replace in production

# ---------- Utility: hashing ----------
def compute_hash(data: bytes, algo: str = "sha256") -> str:
    if algo == "sha256":
        h = hashlib.sha256()
    elif algo in ("sha3_256", "sha3"):
        h = hashlib.sha3_256()
    else:
        raise ValueError("Unsupported algorithm")
    h.update(data)
    return h.hexdigest()

# ---------- Utility: bitwise helpers ----------
def _bytes_to_bits(b: bytes) -> List[int]:
    out = []
    for byte in b:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out

def _bits_to_bytes(bits: List[int]) -> bytes:
    by = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte = (byte << 1) | (bits[i + j] & 1)
            else:
                byte = (byte << 1)
        by.append(byte)
    return bytes(by)

# ---------- Steganography: LSB in RGB PNG ----------
MAGIC = b"SFIC"  # Stenographic File Integrity Checker
HEADER_LEN = 8    # 4 bytes magic + 4 bytes length

def _ensure_png_rgb(img: Image.Image) -> Image.Image:
    # Convert to RGB and ensure it's lossless format (PNG write later)
    if img.mode != "RGB":
        img = img.convert("RGB")
    return img

def _embed_bytes_into_image(img: Image.Image, payload: bytes) -> Image.Image:
    img = _ensure_png_rgb(img)
    w, h = img.size
    pix = img.load()

    header = MAGIC + len(payload).to_bytes(4, "big")
    data = header + payload
    bits = _bytes_to_bits(data)
    capacity_bits = w * h * 3
    if len(bits) > capacity_bits:
        raise ValueError(f"Payload too large for this image. Need {len(bits)} bits, have {capacity_bits} bits. "
                         f"Try a larger image or fewer files.")

    idx = 0
    for y in range(h):
        for x in range(w):
            if idx >= len(bits):
                break
            r, g, b = pix[x, y]
            if idx < len(bits):
                r = (r & 0xFE) | bits[idx]; idx += 1
            if idx < len(bits):
                g = (g & 0xFE) | bits[idx]; idx += 1
            if idx < len(bits):
                b = (b & 0xFE) | bits[idx]; idx += 1
            pix[x, y] = (r, g, b)
        if idx >= len(bits):
            break
    return img

def _extract_bytes_from_image(img: Image.Image) -> bytes:
    img = _ensure_png_rgb(img)
    w, h = img.size
    pix = img.load()

    bits = []
    # Read enough for header first (8 bytes -> 64 bits)
    for y in range(h):
        for x in range(w):
            r, g, b = pix[x, y]
            bits.extend([r & 1, g & 1, b & 1])
            if len(bits) >= (HEADER_LEN * 8):
                # try to parse header
                header_bytes = _bits_to_bytes(bits[:HEADER_LEN*8])
                if header_bytes[:4] == MAGIC:
                    payload_len = int.from_bytes(header_bytes[4:8], "big")
                    total_bits = (HEADER_LEN + payload_len) * 8
                    # If not enough bits yet, continue reading
                    if len(bits) < total_bits:
                        # need to collect remaining bits
                        for yy in range(y, h):
                            for xx in range(x+1 if yy == y else 0, w):
                                rr, gg, bb = pix[xx, yy]
                                bits.extend([rr & 1, gg & 1, bb & 1])
                                if len(bits) >= total_bits:
                                    payload = _bits_to_bytes(bits[HEADER_LEN*8:total_bits])
                                    return payload
                    else:
                        payload = _bits_to_bytes(bits[HEADER_LEN*8:total_bits])
                        return payload
                # else keep scanning until header is detected at a boundary (simple approach uses start)
                # but our embed starts at 0, so if magic doesn't match, treat as not found
                # We'll continue collecting all bits and check once more below.
        # end for x
    # Second attempt: if full image read, parse header globally
    if len(bits) >= HEADER_LEN*8:
        header_bytes = _bits_to_bytes(bits[:HEADER_LEN*8])
        if header_bytes[:4] != MAGIC:
            raise ValueError("No embedded data found (MAGIC not present).")
        payload_len = int.from_bytes(header_bytes[4:8], "big")
        total_bits = (HEADER_LEN + payload_len) * 8
        if len(bits) < total_bits:
            raise ValueError("Embedded payload appears truncated.")
        payload = _bits_to_bytes(bits[HEADER_LEN*8:total_bits])
        return payload
    raise ValueError("Image too small or no data present.")

# ---------- HTML template (Tailwind via CDN) ----------
PAGE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Stenographic File Integrity Checker</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
  <div class="max-w-5xl mx-auto p-6">
    <header class="mb-8">
      <h1 class="text-3xl font-bold">🔐 Stenographic File Integrity Checker</h1>
      <p class="text-slate-300">Embed and verify file hashes secretly inside PNG images (LSB steganography).</p>
    </header>

    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="mb-4">
          {% for m in messages %}
            <div class="p-3 rounded bg-emerald-700/30 border border-emerald-600 mb-2">{{ m }}</div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    <div class="grid md:grid-cols-2 gap-6">
      <!-- Embed Card -->
      <div class="rounded-2xl shadow-lg bg-slate-800 border border-slate-700">
        <div class="p-5">
          <h2 class="text-xl font-semibold mb-3">Embed Hashes</h2>
          <form action="{{ url_for('embed') }}" method="post" enctype="multipart/form-data" class="space-y-3">
            <div>
              <label class="block text-sm mb-1">Target files (one or more)</label>
              <input name="targets" type="file" multiple required class="file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-indigo-600 file:text-white file:cursor-pointer block w-full text-slate-200">
            </div>
            <div>
              <label class="block text-sm mb-1">Cover PNG image</label>
              <input name="cover" type="file" accept="image/png,image/*" required class="file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-indigo-600 file:text-white file:cursor-pointer block w-full text-slate-200">
            </div>
            <div class="flex items-center gap-4">
              <label class="text-sm">Hash algorithm:</label>
              <label class="inline-flex items-center gap-2">
                <input type="radio" name="algo" value="sha256" checked> <span>SHA-256</span>
              </label>
              <label class="inline-flex items-center gap-2">
                <input type="radio" name="algo" value="sha3_256"> <span>SHA3-256</span>
              </label>
            </div>
            <button class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 transition">Embed & Download</button>
          </form>
          <p class="text-xs text-slate-400 mt-3">Tip: Larger images can carry more data. PNG recommended.</p>
        </div>
      </div>

      <!-- Verify Card -->
      <div class="rounded-2xl shadow-lg bg-slate-800 border border-slate-700">
        <div class="p-5">
          <h2 class="text-xl font-semibold mb-3">Extract / Verify</h2>
          <form action="{{ url_for('verify') }}" method="post" enctype="multipart/form-data" class="space-y-3">
            <div>
              <label class="block text-sm mb-1">Stego image (PNG)</label>
              <input name="stego" type="file" accept="image/png,image/*" required class="file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-indigo-600 file:text-white file:cursor-pointer block w-full text-slate-200">
            </div>
            <div>
              <label class="block text-sm mb-1">Current files to check (optional; match by filename)</label>
              <input name="targets" type="file" multiple class="file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-purple-600 file:text-white file:cursor-pointer block w-full text-slate-200">
            </div>
            <button class="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 transition">Extract / Verify</button>
          </form>
        </div>
      </div>
    </div>

    {% if results %}
      <div class="mt-8 rounded-2xl bg-slate-800 border border-slate-700 shadow-lg">
        <div class="p-5">
          <h3 class="text-lg font-semibold mb-3">Verification Results</h3>
          <div class="overflow-x-auto">
            <table class="min-w-full text-sm">
              <thead>
                <tr class="text-left text-slate-300">
                  <th class="py-2 pr-4">Filename</th>
                  <th class="py-2 pr-4">Embedded Hash</th>
                  <th class="py-2 pr-4">Current Hash</th>
                  <th class="py-2 pr-4">Status</th>
                </tr>
              </thead>
              <tbody>
                {% for row in results['rows'] %}
                <tr class="border-t border-slate-700">
                  <td class="py-2 pr-4 font-mono">{{ row['name'] }}</td>
                  <td class="py-2 pr-4 font-mono">{{ row['embedded'] }}</td>
                  <td class="py-2 pr-4 font-mono">{{ row['current'] or '-' }}</td>
                  <td class="py-2 pr-4">
                    {% if row['match'] is none %}
                      <span class="px-2 py-1 rounded bg-amber-600/40 border border-amber-500">Not checked</span>
                    {% elif row['match'] %}
                      <span class="px-2 py-1 rounded bg-emerald-700/40 border border-emerald-600">OK</span>
                    {% else %}
                      <span class="px-2 py-1 rounded bg-rose-700/40 border border-rose-600">MISMATCH</span>
                    {% endif %}
                  </td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <p class="text-xs text-slate-400 mt-3">Algo: {{ results['algo'] }} | Embedded: {{ results['timestamp'] }}</p>
        </div>
      </div>
    {% endif %}

    <footer class="mt-10 text-xs text-slate-400">
      Built with 🧠 Flask + Pillow. Demo only; do not use for high-stakes security without review.
    </footer>
  </div>
</body>
</html>
"""

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def index():
    return render_template_string(PAGE)

@app.route("/embed", methods=["POST"])
def embed():
    try:
        algo = request.form.get("algo", "sha256")
        cover_file = request.files.get("cover")
        target_files = request.files.getlist("targets")

        if not cover_file or not target_files:
            flash("Provide a cover image and at least one target file.")
            return redirect(url_for("index"))

        # Read cover image
        cover_img = Image.open(cover_file.stream)

        # Build payload JSON
        entries = []
        for f in target_files:
            data = f.read()
            sha = compute_hash(data, algo=algo)
            entries.append({"name": f.filename, "sha": sha})
        payload_obj = {
            "algo": "sha3_256" if algo in ("sha3", "sha3_256") else "sha256",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "entries": entries,
            "version": "1.0"
        }
        payload_bytes = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")

        # Embed
        stego_img = _embed_bytes_into_image(cover_img, payload_bytes)

        # Return as PNG download
        buf = io.BytesIO()
        stego_img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png", as_attachment=True, download_name="stego_output.png")
    except Exception as e:
        flash(str(e))
        return redirect(url_for("index"))

@app.route("/verify", methods=["POST"])
def verify():
    try:
        stego_file = request.files.get("stego")
        if not stego_file:
            flash("Provide a stego image to extract.")
            return redirect(url_for("index"))
        targets = request.files.getlist("targets")

        img = Image.open(stego_file.stream)
        payload = _extract_bytes_from_image(img)
        payload_obj = json.loads(payload.decode("utf-8"))

        # Map current hashes (if any uploaded) by name
        current_map = {}
        for f in targets:
            data = f.read()
            algo = payload_obj.get("algo", "sha256")
            current_map[f.filename] = compute_hash(data, algo=algo)

        rows = []
        for ent in payload_obj.get("entries", []):
            name = ent.get("name")
            embedded = ent.get("sha")
            curr = current_map.get(name)
            match = None
            if curr:
                match = (curr == embedded)
            rows.append({"name": name, "embedded": embedded, "current": curr, "match": match})

        return render_template_string(PAGE, results={"rows": rows, "algo": payload_obj.get("algo"), "timestamp": payload_obj.get("timestamp")})
    except Exception as e:
        flash(str(e))
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860, debug=True)
