# Stenographic File Integrity Checker (Web)

A simple Flask web app that hides file integrity hashes (SHA-256 / SHA3-256) inside a PNG's pixel data using LSB steganography, and later extracts them to verify integrity.

## Features
- Hash multiple files and embed the hashes in a cover PNG.
- Extract embedded JSON (algo, timestamp, entries[name, sha]).
- Verify current files against embedded hashes, with a clear UI.
- Single-file Flask app; Tailwind UI via CDN.

## Quickstart
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
# open http://localhost:7860
```

## Notes
- Only PNG (or images convertible to RGB) are supported to preserve lossless pixels.
- Capacity ≈ width * height * 3 bits; larger images carry more data.
- Do not use on JPEG (lossy) as it will break the hidden data.

## Testing
Basic unit tests live in `tests/test_steg.py`.

## Security Considerations
This is a learning/demo tool. For production use, consider:
- Authenticating the payload (HMAC or signature) to prevent spoofing.
- Encrypting the payload to improve secrecy.
- Handling audio covers and alternate embedding strategies.
