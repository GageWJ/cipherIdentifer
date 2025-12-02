import base64
import re
from urllib.parse import unquote
from collections import Counter


# CLEAN LETTERS
def clean_letters(text):
    return "".join(c.lower() for c in text if c.isalpha())

# BASE ENCODINGS
def is_base64(text):
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", text):
        return False
    if len(text) % 4 != 0:
        return False
    try:
        base64.b64decode(text, validate=True)
        return True
    except:
        return False


def is_base32(text):
    if not re.fullmatch(r"[A-Z2-7=]+", text.upper()):
        return False
    try:
        base64.b32decode(text, casefold=True)
        return True
    except:
        return False


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def is_base58(text):
    return all(c in BASE58_ALPHABET for c in text)


def is_hex(text):
    cleaned = text.replace(" ", "")
    return bool(re.fullmatch(r"[0-9A-Fa-f]+", cleaned)) and len(cleaned) % 2 == 0


def is_url_encoded(text):
    return "%" in text and unquote(text) != text


# ENGLISH FREQUENCY TABLE
EN_FREQ = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
    'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
    'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
    'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
    'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
    'y': 0.01974, 'z': 0.00074
}


# CHI-SQUARED + CAESAR
def chi_squared(text):
    N = len(text)
    if N == 0:
        return float('inf')
    freq = Counter(text)
    chi = 0
    for letter, expected in EN_FREQ.items():
        observed = freq.get(letter, 0)
        chi += (observed - expected * N) ** 2 / (expected * N)
    return chi


def decrypt_caesar(text, shift):
    result = ""
    for c in text:
        if c.isalpha():
            result += chr(((ord(c.lower()) - 97 - shift) % 26) + 97)
        else:
            result += c
    return result


def all_caesar_scores(text):
    scores = []
    for shift in range(26):
        decrypted = decrypt_caesar(text, shift)
        score = chi_squared(clean_letters(decrypted))
        scores.append((shift, score, decrypted))
    return scores


COMMON_PATTERNS = ["TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN"]


def detect_caesar(text):
    scores = all_caesar_scores(text)

    best_shift, best_score, best_plain = min(scores, key=lambda x: x[1])
    other_scores = [s for sh, s, _ in scores if sh != best_shift]
    avg_other = sum(other_scores) / len(other_scores)

    if best_score > 80:
        return None
    if best_score >= avg_other * 0.50:
        return None

    if not any(p.lower() in best_plain for p in COMMON_PATTERNS):
        return None

    return best_shift, best_plain


# ATBASH CIPHER
def decrypt_atbash(text):
    result = ""
    for c in text:
        if c.isalpha():
            # atbash: A <-> Z
            base = ord('a')
            result += chr(base + (25 - (ord(c.lower()) - base)))
        else:
            result += c
    return result


def detect_atbash(text):
    decrypted = decrypt_atbash(text)
    low = decrypted.lower()

    # must contain English-like digrams
    if any(p.lower() in low for p in COMMON_PATTERNS):
        return decrypted

    return None


# SUBSTITUTION DETECTOR (IC-based, detect only)
def index_of_coincidence(text):
    N = len(text)
    if N < 2:
        return 0
    freq = Counter(text)
    return sum(v*(v-1) for v in freq.values()) / (N*(N-1))


def looks_like_substitution(text):
    if len(text) < 12:
        return False
    ic = index_of_coincidence(text)
    return 0.055 <= ic <= 0.075


# MAIN DETECTOR + AUTO DECRYPTION
def detect(text):
    stripped = text.strip()

    # Base encodings
    if is_hex(stripped):
        cleaned = stripped.replace(" ", "")
        try:
            decoded = bytes.fromhex(cleaned).decode(errors="replace")
            return "HEX", decoded
        except:
            return "HEX", "Invalid ASCII in hex"

    if is_base64(stripped):
        try:
            decoded = base64.b64decode(stripped).decode(errors="replace")
            return "BASE64", decoded
        except:
            return "BASE64", "Invalid Base64 content"

    if is_base32(stripped):
        try:
            decoded = base64.b32decode(stripped).decode(errors="replace")
            return "BASE32", decoded
        except:
            return "BASE32", "Invalid Base32 content"

    if is_base58(stripped):
        try:
            value = 0
            for char in stripped:
                value = value * 58 + BASE58_ALPHABET.index(char)
            decoded = value.to_bytes((value.bit_length() + 7) // 8, 'big').decode(errors="replace")
            return "BASE58", decoded
        except:
            return "BASE58", "Invalid Base58 content"

    if is_url_encoded(stripped):
        return "URL-ENCODING", unquote(stripped)

    # Cipher detection
    letters = clean_letters(stripped)

    # Detect Caesar
    if len(letters) >= 8:
        caesar = detect_caesar(stripped)
        if caesar:
            shift, plaintext = caesar
            return f"CAESAR (ROT-{shift})", plaintext

    # Detect Atbash
    if len(letters) >= 5:
        atbash_plain = detect_atbash(stripped)
        if atbash_plain:
            return "ATBASH", atbash_plain

    # Detect substitution
    if looks_like_substitution(letters):
        return "SUBSTITUTION", stripped

    # Fallback
    return "UNKNOWN", stripped

# RUN SCRIPT
if __name__ == "__main__":
    user_input = input("Enter text: ").strip()
    kind, result = detect(user_input)

    print(f"\nDetected: {kind}")
    print(f"Decrypted Output:\n{result}\n")

