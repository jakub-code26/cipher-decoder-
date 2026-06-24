"""
Ghost in the Wires - Chapter Cipher Decoder
Based on Kevin Mitnick's book cipher challenges.

Supported ciphers:
    - Caesar cipher (auto-detect via dictionary scoring)
    - ROT13
    - Atbash
    - More to be added as new cipher types are identified in the book
"""

import string
import os
from collections import Counter

# ─── Dictionary loader ────────────────────────────────────────────────────────

# Common English words as fallback (no installation needed)
COMMON_WORDS = {
    "the", "of", "and", "to", "a", "in", "is", "it", "you", "that", "he",
    "was", "for", "on", "are", "with", "as", "his", "they", "at", "be",
    "this", "from", "or", "one", "had", "by", "but", "not", "what", "all",
    "were", "when", "we", "there", "can", "an", "your", "which", "their",
    "said", "if", "do", "will", "each", "about", "how", "up", "out", "them",
    "then", "she", "many", "some", "so", "these", "would", "other", "into",
    "has", "her", "two", "him", "more", "write", "go", "see", "no", "way",
    "could", "my", "than", "first", "been", "its", "who", "now", "people",
    "have", "like", "time", "very", "know", "used", "just", "own", "i",
    "cost", "bus", "driver", "punch", "transfers", "phone", "call", "system",
    "computer", "security", "password", "access", "hack", "code", "network"
}


def load_dictionary():
    """
    Load word list for dictionary scoring.
    Tries system dictionary first, falls back to built-in word list.
    """
    system_paths = [
        "/usr/share/dict/words",           # Mac / Linux
        "/usr/dict/words",                 # older Unix
    ]
    for path in system_paths:
        if os.path.exists(path):
            with open(path, "r") as f:
                words = {line.strip().lower() for line in f if line.strip()}
            print(f"  Dictionary: system ({len(words):,} words)")
            return words

    # Fallback: try pyenchant
    try:
        import enchant
        d = enchant.Dict("en_US")
        print("  Dictionary: pyenchant")
        return d
    except ImportError:
        pass

    print(f"  Dictionary: built-in ({len(COMMON_WORDS)} common words)")
    return COMMON_WORDS


def word_in_dict(word, dictionary):
    """Check if a word exists in the dictionary (handles both set and enchant)."""
    w = word.lower().strip(string.punctuation)
    if not w:
        return False
    if hasattr(dictionary, "check"):
        return dictionary.check(w)
    return w in dictionary


# ─── Caesar ───────────────────────────────────────────────────────────────────

def caesar_decrypt(text, shift):
    """Decrypt a Caesar cipher with a given shift."""
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)


def caesar_auto(text, dictionary):
    """
    Find the correct Caesar shift by scoring each decryption
    against a dictionary. Returns (shift, decrypted_text, score).
    """
    best_shift = 0
    best_score = -1
    best_result = text

    for shift in range(26):
        decrypted = caesar_decrypt(text, shift)
        words = decrypted.split()
        if not words:
            continue
        matches = sum(1 for w in words if word_in_dict(w, dictionary))
        score = matches / len(words)

        if score > best_score:
            best_score = score
            best_shift = shift
            best_result = decrypted

    return best_shift, best_result, best_score


# ─── ROT13 ────────────────────────────────────────────────────────────────────

def rot13(text):
    """ROT13 is Caesar with shift 13 — its own inverse."""
    return caesar_decrypt(text, 13)


# ─── Atbash ───────────────────────────────────────────────────────────────────

def atbash(text):
    """Atbash cipher: A↔Z, B↔Y, C↔X, etc."""
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr(base + 25 - (ord(char) - base)))
        else:
            result.append(char)
    return "".join(result)

# ─── Vigenère ─────────────────────────────────────────────────────────────────

def vigenere_decrypt(text, keyword):
    """Decrypt a Vigenère cipher with a given keyword."""
    keyword = keyword.lower()
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(keyword[key_index % len(keyword)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def vigenere_auto(text, dictionary, max_key_length=10):
    """
    Crack a Vigenère cipher without knowing the keyword.
    Tests key lengths 2-10, cracks each group with frequency analysis.
    Returns (keyword, decrypted_text, score).
    """
    best_keyword = ""
    best_score = -1
    best_result = text

    for key_len in range(2, max_key_length + 1):
        keyword = ""
        for i in range(key_len):
            group = [text[j] for j in range(i, len(text), key_len) if text[j].isalpha()]
            if not group:
                continue
            freq = Counter(c.upper() for c in group)
            most_common = freq.most_common(1)[0][0]
            shift = (ord(most_common) - ord('E')) % 26
            keyword += chr(ord('a') + shift)

        decrypted = vigenere_decrypt(text, keyword)
        words = decrypted.split()
        matches = sum(1 for w in words if word_in_dict(w, dictionary)) if words else 0
        score = matches / len(words) if words else 0

        if score > best_score:
            best_score = score
            best_keyword = keyword
            best_result = decrypted

    return best_keyword, best_result, round(best_score * 100)

# ─── Frequency analysis ───────────────────────────────────────────────────────

def frequency_analysis(text):
    """Show letter frequencies in the cipher text."""
    letters = [c.upper() for c in text if c.isalpha()]
    total = len(letters)
    if total == 0:
        return {}
    freq = Counter(letters)
    return {
        letter: {"count": count, "percent": round((count / total) * 100, 1)}
        for letter, count in freq.most_common()
    }


# ─── Display helpers ──────────────────────────────────────────────────────────

def print_separator(char="─", length=60):
    print(char * length)


def print_frequency_analysis(text):
    analysis = frequency_analysis(text)
    if not analysis:
        return
    print_separator()
    print("FREQUENCY ANALYSIS")
    print_separator()
    print(f"  {'Letter':<8} {'Count':<8} {'%':<8} Bar")
    print(f"  {'──────':<8} {'─────':<8} {'──────':<8}")
    for letter, data in analysis.items():
        bar = "█" * int(data["percent"])
        print(f"  {letter:<8} {data['count']:<8} {data['percent']:<8} {bar}")
    print()


def print_caesar_all(text, dictionary, top_n=5):
    """Print all shifts ranked by dictionary score."""
    results = []
    for shift in range(26):
        decrypted = caesar_decrypt(text, shift)
        words = decrypted.split()
        matches = sum(1 for w in words if word_in_dict(w, dictionary)) if words else 0
        score = round((matches / len(words)) * 100) if words else 0
        results.append((shift, score, decrypted))

    results.sort(key=lambda x: x[1], reverse=True)

    print_separator()
    print(f"CAESAR — top {top_n} shifts by dictionary score")
    print_separator()
    for shift, score, result in results[:top_n]:
        print(f"  Shift {shift:>2} ({score:>3}% match) → {result}")
    print()


# ─── Main ─────────────────────────────────────────────────────────────────────

def decode(text, mode="auto"):
    """
    Decode a cipher text.

    Modes:
        auto   — dictionary scoring to find best Caesar shift (default)
        brute  — show all 26 shifts ranked by dictionary score
        rot13  — ROT13
        atbash — Atbash
        freq   — frequency analysis only
    """
    print()
    print("  GHOST IN THE WIRES — Cipher Decoder")
    print_separator("═")
    print(f"  Input : {text}")
    print(f"  Mode  : {mode}")
    print_separator()

    dictionary = load_dictionary()
    print_separator("═")
    print()

    if mode == "auto":
        shift, result, score = caesar_auto(text, dictionary)
        confidence = round(score * 100)
        print_separator()
        print(f"CAESAR AUTO-DETECT — shift {shift} ({confidence}% word match)")
        print_separator()
        print(f"  {result}")
        print()

    elif mode == "brute":
        print_caesar_all(text, dictionary, top_n=26)
        print_frequency_analysis(text)

    elif mode == "top":
        print_caesar_all(text, dictionary, top_n=5)

    elif mode == "rot13":
        result = rot13(text)
        print_separator()
        print("ROT13")
        print_separator()
        print(f"  {result}")
        print()

    elif mode == "atbash":
        result = atbash(text)
        print_separator()
        print("ATBASH")
        print_separator()
        print(f"  {result}")
        print()

    elif mode == "reverse":
        reversed_text = text[::-1]
        shift, result, score = caesar_auto(reversed_text, dictionary)
        confidence = round(score * 100)
        print_separator()
        print(f"REVERSE CAESAR — shift {shift} ({confidence}% word match)")
        print_separator()
        print(f"  {result}")
        print()

    elif mode == "vigenere":
        keyword, result, score = vigenere_auto(text, dictionary)
        print_separator()
        print(f"VIGENÈRE AUTO-CRACK — keyword: '{keyword}' ({score}% match)")
        print_separator()
        print(f"  {result}")
        print()

    elif mode == "freq":
        print_frequency_analysis(text)

    else:
        print(f"Unknown mode: {mode}")
        print("Available modes: auto, brute, top, rot13, atbash, freq")


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print()
        print("Usage:")
        print('  python3 decoder.py "your cipher text"')
        print('  python3 decoder.py "your cipher text" brute')
        print('  python3 decoder.py "your cipher text" top')
        print('  python3 decoder.py "your cipher text" rot13')
        print('  python3 decoder.py "your cipher text" atbash')
        print('  python3 decoder.py "your cipher text" freq')
        print()
        print("Default mode: auto (dictionary scoring)")
        print()
        sys.exit(0)

    cipher_text = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "auto"
    decode(cipher_text, mode)
