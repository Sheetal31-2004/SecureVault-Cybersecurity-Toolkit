import os
import magic
import hashlib
import sqlite3
import math

from datetime import datetime
from PyPDF2 import PdfReader


# ==========================================================
# HASH FUNCTIONS
# ==========================================================

def calculate_hash(filepath, algorithm):

    hasher = hashlib.new(algorithm)

    with open(filepath, "rb") as f:

        while True:

            chunk = f.read(4096)

            if not chunk:
                break

            hasher.update(chunk)

    return hasher.hexdigest()


# ==========================================================
# HASH DATABASE
# ==========================================================

def initialize_hash_database():

    conn = sqlite3.connect("file_hashes.db")

    cursor = conn.cursor()

    cursor.execute("""

        CREATE TABLE IF NOT EXISTS file_hashes(

            filename TEXT PRIMARY KEY,

            sha256 TEXT

        )

    """)

    conn.commit()
    conn.close()


def save_hash(filename, sha256):

    conn = sqlite3.connect("file_hashes.db")

    cursor = conn.cursor()

    cursor.execute("""

        INSERT OR REPLACE INTO file_hashes
        VALUES (?, ?)

    """, (filename, sha256))

    conn.commit()
    conn.close()


def get_saved_hash(filename):

    conn = sqlite3.connect("file_hashes.db")

    cursor = conn.cursor()

    cursor.execute("""

        SELECT sha256
        FROM file_hashes
        WHERE filename = ?

    """, (filename,))

    row = cursor.fetchone()

    conn.close()

    if row:
        return row[0]

    return None


# ==========================================================
# MALWARE SIGNATURES
# ==========================================================

def check_malware_signatures(filepath):

    signatures = [

        "powershell",
        "cmd.exe",
        "wget",
        "curl",
        "base64",
        "eval(",
        "exec(",
        "shell",
        "subprocess",
        "createremotethread",
        "virtualalloc",
        "writeprocessmemory",
        "reg add",
        "taskkill",
        "rundll32",
        "mshta",
        "certutil",
        "net user",
        "net localgroup",
        "mimikatz"

    ]

    found = []

    try:

        with open(filepath, "rb") as f:

            content = f.read().decode(
                errors="ignore"
            ).lower()

        for signature in signatures:

            if signature in content:
                found.append(signature)

    except:
        pass

    return found


# ==========================================================
# FILE ENTROPY
# ==========================================================

def calculate_entropy(filepath):

    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) == 0:
        return 0

    entropy = 0

    for x in range(256):

        p = data.count(bytes([x])) / len(data)

        if p > 0:

            entropy -= p * math.log2(p)

    return round(entropy, 2)


# ==========================================================
# PDF METADATA
# ==========================================================

def pdf_metadata(filepath):

    metadata = []

    try:

        reader = PdfReader(filepath)

        info = reader.metadata

        metadata.append(f"Pages : {len(reader.pages)}")

        if info:

            metadata.append(
                f"Author : {info.get('/Author', 'Unknown')}"
            )

            metadata.append(
                f"Creator : {info.get('/Creator', 'Unknown')}"
            )

            metadata.append(
                f"Producer : {info.get('/Producer', 'Unknown')}"
            )

            metadata.append(
                f"Creation Date : {info.get('/CreationDate', 'Unknown')}"
            )

            metadata.append(
                f"Modification Date : {info.get('/ModDate', 'Unknown')}"
            )

        else:

            metadata.append(
                "Metadata Not Available"
            )

    except:

        metadata.append(
            "Metadata Extraction Failed"
        )

    return metadata

# ==========================================================
# MAIN FILE SCANNER
# ==========================================================

def scan_file_for_vulnerabilities(file_path, action):

    results = []

    initialize_hash_database()

    if not os.path.exists(file_path):
        return ["❌ File does not exist."]

    filename = os.path.basename(file_path)
    extension = os.path.splitext(filename)[1].lower()
    filesize = os.path.getsize(file_path)

    modified = datetime.fromtimestamp(
        os.path.getmtime(file_path)
    ).strftime("%d-%m-%Y %H:%M:%S")

    mime = magic.from_file(file_path, mime=True)

    # ------------------------------------------------------
    # Pre-calculate hashes
    # ------------------------------------------------------

    md5 = calculate_hash(file_path, "md5")
    sha1 = calculate_hash(file_path, "sha1")
    sha256 = calculate_hash(file_path, "sha256")

    matches = []
    entropy = 0
    risk_score = 100
    level = "LOW"
    recommendations = []

    # ==========================================================
    # FILE SCAN
    # ==========================================================

    if action == "scan":

        results.append("=" * 60)
        results.append("FILE INFORMATION")
        results.append("=" * 60)

        results.append(f"File Name        : {filename}")
        results.append(f"Extension        : {extension}")
        results.append(f"File Size        : {round(filesize / 1024, 2)} KB")
        results.append(f"MIME Type        : {mime}")
        results.append(f"Last Modified    : {modified}")

        results.append("")

        results.append("=" * 60)
        results.append("FILE METADATA")
        results.append("=" * 60)

        if extension == ".pdf":

            metadata = pdf_metadata(file_path)

            for item in metadata:
                results.append(item)

        else:

            results.append(
                "Metadata extraction is currently supported for PDF files only."
            )

        results.append("")
        results.append("=" * 60)
        results.append("SCAN COMPLETED")
        results.append("=" * 60)

        return results

    # ==========================================================
    # HASH GENERATOR
    # ==========================================================

    elif action == "hash":

        results.append("=" * 60)
        results.append("FILE HASHES")
        results.append("=" * 60)

        results.append(f"MD5      : {md5}")
        results.append(f"SHA1     : {sha1}")
        results.append(f"SHA256   : {sha256}")

        results.append("")

        results.append("=" * 60)
        results.append("HASH GENERATION COMPLETED")
        results.append("=" * 60)

        return results
    
    # ==========================================================
    # FILE INTEGRITY CHECK
    # ==========================================================

    elif action == "integrity":

        results.append("=" * 60)
        results.append("FILE INTEGRITY CHECK")
        results.append("=" * 60)

        stored_hash = get_saved_hash(filename)

        if stored_hash is None:

            results.append("Status : First Scan")
            results.append("No previous hash available.")
            save_hash(filename, sha256)

        elif stored_hash == sha256:

            results.append("Integrity Status : VERIFIED")
            results.append("File has NOT been modified.")

        else:

            results.append("Integrity Status : FAILED")
            results.append("File contents have been modified.")

            save_hash(filename, sha256)

        results.append("")

        results.append("=" * 60)
        results.append("INTEGRITY CHECK COMPLETED")
        results.append("=" * 60)

        return results

    # ==========================================================
    # MALWARE CHECK
    # ==========================================================

    elif action == "malware":

        matches = check_malware_signatures(file_path)

        results.append("=" * 60)
        results.append("MALWARE SIGNATURE SCAN")
        results.append("=" * 60)

        if matches:

            results.append("Suspicious Patterns Found:")

            for item in matches:

                results.append(f"• {item}")

            risk_score -= min(len(matches) * 5, 30)

        else:

            results.append("No known malware signatures detected.")

        results.append("")

        # ==========================================================
        # MALWARE ANALYSIS
        # ==========================================================

        results.append("=" * 60)
        results.append("MALWARE ANALYSIS")
        results.append("=" * 60)

        dangerous_extensions = [

            ".exe",
            ".dll",
            ".bat",
            ".cmd",
            ".scr",
            ".ps1",
            ".vbs",
            ".js",
            ".jar",
            ".com"

        ]

        if extension in dangerous_extensions:

            results.append("Dangerous Extension : YES")
            risk_score -= 25

        else:

            results.append("Dangerous Extension : NO")

        if mime in [

            "application/x-dosexec",
            "application/x-msdownload"

        ]:

            results.append("Executable File : YES")
            risk_score -= 20

        elif mime == "application/javascript":

            results.append("JavaScript File Detected")
            risk_score -= 10

        elif mime == "text/html":

            results.append("HTML File Detected")

        elif mime == "application/x-python-code":

            results.append("Python Script Detected")

        else:

            results.append("No suspicious MIME type detected.")

        if len(filename.split(".")) > 2:

            results.append("Multiple Extension : YES")
            risk_score -= 15

        else:

            results.append("Multiple Extension : NO")

        results.append("")

    # ==========================================================
    # FILE INTEGRITY CHECK
    # ==========================================================

    elif action == "integrity":

        results.append("=" * 60)
        results.append("FILE INTEGRITY CHECK")
        results.append("=" * 60)

        stored_hash = get_saved_hash(filename)

        if stored_hash is None:

            results.append("Status : First Scan")
            results.append("No previous hash available.")
            save_hash(filename, sha256)

        elif stored_hash == sha256:

            results.append("Integrity Status : VERIFIED")
            results.append("File has NOT been modified.")

        else:

            results.append("Integrity Status : FAILED")
            results.append("File contents have been modified.")

            save_hash(filename, sha256)

        results.append("")

        results.append("=" * 60)
        results.append("INTEGRITY CHECK COMPLETED")
        results.append("=" * 60)

        return results

    # ==========================================================
    # MALWARE CHECK
    # ==========================================================

    elif action == "malware":

        matches = check_malware_signatures(file_path)

        results.append("=" * 60)
        results.append("MALWARE SIGNATURE SCAN")
        results.append("=" * 60)

        if matches:

            results.append("Suspicious Patterns Found:")

            for item in matches:

                results.append(f"• {item}")

            risk_score -= min(len(matches) * 5, 30)

        else:

            results.append("No known malware signatures detected.")

        results.append("")

        # ==========================================================
        # MALWARE ANALYSIS
        # ==========================================================

        results.append("=" * 60)
        results.append("MALWARE ANALYSIS")
        results.append("=" * 60)

        dangerous_extensions = [

            ".exe",
            ".dll",
            ".bat",
            ".cmd",
            ".scr",
            ".ps1",
            ".vbs",
            ".js",
            ".jar",
            ".com"

        ]

        if extension in dangerous_extensions:

            results.append("Dangerous Extension : YES")
            risk_score -= 25

        else:

            results.append("Dangerous Extension : NO")

        if mime in [

            "application/x-dosexec",
            "application/x-msdownload"

        ]:

            results.append("Executable File : YES")
            risk_score -= 20

        elif mime == "application/javascript":

            results.append("JavaScript File Detected")
            risk_score -= 10

        elif mime == "text/html":

            results.append("HTML File Detected")

        elif mime == "application/x-python-code":

            results.append("Python Script Detected")

        else:

            results.append("No suspicious MIME type detected.")

        if len(filename.split(".")) > 2:

            results.append("Multiple Extension : YES")
            risk_score -= 15

        else:

            results.append("Multiple Extension : NO")

        results.append("")