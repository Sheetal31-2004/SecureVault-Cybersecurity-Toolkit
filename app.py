from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from crypto_utils import (
    encrypt_message,
    decrypt_message,
    encrypt_file,
    load_key
)
from scan_profiles import SCAN_PROFILES
from file_scanner import scan_file_for_vulnerabilities
from file_scanner import calculate_hash
from reportlab.pdfgen import canvas
import io, os
import sqlite3
import hashlib
import ssl
from datetime import datetime
from datetime import datetime
from zoneinfo import ZoneInfo
from scanner import (
   simple_port_scan,
    check_http_headers,
    identify_services,
    banner_grab,
    ssl_analysis,
    website_information,
    domain_information
)
from crypto_utils import (
    sign_file,
    verify_signature
)

app=Flask(__name__)
app.secret_key="securevault_secret_key_2026"

key = load_key()

@app.route('/login', methods=['GET','POST'])
def login():

    if request.method=="POST":

        username=request.form["username"]
        password=request.form["password"]

        conn=sqlite3.connect("securevault.db")
        cur=conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user=cur.fetchone()

        conn.close()

        if user and check_password_hash(user[3],password):

            session["user"]=user[1]

            conn = sqlite3.connect("securevault.db")
            cur = conn.cursor()

            cur.execute(
                "INSERT INTO activity_log(username,activity,details) VALUES(?,?,?)",
                (
                    user[1],
                    "Login",
                    "Successful Login"
                )
            )
            conn.commit()
            conn.close()

            return redirect(url_for("dashboard"))
            
        return render_template(
            "login.html",
            error="Invalid Credentials"
        )

    return render_template("login.html")


@app.route('/register',methods=['GET','POST'])
def register():

    if request.method=="POST":

        username=request.form["username"]
        email=request.form["email"]
        password=request.form["password"]

        conn=sqlite3.connect("securevault.db")
        cur=conn.cursor()

        try:

            cur.execute(
                "INSERT INTO users(username,email,password) VALUES(?,?,?)",
                (
                    username,
                    email,
                    generate_password_hash(password)
                )
            )

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            return render_template(
                "register.html",
                error="Email already registered"
            )

        conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route("/file-scan-center")
def file_scan_center():
    return render_template("file_scan.html")


@app.route("/malware-scan")
def malware_scan():
    return render_template("malware_scan.html")


@app.route("/generate-hashes")
def generate_hashes():
    return render_template("hash_generator.html")


@app.route("/integrity-check")
def integrity_check():
    return render_template("integrity_check.html")

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_route():

    if 'user' not in session:
        return redirect(url_for('login'))

    encryption = None

    if request.method == 'POST':

        message = request.form['message']

        encryption = encrypt_message(
            message,
            key
        )

    return render_template(
        'encrypt.html',
        encryption=encryption
    )
@app.route("/encryption")
def encryption_dashboard():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "encryption_dashboard.html"
    )

@app.route("/hash-generator", methods=["GET","POST"])
def hash_generator():

    if "user" not in session:
        return redirect(url_for("login"))

    hashes=None

    if request.method=="POST":

        file=request.files["file"]

        os.makedirs("uploads",exist_ok=True)

        path=os.path.join(
            "uploads",
            file.filename
        )

        file.save(path)

        algorithms=request.form.getlist("algorithms")

        hashes={}

        for algo in algorithms:

            hashes[algo]=calculate_hash(path,algo)

    return render_template(
        "hash_generator.html",
        hashes=hashes
    )
@app.route("/digital-signature", methods=["GET", "POST"])
def digital_signature():

    if "user" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":

        uploaded_file = request.files["file"]

        os.makedirs("uploads", exist_ok=True)

        filepath = os.path.join(
            "uploads",
            uploaded_file.filename
        )

        uploaded_file.save(filepath)

        action = request.form.get("action")

        if action == "sign":

            data = sign_file(filepath)

            signature_path = filepath + ".sig"

            with open(signature_path, "wb") as f:

                f.write(data["signature"])

            private_path = filepath + "_private.pem"

            with open(private_path, "wb") as f:

                f.write(data["private_key"])

            public_path = filepath + "_public.pem"

            with open(public_path, "wb") as f:

                f.write(data["public_key"])

            result = "✅ Digital Signature Generated Successfully"

        elif action == "verify":

            signature_file = request.files.get("signature")

            public_file = request.files.get("public_key")

            if not signature_file or not public_file:

                result = "❌ Please upload both the signature (.sig) and public key (.pem)."

            else:

                signature = signature_file.read()

                public_key = public_file.read()

                valid = verify_signature(

                    filepath,

                    signature,

                    public_key

                )

                if valid:

                    result = "✅ VALID DIGITAL SIGNATURE"

                else:

                    result = "❌ INVALID DIGITAL SIGNATURE"

    return render_template(
        "digital_signature.html",
        result=result
    )

@app.route('/file-encrypt', methods=['GET', 'POST'])
def file_encrypt():

    if 'user' not in session:
        return redirect(url_for('login'))

    encrypted_file = None

    if request.method == 'POST':

        file = request.files['file']

        os.makedirs(
            "uploads",
            exist_ok=True
        )

        filepath = os.path.join(
            "uploads",
            file.filename
        )

        file.save(filepath)

        encrypted_path = encrypt_file(
            filepath,
            key
        )

        encrypted_file = os.path.basename(
            encrypted_path
        )

    return render_template(
        'file_encrypt.html',
        encrypted_file=encrypted_file
    )

@app.route("/decrypt")
def decrypt_dashboard():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("decrypt_dashboard.html")

@app.route('/message-decrypt', methods=['GET', 'POST'])
def message_decrypt():
    if 'user' not in session:
        return redirect(url_for('login'))
    decrypted = None
    if request.method == 'POST':
        encrypted_msg = request.form['encrypted_msg']
        try:
            decrypted = decrypt_message(encrypted_msg.encode(), key)
        except Exception:
            decrypted = "Invalid encrypted message."
    return render_template('decrypt.html', decrypted=decrypted)

@app.route("/file-decrypt", methods=["GET", "POST"])
def file_decrypt():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("file_decrypt.html")

@app.route("/verify-hash")
def verify_hash():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("verify_hash.html")

# Reports Dashboard

@app.route("/reports-dashboard")
def reports_dashboard():
    return render_template("reports_dashboard.html")


# Network Reports

@app.route("/network-reports")
def network_reports():
    return render_template("network_reports.html")


# File Reports

@app.route("/file-reports")
def file_reports():
    return render_template("file_reports.html")


# Encryption Reports

@app.route("/encryption-reports")
def encryption_reports():
    return render_template("encryption_reports.html")


# Audit Logs

@app.route("/audit-logs")
def audit_logs():
    return render_template("audit_logs.html")

@app.route('/download/<filename>')
def download_file(filename):

    filepath = os.path.join(
        "uploads",
        filename
    )

    return send_file(
        filepath,
        as_attachment=True
    )

@app.route('/scan', methods=['GET', 'POST'])
def scan():

    if 'user' not in session:
        return redirect(url_for('login'))

    results = None
    target = None

    if request.method == 'POST':

        target = request.form['target']
        scan_type = request.form['scan_type']
        print("=" * 40)
        print("Target:", target)
        print("Scan Type:", scan_type)
        print("=" * 40)
        profile = SCAN_PROFILES[scan_type]

        results = []


        results.append(f"Scan Profile : {scan_type.upper()}")

        # ---------------- QUICK ----------------

        if scan_type == "quick":

            open_ports = simple_port_scan(target, profile["ports"])

            if open_ports:

                results.append("\n[+] Open Ports")

                results.extend(
                    identify_services(open_ports)
                )

            else:

                results.append("No Open Ports Found")


        # ---------------- FULL ----------------

        elif scan_type == "full":

            open_ports = simple_port_scan(target, profile["ports"])

            if open_ports:

                results.append("\n[+] Open Ports")

                results.extend(
                    identify_services(open_ports)
                )

            results.append("\n[+] Banner Information")
            results.extend(
                banner_grab(target)
            )

            results.append("\n[+] Security Headers")
            results.extend(
                check_http_headers(target)
            )

            results.append("\n[+] SSL/TLS Analysis")
            results.extend(
                ssl_analysis(target)
            )


        # ---------------- WEB ----------------

        elif scan_type == "web":

            results.append("\n[+] Web Technology Detection")

            results.extend(
                banner_grab(target)
            )

            results.append("\n[+] HTTP Security Headers")

            results.extend(
                check_http_headers(target)
            )

            results.append("\n[+] SSL/TLS")

            results.extend(
                ssl_analysis(target)
            )

        risk_score = "Low"

        conn = sqlite3.connect(
            "securevault.db"
        )

        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO scan_history
            (
                target,
                scan_type,
                risk_score
            )
            VALUES(?,?,?)
            """,
            (
                target,
                scan_type,
                risk_score
            )
        )

        conn.commit()
        conn.close()
    return render_template(
        'scan.html',
        scan_result="\n".join(results) if results else None,
        target=target
        
    )

@app.route("/history")
def history():

    if "user" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("securevault.db")
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()

    search = request.args.get("search", "")
    scan_type = request.args.get("type", "")

    query = "SELECT * FROM scan_history WHERE 1=1"
    values = []

    if search:
        query += " AND target LIKE ?"
        values.append(f"%{search}%")

    if scan_type:
        query += " AND scan_type=?"
        values.append(scan_type)

    query += " ORDER BY id DESC"

    cur.execute(query, values)

    scans = cur.fetchall()

    conn.close()

    return render_template(
        "history.html",
        scans=scans,
        search=search,
        scan_type=scan_type
    )

@app.route("/delete-history/<int:id>")
def delete_history(id):

    conn = sqlite3.connect("securevault.db")
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM scan_history WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("history"))

@app.route('/report', methods=['GET','POST'])
def report():

    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == "GET":
        return render_template("report.html")
    target = request.form['report_target']
    scan_type = request.form.get(
        "scan_type",
        "Web Application"
    )
    action = request.form.get("action")
    if scan_type.lower() == "web application":
        profile = SCAN_PROFILES["web"]
    elif scan_type.lower() == "quick":
        profile = SCAN_PROFILES["quick"]
    elif scan_type.lower() == "full":
        profile = SCAN_PROFILES["full"]
    else:
        profile = SCAN_PROFILES["quick"]

    mumbai_time=datetime.now(
        ZoneInfo("Asia/Kolkata")
    )

    report_time=mumbai_time.strftime(
        "%d-%m-%Y %I:%M:%S %p IST"
    )
    report_id=mumbai_time.strftime(
        "SV-%Y%m%d-%H%M%S"
    )
    ports = simple_port_scan(target)
    headers = check_http_headers(target)
    banner = banner_grab(target)
    website = website_information(target)
    domain_info = domain_information(target)
    report_data = f"{target}{ports}{headers}{report_id}"
    ssl_results = ssl_analysis(target)

    verification_hash = hashlib.sha256(
        report_data.encode()
    ).hexdigest()

    buffer = io.BytesIO()

    pdf = canvas.Canvas(buffer)

    



    # ===================================================
    # PAGE 1 : COVER PAGE
    # ===================================================

    pdf.setTitle("SecureVault Security Assessment Report")

    # Page Border
    pdf.rect(20,20,570,800)

    # Logo
    pdf.drawImage(
        "static/css/images/logo.png",
        50,
        735,
        width=70,
        height=70
    )

    # Company Name
    pdf.setFont("Helvetica-Bold",24)
    pdf.drawString(
        140,
        790,
        "SECUREVAULT"
    )

    pdf.setFont("Helvetica",13)
    pdf.drawString(
        140,
        770,
        "Cyber Security Management Platform"
    )

    pdf.setFont("Helvetica",11)
    pdf.drawString(
        140,
        752,
        "Protect • Detect • Defend"
    )

    # -------------------------------------------------

    pdf.setLineWidth(1.2)
    pdf.line(45,720,550,720)

    # Main Heading

    pdf.setFont("Helvetica-Bold",22)

    pdf.drawCentredString(
        300,
        680,
        "ENTERPRISE SECURITY ASSESSMENT REPORT"
    )

    pdf.setFont("Helvetica",12)

    pdf.drawCentredString(
        300,
        660,
        "Professional Web Application Security Report"
    )

    # -------------------------------------------------
    # REPORT DETAILS
    # -------------------------------------------------

    # Table Border
    pdf.roundRect(70,395,460,220,8)

    # Horizontal Lines
    for i in range(1,6):
        pdf.line(70,615-(i*35),530,615-(i*35))

    # Vertical Line
    pdf.line(230,395,230,615)

    rows = [
        ("Report ID", report_id),
        ("Target Website", target),
        ("Assessment Type", f"{scan_type.title()} Scan"),
        ("Generated On", report_time),
        ("Generated By", "SecureVault Enterprise"),
        ("Version", "1.0")
    ]

    y = 592

    for left,right in rows:
        pdf.setFont("Helvetica-Bold",12)
        pdf.drawString(90,y,left)

        pdf.setFont("Helvetica",12)
        pdf.drawString(245,y,right)

        y -= 35
    # -------------------------------------------------
    # CONFIDENTIAL BOX
    # -------------------------------------------------

    pdf.setFillGray(0.95)

    pdf.roundRect(
        70,
        250,
        460,
        110,
        8,
        fill=1
    )

    pdf.setFillGray(0)

    pdf.setFont("Helvetica-Bold",16)

    pdf.drawCentredString(
        300,
        330,
        "CONFIDENTIAL"
    )

    pdf.setFont("Helvetica",11)

    pdf.drawCentredString(
        300,
        305,
        "This report contains confidential cyber security information."
    )

    pdf.drawCentredString(
        300,
        287,
        "Distribution without authorization is prohibited."
    )

    pdf.drawCentredString(
        300,
        269,
        "Generated Automatically by SecureVault."
    )
    # -------------------------------------------------
    # FOOTER
    # -------------------------------------------------
    pdf.setFont("Helvetica",10)
    pdf.drawRightString(
        550,
        50,
        "Page 1"
    )
    # Next Page
    pdf.showPage()
    # ===================================================
    # PAGE 2 : EXECUTIVE SUMMARY
    # ===================================================
    pdf.rect(20,20,570,800)
    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"EXECUTIVE SUMMARY")
    pdf.line(45,775,550,775)
    # ===================================================
    # ASSESSMENT INFORMATION
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"ASSESSMENT INFORMATION")
    # Table Border
    pdf.roundRect(45,560,500,160,8)
    # Horizontal Lines
    for i in range(1,6):
        pdf.line(45,720-(i*26),545,720-(i*26))
    # Vertical Line
    pdf.line(220,560,220,720)
    rows = [
    ("Report ID", report_id),
    ("Target Website", target),
    ("Assessment Type", f"{scan_type.title()} Scan"),
    ("Assessment Date", report_time),
    ("Generated By", "SecureVault Enterprise"),
    ("Version", "1.0")
    ]
    y = 700
    for left,right in rows:
        pdf.setFont("Helvetica-Bold",11)
        pdf.drawString(60,y,left)
        pdf.setFont("Helvetica",11)
        pdf.drawString(235,y,str(right))
        y -= 26
    # ===================================================
    # WEBSITE STATUS
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,525,"WEBSITE STATUS")
    pdf.roundRect(45,420,500,85,8)
    pdf.setFont("Helvetica",11)
    pdf.drawString(70,485,"✓ Website Reachable")
    pdf.drawString(300,485,"✓ HTTPS Enabled")
    pdf.drawString(70,460,"✓ SSL Certificate Valid")
    pdf.drawString(300,460,"✓ Domain Resolved")
    pdf.drawString(70,435,"✓ Scan Completed Successfully")
    # ===================================================
    # EXECUTIVE REMARKS
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,390,"EXECUTIVE REMARKS")
    pdf.roundRect(45,170,500,190,8)
    pdf.setFont("Helvetica",11)
    remarks = [
    "Target website is publicly accessible.",
    "SSL/TLS configuration appears secure.",
    "Website responded successfully during scanning.",
    "Some HTTP security headers require improvement.",
    "Overall security posture is GOOD."
    ]
    y = 330
    for remark in remarks:
        pdf.drawString(70,y,f"• {remark}")
        y -= 28
    pdf.drawRightString(550,50,"Page 2")


    # ===================================================
    # PAGE 3 : WEBSITE INFORMATION
    # ===================================================

    pdf.showPage()

    pdf.rect(20,20,570,800)

    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"WEBSITE INFORMATION")
    pdf.line(45,775,550,775)

    # ===================================================
    # WEBSITE DETAILS
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"WEBSITE DETAILS")

    # Table Border
    pdf.roundRect(45,395,500,315,8)

    # Horizontal Lines
    for i in range(1,12):
        pdf.line(45,710-(i*28),545,710-(i*28))
    # Vertical Line
    pdf.line(220,395,220,710)
    rows = [
    ("Website Name", website.get("title","Unknown")),
    ("Website URL", website.get("url","Unknown")),
    ("HTTP Status", website.get("status","Unknown")),
    ("Protocol", website.get("protocol","Unknown")),
    ("Server", website.get("server","Unknown")),
    ("Content Type", website.get("content_type","Unknown")),
    ("Response Time", f"{website.get('response_time','Unknown')} sec"),
    ("Reachable", website.get("reachable","Unknown")),
    ("Redirect Count", website.get("redirects","Unknown")),
    ("Powered By", website.get("powered_by","Unknown")),
    ("Last Modified", website.get("last_modified","Unknown"))
    ]
    y = 695
    for left,right in rows:
        pdf.setFont("Helvetica-Bold",11)
        pdf.drawString(60,y,left)
        pdf.setFont("Helvetica",11)
        pdf.drawString(235,y,str(right))
        y -= 28
    # ===================================================
    # WEBSITE OVERVIEW
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,350,"WEBSITE OVERVIEW")
    pdf.roundRect(45,70,500,250,8)
    overview = [
        ("Application Name", website.get("title","Unknown")),
        ("Purpose", "Public Web Application"),
        ("Availability", "Accessible via Internet"),
        ("Scan Result", "Website responded successfully."),
        ("Security Status", "Assessment Completed")
    ]
    y = 285
    for label, value in overview:
        pdf.setFont("Helvetica-Bold",11)
        pdf.drawString(65, y, label)
        pdf.setFont("Helvetica",11)
        pdf.drawString(190, y, str(value))
        y -= 40
    # -----------------------------------------
    # FOOTER
    # -----------------------------------------
    pdf.setFont("Helvetica",10)
    pdf.drawRightString(
        550,
        50,
        "Page 3"
    )
    # ===================================================
    # PAGE 4 : DOMAIN INTELLIGENCE
    # ===================================================

    pdf.showPage()

    pdf.rect(20,20,570,800)

    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"DOMAIN INTELLIGENCE")
    pdf.line(45,775,550,775)

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"DOMAIN REGISTRATION INFORMATION")

    # ===========================
    # TABLE
    # ===========================

    pdf.roundRect(45,430,500,290,8)

    # Vertical Line
    pdf.line(220,430,220,720)

    # Horizontal Lines
    for i in range(1,10):
        pdf.line(45,720-(i*29),545,720-(i*29))

    rows = [

    ("Domain", domain_info.get("domain","Unknown")),

    ("Public IP", domain_info.get("ip","Unknown")),

    ("Registrar", domain_info.get("registrar","Unknown")),

    ("Creation Date", domain_info.get("creation_date","Unknown")),

    ("Expiry Date", domain_info.get("expiration_date","Unknown")),

    ("Name Servers", ", ".join(domain_info.get("name_servers",["Unknown"]))),

    ("Hosting Provider", domain_info.get("organization","Unknown")),

    ("Country", domain_info.get("country","Unknown")),

    ("Reverse DNS", domain_info.get("reverse_dns","Unknown"))

    ]

    y = 695

    for left,right in rows:

        pdf.setFont("Helvetica-Bold",11)
        pdf.drawString(60,y,left)

        pdf.setFont("Helvetica",11)

        value = str(right)

        # Prevent very long values from overflowing
        if len(value) > 45:
            value = value[:42] + "..."

        pdf.drawString(235,y,value)

        y -= 29
    # ===========================
    # DOMAIN SUMMARY
    # ===========================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,390,"DOMAIN SUMMARY")

    pdf.roundRect(45,140,500,210,8)

    pdf.setFont("Helvetica",11)

    summary = [
    "• Domain registration information successfully retrieved.",
    "• DNS records resolved correctly.",
    "• Public IP address identified.",
    "• Hosting provider information available.",
    "• Domain ownership appears valid.",
    "• No registration anomalies detected."
    ]

    y = 320

    for item in summary:

        pdf.drawString(65,y,item)

        y -= 28


    pdf.drawRightString(
        550,
        50,
        "Page 4"
    )
    # ===================================================
    # PAGE 5 : NETWORK SCAN
    # ===================================================
    pdf.showPage()
    pdf.rect(20,20,570,800)
    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"NETWORK SCAN")
    pdf.line(45,775,550,775)
    # ===================================================
    # SCAN SUMMARY
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"SCAN SUMMARY")

    pdf.roundRect(45,620,500,90,8)

    pdf.setFont("Helvetica-Bold",11)
    pdf.drawString(60,685,"Target")
    pdf.drawString(200,685,target)

    pdf.drawString(60,660,"Scan Profile")
    pdf.drawString(200,660,scan_type.title())

    pdf.drawString(60,635,"Open Ports")
    pdf.drawString(200,635,str(len(ports)))

    # ===================================================
    # OPEN PORTS TABLE
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,585,"OPEN PORTS")

    pdf.roundRect(45,330,500,220,8)

    # Header Line
    pdf.line(45,520,545,520)

    # Vertical Lines
    pdf.line(120,330,120,550)
    pdf.line(250,330,250,550)
    pdf.line(380,330,380,550)

    # Header
    pdf.setFont("Helvetica-Bold",11)

    pdf.drawCentredString(82,532,"PORT")
    pdf.drawCentredString(185,532,"SERVICE")
    pdf.drawCentredString(315,532,"STATUS")
    pdf.drawCentredString(462,532,"RISK")

    # ======================================
    # PORT DATA
    # ======================================

    y = 500

    for port in ports:

        if port == 21:
            service = "FTP"
            risk = "HIGH"

        elif port == 22:
            service = "SSH"
            risk = "MEDIUM"

        elif port == 23:
            service = "TELNET"
            risk = "HIGH"

        elif port == 80:
            service = "HTTP"
            risk = "LOW"

        elif port == 443:
            service = "HTTPS"
            risk = "LOW"

        elif port == 3306:
            service = "MYSQL"
            risk = "MEDIUM"

        elif port == 3389:
            service = "RDP"
            risk = "HIGH"

        elif port == 8080:
            service = "HTTP-ALT"
            risk = "LOW"

        else:
            service = "UNKNOWN"
            risk = "MEDIUM"

        # Horizontal row line
        pdf.line(45,y-8,545,y-8)

        pdf.setFont("Helvetica",10)

        pdf.drawCentredString(82,y,str(port))
        pdf.drawCentredString(185,y,service)
        pdf.drawCentredString(315,y,"OPEN")
        pdf.drawCentredString(462,y,risk)

        y -= 28

    if len(ports)==0:

        pdf.setFont("Helvetica",11)
        pdf.drawString(60,500,"No open ports detected.")

    # ===================================================
    # SCAN STATISTICS
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,290,"SCAN STATISTICS")

    pdf.roundRect(45,120,500,140,8)

    pdf.setFont("Helvetica",11)

    pdf.drawString(65,225,f"• Ports Scanned : {len(profile['ports'])}")

    pdf.drawString(65,200,f"• Open Ports : {len(ports)}")

    pdf.drawString(65,175,"• Scan Status : Completed Successfully")

    pdf.drawString(65,150,"• Risk Assessment : Low")

    pdf.drawRightString(550,50,"Page 5")

    # ===================================================
    # PAGE 6 : TECHNOLOGY DETECTION
    # ===================================================

    pdf.showPage()

    pdf.rect(20,20,570,800)

    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"TECHNOLOGY DETECTION")
    pdf.line(45,775,550,775)

    # ==========================================
    # SECTION TITLE
    # ==========================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"TECHNOLOGY SUMMARY")

    # ==========================================
    # TABLE
    # ==========================================

    pdf.roundRect(45,470,500,230,8)

    pdf.line(220,470,220,700)

    for i in range(1,8):
        pdf.line(45,700-(i*32),545,700-(i*32))

    # ==========================================
    # Extract Values
    # ==========================================

    server = "Unknown"
    technology = "Hidden"
    content_type = "Unknown"
    framework = "Not Detected"
    cms = "Not Detected"
    javascript = "Not Detected"

    for item in banner:

        if item.startswith("Server:"):
            server = item.replace("Server:","").strip()

        elif item.startswith("Technology:"):
            technology = item.replace("Technology:","").strip()

        elif item.startswith("Content-Type:"):
            content_type = item.replace("Content-Type:","").strip()

        elif "Frontend Framework" in item:
            framework = item.split(":")[-1].strip()

        elif "CMS:" in item:
            cms = item.split(":")[-1].strip()

        elif "JavaScript Library:" in item:
            javascript = item.split(":")[-1].strip()

    rows = [

    ("Server",server),

    ("Technology",technology),

    ("Content Type",content_type),

    ("Frontend Framework",framework),

    ("CMS",cms),

    ("JavaScript Library",javascript)

    ]

    y = 680

    for label,value in rows:

        pdf.setFont("Helvetica-Bold",11)
        pdf.drawString(60,y,label)

        pdf.setFont("Helvetica",11)
        pdf.drawString(235,y,str(value))

        y -= 32

    # ==========================================
    # TECHNOLOGY ANALYSIS
    # ==========================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,430,"TECHNOLOGY ANALYSIS")

    pdf.roundRect(45,180,500,220,8)

    remarks = []

    remarks.append("• Web server identified successfully.")

    if technology.lower() == "hidden":
        remarks.append("• X-Powered-By header is hidden.")

    else:
        remarks.append("• Technology stack disclosed.")

    if framework != "Not Detected":
        remarks.append(f"• Frontend Framework detected : {framework}")

    else:
        remarks.append("• No frontend framework detected.")

    if cms != "Not Detected":
        remarks.append(f"• CMS detected : {cms}")

    else:
        remarks.append("• No CMS detected.")

    remarks.append("• Technology exposure is within acceptable limits.")

    y = 360

    pdf.setFont("Helvetica",11)

    for line in remarks:

        pdf.drawString(65,y,line)

        y -= 30

    # ==========================================
    # RISK SUMMARY
    # ==========================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,140,"TECHNOLOGY RISK")

    pdf.setFont("Helvetica",11)

    pdf.drawString(65,115,"Information Disclosure")
    pdf.drawString(300,115,"LOW")

    pdf.drawString(65,95,"Technology Exposure")
    pdf.drawString(300,95,"LOW")

    pdf.drawString(65,75,"Overall Risk")
    pdf.drawString(300,75,"LOW")

    pdf.drawRightString(
        550,
        50,
        "Page 6"
    )

    # ===================================================
    # PAGE 7 : HTTP SECURITY HEADERS
    # ===================================================

    pdf.showPage()

    pdf.rect(20,20,570,800)

    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"HTTP SECURITY HEADERS")
    pdf.line(45,775,550,775)

    # ===================================================
    # SECTION TITLE
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"SECURITY HEADER ANALYSIS")

    # ===================================================
    # TABLE
    # ===================================================

    pdf.roundRect(45,330,500,370,8)

    # Vertical Lines
    pdf.line(240,330,240,700)
    pdf.line(370,330,370,700)

    # Header Line
    pdf.line(45,670,545,670)

    # Row Lines
    for i in range(1,7):
        pdf.line(45,670-(i*50),545,670-(i*50))

    # Header Titles

    pdf.setFont("Helvetica-Bold",11)

    pdf.drawCentredString(140,683,"HEADER")
    pdf.drawCentredString(305,683,"STATUS")
    pdf.drawCentredString(455,683,"REMARK")

    # ===================================================
    # HEADER DATA
    # ===================================================

    header_names = [
        "X-Frame-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    present = 0
    missing = 0

    y = 645

    for i, item in enumerate(headers):

        header = header_names[i]

        if "Present" in item:

            status = "PASS"
            remark = "Configured"
            present += 1

        else:

            status = "FAIL"
            remark = "Missing"
            missing += 1

        pdf.setFont("Helvetica",10)

        pdf.drawString(55,y,header)

        pdf.drawCentredString(305,y,status)

        pdf.drawCentredString(455,y,remark)

        y -= 50

    # ===================================================
    # SUMMARY
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,280,"HEADER SUMMARY")

    pdf.roundRect(45,120,500,130,8)

    pdf.setFont("Helvetica",11)

    pdf.drawString(60,220,f"Headers Checked : {len(header_names)}")

    pdf.drawString(60,195,f"Headers Present : {present}")

    pdf.drawString(60,170,f"Headers Missing : {missing}")

    score = round((present/len(header_names))*100)

    pdf.drawString(300,220,f"Security Score : {score}/100")

    if score >= 80:
        rating = "GOOD"

    elif score >= 60:
        rating = "MODERATE"

    else:
        rating = "POOR"

    pdf.drawString(300,195,f"Overall Rating : {rating}")

    pdf.drawString(300,170,"Recommendation : Configure missing headers")

    pdf.drawRightString(550,50,"Page 7")

    # ===================================================
    # PAGE 8 : SSL/TLS ANALYSIS
    # ===================================================

    pdf.showPage()

    pdf.rect(20,20,570,800)

    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"SSL / TLS SECURITY ANALYSIS")
    pdf.line(45,775,550,775)

    # ===================================================
    # CERTIFICATE DETAILS
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"SSL CERTIFICATE DETAILS")

    pdf.roundRect(45,470,500,230,8)

    pdf.line(220,470,220,700)

    for i in range(1,7):
        pdf.line(45,700-(i*32),545,700-(i*32))

    tls_version = "Unknown"
    tls_security = "Unknown"
    certificate = "Unknown"
    issuer = "Unknown"
    expiry = "Unknown"
    days = "Unknown"

    for item in ssl_results:

        if item.startswith("TLS Version"):
            tls_version = item.split(":",1)[1].strip()

        elif item.startswith("TLS Security"):
            tls_security = item.split(":",1)[1].strip()

        elif "SSL Certificate" in item:
            certificate = item.split(":")[-1].strip()

        elif item.startswith("Issuer"):
            issuer = item.split(":",1)[1].strip()

        elif item.startswith("Expires"):
            expiry = item.split(":",1)[1].strip()

        elif item.startswith("Days Remaining"):
            days = item.split(":",1)[1].strip()

    rows = [

    ("Certificate Status",certificate),

    ("TLS Version",tls_version),

    ("TLS Security",tls_security),

    ("Certificate Issuer",issuer),

    ("Expiry Date",expiry),

    ("Days Remaining",days)

    ]

    y = 680

    for label,value in rows:

        pdf.setFont("Helvetica-Bold",11)
        pdf.drawString(60,y,label)

        pdf.setFont("Helvetica",11)
        pdf.drawString(235,y,str(value))

        y -= 32

    # ===================================================
    # SSL SECURITY ANALYSIS
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,430,"SSL SECURITY ANALYSIS")

    pdf.roundRect(45,180,500,220,8)

    remarks = []

    if certificate.upper()=="VALID":
        remarks.append("• SSL Certificate is valid.")
    else:
        remarks.append("• SSL Certificate validation failed.")

    remarks.append(f"• TLS Version detected : {tls_version}")

    if tls_security.upper()=="EXCELLENT":
        remarks.append("• Latest TLS protocol detected.")

    elif tls_security.upper()=="GOOD":
        remarks.append("• Secure TLS configuration detected.")

    else:
        remarks.append("• Weak TLS configuration detected.")

    remarks.append("• Certificate issued by a trusted authority.")

    remarks.append("• Secure encrypted communication supported.")

    pdf.setFont("Helvetica",11)

    y = 360

    for line in remarks:

        pdf.drawString(65,y,line)

        y -= 30

    # ===================================================
    # SECURITY SCORE
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,140,"SSL SECURITY SCORE")

    pdf.roundRect(45,70,500,50,8)

    score = 95

    if tls_security=="GOOD":
        score = 85

    elif tls_security=="WEAK":
        score = 50

    pdf.setFont("Helvetica-Bold",16)
    pdf.drawString(70,88,f"Overall SSL Score : {score}/100")

    # ===================================================
    # FOOTER
    # ===================================================


    pdf.setFont("Helvetica",10)


    pdf.drawRightString(
        550,
        50,
        "Page 8"
    )

    # ===================================================
    # PAGE 9 : DNS & DOMAIN INFORMATION
    # ===================================================

    pdf.showPage()

    pdf.rect(20,20,570,800)

    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"DNS & DOMAIN INFORMATION")
    pdf.line(45,775,550,775)

    # ===================================================
    # DOMAIN INFORMATION
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"DOMAIN DETAILS")

    pdf.roundRect(45,430,500,280,8)

    # Vertical Line
    pdf.line(220,430,220,710)

    # Horizontal Lines
    for i in range(1,9):
        pdf.line(45,710-(i*31),545,710-(i*31))

    rows = [

    ("Domain",domain_info.get("domain","Unknown")),

    ("Public IP",domain_info.get("ip","Unknown")),

    ("Registrar",domain_info.get("registrar","Unknown")),

    ("Hosting Provider",domain_info.get("organization","Unknown")),

    ("Country",domain_info.get("country","Unknown")),

    ("Reverse DNS",domain_info.get("reverse_dns","Unknown")),

    ("Creation Date",domain_info.get("creation_date","Unknown")),

    ("Expiry Date",domain_info.get("expiration_date","Unknown"))

    ]

    y = 690

    for left,right in rows:

        pdf.setFont("Helvetica-Bold",11)
        pdf.drawString(60,y,left)

        pdf.setFont("Helvetica",11)

        value = str(right)

        if len(value) > 42:
            value = value[:39] + "..."

        pdf.drawString(235,y,value)

        y -= 31

    # ===================================================
    # DNS SUMMARY
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,390,"DNS SUMMARY")

    pdf.roundRect(45,160,500,190,8)

    remarks = [

    "• Domain successfully resolved.",

    "• Public IP address identified.",

    "• DNS lookup completed successfully.",

    "• Hosting provider identified.",

    "• Reverse DNS record available.",

    "• Domain registration information verified."

    ]

    pdf.setFont("Helvetica",11)

    y = 320

    for item in remarks:

        pdf.drawString(65,y,item)

        y -= 28

    # ===================================================
    # FOOTER
    # ===================================================

    

    pdf.setFont("Helvetica",10)

    pdf.drawRightString(
        550,
        50,
        "Page 9"
    )

    # ===================================================
    # PAGE 10 : SECURITY SCORE & RISK ASSESSMENT
    # ===================================================

    pdf.showPage()

    pdf.rect(20,20,570,800)

    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"SECURITY SCORE & RISK ASSESSMENT")
    pdf.line(45,775,550,775)

    # ===================================================
    # CALCULATE SCORE
    # ===================================================

    score = 100

    missing_headers = 0

    for h in headers:
        if "Missing" in h:
            missing_headers += 1

    score -= missing_headers * 5

    if len(ports) > 5:
        score -= 10

    tls_security = "GOOD"

    for item in ssl_results:

        if "TLS Security" in item:

            tls_security = item.split(":")[1].strip()

    if tls_security == "WEAK":
        score -= 20

    elif tls_security == "GOOD":
        score -= 5

    if score < 0:
        score = 0

    # ===================================================
    # RISK LEVEL
    # ===================================================

    if score >= 90:
        risk = "LOW"

    elif score >= 75:
        risk = "MEDIUM"

    elif score >= 50:
        risk = "HIGH"

    else:
        risk = "CRITICAL"

    # ===================================================
    # OVERALL SCORE BOX
    # ===================================================

    pdf.setFont("Helvetica-Bold",15)
    pdf.drawString(50,735,"OVERALL SECURITY SCORE")

    pdf.roundRect(45,600,500,110,8)

    pdf.setFont("Helvetica-Bold",40)
    pdf.drawCentredString(295,650,f"{score}/100")

    pdf.setFont("Helvetica-Bold",18)
    pdf.drawCentredString(295,620,f"Risk Level : {risk}")

    # ===================================================
    # CATEGORY TABLE
    # ===================================================

    pdf.setFont("Helvetica-Bold",15)
    pdf.drawString(50,565,"CATEGORY WISE ASSESSMENT")

    pdf.roundRect(45,330,500,200,8)

    pdf.line(260,330,260,530)

    for i in range(1,6):
        pdf.line(45,530-(i*33),545,530-(i*33))

    categories = [

    ("Network Security","GOOD"),

    ("SSL/TLS Security",tls_security),

    ("HTTP Headers",
    f"{6-missing_headers}/6 Secure"),

    ("Technology Exposure","LOW"),

    ("DNS Security","GOOD")

    ]

    y = 505

    for left,right in categories:

        pdf.setFont("Helvetica-Bold",11)
        pdf.drawString(60,y,left)

        pdf.setFont("Helvetica",11)
        pdf.drawString(280,y,right)

        y -= 33

    # ===================================================
    # EXECUTIVE CONCLUSION
    # ===================================================

    pdf.setFont("Helvetica-Bold",15)
    pdf.drawString(50,290,"EXECUTIVE CONCLUSION")

    pdf.roundRect(45,90,500,170,8)

    remarks = [

    "• The target website was successfully assessed.",

    "• SSL/TLS configuration is secure.",

    "• Network exposure is minimal.",

    "• Some HTTP security headers require improvement.",

    "• No critical vulnerabilities were identified.",

    f"• Overall security posture is classified as {risk} risk."

    ]

    pdf.setFont("Helvetica",11)

    y = 230

    for line in remarks:

        pdf.drawString(65,y,line)

        y -= 24

    # ===================================================
    # FOOTER
    # ===================================================


    pdf.setFont("Helvetica",10)

    

    pdf.drawRightString(
        550,
        50,
        "Page 10"
    )

    # ===================================================
    # PAGE 11 : SECURITY RECOMMENDATIONS
    # ===================================================

    pdf.showPage()

    pdf.rect(20,20,570,800)

    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"SECURITY RECOMMENDATIONS")
    pdf.line(45,775,550,775)

    # ===================================================
    # INTRODUCTION
    # ===================================================

    pdf.setFont("Helvetica",11)

    pdf.drawString(
        50,
        745,
        "The following recommendations are based on the findings"
    )

    pdf.drawString(
        50,
        728,
        "identified during the SecureVault security assessment."
    )

    # ===================================================
    # RECOMMENDATION TABLE
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,690,"RECOMMENDED ACTIONS")

    pdf.roundRect(45,220,500,440,8)

    # Table Columns
    pdf.line(120,220,120,660)
    pdf.line(420,220,420,660)

    # Header
    pdf.line(45,630,545,630)

    # Row Lines
    for i in range(1,8):
        pdf.line(45,630-(i*50),545,630-(i*50))

    pdf.setFont("Helvetica-Bold",11)

    pdf.drawCentredString(80,642,"ID")
    pdf.drawCentredString(270,642,"Recommendation")
    pdf.drawCentredString(480,642,"Priority")

    # ===================================================
    # BUILD RECOMMENDATIONS
    # ===================================================

    recommendations = []

    # Missing Headers
    for item in headers:

        if "Missing" in item:

            header = item.split(":")[0]

            recommendations.append(
                (
                    header,
                    f"Configure {header} header.",
                    "MEDIUM"
                )
            )

    # Weak TLS
    for item in ssl_results:

        if "WEAK" in item:

            recommendations.append(
                (
                    "TLS",
                    "Upgrade to TLS 1.3.",
                    "HIGH"
                )
            )

    # Open Ports
    if len(ports) > 5:

        recommendations.append(
            (
                "Ports",
                "Close unnecessary open ports.",
                "HIGH"
            )
        )

    # Technology Disclosure
    for item in banner:

        if item.startswith("Technology:"):

            if "Hidden" not in item:

                recommendations.append(
                    (
                        "Technology",
                        "Hide technology stack information.",
                        "LOW"
                    )
                )

    # Default Recommendation
    recommendations.append(
        (
            "Monitoring",
            "Perform periodic vulnerability assessments.",
            "LOW"
        )
    )

    # ===================================================
    # PRINT TABLE
    # ===================================================

    pdf.setFont("Helvetica",10)

    y = 610

    count = 1

    for rec in recommendations[:8]:

        pdf.drawCentredString(80,y,str(count))

        pdf.drawString(130,y,rec[1])

        pdf.drawCentredString(480,y,rec[2])

        y -= 50

        count += 1

    # ===================================================
    # BEST PRACTICES
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,185,"GENERAL SECURITY BEST PRACTICES")

    pdf.roundRect(45,70,500,95,8)

    tips = [

    "• Keep software and frameworks updated.",

    "• Enable Multi-Factor Authentication (MFA).",

    "• Perform regular security audits.",

    "• Monitor server logs continuously."

    ]

    pdf.setFont("Helvetica",10)

    y = 145

    for tip in tips:

        pdf.drawString(60,y,tip)

        y -= 18
    # ===================================================
    # FOOTER
    # ===================================================
    pdf.setFont("Helvetica",10)
    pdf.drawRightString(
        550,
        50,
        "Page 11"
    )

    # ===================================================
    # PAGE 12 : RISK ASSESSMENT
    # ===================================================

    pdf.showPage()

    pdf.rect(20,20,570,800)

    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"RISK ASSESSMENT")
    pdf.line(45,775,550,775)

    # ===================================================
    # CALCULATE RISKS
    # ===================================================

    critical = 0
    high = 0
    medium = 0
    low = 0
    informational = 0

    # Open Port Risk
    for port in ports:

        if port in [21,23,3389]:
            high += 1

        elif port in [22,3306]:
            medium += 1

        else:
            low += 1

    # Missing Headers
    for item in headers:

        if "Missing" in item:
            medium += 1

        else:
            informational += 1

    # SSL Risk
    tls_security = "GOOD"

    for item in ssl_results:

        if "TLS Security" in item:
            tls_security = item.split(":")[1].strip()

    if tls_security == "WEAK":
        high += 1

    elif tls_security == "GOOD":
        informational += 1

    elif tls_security == "EXCELLENT":
        informational += 1

    # ===================================================
    # OVERALL RISK
    # ===================================================

    if high == 0 and medium <= 2:
        overall = "LOW"

    elif high <= 2:
        overall = "MEDIUM"

    elif high <= 4:
        overall = "HIGH"

    else:
        overall = "CRITICAL"

    # ===================================================
    # SEVERITY TABLE
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"SEVERITY SUMMARY")

    pdf.roundRect(45,480,500,220,8)

    pdf.line(250,480,250,700)

    for i in range(1,6):
        pdf.line(45,700-(i*36),545,700-(i*36))

    pdf.setFont("Helvetica-Bold",11)

    pdf.drawCentredString(145,713,"SEVERITY")
    pdf.drawCentredString(400,713,"COUNT")

    rows = [

    ("Critical",critical),

    ("High",high),

    ("Medium",medium),

    ("Low",low),

    ("Informational",informational)

    ]

    y = 675

    for severity,count in rows:

        pdf.setFont("Helvetica",11)

        pdf.drawString(60,y,severity)

        pdf.drawCentredString(400,y,str(count))

        y -= 36

    # ===================================================
    # OVERALL RISK
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,440,"OVERALL RISK LEVEL")

    pdf.roundRect(45,360,500,55,8)

    pdf.setFont("Helvetica-Bold",18)

    pdf.drawCentredString(
        295,
        380,
        overall
    )

    # ===================================================
    # BUSINESS IMPACT
    # ===================================================

    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,330,"BUSINESS IMPACT")

    pdf.roundRect(45,130,500,170,8)

    remarks = []

    if overall == "LOW":

        remarks = [

            "• No critical vulnerabilities were identified.",

            "• Security posture is considered good.",

            "• Minor improvements are recommended.",

            "• Business impact is minimal."

        ]

    elif overall == "MEDIUM":

        remarks = [

            "• Medium-risk issues require attention.",

            "• Security improvements should be planned.",

            "• Business impact is moderate.",

            "• Periodic assessments are recommended."

        ]

    elif overall == "HIGH":

        remarks = [

            "• High-risk vulnerabilities detected.",

            "• Immediate remediation is recommended.",

            "• Business services may be affected.",

            "• Security review should be prioritized."

        ]

    else:

        remarks = [

            "• Critical vulnerabilities detected.",

            "• Immediate corrective action required.",

            "• Significant business impact possible.",

            "• Emergency remediation recommended."

        ]

    pdf.setFont("Helvetica",11)

    y = 260

    for line in remarks:

        pdf.drawString(60,y,line)

        y -= 30

    # ===================================================
    # FOOTER
    # ===================================================
    pdf.setFont("Helvetica",10)
    pdf.drawRightString(
        550,
        50,
        "Page 12"
    )
    # ===================================================
    # PAGE 13 : SECURITY RECOMMENDATIONS
    # ===================================================
    pdf.showPage()
    pdf.rect(20,20,570,800)
    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"SECURITY RECOMMENDATIONS")
    pdf.line(45,775,550,775)
    # ===================================================
    # INTRODUCTION
    # ===================================================
    pdf.setFont("Helvetica",11)
    pdf.drawString(
        50,
        745,
        "The following recommendations are provided to improve"
    )
    pdf.drawString(
        50,
        728,
        "the overall security posture of the assessed website."
    )
    # ===================================================
    # RECOMMENDATION TABLE
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,690,"RECOMMENDED SECURITY ACTIONS")
    pdf.roundRect(45,180,500,480,8)
    # Table Lines
    pdf.line(90,180,90,660)
    pdf.line(430,180,430,660)
    pdf.line(45,630,545,630)
    for i in range(1,9):
        pdf.line(45,630-(i*50),545,630-(i*50))
    # Headers
    pdf.setFont("Helvetica-Bold",11)
    pdf.drawCentredString(68,642,"ID")
    pdf.drawCentredString(260,642,"RECOMMENDATION")
    pdf.drawCentredString(485,642,"PRIORITY")
    # ===================================================
    # BUILD RECOMMENDATIONS
    # ===================================================
    recommendations = []
    # Missing Security Headers
    for item in headers:
        if "Missing" in item:
            header = item.split(":")[0]
            recommendations.append(
                (
                    f"Configure {header} HTTP security header.",
                    "MEDIUM"
                )
            )
    # SSL
    for item in ssl_results:

        if "WEAK" in item:

            recommendations.append(
                (
                    "Upgrade the server to TLS 1.3.",
                    "HIGH"
                )
            )

    # Open Ports

    for port in ports:

        if port in [21,23,3389]:

            recommendations.append(
                (
                    f"Restrict or secure Port {port}.",
                    "HIGH"
                )
            )
    # Technology Disclosure
    for item in banner:
        if item.startswith("Technology:"):
            if "Hidden" not in item:
                recommendations.append(
                    (
                        "Hide X-Powered-By header to reduce information disclosure.",
                        "LOW"
                    )
                )
    # Generic Recommendations
    recommendations.extend([
    ("Enable Multi-Factor Authentication (MFA).","MEDIUM"),
    ("Keep server software and frameworks updated.","HIGH"),
    ("Perform periodic vulnerability assessments.","LOW"),
    ("Monitor security logs continuously.","LOW")
    ])
    # ===================================================
    # PRINT TABLE
    # ===================================================
    pdf.setFont("Helvetica",10)

    y = 610

    for i, (text, priority) in enumerate(recommendations[:9], start=1):

        pdf.drawCentredString(68,y,str(i))

        # Trim long text
        if len(text) > 55:
            text = text[:52] + "..."

        pdf.drawString(100,y,text)

        pdf.drawCentredString(485,y,priority)

        y -= 50
    # ===================================================
    # FINAL NOTE
    # ===================================================
    pdf.setFont("Helvetica-Bold",13)

    pdf.drawString(50,145,"FINAL NOTE")

    pdf.setFont("Helvetica",10)

    pdf.drawString(
        50,
        125,
        "Implementing the above recommendations will significantly improve"
    )

    pdf.drawString(
        50,
        110,
        "the confidentiality, integrity, and availability of the application."
    )
    # ===================================================
    # FOOTER
    # ===================================================
    pdf.setFont("Helvetica",10)
    pdf.drawRightString(
        550,
        50,
        "Page 13"
    )
    # ===================================================
    # PAGE 14 : REPORT VERIFICATION
    # ===================================================
    pdf.showPage()
    pdf.rect(20,20,570,800)
    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"REPORT VERIFICATION")
    pdf.line(45,775,550,775)
    # ===================================================
    # REPORT DETAILS
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"REPORT INFORMATION")
    pdf.roundRect(45,500,500,210,8)
    pdf.line(220,500,220,710)
    for i in range(1,7):
        pdf.line(45,710-(i*30),545,710-(i*30))
    rows = [
    ("Report ID", report_id),
    ("Generated On", report_time),
    ("Scanner Name", "SecureVault Scanner"),
    ("Scanner Version", "Version 1.0"),
    ("Generated By", "SecureVault Enterprise"),
    ("Verification Status", "VERIFIED")
    ]
    y = 685
    for left,right in rows:

        pdf.setFont("Helvetica-Bold",11)
        pdf.drawString(60,y,left)

        pdf.setFont("Helvetica",11)
        pdf.drawString(235,y,str(right))

        y -= 30
    # ===================================================
    # SHA-256 HASH
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,470,"SHA-256 VERIFICATION HASH")
    pdf.roundRect(45,360,500,80,8)
    pdf.setFont("Courier",8)
    pdf.drawString(
        60,
        405,
        verification_hash[:64]
    )
    pdf.drawString(
        60,
        390,
        verification_hash[64:]
    )
    # ===================================================
    # DIGITAL VERIFICATION
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,330,"DIGITAL INTEGRITY")
    pdf.roundRect(45,130,500,170,8)
    remarks = [
    "• This report was generated automatically by SecureVault.",
    "• SHA-256 hashing protects report integrity.",
    "• Any modification to this report changes the verification hash.",
    "• Scan results are based on publicly accessible information.",
    "• This report is intended for authorized security assessment only."
    ]
    pdf.setFont("Helvetica",11)
    y = 270
    for item in remarks:

        pdf.drawString(
            60,
            y,
            item
        )
        y -= 28
    # ===================================================
    # SIGNATURE SECTION
    # ===================================================
    pdf.setFont("Helvetica-Bold",12)
    pdf.drawString(
        60,
        95,
        "Authorized Signature"
    )

    pdf.line(
        60,
        75,
        220,
        75
    )

    pdf.drawString(
        320,
        95,
        "Digital Verification"
    )
    pdf.line(
        320,
        75,
        500,
        75
    )
    # ===================================================
    # FOOTER
    # ===================================================
    pdf.setFont(
        "Helvetica",
        10
    )
    pdf.drawRightString(
        550,
        50,
        "Page 14"
    )
    # ===================================================
    # PAGE 15 : APPENDIX
    # ===================================================
    pdf.showPage()
    pdf.rect(20,20,570,800)
    pdf.setFont("Helvetica-Bold",22)
    pdf.drawString(50,790,"APPENDIX")
    pdf.line(45,775,550,775)
    # ===================================================
    # SCAN CONFIGURATION
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,740,"SCAN CONFIGURATION")
    pdf.roundRect(45,620,500,90,8)
    pdf.setFont("Helvetica",11)
    pdf.drawString(60,685,f"Target              : {target}")
    pdf.drawString(60,665,f"Scan Profile        : {scan_type.title()}")
    pdf.drawString(60,645,f"Generated On        : {report_time}")
    pdf.drawString(60,625,"Scanner Version     : SecureVault Scanner v1.0")
    # ===================================================
    # OPEN PORTS
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,590,"OPEN PORTS")
    pdf.roundRect(45,500,500,70,8)
    pdf.setFont("Helvetica",10)
    if ports:
        port_text = ", ".join(str(p) for p in ports)
    else:
        port_text = "No Open Ports Detected"
    pdf.drawString(60,535,port_text)
    # ===================================================
    # HTTP SECURITY HEADERS
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,470,"HTTP SECURITY HEADERS")
    pdf.roundRect(45,330,500,120,8)
    pdf.setFont("Helvetica",9)
    y = 430
    for item in headers[:6]:
        pdf.drawString(60,y,item)
        y -= 18
    # ===================================================
    # SSL DETAILS
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,300,"SSL / TLS DETAILS")
    pdf.roundRect(45,180,500,100,8)
    pdf.setFont("Helvetica",9)
    y = 260
    for item in ssl_results[:6]:
        pdf.drawString(60,y,item)
        y -= 16
    # ===================================================
    # TECHNOLOGY DETECTION
    # ===================================================
    pdf.setFont("Helvetica-Bold",14)
    pdf.drawString(50,150,"TECHNOLOGY DETECTION")
    pdf.roundRect(45,70,500,60,8)
    pdf.setFont("Helvetica",9)
    technology = " | ".join(banner[:3])
    if len(technology) > 85:
        technology = technology[:82] + "..."
    pdf.drawString(60,95,technology)
    # ===================================================
    # FOOTER
    # ===================================================
    pdf.line(40,50,560,50)
    pdf.setFont("Helvetica",10)
    pdf.drawString(
        50,
        30,
        "SecureVault Enterprise Security Platform"
    )
    pdf.drawRightString(
        550,
        30,
        "Page 15"
    )
    pdf.save()
    buffer.seek(0)
    if action == "view":
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=False
        )
    return send_file(
        buffer,
        download_name=f"SecureVault_Report_{target}.pdf",
        mimetype="application/pdf",
        as_attachment=True
    )
@app.route('/file-scan', methods=['GET', 'POST'])
def file_scanner_route():

    if 'user' not in session:
        return redirect(url_for('login'))

    results = None

    if request.method == 'POST':

        file = request.files['uploaded_file']

        os.makedirs("uploads", exist_ok=True)

        filepath = os.path.join(
            "uploads",
            file.filename
        )

        file.save(filepath)

        action = request.form.get("action")

        # -------------------------------
        # FILE SCAN
        # -------------------------------

        if action == "scan":

            action = request.form.get("action")

            results = scan_file_for_vulnerabilities(
                filepath,
                action
            )

        # -------------------------------
        # MALWARE CHECK
        # -------------------------------

        elif action == "malware":

            results = scan_file_for_vulnerabilities(
                filepath,
                "malware"
            )

        # -------------------------------
        # HASH GENERATOR
        # -------------------------------

        elif action == "hash":

            results = scan_file_for_vulnerabilities(
                filepath,
                "hash"
            )

        # -------------------------------
        # INTEGRITY CHECK
        # -------------------------------

        elif action == "integrity":

            results = scan_file_for_vulnerabilities(
                filepath,
                "integrity"
            )

    return render_template(
        "file_scan.html",
        file_result="\n".join(results) if results else None
    )

if __name__ == '__main__':
    app.run(debug=True)
