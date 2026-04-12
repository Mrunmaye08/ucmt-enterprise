from flask import Flask, render_template, request, redirect, session, send_file
from scanner import get_system_info, scan_open_ports
import datetime
import uuid

# PDF
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

app = Flask(__name__)
app.secret_key = "ucmt_secret"

# ---------------- ISO MAPPING ----------------
iso_mapping = {
    "Open Ports Detected": "A.8.20 Network Security",
    "Weak Password Policy": "A.5.17 Access Control",
    "No Backup Strategy": "A.8.13 Backup",
    "No Security Policy": "A.5.1 Policies",
    "No Incident Response Plan": "A.5.24 Incident Management",
    "No Awareness Training": "A.6.3 Security Awareness",
    "No Risk Management Policy": "A.5.4 Management Responsibilities"
}

# ---------------- CALCULATIONS ----------------
def calculate_compliance(risks):
    if not risks:
        return 0
    mapped = sum(1 for r in risks if r.get("control") != "Not Mapped")
    return int((mapped / len(risks)) * 100)


def calculate_readiness(risks, training):
    risk_score = min(len(risks) * 10, 100)
    return int(((100 - risk_score) + training) / 2)


# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin":
            session["user"] = "admin"
            session["risks"] = []
            session["training_score"] = 0
            return redirect("/dashboard")
    return render_template("login.html")


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    risks = session.get("risks", [])
    training_score = session.get("training_score", 0)

    total = len(risks)
    high = len([r for r in risks if r["severity"] == "High"])
    medium = len([r for r in risks if r["severity"] == "Medium"])
    low = len([r for r in risks if r["severity"] == "Low"])

    compliance = calculate_compliance(risks)
    readiness = calculate_readiness(risks, training_score)

    if readiness < 40:
        level = "Poor"
    elif readiness < 70:
        level = "Moderate"
    else:
        level = "Good"

    return render_template("dashboard.html",
                           total=total,
                           high=high,
                           medium=medium,
                           low=low,
                           training=training_score,
                           compliance=compliance,
                           readiness=readiness,
                           level=level)


# ---------------- SCAN ----------------
@app.route("/scan")
def scan():
    if "user" not in session:
        return redirect("/")

    system = get_system_info()
    ports = scan_open_ports()
    scan_time = datetime.datetime.now()

    return render_template("scan.html",
                           system=system,
                           ports=ports,
                           scan_time=scan_time)


# ---------------- AWARENESS ----------------
@app.route("/awareness")
def awareness():
    if "user" not in session:
        return redirect("/")
    return render_template("awareness.html")


# ---------------- TRAINING ----------------
@app.route("/training", methods=["GET", "POST"])
def training():
    if "user" not in session:
        return redirect("/")

    if request.method == "POST":
        score = 0
        for i in range(1, 6):
            score += int(request.form.get(f"q{i}", 0))

        session["training_score"] = int((score / 5) * 100)
        return redirect("/dashboard")

    return render_template("training.html")


# ---------------- RISKS ----------------
@app.route("/risks", methods=["GET", "POST"])
def risks():
    if "user" not in session:
        return redirect("/")

    risks = session.get("risks", [])

    if request.method == "POST":
        risk = request.form.get("risk")
        custom = request.form.get("custom_risk")
        severity = request.form.get("severity")

        if risk == "custom":
            risk = custom

        risks.append({
            "name": risk,
            "severity": severity,
            "control": iso_mapping.get(risk, "Not Mapped")
        })

        session["risks"] = risks

    return render_template("risks.html", risks=risks)


# -------- PAGE BORDER ----------
def draw_border(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.darkblue)
    canvas.setLineWidth(2)
    canvas.rect(20, 20, A4[0] - 40, A4[1] - 40)
    canvas.restoreState()


# ---------------- REPORT ----------------
@app.route("/report")
def report():
    if "user" not in session:
        return redirect("/")

    risks = session.get("risks", [])
    training_score = session.get("training_score", 0)

    total = len(risks)
    high = len([r for r in risks if r["severity"] == "High"])
    medium = len([r for r in risks if r["severity"] == "Medium"])
    low = len([r for r in risks if r["severity"] == "Low"])

    compliance = calculate_compliance(risks)
    readiness = calculate_readiness(risks, training_score)

    system = get_system_info()

    audit_id = str(uuid.uuid4())[:8]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    file = "UCMT_Report.pdf"

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        name="title",
        alignment=TA_CENTER,
        fontSize=20,
        textColor=colors.darkblue
    )

    story = []

    # HEADER
    story.append(Paragraph("Unified Compliance Management Tool", title_style))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Enterprise Security Assessment Report", styles['Heading2']))
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"Audit ID: {audit_id}", styles['Normal']))
    story.append(Paragraph(f"Generated: {now}", styles['Normal']))
    story.append(Spacer(1, 25))

    # HEATMAP (FIXED)
    story.append(Paragraph("Risk Heat Map", styles['Heading2']))
    story.append(Spacer(1, 10))

    drawing = Drawing(400, 200)
    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 30
    chart.height = 150
    chart.width = 300

    # ✅ FIX: ensure all bars visible
    chart.data = [[max(high,1), max(medium,1), max(low,1)]]
    chart.categoryAxis.categoryNames = ["High", "Medium", "Low"]

    # Different colors
    chart.bars[0].fillColor = colors.red

    drawing.add(chart)
    story.append(drawing)

    story.append(PageBreak())

    # SYSTEM INFO
    story.append(Paragraph("System Information", styles['Heading2']))

    sys_table = Table([
        ["Hostname", system["hostname"]],
        ["IP", system["ip"]],
        ["OS", system["os"]],
        ["Firewall", system["firewall"]],
        ["Antivirus", system["antivirus"]],
        ["Encryption", system["encryption"]],
        ["Backup", system["backup"]],
    ])

    sys_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    story.append(sys_table)
    story.append(Spacer(1, 20))

    # METRICS
    story.append(Paragraph("Security Metrics", styles['Heading2']))

    metrics = Table([
        ["Metric", "Value"],
        ["Total Risks", total],
        ["High", high],
        ["Medium", medium],
        ["Low", low],
        ["Training Score", f"{training_score}%"],
        ["ISO Compliance", f"{compliance}%"],
        ["Startup Readiness", f"{readiness}%"]
    ])

    metrics.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    story.append(metrics)
    story.append(Spacer(1, 20))

    # RISK REGISTER (FIXED TABLE STYLE)
    story.append(Paragraph("Risk Register", styles['Heading2']))

    risk_data = [["Risk", "Severity", "ISO Control"]]

    for r in risks:
        risk_data.append([r["name"], r["severity"], r.get("control", "Not Mapped")])

    risk_table = Table(risk_data)

    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    story.append(risk_table)
    story.append(Spacer(1, 20))	

    # AI RECOMMENDATIONS
    story.append(Paragraph("AI Recommendations", styles['Heading2']))

    if high > 0:
        story.append(Paragraph("- Immediate action required for high risks", styles['Normal']))
    if compliance < 70:
        story.append(Paragraph("- Improve ISO compliance", styles['Normal']))
    if training_score < 70:
        story.append(Paragraph("- Conduct awareness training", styles['Normal']))
    if readiness < 60:
        story.append(Paragraph("- Improve security posture", styles['Normal']))

    story.append(Spacer(1, 20))
    story.append(Paragraph("Generated by UCMT Enterprise AI Security Platform", styles['Italic']))

    doc = SimpleDocTemplate(file, pagesize=A4)
    doc.build(story, onFirstPage=draw_border, onLaterPages=draw_border)

    return send_file(file, as_attachment=True)


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)

