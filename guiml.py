from tkinter import *
from tkinter import filedialog, messagebox
import subprocess
import tkinter.font as tkfont
import ttkbootstrap as tb
import math
import os
from fpdf import FPDF
import datetime

# Initialize GUI
root = tb.Window(themename="darkly")
root.title("BlackSwanAV")
root.geometry("1440x900")

# Set formal monospace font
default_font = tkfont.nametofont("TkDefaultFont")
default_font.configure(family="Courier New", size=13)
text_font = tkfont.Font(family="Courier New", size=13)

file_path = ""
upload_type = "file"

def file_dialog():
    global file_path
    if upload_type == "file":
        file_path = filedialog.askopenfilename()
    else:
        file_path = filedialog.askdirectory()
    file_label.config(text="Chosen path: " + file_path if file_path else "No path selected")

def execute_engine(file_path):
    if not file_path:
        file_label.config(text="No path selected")
        return

    file_label.config(text=file_path)
    result = subprocess.run(
        ["/home/surja/Downloads/Black-Swan-main/engine", file_path],
        stdout=subprocess.PIPE
    )
    output = result.stdout.decode()
    output_text.delete(1.0, END)
    output_text.insert(END, output)
    output_text.see(END)

    rule_hits = []
    for line in output.splitlines():
        if "Rule matched:" in line:
            rule_hits.append(line.split("Rule matched:")[1].strip())

    entropy_score = 0
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            freq = [float(data.count(byte)) / len(data) for byte in range(256)]
            entropy_score = -sum([f * math.log2(f) for f in freq if f > 0])
    except:
        entropy_score = 0

    rule_count = len(rule_hits)
    entropy_component = min(max((entropy_score - 6.5) * 10, 0), 40)
    rule_component = min(rule_count * 10, 60)
    risk_score = int(entropy_component + rule_component)

    pdf_path = generate_pdf_report(file_path, rule_hits, entropy_score, risk_score)

    # Show success message with path
    messagebox.showinfo("Scan Finished", f"Report successfully generated at:\n{pdf_path}")

def toggle_upload_type():
    global upload_type
    upload_type = "directory" if upload_type == "file" else "file"
    toggle_button.config(text="Switch to File Upload" if upload_type == "directory" else "Switch to Directory Upload")

# --- GUI Widgets ---
tb.Label(text="Black Swan Antivirus", font=("Courier New", 36, "bold"), bootstyle="default").pack(pady=10)

toggle_button = tb.Button(text="Switch to Directory Upload", bootstyle="secondary", command=toggle_upload_type)
toggle_button.pack(pady=10)

file_label = tb.Label(text="No file selected", font=("Courier New", 12), bootstyle="default")
file_label.pack(pady=10)

image = PhotoImage(file="images/upload_image.png")
image_button = tb.Label(image=image)
image_button.pack(pady=10)
image_button.bind("<Button-1>", lambda event: file_dialog())

tb.Button(text="Upload & Scan", bootstyle="primary outline", command=lambda: execute_engine(file_path), padding="40 15").pack(pady=20)

tb.Label(text="Scan Results", font=("Courier New", 28, "bold"), bootstyle="default").pack(pady=20)

output_text = Text(root, width=160, height=30, wrap='word', font=text_font)
output_text.pack(pady=10)

# --- PDF Report Generator ---
def generate_pdf_report(filepath, rule_hits, entropy_score, risk_score):
    filename = os.path.basename(filepath)
    name_only = os.path.splitext(filename)[0]
    report_name = f"{name_only}_report.pdf"
    report_path = os.path.join(os.path.expanduser("~"), "Desktop", report_name)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Frame Border
    margin = 10
    pdf.rect(x=margin, y=margin, w=190, h=277)

    pdf.set_font("Courier", 'B', 16)
    pdf.cell(0, 10, "---------- BLACK SWAN ANTIVIRUS REPORT ----------", ln=True, align='C')

    pdf.set_font("Courier", size=12)
    pdf.ln(8)
    pdf.cell(0, 10, f"Scan Timestamp : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(0, 10, f"Scanned File    : {filename}", ln=True)
    pdf.cell(0, 10, f"File Path       : {filepath}", ln=True)

    pdf.ln(10)
    pdf.set_font("Courier", 'B', 13)
    pdf.cell(0, 10, "---------- ANALYSIS SUMMARY ----------", ln=True)
    pdf.set_font("Courier", size=12)
    pdf.cell(0, 10, f"Entropy Score   : {entropy_score:.2f}", ln=True)
    pdf.cell(0, 10, f"Rule Matches    : {len(rule_hits)}", ln=True)
    pdf.cell(0, 10, f"Risk Score      : {risk_score}/100", ln=True)

    if risk_score >= 80:
        pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 10, "ALERT: HIGH RISK - Immediate action recommended.", ln=True)
    elif risk_score >= 50:
        pdf.set_text_color(255, 165, 0)
        pdf.cell(0, 10, "WARNING: MODERATE RISK - Suspicious indicators found.", ln=True)
    else:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 10, "STATUS: LOW RISK - No strong threat patterns found.", ln=True)

    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)
    pdf.set_font("Courier", 'B', 13)
    pdf.cell(0, 10, "---------- MATCHED RULES ----------", ln=True)

    pdf.set_font("Courier", size=12)
    if rule_hits:
        for rule in rule_hits:
            pdf.cell(0, 10, f"- {rule}", ln=True)
    else:
        pdf.cell(0, 10, "No rules matched.", ln=True)

    pdf.ln(10)
    pdf.set_font("Courier", 'I', 10)
    pdf.cell(0, 10, "Report generated by Black Swan Antivirus", ln=True, align='C')

    pdf.output(report_path)
    return report_path

# --- Mainloop ---
root.mainloop()
