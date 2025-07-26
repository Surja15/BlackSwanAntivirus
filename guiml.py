from tkinter import *
from tkinter import filedialog
import subprocess
import tkinter.font as tkfont
import ttkbootstrap as tb
import math
import pefile
import os
from fpdf import FPDF
import datetime

root = tb.Window(themename="darkly")

root.title("BlackSwanAV")
root.geometry("1440x900")

# Set global default font to DejaVu Sans Mono, size 14 (adjust size if needed)
default_font = tkfont.nametofont("TkDefaultFont")
default_font.configure(family="DejaVu Sans Mono", size=14)

# Also update TkText font default (since Text widget doesn't inherit TkDefaultFont)
text_font = tkfont.Font(family="DejaVu Sans Mono", size=14)

file_path = ""
upload_type = "file"  # Default upload type is file

def file_dialog():
    global file_path
    if upload_type == "file":
        file_path = filedialog.askopenfilename()
    else:
        file_path = filedialog.askdirectory()
    if file_path:
        file_label.config(text="Chosen path: " + file_path)
    else:
        file_label.config(text="No path selected")

def execute_engine(file_path):
    if file_path:
        file_label.config(text=file_path)
        result = subprocess.run(
            ["/home/surja/Downloads/Black-Swan-main/engine", file_path],
            stdout=subprocess.PIPE
        )
        output = result.stdout.decode()
        output_text.delete(1.0, END)
        output_text.insert(END, output)
        output_text.see(END)

        # Extract rule names from output
        rule_hits = []
        for line in output.splitlines():
            if "Rule matched:" in line:
                rule_hits.append(line.replace("Rule matched:", "").strip())

        # Calculate entropy
        entropy_score = 0
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                if data:
                    import math
                    freq = [float(data.count(byte)) / len(data) for byte in range(256)]
                    entropy_score = -sum([f * math.log2(f) for f in freq if f > 0])
        except Exception as e:
            entropy_score = 0

        # Risk score based on rule count
        rule_count = len(rule_hits)
        risk_score = min(rule_count * 10, 100)

        # Generate PDF
        generate_pdf_report(file_path, rule_hits, entropy_score, risk_score)

    else:
        file_label.config(text="No path selected")


def toggle_upload_type():
    global upload_type
    if upload_type == "file":
        upload_type = "directory"
        toggle_button.config(text="Switch to File Upload")
    else:
        upload_type = "file"
        toggle_button.config(text="Switch to Directory Upload")

# Top heading with bigger font size explicitly
my_label = tb.Label(text="Black Swan Antivirus", font=("DejaVu Sans Mono", 40, "bold"), bootstyle="default")
my_label.pack(pady=10)

toggle_button = tb.Button(text="Switch to Directory Upload", bootstyle="secondary", command=toggle_upload_type)
toggle_button.pack(pady=10)

file_label = tb.Label(text="", font=("DejaVu Sans Mono", 12), bootstyle="default")
file_label.pack(pady=10)

image = PhotoImage(file="images/upload_image.png")
image_button = tb.Label(image=image)
image_button.pack(pady=10)
image_button.bind("<Button-1>", lambda event: file_dialog())

my_button = tb.Button(text="Upload", bootstyle="primary, outline", command=lambda: execute_engine(file_path))
my_button.config(padding="40 15")
my_button.pack(pady=20)

my_label2 = tb.Label(text="Scan results", font=("DejaVu Sans Mono", 30, "bold"), bootstyle="default")
my_label2.pack(pady=20)

output_text = Text(root, width=200, height=30, wrap='word', font=text_font)
output_text.pack(pady=10)
def generate_pdf_report(filepath, rule_hits, entropy_score, risk_score):
    filename = os.path.basename(filepath)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Black Swan Antivirus Report", ln=True, align='C')
    
    pdf.set_font("Arial", size=12)
    pdf.ln(10)
    pdf.cell(0, 10, f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(0, 10, f"File Scanned: {filename}", ln=True)
    pdf.cell(0, 10, f"Full Path: {filepath}", ln=True)

    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Analysis Summary:", ln=True)

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Entropy Score: {entropy_score:.2f}", ln=True)
    pdf.cell(0, 10, f"Risk Score (based on rule matches): {risk_score}/100", ln=True)

    pdf.ln(5)
    if risk_score >= 70:
        pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 10, f"⚠️ High Risk: Multiple suspicious patterns detected.", ln=True)
    elif risk_score >= 40:
        pdf.set_text_color(255, 140, 0)
        pdf.cell(0, 10, f"⚠️ Medium Risk: Potentially suspicious behavior.", ln=True)
    else:
        pdf.set_text_color(0, 150, 0)
        pdf.cell(0, 10, f"✓ Low Risk: No major threats found.", ln=True)

    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Matched Rules:", ln=True)
    pdf.set_font("Arial", size=12)
    if rule_hits:
        for rule in rule_hits:
            pdf.cell(0, 10, f"- {rule}", ln=True)
    else:
        pdf.cell(0, 10, "No rules matched.", ln=True)

    output_path = os.path.join(os.path.expanduser("~"), "Desktop", "scan_report.pdf")
    pdf.output(output_path)
    print(f"PDF report saved at: {output_path}")

root.mainloop()
