from tkinter import *
from tkinter import filedialog
import subprocess
import tkinter.font as tkfont
import ttkbootstrap as tb
import os
import math
from datetime import datetime

root = tb.Window(themename="darkly")
root.title("BlackSwanAV")
root.geometry("1440x900")

default_font = tkfont.nametofont("TkDefaultFont")
default_font.configure(family="DejaVu Sans Mono", size=14)
text_font = tkfont.Font(family="DejaVu Sans Mono", size=14)

file_path = ""
upload_type = "file"  # Default is file

# -------------------- Entropy Function --------------------
def calculate_entropy(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if not data:
            return 0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        entropy = 0
        for count in byte_counts:
            if count == 0:
                continue
            p = count / len(data)
            entropy -= p * math.log2(p)
        return round(entropy, 2)
    except:
        return 0

# -------------------- Risk Heuristic --------------------
def estimate_risk(entropy, output):
    score = 0
    if entropy > 7.0:
        score += 40
    if "suspicious" in output.lower():
        score += 30
    if "malware" in output.lower() or "payload" in output.lower():
        score += 30
    return min(100, score)

# -------------------- Report Generator --------------------
def generate_report(file_path, yara_output):
    entropy = calculate_entropy(file_path)
    keyword_weights = {
        "malware": 15,
        "trojan": 20,
        "ransom": 20,
        "shellcode": 20,
        "payload": 15,
        "exploit": 15,
        "backdoor": 20,
        "obfuscation": 10,
        "packer": 10,
        "suspicious": 10,
        "encoded": 10
    }

    matched_rules = set()
    score = 0

    for line in yara_output.splitlines():
        if line.strip():
            rule_name = line.split()[0]
            matched_rules.add(rule_name)

        line_lower = line.lower()
        for keyword, weight in keyword_weights.items():
            if keyword in line_lower:
                score += weight

    # Add 1 point for each rule matched (base boost)
    score += len(matched_rules)

    # Entropy influence
    if entropy > 7.5:
        score += 20
    elif entropy > 6.5:
        score += 10

    # Cap score at 100
    score = min(score, 100)

    # Risk Category
    if score >= 85:
        verdict = "High Risk"
    elif score >= 60:
        verdict = "Suspicious"
    else:
        verdict = "Low Risk / Clean"

    # Recommendation only for extreme cases
    if score >= 85 or len(matched_rules) >= 20:
        recommendation = "\nRecommendation: Immediate quarantine and further analysis recommended."
    else:
        recommendation = ""

    # Format the report
    report_content = f"""
======= BlackSwanAV Scan Report =======

File Scanned: {file_path}
Number of Rules Matched: {len(matched_rules)}
Entropy: {entropy}
Risk Score: {score}/100
Verdict: {verdict}
{recommendation}

Matched Rules:
{chr(10).join(matched_rules)}

Raw YARA Output:
{yara_output}

=======================================
"""
    report_file = file_path + "_scan_report.txt"
    with open(report_file, "w") as f:
        f.write(report_content)

    return report_file

# -------------------- UI Logic --------------------
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
        result = subprocess.run(
            ["/home/surja/Downloads/Black-Swan-main/engine", file_path],
            stdout=subprocess.PIPE,
        )
        output = result.stdout.decode()
        output_text.delete(1.0, END)
        output_text.insert(END, output)
        output_text.see(END)

        # -------- Generate Report --------
        report_path = generate_report(file_path, output)
        output_text.insert(END, f"\n[✓] Professional Report saved at:\n{report_path}\n")
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

# -------------------- UI Elements --------------------
my_label = tb.Label(
    text="Black Swan Antivirus", font=("DejaVu Sans Mono", 40, "bold"), bootstyle="default"
)
my_label.pack(pady=10)

toggle_button = tb.Button(
    text="Switch to Directory Upload", bootstyle="secondary", command=toggle_upload_type
)
toggle_button.pack(pady=10)

file_label = tb.Label(text="", font=("DejaVu Sans Mono", 12), bootstyle="default")
file_label.pack(pady=10)

image = PhotoImage(file="images/upload_image.png")
image_button = tb.Label(image=image)
image_button.pack(pady=10)
image_button.bind("<Button-1>", lambda event: file_dialog())

my_button = tb.Button(
    text="Upload", bootstyle="primary, outline", command=lambda: execute_engine(file_path)
)
my_button.config(padding="40 15")
my_button.pack(pady=20)

my_label2 = tb.Label(
    text="Scan results", font=("DejaVu Sans Mono", 30, "bold"), bootstyle="default"
)
my_label2.pack(pady=20)

output_text = Text(root, width=200, height=30, wrap="word", font=text_font)
output_text.pack(pady=10)

root.mainloop()
