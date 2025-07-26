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
def calculate_entropy(file_path):
    if not os.path.isfile(file_path):
        return 0.0
    with open(file_path, "rb") as f:
        byte_arr = list(f.read())
    if not byte_arr:
        return 0.0
    freq_list = [0] * 256
    for byte in byte_arr:
        freq_list[byte] += 1
    entropy = 0.0
    file_size = len(byte_arr)
    for freq in freq_list:
        if freq > 0:
            p = freq / file_size
            entropy -= p * math.log2(p)
    return round(entropy, 3)

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

def get_verdict(score):
    if score > 75:
        return "Malicious"
    elif score > 40:
        return "Suspicious"
    else:
        return "Clean"

# -------------------- Report Generator --------------------
def generate_report(file_path, output):
    file_name = os.path.basename(file_path)
    dir_name = os.path.dirname(file_path)
    report_path = os.path.join(dir_name, f"report_{file_name}.txt")

    file_size = round(os.path.getsize(file_path) / 1024, 2)
    entropy = calculate_entropy(file_path)
    risk_score = estimate_risk(entropy, output)
    verdict = get_verdict(risk_score)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(report_path, "w") as f:
        f.write("====== Black Swan Antivirus Report ======\n")
        f.write(f"Generated on   : {timestamp}\n")
        f.write(f"File Name      : {file_name}\n")
        f.write(f"File Path      : {file_path}\n")
        f.write(f"File Size      : {file_size} KB\n")
        f.write(f"Entropy        : {entropy}\n")
        f.write(f"Risk Score     : {risk_score}/100\n")
        f.write(f"ML-style Verdict: {verdict}\n\n")
        f.write("----------- Scan Output -----------\n")
        f.write(output + "\n")
        f.write("----------- Recommendations -----------\n")
        if verdict == "Malicious":
            f.write("- Immediate quarantine recommended.\n- Do not execute the file.\n- Submit to virus lab.\n")
        elif verdict == "Suspicious":
            f.write("- Manual inspection recommended.\n- Avoid running unless trusted.\n")
        else:
            f.write("- No immediate threats detected.\n")

    return report_path

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
        result = subprocess.run(["/home/surja/Downloads/Black-Swan-main/engine", file_path], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        output_text.delete(1.0, END)
        output_text.insert(END, output)
        output_text.see(END)

        # -------- Generate Report --------
        report_path = generate_report(file_path, output)
        output_text.insert(END, f"\n[✓] Report saved to: {report_path}\n")
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

root.mainloop()
