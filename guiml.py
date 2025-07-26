from tkinter import *
from tkinter import filedialog
import subprocess
import tkinter.font as tkfont
import ttkbootstrap as tb
import math
import pefile
import os
import datetime
import re

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

def format_report(file_name, engine_output, analysis_report):
    divider = "-" * 60
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract flagged rules from engine output (assuming pattern like: rule: X, Y, Z)
    rule_matches = re.findall(r"rule[s]?:\s*(.*)", engine_output, re.IGNORECASE)
    rules = []
    for match in rule_matches:
        rules.extend([r.strip() for r in match.split(',') if r.strip()])
    rules = sorted(set(rules))  # Remove duplicates, sort alphabetically

    report = []
    report.append(f"{'BLACK SWAN ANTIVIRUS SCAN REPORT':^60}")
    report.append(divider)
    report.append(f"Timestamp: {timestamp}")
    report.append(f"Filename : {file_name}")
    report.append(f"Location : {os.path.abspath(file_name)}")
    report.append(divider)

    report.append(">> ANALYSIS <<")
    report.append("--Entropy calculated using Shannon's Information Entropy formula--")
    report.append(analysis_report.strip())
    report.append(divider)

    if rules:
        report.append(">> FLAGGED RULES <<")
        for rule in rules:
            report.append(f"- {rule}")
        report.append(divider)

    report.append("End of Report")
    report.append(divider)

    return "\n".join(report)

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
        result = subprocess.run(["/home/surja/Downloads/Black-Swan-main/engine", file_path], stdout=subprocess.PIPE)
        output_text.delete(1.0, END)
        output_text.insert(END, result.stdout.decode())
        output_text.see(END)
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
def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    for count in byte_counts:
        if count:
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

import pefile
import math
import os

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    for count in byte_counts:
        if count:
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def analyze_file_features(path):
    if not os.path.isfile(path):
        return "Invalid file path."

    try:
        with open(path, "rb") as f:
            raw_data = f.read()

        file_entropy = calculate_entropy(raw_data)

        # Try parsing as PE file
        try:
            pe = pefile.PE(data=raw_data)
        except pefile.PEFormatError:
            return (
                f"Entropy (Shannon): {file_entropy}\n"
                "Not a valid PE executable — skipping further analysis."
            )

        num_sections = len(pe.sections)
        suspicious_sections = []
        section_entropies = []

        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip('\x00')
            entropy = round(section.get_entropy(), 2)
            section_entropies.append(entropy)
            if entropy > 6.8:
                suspicious_sections.append((name, entropy))

        # Analyze imports
        imports = []
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode(errors="ignore"))
        except AttributeError:
            imports = []

        suspicious_apis = [
            "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
            "LoadLibraryA", "GetProcAddress", "WinExec", "ShellExecuteA"
        ]
        flagged_apis = [api for api in suspicious_apis if any(api in i for i in imports)]

        # Basic risk score heuristic
        risk_score = 0
        if file_entropy > 6.5:
            risk_score += 20
        risk_score += len(suspicious_sections) * 5
        risk_score += len(flagged_apis) * 10
        risk_score = min(risk_score, 100)

        # Format result
        output = []
        output.append(f"Entropy (Shannon): {file_entropy}")
        output.append(f"Number of Sections: {num_sections}")
        output.append("Suspicious Sections:")
        if suspicious_sections:
            for name, ent in suspicious_sections:
                output.append(f"  - {name}: Entropy={ent}")
        else:
            output.append("  None")

        output.append(f"Flagged Suspicious APIs: {flagged_apis or 'None'}")
        output.append(f"Risk Score (0-100): {risk_score}")

        return "\n".join(output)

    except Exception as e:
        return f"Error during analysis: {e}"


# Hook it to run after engine output
def execute_engine(file_path):
    if not file_path:
        file_label.config(text="No path selected")
        return

    file_label.config(text=file_path)
    
    # Run external engine
    result = subprocess.run(["/home/surja/Downloads/Black-Swan-main/engine", file_path], stdout=subprocess.PIPE)
    engine_output = result.stdout.decode()

    # Perform static analysis
    static_report = analyze_file_features(file_path)

    # Combine and show in GUI
    full_report = engine_output + "\n" + static_report
    output_text.delete(1.0, END)
    output_text.insert(END, full_report)
    output_text.see(END)

    # Create professional-looking .txt report
    file_name = os.path.basename(file_path)
    report_path = os.path.join(os.path.dirname(file_path), f"{file_name}_BlackSwanReport.txt")

    with open(report_path, "w", encoding="utf-8") as report:
        report.write(format_report(file_name, engine_output, static_report))

    print(f"Report saved to: {report_path}")

root.mainloop()
