from tkinter import *
from tkinter import filedialog
import subprocess
import tkinter.font as tkfont
import ttkbootstrap as tb
import math
import pefile
import os

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

def analyze_file_features(path):
    if not os.path.isfile(path):
        return "Invalid file path."

    try:
        # Load raw data
        with open(path, "rb") as f:
            raw_data = f.read()
        file_entropy = calculate_entropy(raw_data)

        # Parse PE file
        pe = pefile.PE(path)
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

        suspicious_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibraryA", "GetProcAddress"]
        flagged_apis = [api for api in suspicious_apis if any(api in i for i in imports)]

        # Risk Scoring (very basic heuristic)
        risk_score = 0
        if file_entropy > 6.5:
            risk_score += 20
        risk_score += len(suspicious_sections) * 5
        risk_score += len(flagged_apis) * 10

        # Format output
        output = "\n=== Static Analysis Report ===\n"
        output += f"Overall File Entropy: {file_entropy}\n"
        output += f"Number of Sections: {num_sections}\n"
        output += "Suspicious Sections:\n"
        for name, ent in suspicious_sections:
            output += f"  - {name}: Entropy={ent}\n"
        output += f"Flagged Suspicious APIs: {flagged_apis or 'None'}\n"
        output += f"Risk Score (0-100): {risk_score}\n"
        return output

    except Exception as e:
        return f"Error in analysis: {e}"

# Hook it to run after engine output
def execute_engine(file_path):
    if file_path:
        file_label.config(text=file_path)
        result = subprocess.run(["/home/surja/Downloads/Black-Swan-main/engine", file_path], stdout=subprocess.PIPE)
        output_text.delete(1.0, END)
        output_text.insert(END, result.stdout.decode())

        # Append static analysis report
        static_report = analyze_file_features(file_path)
        output_text.insert(END, "\n" + static_report)
        output_text.see(END)
    else:
        file_label.config(text="No path selected")

root.mainloop()
