from tkinter import *
from tkinter import filedialog
import subprocess
import tkinter.font as tkfont
from datetime import datetime
from fpdf import FPDF
import os
import ttkbootstrap as tb

root = tb.Window(themename="darkly")
root.title("BlackSwanAV")
root.geometry("1440x900")

# Global font
default_font = tkfont.nametofont("TkDefaultFont")
default_font.configure(family="DejaVu Sans Mono", size=14)
text_font = tkfont.Font(family="DejaVu Sans Mono", size=14)

file_path = ""
upload_type = "file"

def file_dialog():
    global file_path
    if upload_type == "file":
        file_path = filedialog.askopenfilename()
    else:
        file_path = filedialog.askdirectory()
    file_label.config(text="Chosen path: " + file_path if file_path else "No path selected")

def toggle_upload_type():
    global upload_type
    upload_type = "directory" if upload_type == "file" else "file"
    toggle_button.config(text="Switch to File Upload" if upload_type == "directory" else "Switch to Directory Upload")

def generate_pdf_report(matched_rules, file_path):
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"report_{now}.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    pdf.rect(10, 10, 190, 277)  # border
    pdf.cell(0, 10, "BlackSwanAV Threat Report", ln=True, align='C')
    pdf.ln(10)
    pdf.cell(0, 10, f"Scanned Path: {file_path}", ln=True)
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Matched YARA Rules:", ln=True)
    pdf.set_font("Arial", size=12)
    if matched_rules:
        for rule in matched_rules:
            pdf.cell(0, 10, f"- {rule}", ln=True)
    else:
        pdf.cell(0, 10, "No rules matched.", ln=True)
    report_dir = os.path.expanduser("~/Desktop/BlackSwanReports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, filename)
    pdf.output(report_path)
    return report_path

def execute_engine(file_path):
    if not file_path:
        file_label.config(text="No path selected")
        return
    try:
        result = subprocess.run(
            ["/home/surja/Downloads/Black-Swan-main/engine", file_path],
            capture_output=True, text=True, check=True
        )
        output = result.stdout
        matched_rules = [line.split("Matched rule:")[-1].strip() for line in output.splitlines() if "Matched rule:" in line]

        output_text.delete(1.0, END)
        output_text.insert(END, output)
        output_text.insert(END, f"\n\n✅ Scan complete.")
        if matched_rules:
            output_text.insert(END, f"\nMatched Rules:\n" + "\n".join(matched_rules))
        report_path = generate_pdf_report(matched_rules, file_path)
        output_text.insert(END, f"\n\n📄 Report saved to: {report_path}")

    except subprocess.CalledProcessError as e:
        output_text.delete(1.0, END)
        output_text.insert(END, f"Error during scan:\n{e.stderr}")

# GUI Layout
tb.Label(text="Black Swan Antivirus", font=("DejaVu Sans Mono", 40, "bold"), bootstyle="default").pack(pady=10)

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

tb.Label(text="Scan results", font=("DejaVu Sans Mono", 30, "bold"), bootstyle="default").pack(pady=20)

output_text = Text(root, width=200, height=30, wrap='word', font=text_font)
output_text.pack(pady=10)

root.mainloop()
