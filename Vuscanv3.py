import tkinter as tk
from tkinter import messagebox
import re
import requests
import os
from urllib.parse import urlparse
import openai  # นำเข้าไลบรารี openai

# ตั้งค่า OpenAI API Key
openai.api_key = 'YOUR_OPENAI_API_KEY'

print("""
 _   _ _   _ _____ _____   ___   _   _    ___  _____ ls
| | | | | | /  ___/  __ \ / _ \ | \ | |  / _ \|_   _|
| | | | | | \ `--.| /  \// /_\ \|  \| | / /_\ \ | |  
| | | | | | |`--. \ |    |  _  || . ` | |  _  | | |  
\ \_/ / |_| /\__/ / \__/\| | | || |\  |_| | | |_| |_ 
 \___/ \___/\____/ \____/\_| |_/\_| \_(_)_| |_/\___/ 
""")

# ตรวจสอบว่าเป็น IP Address หรือไม่
def is_ip_address(url):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", url) is not None

# ฟังก์ชันเชื่อมต่อกับ OpenAI สำหรับการตรวจจับช่องโหว่
def detect_vulnerability_with_ai(code):
    try:
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=f"Analyze the following code for possible security vulnerabilities, such as SQL Injection, XSS, or CSRF:\n\n{code}\n\nProvide a detailed explanation of the vulnerabilities, if any:",
            max_tokens=150,
            n=1,
            stop=None,
            temperature=0.5
        )
        analysis_result = response.choices[0].text.strip()
        return analysis_result
    except Exception as e:
        return f"Error occurred while connecting to OpenAI: {e}"

# ฟังก์ชันสำหรับสแกนช่องโหว่ SQL Injection
def detect_sql_injection(code):
    # ใช้ OpenAI ในการวิเคราะห์ช่องโหว่
    return detect_vulnerability_with_ai(code)

# ฟังก์ชันสำหรับตรวจจับช่องโหว่ CSRF
def detect_csrf(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            if "csrf" in response.text.lower():
                return "พบช่องโหว่ CSRF"
            else:
                return "ไม่พบช่องโหว่ CSRF"
        else:
            return "ไม่สามารถเชื่อมต่อกับเว็บไซต์ได้"
    except requests.RequestException:
        return "ไม่สามารถเชื่อมต่อกับเว็บไซต์ได้"

# ฟังก์ชันสำหรับสแกน URL
def scan_url():
    url = url_entry.get().strip()

    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    if is_ip_address(urlparse(url).netloc):
        result_text.insert(tk.END, "กำลังสแกน IP Address...\n")
    else:
        result_text.insert(tk.END, "กำลังสแกนโดเมน...\n")

    try:
        response = requests.get(url)
        if response.status_code == 200:
            result_text.insert(tk.END, f"การเชื่อมต่อสำเร็จ: {url}\n")
            csrf_result = detect_csrf(url)
            result_text.insert(tk.END, csrf_result + "\n")
        else:
            result_text.insert(tk.END, "การเชื่อมต่อไม่สำเร็จ\n")
    except requests.RequestException:
        result_text.insert(tk.END, "ไม่สามารถเชื่อมต่อกับเว็บไซต์ได้\n")

# ฟังก์ชันสำหรับการสแกน SQL Injection
def scan_sql():
    code_to_scan = code_entry.get("1.0", tk.END)
    result = detect_sql_injection(code_to_scan)
    result_text.insert(tk.END, result + "\n")

# ฟังก์ชันสำหรับการล้างผลลัพธ์
def clear_results():
    result_text.delete("1.0", tk.END)

# ฟังก์ชันสำหรับการแสดงข้อความ About
def show_about():
    messagebox.showinfo("About", "โปรแกรมนี้เป็นเครื่องมือสำหรับสแกนหาช่องโหว่ SQL Injection และ CSRF ภายในเว็บไซต์ โดยใช้การวิเคราะห์จาก AI")

# สร้างหน้าต่างหลัก
root = tk.Tk()
root.title("Vulnerability Scanner Tool")
root.geometry("700x500")

# ปรับแต่งสไตล์ของ GUI ให้สวยงาม
root.configure(bg="#f0f0f0")

# กรอบ URL
url_frame = tk.Frame(root, bg="#f0f0f0")
url_frame.pack(pady=10)

url_label = tk.Label(url_frame, text="ใส่ URL หรือ IP:", bg="#f0f0f0")
url_label.pack(side=tk.LEFT)

url_entry = tk.Entry(url_frame, width=50)
url_entry.pack(side=tk.LEFT, padx=5)

scan_url_button = tk.Button(url_frame, text="สแกน URL", command=scan_url)
scan_url_button.pack(side=tk.LEFT)

# กรอบ SQL Injection
sql_frame = tk.Frame(root, bg="#f0f0f0")
sql_frame.pack(pady=10)

code_label = tk.Label(sql_frame, text="ใส่โค้ดที่ต้องการสแกน SQL:", bg="#f0f0f0")
code_label.pack()

code_entry = tk.Text(sql_frame, height=5, width=50)
code_entry.pack()

scan_sql_button = tk.Button(sql_frame, text="สแกน SQL Injection", command=scan_sql)
scan_sql_button.pack(pady=5)

# แสดงผลการสแกน
result_frame = tk.Frame(root, bg="#f0f0f0")
result_frame.pack(pady=10)

result_label = tk.Label(result_frame, text="ผลการสแกน:", bg="#f0f0f0")
result_label.pack()

result_text = tk.Text(result_frame, height=10, width=70)
result_text.pack()

# ปุ่มล้างผลลัพธ์
clear_button = tk.Button(root, text="ล้างผลลัพธ์", command=clear_results)
clear_button.pack(pady=5)

# เมนู About
menu = tk.Menu(root)
root.config(menu=menu)

help_menu = tk.Menu(menu)
menu.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="About", command=show_about)

root.mainloop()
