import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import re
import random
import os

class PIIExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DSP Privacy Guard")
        self.root.geometry("1000x650")
        self.root.configure(bg="#f8fafc")  # Light Slate Background

        # UI 레이아웃 설정
        self.setup_styles()
        self.setup_ui()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Treeview 스타일 (테이블)
        self.style.configure("Treeview", 
            background="white", 
            foreground="#1e293b", 
            rowheight=30, 
            fieldbackground="white",
            font=("Segoe UI", 10))
        self.style.configure("Treeview.Heading", 
            background="#e2e8f0", 
            foreground="#475569", 
            font=("Segoe UI", 10, "bold"))
        self.style.map("Treeview", background=[('selected', '#6366f1')])

    def setup_ui(self):
        # 상단 헤더 영역 (Title)
        header_frame = tk.Frame(self.root, bg="#f8fafc")
        header_frame.pack(pady=(30, 10), fill=tk.X)
        
        title_label = tk.Label(header_frame, text="Privacy Information Extractor", 
                              font=("Segoe UI", 24, "bold"), bg="#f8fafc", fg="#1e293b")
        title_label.pack()
        
        subtitle_label = tk.Label(header_frame, text="파일 내 개인정보를 안전하게 탐지하고 마스킹합니다.", 
                                 font=("Segoe UI", 10), bg="#f8fafc", fg="#64748b")
        subtitle_label.pack(pady=(5, 10))

        # 중앙 액션 영역 (버튼 및 파일명)
        action_frame = tk.Frame(self.root, bg="#f8fafc")
        action_frame.pack(pady=20)

        # 좌우 대칭을 위한 컨테이너
        btn_container = tk.Frame(action_frame, bg="#f8fafc")
        btn_container.pack()

        self.upload_btn = tk.Button(btn_container, text="텍스트 파일 업로드", 
                                   command=self.load_file, 
                                   bg="#6366f1", fg="white", 
                                   font=("Segoe UI", 11, "bold"),
                                   relief="flat", padx=30, pady=10,
                                   activebackground="#4f46e5", activeforeground="white",
                                   cursor="hand2")
        self.upload_btn.pack()

        self.file_label = tk.Label(action_frame, text="분석할 .txt 파일을 선택하세요", 
                                  font=("Segoe UI", 9), bg="#f8fafc", fg="#94a3b8")
        self.file_label.pack(pady=(10, 0))

        # 중앙 테이블 영역
        table_container = tk.Frame(self.root, bg="white", bd=1, relief="flat")
        table_container.pack(expand=True, fill=tk.BOTH, padx=40, pady=(10, 40))

        columns = ("type", "original", "masked")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", selectmode="browse")
        
        self.tree.heading("type", text="구분")
        self.tree.heading("original", text="원본 정보")
        self.tree.heading("masked", text="마스킹 결과")

        self.tree.column("type", width=120, anchor=tk.CENTER)
        self.tree.column("original", width=380, anchor=tk.W)
        self.tree.column("masked", width=380, anchor=tk.W)

        scrollbar = ttk.Scrollbar(table_container, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def mask_data(self, text):
        """문자열의 약 50%를 랜덤하게 *로 치환"""
        if not text:
            return ""
        
        chars = list(text)
        # 마스킹 대상 인덱스 추출 (구분자 제외)
        indices = [i for i, c in enumerate(chars) if c not in ['-', '.', '@', ':', ' ']]
        
        # 50% 비율로 샘플링
        mask_count = max(1, int(len(indices) * 0.5))
        to_mask = random.sample(indices, mask_count)
        
        for i in to_mask:
            chars[i] = '*'
            
        return "".join(chars)

    def extract_pii(self, content):
        """정규표현식을 사용하여 개인정보 추출"""
        results = []

        # 1. IP주소 (숫자3개.숫자3개.숫자3개.숫자3개)
        ips = re.findall(r'\d{3}\.\d{3}\.\d{3}\.\d{3}', content)
        for item in ips: results.append(("IP 주소", item))

        # 2. 전화번호 (0으로 시작하는 3자리-3~4자리-4자리)
        phones = re.findall(r'0\d{2}-\d{3,4}-\d{4}', content)
        for item in phones: results.append(("전화번호", item))

        # 3. Email (영문시작, 영문/숫자/. @ 영문.영문(.영문))
        emails = re.findall(r'[a-zA-Z][a-zA-Z0-9.]*@[a-zA-Z]+\.[a-zA-Z]+(?:\.[a-zA-Z]+)?', content)
        for item in emails: results.append(("이메일", item))

        # 4. ID (ID: 뒤에 나오는 영숫자)
        ids = re.findall(r'ID:\s*([a-zA-Z0-9]+)', content)
        for item in ids: results.append(("아이디", item))

        # 5. Password (PASS: 뒤에 나오는 영숫자)
        pwds = re.findall(r'PASS:\s*([a-zA-Z0-9]+)', content)
        for item in pwds: results.append(("비밀번호", item))

        # 6. 주민등록번호 (숫자6개-숫자7개 - 수정된 요청사항 기준)
        rrns = re.findall(r'\d{6}-\d{7}', content)
        for item in rrns: results.append(("주민번호", item))

        # 7. 카드번호 (숫자4개-4개-4개-4개)
        cards = re.findall(r'\d{4}-\d{4}-\d{4}-\d{4}', content)
        for item in cards: results.append(("카드번호", item))

        return results

    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="텍스트 파일 선택",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )

        if not file_path:
            return

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.file_label.config(text=f"분석 파일: {os.path.basename(file_path)}", fg="#475569")
            
            # 기존 테이블 데이터 삭제
            for item in self.tree.get_children():
                self.tree.delete(item)

            # 정보 추출
            extracted_data = self.extract_pii(content)

            if not extracted_data:
                messagebox.showinfo("결과", "탐지된 개인정보가 없습니다.")
                return

            # 마스킹 및 테이블 삽입
            for pii_type, original in extracted_data:
                masked = self.mask_data(original)
                self.tree.insert("", tk.END, values=(pii_type, original, masked))

        except Exception as e:
            messagebox.showerror("오류", f"파일을 읽는 중 오류가 발생했습니다: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PIIExtractorApp(root)
    root.mainloop()