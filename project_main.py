import struct
import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import time
import threading

# ==========================================
# PART 1: SHA-1 ENGINE (FROM SCRATCH)
# ==========================================
class SHA1_Engine:
    def __init__(self):
        # Standard SHA-1 Initial Constants (The "IV")
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.buffer = b''
        self.count = 0

    def _left_rotate(self, n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def _process_chunk(self, chunk):
        w = [0] * 80
        # Break chunk into sixteen 32-bit big-endian words
        for i in range(16):
            w[i] = struct.unpack(b'>I', chunk[i*4:i*4+4])[0]
        # Extend to 80 words
        for i in range(16, 80):
            w[i] = self._left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

        a, b, c, d, e = self.h

        # The Main Loop (80 Rounds)
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d); k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d; k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d; k = 0xCA62C1D6

            temp = (self._left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e, d, c, b, a = d, c, self._left_rotate(b, 30), a, temp

        # Update state with the result of this chunk
        self.h = [(x + y) & 0xFFFFFFFF for x, y in zip(self.h, [a, b, c, d, e])]

    def update(self, data):
        if isinstance(data, str): data = data.encode()
        self.buffer += data
        self.count += len(data) * 8
        while len(self.buffer) >= 64:
            self._process_chunk(self.buffer[:64])
            self.buffer = self.buffer[64:]

    def digest(self):
        # Save state to restore later (so we can call digest multiple times)
        original_state = (self.h[:], self.count, self.buffer)
        
        # SHA-1 Padding Rules: 1 bit, then 0 bits, then length
        padding = b'\x80'
        current_len = (self.count // 8) + 1
        while current_len % 64 != 56:
            padding += b'\x00'
            current_len += 1
        padding += struct.pack(b'>Q', self.count)
        
        self.update(padding)
        result = b''.join(struct.pack(b'>I', x) for x in self.h)
        
        # Restore state
        self.h, self.count, self.buffer = original_state
        return result.hex()

    # --- THE VULNERABILITY ---
    def set_state_manually(self, hex_hash, length_of_message_bytes):
        """
        Force-loads a specific hash state into the engine.
        This simulates 'resuming' the machine from a saved point.
        """
        self.h = [int(hex_hash[i:i+8], 16) for i in range(0, 40, 8)]
        self.count = length_of_message_bytes * 8
        self.buffer = b''

# ==========================================
# PART 2: ATTACK LOGIC (THE MATH)
# ==========================================
def calculate_padding_glue(total_len):
    """Calculates the exact bytes the server added as padding."""
    pad = b'\x80'
    current_len = total_len + 1
    while current_len % 64 != 56:
        pad += b'\x00'
        current_len += 1
    pad += struct.pack(b'>Q', total_len * 8)
    return pad

# ==========================================
# PART 3: IMMERSIVE GUI
# ==========================================
class ImmersiveCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Review 1: SHA-1 Length Extension Exploit")
        self.root.geometry("1000x800")
        self.root.configure(bg="#202020")

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background="#202020", foreground="white")
        style.configure("TNotebook.Tab", background="#404040", foreground="white", padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", "#007acc")])

        # Tabs
        tab_control = ttk.Notebook(root)
        self.tab1 = ttk.Frame(tab_control) # Manual Attack
        self.tab2 = ttk.Frame(tab_control) # Automated Tests
        
        tab_control.add(self.tab1, text='  Manual Attack Demo  ')
        tab_control.add(self.tab2, text='  Automated Validation (Graph)  ')
        tab_control.pack(expand=1, fill="both")

        self.setup_manual_tab()
        self.setup_validation_tab()

    def log(self, message, color="white"):
        self.console_log.config(state=tk.NORMAL)
        self.console_log.insert(tk.END, f"> {message}\n", color)
        self.console_log.see(tk.END)
        self.console_log.config(state=tk.DISABLED)
        self.root.update()

    def setup_manual_tab(self):
        # Frame for Controls
        control_frame = tk.Frame(self.tab1, bg="#303030", padx=20, pady=20)
        control_frame.pack(fill="x")

        # Inputs
        tk.Label(control_frame, text="SERVER SECRET:", bg="#303030", fg="#ff5555", font=("Consolas", 12, "bold")).grid(row=0, column=0, sticky="e")
        self.key_entry = tk.Entry(control_frame, width=20, font=("Consolas", 12))
        self.key_entry.insert(0, "Secret123")
        self.key_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(control_frame, text="USER MESSAGE:", bg="#303030", fg="#55ff55", font=("Consolas", 12, "bold")).grid(row=1, column=0, sticky="e")
        self.msg_entry = tk.Entry(control_frame, width=20, font=("Consolas", 12))
        self.msg_entry.insert(0, "file=report.pdf")
        self.msg_entry.grid(row=1, column=1, padx=10, pady=5)

        # Buttons
        btn_hash = tk.Button(control_frame, text="1. SIGN MESSAGE (Server)", bg="#007acc", fg="white", font=("Consolas", 11, "bold"), command=self.server_sign)
        btn_hash.grid(row=2, column=0, columnspan=2, pady=10, sticky="we")

        self.sig_display = tk.Entry(control_frame, width=50, font=("Consolas", 10), justify="center", bg="#101010", fg="#00ccff")
        self.sig_display.grid(row=3, column=0, columnspan=2, pady=5)

        tk.Label(control_frame, text="ATTACK PAYLOAD:", bg="#303030", fg="#ffcc00", font=("Consolas", 12, "bold")).grid(row=4, column=0, sticky="e", pady=(20, 5))
        self.ext_entry = tk.Entry(control_frame, width=20, font=("Consolas", 12))
        self.ext_entry.insert(0, "&admin=true")
        self.ext_entry.grid(row=4, column=1, pady=(20, 5))

        btn_attack = tk.Button(control_frame, text="2. LAUNCH EXTENSION ATTACK", bg="#cc0000", fg="white", font=("Consolas", 11, "bold"), command=self.run_manual_attack)
        btn_attack.grid(row=5, column=0, columnspan=2, pady=10, sticky="we")

        # Hacker Console
        console_frame = tk.Frame(self.tab1, bg="black", padx=10, pady=10)
        console_frame.pack(fill="both", expand=True)
        
        tk.Label(console_frame, text="/// HACKER_TERMINAL_V1.0 ///", bg="black", fg="#00ff00", font=("Courier", 10)).pack(anchor="w")
        
        self.console_log = tk.Text(console_frame, bg="#101010", fg="#00ff00", font=("Courier New", 10), height=15)
        self.console_log.pack(fill="both", expand=True)
        self.console_log.tag_config("green", foreground="#00ff00")
        self.console_log.tag_config("red", foreground="#ff5555")
        self.console_log.tag_config("yellow", foreground="#ffff55")
        self.console_log.tag_config("cyan", foreground="#00ccff")
        self.console_log.tag_config("white", foreground="white")

    def server_sign(self):
        key = self.key_entry.get()
        msg = self.msg_entry.get()
        
        self.log("--- SERVER ACTIVITY ---", "white")
        self.log(f"Server signing: '{msg}' with hidden key.", "white")
        
        s = SHA1_Engine()
        s.update(key + msg)
        sig = s.digest()
        
        self.sig_display.delete(0, tk.END)
        self.sig_display.insert(0, sig)
        self.log(f"Server generated Signature: {sig}", "cyan")
        self.log("-----------------------", "white")

    def run_manual_attack(self):
        # Run in thread so GUI updates live
        threading.Thread(target=self._attack_thread).start()

    def _attack_thread(self):
        key_len_guess = len(self.key_entry.get()) # In real attack, we brute force this.
        original_msg = self.msg_entry.get()
        original_sig = self.sig_display.get()
        extension = self.ext_entry.get()

        if not original_sig:
            self.log("[ERROR] No signature found to attack!", "red")
            return

        self.log("\n[+] INITIATING LENGTH EXTENSION ATTACK...", "yellow")
        time.sleep(0.5)

        # Step 1: Padding Calculation
        self.log(f"[1] Guessing Key Length: {key_len_guess} bytes", "white")
        self.log(f"[1] Calculating Merkle-Damgard Glue for message length {len(original_msg)}...", "white")
        
        total_len = key_len_guess + len(original_msg)
        glue = calculate_padding_glue(total_len)
        
        time.sleep(0.5)
        self.log(f"[+] Glue Calculated: {glue.hex()[:20]}... (Length: {len(glue)})", "cyan")

        # Step 2: State Resumption
        self.log(f"[2] Loading Original Signature into SHA-1 Registers...", "white")
        self.log(f"    State A,B,C,D,E set to {original_sig[:8]}...", "white")
        
        forger = SHA1_Engine()
        # New length = Key + Msg + Glue + Ext
        new_total_len = total_len + len(glue) + len(extension)
        forger.set_state_manually(original_sig, new_total_len - len(extension))
        
        time.sleep(0.5)
        self.log("[+] Engine State Resumed!", "green")

        # Step 3: Extension
        self.log(f"[3] Processing Malicious Payload: '{extension}'", "white")
        forger.update(extension)
        forged_sig = forger.digest()
        
        time.sleep(0.5)
        self.log(f"[!] FORGED SIGNATURE: {forged_sig}", "red")

        # Step 4: Verification
        self.log("\n[?] SENDING TO SERVER FOR VERIFICATION...", "yellow")
        time.sleep(0.8)
        
        # Server Check
        server_key = self.key_entry.get()
        # Note: Server receives (Msg + Glue + Ext) as one blob
        full_payload = server_key.encode() + original_msg.encode() + glue + extension.encode()
        
        s_check = SHA1_Engine()
        s_check.update(full_payload)
        server_calc_sig = s_check.digest()

        if forged_sig == server_calc_sig:
            self.log("[SUCCESS] Server Accepted the Forged Signature!", "green")
            self.log(f"[SUCCESS] Admin Command Executed.", "green")
        else:
            self.log("[FAIL] Server Rejected Signature.", "red")

    def setup_validation_tab(self):
        frame = tk.Frame(self.tab2, bg="#303030")
        frame.pack(fill="both", expand=True)

        btn = tk.Button(frame, text="RUN 25 AUTOMATED TEST CASES", bg="orange", font=("Arial", 12, "bold"), command=self.run_tests)
        btn.pack(pady=20)

        self.canvas = tk.Canvas(frame, width=600, height=300, bg="#202020", highlightthickness=0)
        self.canvas.pack(pady=10)

        self.test_log = tk.Text(frame, height=10, bg="#101010", fg="white", font=("Consolas", 9))
        self.test_log.pack(fill="x", padx=20, pady=20)

    def run_tests(self):
        self.test_log.delete(1.0, tk.END)
        self.test_log.insert(tk.END, f"{'TEST':<5} {'KEY':<5} {'MSG':<5} {'STATUS':<10}\n", "white")
        self.test_log.insert(tk.END, "-"*40 + "\n", "white")
        
        success = 0
        total = 25
        
        for i in range(1, total + 1):
            # Random Data
            key_len = random.randint(5, 15)
            key = ''.join(random.choices(string.ascii_letters, k=key_len))
            msg = "data" + str(i)
            ext = "&hack"
            
            # Server Sig
            s = SHA1_Engine()
            s.update(key + msg)
            valid_sig = s.digest()
            
            # Attack
            glue = calculate_padding_glue(key_len + len(msg))
            forger = SHA1_Engine()
            new_len = key_len + len(msg) + len(glue) + len(ext)
            forger.set_state_manually(valid_sig, new_len - len(ext))
            forger.update(ext)
            forged_sig = forger.digest()
            
            # Verify
            s_check = SHA1_Engine()
            s_check.update(key.encode() + msg.encode() + glue + ext.encode())
            if forged_sig == s_check.digest():
                success += 1
                res = "PASS"
            else:
                res = "FAIL"
            
            self.test_log.insert(tk.END, f"#{i:<4} {key_len:<5} {len(msg):<5} {res:<10}\n")
            self.root.update()
            time.sleep(0.05)

        self.draw_graph(success, total)

    def draw_graph(self, success, total):
        self.canvas.delete("all")
        w, h = 600, 300
        
        # Bars
        success_h = (success / total) * (h - 50)
        fail_h = ((total - success) / total) * (h - 50)
        
        # Green Bar
        self.canvas.create_rectangle(150, h-30, 250, h-30-success_h, fill="#00ff00")
        self.canvas.create_text(200, h-15, text="Success", fill="white")
        self.canvas.create_text(200, h-40-success_h, text=f"{success}", fill="white")

        # Red Bar
        self.canvas.create_rectangle(350, h-30, 450, h-30-fail_h, fill="#ff0000")
        self.canvas.create_text(400, h-15, text="Failed", fill="white")
        self.canvas.create_text(400, h-40-fail_h, text=f"{total-success}", fill="white")

        self.canvas.create_text(300, 30, text=f"ATTACK SUCCESS RATE: {(success/total)*100}%", fill="white", font=("Arial", 14, "bold"))

if __name__ == "__main__":
    root = tk.Tk()
    app = ImmersiveCryptoApp(root)
    root.mainloop()