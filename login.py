# -*- coding: utf-8 -*-
import requests
import threading
import time
import subprocess
import sys
import re
import os
import argparse
import logging
from flask import Flask, jsonify
from DrissionPage import ChromiumPage, ChromiumOptions
from cryptography.fernet import Fernet


# --- AYARLAR ---
ACCOUNTS_FILE = "accounts.txt"
KEY_FILE = "secret.key"
app = Flask(__name__)

# --- TARAYICI AYARLARI (MİNİ PENCERE & PERFORMANS) ---
co = ChromiumOptions()
# Headless'ı kapatıyoruz (Cloudflare takılmasın diye) ama ekran dışına atıyoruz
co.headless(False) 
co.set_argument('--window-size=-1,-1') 
co.set_argument('--window-position=-50000,-50000') 
# Performans ve Hata Önleyici Ayarlar
co.set_argument('--disable-gpu')
co.set_argument('--disable-interventions')
co.set_argument('--disable-notifications')
co.set_argument('--no-first-run')
co.set_argument('--no-service-autorun')
co.set_argument('--password-store=basic')
co.set_argument('--start-minimized')
co.set_argument('--incognito')
co.set_argument('--no-default-browser-check')
co.set_argument('--disable-notifications')
co.set_argument('--disable-autofill')
co.set_argument('--disable-logging')
co.set_argument('--disable-infobars')
co.set_argument('--no-default-browser-check')
co.set_argument('--disable-features=IsolateOrigins,site-per-process')
# Doğrudan siteye uygulama modunda (adres çubuğu olmadan) bağlan
co.set_argument('--app=https://www.craftrise.com.tr')

# Tarayıcıyı Başlat
page = ChromiumPage(addr_or_opts=co)

token_failures = 0
cipher = None 

# --- GÜVENLİK VE ŞİFRELEME ---

def load_or_create_key():
    global cipher
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    cipher = Fernet(key)

def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

def get_next_account_id():
    if not os.path.exists(ACCOUNTS_FILE):
        return 1
    count = 0
    with open(ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                count += 1
    return count + 1

def add_new_account(username, password):
    load_or_create_key()
    encrypted_pass = encrypt_password(password)
    next_id = get_next_account_id()
    account_label = f"account{next_id}"
    
    entry = f'{account_label}; username: "{username}"; password: "{encrypted_pass}"\n'
    
    with open(ACCOUNTS_FILE, "a", encoding="utf-8") as f:
        f.write(entry)

# --- YARDIMCI FONKSİYONLAR ---

def get_account_credentials(account_label):
    load_or_create_key()
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith(account_label + ";"):
                    user_match = re.search(r'username:\s*"([^"]+)"', line)
                    pass_match = re.search(r'password:\s*"([^"]+)"', line)
                    
                    if user_match and pass_match:
                        decrypted_pass = decrypt_password(pass_match.group(1))
                        return user_match.group(1), decrypted_pass
        return None, None
    except:
        return None, None

def restart_warp():
    try:
        subprocess.run(["warp-cli", "disconnect"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        subprocess.run(["warp-cli", "connect"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def initialize_page():
    try:
        # --app parametresi kullandığımız için zaten adrese gitmiş olabiliriz
        # ama garanti olsun diye tekrar yönlendirebiliriz veya bekleyebiliriz.
        page.get('https://www.craftrise.com.tr')
        
        js = """
        const div = document.createElement('div');
        div.id = 'captcha-container';
        document.body.appendChild(div);
        const script = document.createElement('script');
        script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
        script.async = true;
        script.defer = true;
        document.head.appendChild(script);
        script.onload = () => {
            const id = turnstile.render('#captcha-container', {
                sitekey: '0x4AAAAAAA4cK60wpgOTyti9',
                callback: function(token) {
                    window._cf_token = token;
                }
            });
            window._cf_widget_id = id;
        };
        """
        page.run_js(js)
        for _ in range(20):
            if page.run_js('return window._cf_token !== undefined') and page.run_js('return window._cf_widget_id !== undefined'):
                return True
            time.sleep(1)
        return False
    except:
        return False

# --- FLASK API ---

@app.route('/get-token', methods=['GET'])
def get_new_token():
    global token_failures
    try:
        page.run_js("turnstile.reset(window._cf_widget_id);")
        for _ in range(10):
            token = page.run_js('return window._cf_token || null;')
            if token:
                token_failures = 0
                return jsonify({"token": token})
            time.sleep(1)
        token_failures += 1
        if token_failures >= 2:
            restart_warp()
            token_failures = 0
        return jsonify({"error": "Yeni token alinamadi"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_api():
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    log.disabled = True
    from flask import cli
    cli.show_server_banner = lambda *x: None
    app.run(host='127.0.0.1', port=5001, debug=False, use_reloader=False)

# --- LOGIN BÖLÜMÜ ---

def login_and_scrape(username, password):
    session = requests.Session()
    try:
        time.sleep(1.5) # Tarayıcı iyice yüklensin
        
        t_res = requests.get("http://127.0.0.1:5001/get-token", timeout=15)
        cf_token = t_res.json().get("token")
        
        # --- DEĞİŞİKLİK BURADA ---
        if cf_token:
            print(f"\nToken; {cf_token}")
        # -------------------------
        
        if not cf_token:
            return

        session.get('https://www.craftrise.com.tr/')
        phpsessid = session.cookies.get('PHPSESSID')
        
        login_url = "https://www.craftrise.com.tr/posts/post-login.php"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": f"PHPSESSID={phpsessid}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.craftrise.com.tr/"
        }
        
        data = {"value": username, "password": password, "grecaptcharesponse": cf_token}
        response = session.post(login_url, headers=headers, data=data)
        
        res_json = response.json()
        
        if res_json.get("resultType") == "success":
            print("Login Successful")
        else:
            print("Login Failed")

    except Exception as e:
        print(f"Login Failed: {e}")

# --- ANA CALISTIRICI ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CraftRise Token Checker")
    parser.add_argument("account", nargs="?", help="Kontrol edilecek hesap ID'si (örn: account1)")
    parser.add_argument("-n", "--new-account", action="store_true", help="Yeni hesap ekleme modu")
    parser.add_argument("--username", help="Eklenecek kullanıcı adı")
    parser.add_argument("--password", help="Eklenecek şifre")

    args = parser.parse_args()

    if args.new_account:
        if args.username and args.password:
            add_new_account(args.username, args.password)
            sys.exit(0)
        else:
            print("Hata: -n kullanirken --username ve --password zorunludur.")
            sys.exit(1)

    if args.account:
        target_account = args.account
        u, p = get_account_credentials(target_account)

        if not u or not p:
            # Hesap bulunamadıysa sessizce çık veya minik bir hata kodu bas
            sys.exit(1)

        try:
            if not initialize_page():
                sys.exit(1)

            api_thread = threading.Thread(target=run_api, daemon=True)
            api_thread.start()
            
            time.sleep(1)

            login_and_scrape(u, p)
            
        except KeyboardInterrupt:
            pass
        finally:
            try:
                page.quit()
            except:
                pass
    else:
        parser.print_help()
