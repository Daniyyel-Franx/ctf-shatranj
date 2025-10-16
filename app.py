'''from flask import Flask, render_template, request, redirect, url_for, jsonify
import base64

app = Flask(__name__)

# Simulated database
users = [
    {'username': 'admin', 'password': 'secret'}
]

def check_sql_injection(username, password):
    """
    Simulates vulnerable SQL query:
    SELECT * FROM users WHERE username='{username}' AND password='{password}'
    
    Detects common SQLi payloads
    """
    # Common SQLi patterns that bypass authentication
    sqli_patterns = [
        "' OR '1'='1",
        "' OR 1=1",
        "'--",
        "' #",
        "' /*",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR '1'='1' --",
        "' OR 'x'='x",
        "admin' OR '1'='1"
    ]
    
    # Check if any SQLi pattern is in username or password
    for pattern in sqli_patterns:
        if pattern in username or pattern in password:
            return True
    
    # Normal authentication check
    for user in users:
        if user['username'] == username and user['password'] == password:
            return True
    
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    clue = None
    error = None
    
    if request.method == 'POST':
        uname = request.form.get('username', '')
        pwd = request.form.get('password', '')
        
        # Vulnerable to SQLi
        if check_sql_injection(uname, pwd):
            clue = base64.b64encode(b'http://127.0.0.1:5000/xss').decode()
        else:
            error = "Invalid credentials"
    
    return render_template('login.html', clue=clue, error=error)

@app.route('/xss', methods=['GET'])
def xss():
    return render_template('xss.html')

@app.route('/cipher', methods=['GET', 'POST'])
def cipher():
    encrypted = base64.b64encode("IndiaSafe2025".encode()).decode()
    next_url = None
    
    if request.method == 'POST':
        answer = request.form.get('answer', '')
        if answer == "IndiaSafe2025":
            next_url = "/stego"
    
    return render_template('cipher.html', encrypted=encrypted, next_url=next_url)

@app.route('/stego', methods=['GET', 'POST'])
def stego():
    # Message to encrypt
    message = "You are the SAVIOUR"
    
    # One-time pad (extract from image metadata)
    pad = "ABCDEFGHIJKLMNOPQRS"
    
    # Step 1: XOR encryption with OTP
    xor_encrypted = ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(message, pad)])
    
    # Step 2: Caesar cipher with ROT8
    def caesar_encrypt(text, shift):
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
                else:
                    result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(char)
        return ''.join(result)
    
    caesar_encrypted = caesar_encrypt(xor_encrypted, 8)
    encrypted_flag = base64.b64encode(caesar_encrypted.encode()).decode()
    
    true_flag = "CYS{CY5C0M_SAV3S_!ND1@}"
    
    return render_template('stego.html', encrypted_flag=encrypted_flag, pad=pad)

@app.route('/final', methods=['POST'])
def final():
    user_flag = request.form.get('flag', '').strip()
    true_flag = "CYS{CY5C0M_SAV3S_!ND1@}"
    
    if user_flag == "You are the SAVIOUR!!!":
        return jsonify({'success': True, 'flag': true_flag})
    else:
        return jsonify({'success': False, 'message': 'Incorrect message'})

if __name__ == '__main__':
    app.run(debug=True)
    '''


from flask import Flask, render_template, request, redirect, url_for, jsonify
import base64

app = Flask(__name__)

# Simulated database
users = [
    {'username': 'admin', 'password': 'secret'}
]

def check_sql_injection(username, password):
    """
    Simulates vulnerable SQL query:
    SELECT * FROM users WHERE username='{username}' AND password='{password}'
    
    Detects common SQLi payloads
    """
    # Common SQLi patterns that bypass authentication
    sqli_patterns = [
        "' OR '1'='1",
        "' OR 1=1",
        "'--",
        "' #",
        "' /*",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR '1'='1' --",
        "' OR 'x'='x",
        "admin' OR '1'='1"
    ]
    
    # Check if any SQLi pattern is in username or password
    for pattern in sqli_patterns:
        if pattern in username or pattern in password:
            return True
    
    # Normal authentication check
    for user in users:
        if user['username'] == username and user['password'] == password:
            return True
    
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    clue = None
    error = None
    
    if request.method == 'POST':
        uname = request.form.get('username', '')
        pwd = request.form.get('password', '')
        
        # Vulnerable to SQLi
        if check_sql_injection(uname, pwd):
           clue = base64.b64encode(b'https://ctf-shatranj.onrender.com/xss').decode()

        else:
            error = "Invalid credentials"
    
    return render_template('login.html', clue=clue, error=error)

@app.route('/xss', methods=['GET'])
def xss():
    return render_template('xss.html')

@app.route('/cipher', methods=['GET', 'POST'])
def cipher():
    encrypted = base64.b64encode("IndiaSafe2025".encode()).decode()
    next_url = None
    
    if request.method == 'POST':
        answer = request.form.get('answer', '')
        if answer == "IndiaSafe2025":
            next_url = "/stego"
    
    return render_template('cipher.html', encrypted=encrypted, next_url=next_url)

@app.route('/stego', methods=['GET', 'POST'])
def stego():
    # Final target message that we want the user to obtain after the full decoding chain
    final_message = "You are the SAVIOUR!!!"

    # One-time pad (this should match the pad stored in the image comment/metadata)
    # NOTE: pad length must equal final_message length after the chosen intermediate step
    pad = "ABCDEFGHIJKLMNOPQRSTUV"  # 22 chars to match "You are the SAVIOUR!!!"

    # Helper: Caesar cipher (works with negative shifts too)
    def caesar_shift(text, shift):
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
                else:
                    result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(char)
        return ''.join(result)

    # --- Desired transformation chain (what the player will do to retrieve the final message):
    # 1) base64 decode the provided blob (so we publish base64 of the XOR-encrypted bytes)
    # 2) XOR-decrypt with the one-time pad
    # 3) apply ROT+8 (Caesar shift +8) to get the final_message
    # To produce data that follows this chain, we must construct the XOR-encrypted bytes as:
    # xor_encrypted = (rot-8(final_message)) XOR pad

    # Step A: compute the intermediate text that, after ROT+8, yields the final message
    intermediate_before_rot = caesar_shift(final_message, -8)

    # Step B: XOR-encrypt that intermediate text with the pad
    xor_encrypted = ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(intermediate_before_rot, pad)])

    # Step C: publish a base64 of the XOR-encrypted bytes (so first step the player does is base64 decode)
    encrypted_flag = base64.b64encode(xor_encrypted.encode()).decode()

    true_flag = "CYS{CY5C0M_SAV3S_!ND1@}"

    return render_template('stego.html', encrypted_flag=encrypted_flag, pad=pad)

@app.route('/final', methods=['POST'])
def final():
    user_flag = request.form.get('flag', '').strip()
    true_flag = "CYS{CY5C0M_SAV3S_!ND1@}"
    
    if user_flag == "You are the SAVIOUR!!!":
        return jsonify({'success': True, 'flag': true_flag})
    else:
        return jsonify({'success': False, 'message': 'Incorrect message'})

if __name__ == '__main__':
    app.run(debug=True)
