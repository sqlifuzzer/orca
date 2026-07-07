from flask import Flask, request, abort, redirect
from base64 import b64decode
from Crypto.Cipher import AES
import time

# This code is heavily based upon Padex:
# https://github.com/dszakallas/padex

app = Flask(__name__)

key32 = "VHFwdTJlZkx4SkxVbjNYSlE0cmJ6VzlHNWdVMjd2OWU="
iv16 = "WkJNQVZGbkU3OXVCQU5TVg=="

key = b64decode(key32)
iv = b64decode(iv16)

time_delay = 0.05

status_based = False                    # 01 status code will change for successful decrypt
time_based_success_delay = False        # 02 time delay will occur on successful decrypt, not on error
time_based_error_delay = False          # 03 time delay will occur on error, not on successful decrypt
length_based_success_longer = False     # 04 length will increase by 10 on successful decrypt
length_based_success_shorter = False    # 05 length will decrease by 10 on successful decrypt
length_based_error_longer = False       # 06 length will increase by 10 on error
length_based_error_shorter = False      # 07 length will decrease by 10 on error
error_word_error = False                # 08 response will include the word ERROR on error
custom_word_error = False               # 09 response will include a custom word (PADDING) on error
custom_word_success = True             # 10 response will include a custom word on success
location_difference = False              # 11 return 302 redirect with different locations for success and error

encoding = "base64"

def error_handling():
    if status_based:
        return abort(400)                                           # 01
    if time_based_error_delay:
        time.sleep(time_delay)
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 02
    if time_based_success_delay:
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 03
    if length_based_success_longer:
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 04
    if length_based_success_shorter:
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 05
    if length_based_error_longer:
        return '!!! ERROR !!! ER  !!! ERROR !!! !!! ERROR !', 200   # 06
    if length_based_error_shorter:
        return 'E', 200                                            # 07
    if error_word_error:
        return 'OK ALL ERROR   NOMINAL', 200                        # 08
    if custom_word_error:
        return 'BLAHS PADDING PADDING!', 200                        # 09
    if custom_word_success:
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 10
    if location_difference:
        return redirect('/error01', code=302)               # 11

def success_handling():
    if status_based:
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 01
    if time_based_error_delay:
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 02
    if time_based_success_delay:
        time.sleep(time_delay)
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 03
    if length_based_success_longer:
        return 'OK ALL SYSTEMS NOMINAL SYSTEMS NOMINAL !!!!', 200   # 04
    if length_based_success_shorter:
        return 'O', 200                                            # 05
    if length_based_error_longer:
        return 'OK ALL ERRORS NOMINAL ', 200                        # 06
    if length_based_error_shorter:
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 07
    if error_word_error:
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 08
    if custom_word_error:
        return 'OK ALL SYSTEMS NOMINAL', 200                        # 09
    if custom_word_success:
        return 'OK ALL PADDING NOMINAL', 200                        # 10
    if location_difference:
        return redirect('/success', code=302)               # 11

def decrypt(ciphertext):

    if encoding == "base64":
        data = b64decode(ciphertext.replace(' ', '+'))
    else:
        data = ciphertext

    aes = AES.new(key, AES.MODE_CBC, IV=iv)
    mess = aes.decrypt(data)
    pad_size = mess[-1]

    if pad_size < 1 or pad_size > 16:
        res = error_handling()
        return res

    for x in mess[-pad_size:-1]:
        if x != pad_size:
            res = error_handling()
            return res

    # success
    res = success_handling()
    return res
@app.route('/')
def landing():
    html = ("""
            <html>
            <h1>Vulnerable Padding Oracle Application</h1>
            <br>
            <a href="/query-decrypt?msg=/LA0Us7iIXaxTid25gdlIePo8MHYgeBexPGCByF5R8SnrJ4KdTXl/I5SdHQnIS/K2MpuZ+oYBxvnLY5UuAqDDA==">GET Query Decrypt</a>
            <br>
            <a href="/form-decrypt"> POST Body Decrypt</a>
            <br>
            <a href="/json-decrypt"> POST JSON Decrypt</a>                        
            </html>
            """)
    return html

@app.route('/query-decrypt', methods=['GET'])
def query_decrypt():
    html = """
                <html>
                <h1>Vulnerable Padding Oracle Application - GET Query Decrypt</h1>
                <br>
                <a href="/">Home</a>
                <br>
                <a href="/form-decrypt"> POST Body Decrypt</a>
                <br>
                <a href="/json-decrypt"> POST JSON Decrypt</a>                        
                </html>
                """
    if request.args.get('msg'):
        data = request.args.get('msg')
        output = decrypt(data)
        return output
    else:
        return html

@app.route('/form-decrypt', methods=['GET', 'POST'])
def form_decrypt():
    html = """
                <html>
                    <h1>Vulnerable Padding Oracle Application - POST Body Decrypt</h1>
                    <br>
                    <a href="/">Home</a>
                    <br>
                    <a href="/query-decrypt?msg=/LA0Us7iIXaxTid25gdlIePo8MHYgeBexPGCByF5R8SnrJ4KdTXl/I5SdHQnIS/K2MpuZ+oYBxvnLY5UuAqDDA==">GET Query Decrypt</a>
                    <br>
                    <a href="/json-decrypt"> POST JSON Decrypt</a>  
                    <br>
                    <form method="POST">
                        <input type="text" value="/LA0Us7iIXaxTid25gdlIePo8MHYgeBexPGCByF5R8SnrJ4KdTXl/I5SdHQnIS/K2MpuZ+oYBxvnLY5UuAqDDA==" name="msg"/>
                        <br>
                        <input type="submit" value="Submit">
                    </form>                    
                </html>
                """
    if request.method == 'POST':
        if request.form.get('msg'):
            encoded_data = request.form.get('msg')
            data = encoded_data.replace('%3d', '=').replace('%3D', '=').replace('%2b', '+').replace('%2B', '+')
            output = decrypt(data)
            return output
        else:
            return html
    else:
        return html

@app.route('/json-decrypt', methods=['GET', 'POST'])
def json_decrypt():
    html = """
        <html>
        <h1>Vulnerable Padding Oracle Application - POST JSON Decrypt</h1>
        <script>
        function doPost() {
            data = {"msg":"/LA0Us7iIXaxTid25gdlIePo8MHYgeBexPGCByF5R8SnrJ4KdTXl/I5SdHQnIS/K2MpuZ+oYBxvnLY5UuAqDDA=="}
            fetch(`/json-decrypt`, {
                method: "POST",                    
                headers: {
                "Content-Type": "application/json",
                },
                body: JSON.stringify(data), 
            })
            .then(response => {
                console.log(response);
            });
        } 
        </script>
        <br>
        <a href="/">Home</a>
        <br>
        <a href="/form-decrypt"> POST Body Decrypt</a>
        <br>
        <a href="/query-decrypt?msg=/LA0Us7iIXaxTid25gdlIePo8MHYgeBexPGCByF5R8SnrJ4KdTXl/I5SdHQnIS/K2MpuZ+oYBxvnLY5UuAqDDA==">GET Query Decrypt</a>
        <br>
        <button onclick="doPost()">Send JSON</button>                       
        </html>
    """
    if request.method == 'POST':
        request_data = request.get_json()
        if request_data:
            if 'msg' in request_data:
                msg = request_data['msg']
                output = decrypt(msg)
                return output
            else:
                return html
        else:
            return html
    else:
        return html

@app.route('/error01')
def error01():
    html = ("""
            <html>
            <h1>Vulnerable Padding Oracle Application</h1>
            <br>
            <h1>An error has occurred!</h1>
            <br>
            <a href="/query-decrypt?msg=/LA0Us7iIXaxTid25gdlIePo8MHYgeBexPGCByF5R8SnrJ4KdTXl/I5SdHQnIS/K2MpuZ+oYBxvnLY5UuAqDDA==">GET Query Decrypt</a>
            <br>
            <a href="/form-decrypt"> POST Body Decrypt</a>
            <br>
            <a href="/json-decrypt"> POST JSON Decrypt</a>                        
            </html>
            """)
    return html

@app.route('/success')
def success():
    html = ("""
            <html>
            <h1>Vulnerable Padding Oracle Application</h1>
            <br>
            <h1>Success!</h1>
            <br>
            <a href="/query-decrypt?msg=/LA0Us7iIXaxTid25gdlIePo8MHYgeBexPGCByF5R8SnrJ4KdTXl/I5SdHQnIS/K2MpuZ+oYBxvnLY5UuAqDDA==">GET Query Decrypt</a>
            <br>
            <a href="/form-decrypt"> POST Body Decrypt</a>
            <br>
            <a href="/json-decrypt"> POST JSON Decrypt</a>                        
            </html>
            """)
    return html

if __name__ == '__main__':
    # run app in debug mode on port 8989
    app.run(port=8989)
