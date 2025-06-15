# sms_wifi_manager.py
import serial
import time
import subprocess
import re
import os
import logging

SERIAL_PORT = "/dev/ttyUSB2"
BAUDRATE = 115200
AUTHORIZED_NUMBERS_FILE = "/etc/smswifi/authorized_numbers.txt"
ADMIN_NUMBERS_FILE = "/etc/smswifi/admin_numbers.txt"
MIN_PASSWORD_LENGTH = 8

LOG_FILE = "/var/log/smswifi.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# 初始化串口
ser = serial.Serial(SERIAL_PORT, BAUDRATE, timeout=3)
logging.info("串口初始化完成")

def send_at(cmd, delay=1):
    logging.debug(f"发送AT命令: {cmd}")
    ser.write((cmd + '\r').encode())
    time.sleep(delay)
    response = ser.read_all().decode(errors='ignore')
    logging.debug(f"AT响应: {response.strip()}")
    return response

def send_sms(number, text):
    logging.info(f"发送短信至 {number}: {text}")
    send_at('AT+CMGF=1')
    send_at(f'AT+CMGS="{number}"')
    ser.write(text.encode() + b"\x1A")  # Ctrl+Z
    time.sleep(3)

def parse_sms_command(text):
    text = text.strip()
    if not text.lower().startswith("setwifi#"):
        return None, None
    parts = text.split("#")
    if len(parts) >= 4:
        ssid = parts[1]
        passwd = parts[2]
        return ssid, passwd
    return None, None

def update_wifi_config(ssid, password):
    logging.info(f"更新WiFi配置: SSID={ssid}")
    subprocess.run(['uci', 'set', f'wireless.@wifi-iface[0].ssid={ssid}'], check=True)
    subprocess.run(['uci', 'set', f'wireless.@wifi-iface[0].key={password}'], check=True)
    subprocess.run(['uci', 'commit', 'wireless'], check=True)
    subprocess.run(['wifi'], check=True)
    logging.info("WiFi配置已应用")

def load_number_file(path):
    numbers = set()
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                number = line.split("#")[0].strip()
                if number:
                    numbers.add(number)
    except Exception as e:
        logging.warning(f"无法读取 {path}: {e}")
    return numbers

def add_authorized_number(new_number):
    nums = load_number_file(AUTHORIZED_NUMBERS_FILE)
    if new_number in nums:
        return f"{new_number} exist"
    with open(AUTHORIZED_NUMBERS_FILE, "a") as f:
        f.write(new_number + "\n")
    logging.info(f"添加授权号码: {new_number}")
    return f"{new_number} success"

def delete_authorized_number(del_number):
    nums = load_number_file(AUTHORIZED_NUMBERS_FILE)
    if del_number not in nums:
        return f"{del_number} not exist"
    with open(AUTHORIZED_NUMBERS_FILE, "w") as f:
        for n in nums:
            if n != del_number:
                f.write(n + "\n")
    logging.info(f"删除授权号码: {del_number}")
    return f"{del_number} success"

def process_setwifi(sender, content):
    ssid, passwd = parse_sms_command(content)
    if not ssid or not passwd:
        send_sms(sender, "Template: setwifi#SSID#PASS#")
    elif len(passwd) < MIN_PASSWORD_LENGTH:
        send_sms(sender, f"Password must be {MIN_PASSWORD_LENGTH} or more letters")
    else:
        try:
            update_wifi_config(ssid, passwd)
            send_sms(sender, f"Set WiFi OK\nSSID={ssid}")
        except Exception as e:
            logging.error(f"Set WiFi fail: {e}")
            send_sms(sender, f"Set WiFi fail: {str(e)}")

def check_sms():
    send_at('AT+CMGF=1')
    response = send_at('AT+CMGL="REC UNREAD"', delay=2)

    messages = re.findall(r'\+CMGL: (\d+),.*?,"(.+?)",.*\n(.*?)\r\n', response)
    for index, sender, content in messages:
        content = content.strip()
        logging.info(f"接收到短信：来自 {sender} 内容: {content}")

        admin_numbers = load_number_file(ADMIN_NUMBERS_FILE)
        authorized_numbers = load_number_file(AUTHORIZED_NUMBERS_FILE)

        if sender in admin_numbers:
            lower = content.lower()
            if lower.startswith("addauth#"):
                number = content.split("#")[1].strip()
                msg = add_authorized_number(number)
                send_sms(sender, f"[Add] {msg}")
            elif lower.startswith("delauth#"):
                number = content.split("#")[1].strip()
                msg = delete_authorized_number(number)
                send_sms(sender, f"[Del] {msg}")
            elif lower.startswith("listauth#"):
                nums = load_number_file(AUTHORIZED_NUMBERS_FILE)
                send_sms(sender, "[List]\n" + ("\n".join(nums) or "无"))
            elif lower.startswith("setwifi#"):
                process_setwifi(sender, content)
            else:
                send_sms(sender, "Unknown instructions")

        elif sender in authorized_numbers:
            if content.lower().startswith("setwifi#"):
                process_setwifi(sender, content)
            else:
                send_sms(sender, "Invalid instructions")
        else:
            logging.info(f"Not authorized number: {sender}")

        send_at(f"AT+CMGD={index}")

if __name__ == '__main__':
    logging.info("短信守护进程启动")
    while True:
        try:
            check_sms()
        except Exception as e:
            logging.error(f"运行时异常: {e}")
        time.sleep(10)

