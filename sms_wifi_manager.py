#!/usr/bin/env python3
"""
短信检测守护程序 - 增强日志与安全防护版
功能：通过串口检测短信，执行WiFi配置更新和授权号码管理
安全增强：输入验证、日志轮转、异常处理
日志增强：多级别日志、详细上下文、异常堆栈
"""
import serial
import time
import subprocess
import re
import os
import logging
import logging.handlers
from datetime import datetime

# ==================== 安全配置 ====================
SERIAL_PORT = "/dev/ttyUSB2"
BAUDRATE = 115200
AUTHORIZED_NUMBERS_FILE = "/etc/smswifi/authorized_numbers.txt"
ADMIN_NUMBERS_FILE = "/etc/smswifi/admin_numbers.txt"
MIN_PASSWORD_LENGTH = 8
MAX_SSID_LENGTH = 32
MAX_PASSWORD_LENGTH = 64

# ==================== 高级日志配置 ====================
LOG_FILE = "/var/log/smswifi.log"
logger = logging.getLogger("SMSWiFiManager")
logger.setLevel(logging.DEBUG)  # 开发时使用DEBUG，生产环境改为INFO

# 创建带轮转的文件处理器（防止日志过大）
file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, 
    maxBytes=5 * 1024 * 1024,  # 5MB
    backupCount=3
)
file_handler.setLevel(logging.DEBUG)

# 控制台处理器（仅显示警告及以上）
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# 日志格式（添加模块名和函数名）
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)-8s] %(name)s:%(funcName)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ==================== 安全初始化 ====================
def secure_file_permissions():
    """设置关键文件的安全权限"""
    try:
        os.chmod(AUTHORIZED_NUMBERS_FILE, 0o600)
        os.chmod(ADMIN_NUMBERS_FILE, 0o600)
        os.chmod(LOG_FILE, 0o640)
        logger.info("关键文件权限已加固")
    except Exception as e:
        logger.error(f"文件权限设置失败: {e}", exc_info=True)

# ==================== 核心功能 ====================
def init_serial():
    """安全初始化串口连接"""
    try:
        ser = serial.Serial(SERIAL_PORT, BAUDRATE, timeout=3)
        logger.info(f"串口初始化成功: {SERIAL_PORT}@{BAUDRATE}")
        return ser
    except serial.SerialException as e:
        logger.critical(f"串口初始化失败: {e}", exc_info=True)
        raise

ser = init_serial()

# 增强AT指令稳定性
def send_at(cmd, delay=1):
    """发送AT命令并记录详细日志"""
    try:
        logger.debug(f"发送AT命令: {cmd}")
        ser.write((cmd + '\r').encode())
        time.sleep(delay)
        response = ser.read_all().decode(errors='ignore')
        logger.debug(f"AT响应: {response.strip()}")
        if "ERROR" in response:
            logger.warning(f"AT指令错误: {cmd} -> {response.strip()}")
        return response
    except serial.SerialException as e:
        logger.critical(f"串口异常: {e}", exc_info=True)
        reconnect_serial()  # 自动重连串口

def reconnect_serial():
    global ser
    try:
        ser.close()
        ser = serial.Serial(SERIAL_PORT, BAUDRATE, timeout=3)
        logger.info("串口已重新连接")
    except Exception as e:
        logger.error(f"串口重连失败: {e}")

def send_sms(number, text):
    """发送短信"""
    try:
        # 记录号码和内容
        logger.info(f"短信发送: 至 {number} | 内容: {text}")

        # 短信发送
        send_at('AT+CMGF=1')
        send_at(f'AT+CMGS="{number}"')
        ser.write(text.encode() + b"\x1A")  # Ctrl+Z
        time.sleep(2)
        return True
    except Exception as e:
        logger.error(f"短信发送失败: {e}", exc_info=True)
        return False

# ==================== 输入验证与安全处理 ====================
def validate_number(number):
    """验证电话号码格式"""
    return re.match(r'^\+?[1-9]\d{4,14}$', number) is not None

def validate_ssid(ssid):
    """验证SSID安全性"""
    if len(ssid) > MAX_SSID_LENGTH:
        return False
    # 防止命令注入
    return not any(char in ssid for char in [';', '&', '|', '$', '`'])

def validate_password(password):
    """验证密码安全性"""
    return (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH and 
            not any(char in password for char in ['"', "'", '\\']))

def parse_sms_command(text):
    """解析短信命令（添加严格验证）"""
    text = text.strip()
    if not text.lower().startswith("setwifi#"):
        return None, None

    parts = text.split("#")
    if len(parts) < 4:
        return None, None

    ssid = parts[1].strip()
    passwd = parts[2].strip()

    # 安全验证
    if not validate_ssid(ssid) or not validate_password(passwd):
        logger.warning(f"无效的SSID或密码: SSID={ssid[:5]}..., Pass={passwd[:2]}...")
        return None, None

    return ssid, passwd

# ==================== 系统操作 ====================
def update_wifi_config(ssid, password):
    """更新WiFi配置（带操作验证）"""
    try:
        logger.info(f"更新WiFi配置: SSID={ssid[:5]}...")

        # 使用安全参数传递
        subprocess.run(
            ['uci', 'set', f'wireless.@wifi-iface[0].ssid={ssid}'],
            check=True,
            shell=False
        )
        subprocess.run(
            ['uci', 'set', f'wireless.@wifi-iface[0].key={password}'],
            check=True,
            shell=False
        )
        subprocess.run(['uci', 'commit', 'wireless'], check=True, shell=False)
        subprocess.run(['wifi'], check=True, shell=False)

        logger.info("WiFi配置已成功应用")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"WiFi配置失败 [exit:{e.returncode}]: {e.cmd}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"未知配置错误: {e}", exc_info=True)
        return False

# ==================== 授权管理 ====================
def load_number_file(path):
    """加载号码文件（带格式验证）"""
    numbers = set()
    try:
        if not os.path.exists(path):
            logger.warning(f"文件不存在: {path}")
            return numbers

        with open(path, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                number = line.split("#")[0].strip()
                if validate_number(number):
                    numbers.add(number)
                else:
                    logger.warning(f"文件{path}第{line_num}行包含无效号码: {number}")
        return numbers
    except Exception as e:
        logger.error(f"读取号码文件失败: {path} - {e}", exc_info=True)
        return set()

def modify_number_file(path, operation, number):
    """安全修改号码文件"""
    if not validate_number(number):
        return "invalid_number"

    try:
        numbers = load_number_file(path)
        changed = False

        if operation == "add":
            if number in numbers:
                return "exists"
            numbers.add(number)
            changed = True
        elif operation == "del":
            if number not in numbers:
                return "not_exist"
            numbers.remove(number)
            changed = True

        if changed:
            # 原子写入：先写入临时文件再重命名
            temp_path = f"{path}.tmp"
            with open(temp_path, "w") as f:
                for num in sorted(numbers):
                    f.write(f"{num}\n")
            os.replace(temp_path, path)
            return "success"

        return "no_change"
    except Exception as e:
        logger.error(f"{operation}操作失败: {e}", exc_info=True)
        return "error"

# ==================== 短信处理 ====================
def process_setwifi(sender, content):
    """处理设置WiFi请求"""
    ssid, passwd = parse_sms_command(content)
    if not ssid or not passwd:
        send_sms(sender, "Template: setwifi#SSID#PASSWORD#")
        return

    try:
        if update_wifi_config(ssid, passwd):
            send_sms(sender, f"WiFi update success\nSSID:{ssid[:10]}...")
        else:
            send_sms(sender, "WiFi update fail")
    except Exception as e:
        logger.error(f"处理SetWifi异常: {e}", exc_info=True)
        send_sms(sender, "wifi update exception")

def process_admin_command(sender, content):
    """处理管理员命令"""
    lower = content.lower()
    response = ""

    if lower.startswith("addauth#"):
        parts = content.split("#")
        if len(parts) >= 2:
            number = parts[1].strip()
            result = modify_number_file(AUTHORIZED_NUMBERS_FILE, "add", number)
            response = f"add: {number} {result}"
    elif lower.startswith("delauth#"):
        parts = content.split("#")
        if len(parts) >= 2:
            number = parts[1].strip()
            result = modify_number_file(AUTHORIZED_NUMBERS_FILE, "del", number)
            response = f"del: {number} {result}"
    elif lower.startswith("listauth"):
        nums = load_number_file(AUTHORIZED_NUMBERS_FILE)
        response = "list:\n" + "\n".join(nums) or "none"
    elif lower.startswith("setwifi#"):
        process_setwifi(sender, content)
        return

    if response:
        send_sms(sender, response[:160])  # 限制短信长度

def get_sms_storage():
    """查询当前短信存储位置"""
    response = send_at('AT+CPMS?')
    match = re.search(r'\+CPMS: \"([SME]{2})\"', response)
    if match:
        return match.group(1)  # 返回当前存储区标识（如"ME"）
    return None

def switch_storage():
    # 步骤1：查询当前存储位置
    current_storage = get_sms_storage()
    if not current_storage:
        logger.info(f"❌ 无法获取存储位置，请检查设备状态")
        return
    # 步骤2：切换到目标存储（如Modem内部存储"ME"）
    if current_storage =="ME":
        target_storage = "SM"
    else:
        target_storage = "ME"
    """切换到目标短信存储位置"""
    response = send_at(f'AT+CPMS="{target_storage}"')
    return any("OK" in line for line in response)


# ==================== 主循环 ====================
def process_messages(messages):
    processed_count = 0
    for index, status, sender, content in messages:
        content = content.strip()
        logger.info(f"处理短信 [状态:{status}] 发件人:{sender} 内容:{content[:20]}...")

        # 加载权限列表
        admin_numbers = load_number_file(ADMIN_NUMBERS_FILE)
        authorized_numbers = load_number_file(AUTHORIZED_NUMBERS_FILE)

        # 权限检查
        if sender in admin_numbers:
            logger.debug(f"管理员指令: {content[:20]}...")
            process_admin_command(sender, content)
        elif sender in authorized_numbers:
            logger.debug(f"授权用户指令: {content[:20]}...")
            if content.lower().startswith("setwifi#"):
                process_setwifi(sender, content)
            else:
                send_sms(sender, "Invalid instruction")
        else:
            logger.warning(f"未授权号码: {sender}")
            # 可选：记录但忽略或发送拒绝消息

        # 删除已处理短信

        time.sleep(3)
        send_at(f"AT+CMGD={index}")
        # sometime delete ok,but fail in fact,switch to ME delete again
        switch_storage()
        send_at(f"AT+CMGD={index}")

        processed_count += 1
    return processed_count


def check_sms():
    """检查并处理新短信"""
    try:
        # 检查未读短信
        send_at('AT+CMGF=1')
        response = send_at('AT+CMGL="REC UNREAD"', delay=2)
        logger.info(response)
        # 解析短信
        messages = re.findall(r'\+CMGL: (\d+),\"(.+?)\",\"(.+?)\",.*\n(.*?)\r\n', response)
	# sometime can't receive unread sms, retry receive read sms
        if len(messages)< 1:
#            switch_storage()
            response = send_at('AT+CMGL="REC READ"', delay=2)
            logger.info(response)
            messages = re.findall(r'\+CMGL: (\d+),\"(.+?)\",\"(.+?)\",.*\n(.*?)\r\n', response)
#            send_at('AT+CPMS?')
        process_messages(messages)
    except Exception as e:
        logger.error(f"短信处理循环异常: {e}", exc_info=True)

def process_all_sms():
    """全量扫描并处理所有短信（包括已读/未读）"""
    try:
        logger.info("开始全量扫描短信...")
        response = send_at('AT+CMGL="ALL"', delay=5)  # 延长等待时间确保完整返回
        logger.info(response)

        # 解析所有短信（格式：索引,状态,号码,内容）
        messages = re.findall(r'\+CMGL: (\d+),\"(.+?)\",\"(.+?)\",.*\n(.*?)\r\n', response)
        logger.info(messages)
        processed_count = process_messages(messages)
        logger.info(f"全量扫描完成，共处理 {processed_count} 条未读短信")
    except Exception as e:
        logger.error(f"全量扫描异常: {e}", exc_info=True)

# 主循环（双重检测机制）
if __name__ == '__main__':
    last_full_scan = 0  # 上次全量扫描时间戳
    SCAN_INTERVAL = 60   # 全量扫描间隔（秒）

    while True:
        try:
            current_time = time.time()
            # 条件1：每30秒触发全量扫描
            if current_time - last_full_scan >= SCAN_INTERVAL:
                process_all_sms()
                last_full_scan = current_time

            # 条件2：持续检查新短信（高频但低负载）
            check_sms()
            time.sleep(10)  # 新短信检测间隔

        except Exception as e:
            logger.critical(f"主循环异常: {e}", exc_info=True)
            time.sleep(30)  # 异常时延长等待


