import sys
import yaml
import paramiko
import logging
from logging.handlers import TimedRotatingFileHandler
import smtplib
from email.mime.text import MIMEText
import subprocess
import time
import datetime

# Класс для представления устройства в сети
class Device:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.is_accessible = False

    # Настраиваем устройство для ответов на ICMP запросы
    def configure_device(self, logger):
        # Файл лога для записи активности SSH
        paramiko_log_file = f"paramiko-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.log"
        paramiko.util.log_to_file(paramiko_log_file)

        # Создаем SSH клиент
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        shell = None

        try:
            # Подключаемся к устройству
            ssh_client.connect(self.ip, username=self.username, password=self.password, allow_agent=False, look_for_keys=False)
            shell = ssh_client.invoke_shell()

            # Команды для настройки устройства
            commands = [
                'conf t\n',
                'no ip icmp rate-limit unreachable\n',
                'end\n',
                'write memory\n'
            ]

            # Отправляем команды на устройство
            for command in commands:
                shell.send(command)
                time.sleep(1)

            # Читаем вывод команд
            output = shell.recv(65535).decode()
            logger.record(f"Configuration output for {self.ip}:\n{output}", "info")
            self.is_accessible = True
            logger.record(f"Device {self.ip} configured for ICMP responses.", "info")

        except paramiko.ssh_exception.NoValidConnectionsError as e:
            logger.record(f"Could not connect to device {self.ip}: {e}", "error")
            self.is_accessible = False
        except paramiko.AuthenticationException:
            logger.record(f"Authentication failed for device {self.ip}. Please check the username/password.", "error")
            self.is_accessible = False
        except paramiko.SSHException as e:
            logger.record(f"Error occurred during SSH communication with device {self.ip}: {e}", "error")
            self.is_accessible = False
        except Exception as e:
            logger.record(f"An unexpected error occurred while configuring device {self.ip}: {e}", "error")
            self.is_accessible = False
        finally:
            # Закрываем соединения
            if shell:
                shell.close()
            if ssh_client:
                ssh_client.close()

# Управляет группой устройств и проверяет их доступность
class DeviceManager:
    def __init__(self, devices, max_failures, notification_manager, logger):
        self.devices = devices
        self.max_failures = max_failures
        self.notification_manager = notification_manager
        self.logger = logger
        self.failures = {device.ip: 0 for device in devices}
        self.successful_pings = {device.ip: 0 for device in devices}

    # Проверяем доступность устройств
    def check_devices(self):
        for device in self.devices:
            monitor = ICMPMonitor(device, self.logger)
            result = monitor.monitor()
            if result:
                self.successful_pings[device.ip] += 1
                if self.successful_pings[device.ip] >= 3:
                    self.logger.record(f"Device {device.ip} has responded to ICMP ping 3 times consecutively. Exiting program.", "info")
                    sys.exit(0)
                self.failures[device.ip] = 0
            else:
                self.failures[device.ip] += 1
                self.successful_pings[device.ip] = 0
                self.logger.record(f"Device {device.ip} is not accessible! Failure count: {self.failures[device.ip]}", "warning")
                if self.failures[device.ip] >= self.max_failures:
                    if self.notification_manager.send_notification(device.ip):
                        sys.exit(0)

# Мониторинг устройства с использованием ICMP пинга
class ICMPMonitor:
    def __init__(self, device, logger):
        self.device = device
        self.logger = logger

    # Пингует устройство
    def ping_device(self):
        response = subprocess.run(["ping", "-n", "1", self.device.ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return response.returncode == 0

    # Мониторит доступность устройства
    def monitor(self):
        if not self.device.is_accessible:
            self.logger.record(f"Device {self.device.ip} is not configured for ICMP responses.", "error")
            return False
        result = self.ping_device()
        self.logger.record(f"{self.device.ip} - {'Available' if result else 'Not available'}", "info")
        return result

# Управляет уведомлениями
class NotificationManager:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    # Отправляет уведомление о недоступности устройства
    def send_notification(self, ip):
        subject = "Network Device Monitoring Alert"
        message = f"Device {ip} is not accessible!"
        mail_sender = MailSender(self.config, self.logger)
        success = mail_sender.send_mail(subject, message)
        if success:
            self.logger.record("Notification sent successfully", "info")
        else:
            self.logger.record(f"Failed to send notification for {ip}", "error")
            print(f"Critical error: Unable to send notification for device {ip}. Exiting.")
            sys.exit(1)
        return success

# Класс для логирования
class Logger:
    def __init__(self, log_path):
        self.logger = logging.getLogger('DeviceMonitorLogger')
        self.logger.setLevel(logging.INFO)

        # Уникальное имя файла лога с датой и временем
        unique_log_file = f"{log_path}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.log"

        # Устанавливаем обработчик для ротации файла лога
        handler = TimedRotatingFileHandler(unique_log_file, when="midnight", interval=1, backupCount=7)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.validate_log_path(unique_log_file)

    # Записываем сообщение в лог
    def record(self, message, level="info"):
        level = level.lower()
        if hasattr(self.logger, level):
            getattr(self.logger, level)(message)
        else:
            self.logger.error(f"Logging level not recognized: {level}. Message was: {message}")

    # Проверяем, доступен ли путь для записи лога
    def validate_log_path(self, log_path):
        try:
            with open(log_path, 'a') as test_write:
                pass
        except IOError as e:
            print(f"Error: The log path '{log_path}' is not writable: {e}")
            sys.exit(1)

# Класс для отправки уведомлений по электронной почте
class MailSender:
    def __init__(self, config, logger):
        self.smtp_server = config['smtp_server']
        self.smtp_port = config['smtp_port']
        self.sender_email = config['sender_email']
        self.sender_password = config['sender_password']
        self.recipient_email = config['recipient_email']
        self.logger = logger

    # Отправляем электронное письмо
    def send_mail(self, subject, body):
        message = MIMEText(body)
        message['From'] = self.sender_email
        message['To'] = self.recipient_email
        message['Subject'] = subject

        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.sendmail(self.sender_email, self.recipient_email, message.as_string())
            server.quit()
            return True
        except Exception as e:
            self.logger.record(f"Failed to send mail: {e}", "error")
            return False

# Загрузчик конфигурации
class ConfigLoader:
    @staticmethod
    def load_config(file_path):
        with open(file_path, "r") as f:
            return yaml.safe_load(f)

# Точка входа в программу
if __name__ == "__main__":
    try:
        # Загружаем конфигурацию
        config = ConfigLoader.load_config("config.yaml")
    except Exception as e:
        print(f"Failed to load configuration: {e}")
        sys.exit(1)

    # Инициализация объекта логгера с путем, указанным в конфигурации
    logger = Logger(config["log_path"])

    try:
        devices = [Device(**device) for device in config["devices"]]
        notification_manager = NotificationManager(config, logger)
        device_manager = DeviceManager(devices, config["max_failures"], notification_manager, logger)

        # Конфигурирование каждого устройства
        for device in devices:
            device.configure_device(logger)

        # Цикл для мониторинга устройств
        while True:
            device_manager.check_devices()
            time.sleep(config["monitoring_interval"])
    except Exception as e:
        logger.record(f"An unexpected error occurred: {e}", "error")
