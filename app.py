from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, session
import sqlite3
import socket
import threading
import time
import datetime
import io
import csv
import pytz
import os
import requests
import json
import subprocess
import platform
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps

app = Flask(__name__)
app.secret_key = 'secret_key_for_tps_monitoring_system'

VALID_USERNAME = "TPS"
VALID_PASSWORD = "S3cur3M0n1t0r1ngP@$$w0rd!"

DATABASE = 'network_monitoring.db'

iran_timezone = pytz.timezone('Asia/Tehran')

GATEWAYS = {
    'gw1': '172.18.63.41',
    'gw2': '172.18.63.42',
    'gw3': '172.18.63.43',
    'gw4': '172.18.63.44',
    'gw5': '172.18.63.45',
    'gw6': '172.18.63.46'
}

CLIENTS = {
    'gw1': [
        {'name': 'gw1-c1', 'ip': '172.18.64.41', 'plc_ip': '172.18.64.51'},
        {'name': 'gw1-c2', 'ip': '172.18.64.42', 'plc_ip': '172.18.64.52'},
        {'name': 'gw1-c3', 'ip': '172.18.64.43', 'plc_ip': '172.18.64.53'},
        {'name': 'gw1-c4', 'ip': '172.18.64.44', 'plc_ip': '172.18.64.54'},
        {'name': 'gw1-c5', 'ip': '172.18.64.45', 'plc_ip': '172.18.64.55'}
    ],
    'gw2': [
        {'name': 'gw2-c1', 'ip': '172.18.65.41', 'plc_ip': '172.18.65.51'},
        {'name': 'gw2-c2', 'ip': '172.18.65.42', 'plc_ip': '172.18.65.52'},
        {'name': 'gw2-c3', 'ip': '172.18.65.43', 'plc_ip': '172.18.65.53'},
        {'name': 'gw2-c4', 'ip': '172.18.65.44', 'plc_ip': '172.18.65.54'},
        {'name': 'gw2-c5', 'ip': '172.18.65.45', 'plc_ip': '172.18.65.55'}
    ],
    'gw3': [
        {'name': 'gw3-c1', 'ip': '172.18.66.41', 'plc_ip': '172.18.66.51'},
        {'name': 'gw3-c2', 'ip': '172.18.66.42', 'plc_ip': '172.18.66.52'},
        {'name': 'gw3-c3', 'ip': '172.18.66.43', 'plc_ip': '172.18.66.53'},
        {'name': 'gw3-c4', 'ip': '172.18.66.44', 'plc_ip': '172.18.66.54'},
        {'name': 'gw3-c5', 'ip': '172.18.66.45', 'plc_ip': '172.18.66.55'}
    ],
    'gw4': [
        {'name': 'gw4-c1', 'ip': '172.18.67.41', 'plc_ip': '172.18.67.51'},
        {'name': 'gw4-c2', 'ip': '172.18.67.42', 'plc_ip': '172.18.67.52'},
        {'name': 'gw4-c3', 'ip': '172.18.67.43', 'plc_ip': '172.18.67.53'},
    ],
    'gw5': [
        {'name': 'gw5-c1', 'ip': '172.18.68.41', 'plc_ip': '172.18.68.51'},
        {'name': 'gw5-c2', 'ip': '172.18.68.42', 'plc_ip': '172.18.68.52'},
        {'name': 'gw5-c3', 'ip': '172.18.68.43', 'plc_ip': '172.18.68.53'}
    ],
    'gw6': [
        {'name': 'gw6-c1', 'ip': '172.18.69.41', 'plc_ip': '172.18.69.51'},
        {'name': 'gw6-c2', 'ip': '172.18.69.42', 'plc_ip': '172.18.69.52'},
        {'name': 'gw6-c3', 'ip': '172.18.69.43', 'plc_ip': '172.18.69.53'}
    ]
}

EXTERNAL_SERVER = 'http://185.80.196.129:6500'

COLLECT_PERFORMANCE_METRICS = True
PING_TIMEOUT = 1
PING_COUNT = 1
PLC_MAX_LATENCY = 2000
PLC_ACCEPTABLE_LOSS = 60


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == VALID_USERNAME and password == VALID_PASSWORD:
            session['user_id'] = username
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            error = 'نام کاربری یا رمز عبور نادرست است'

    return render_template('login.html', error=error)


# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


def init_db():
    """Initialize database tables if they don't exist"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Device status table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS device_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL,
        device_ip TEXT NOT NULL,
        device_type TEXT NOT NULL,
        parent_gateway TEXT,
        status INTEGER NOT NULL,
        response_time REAL,
        last_checked TIMESTAMP NOT NULL,
        UNIQUE(device_name)
    )
    ''')

    # Status history table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS status_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL,
        device_ip TEXT NOT NULL,
        device_type TEXT NOT NULL,
        parent_gateway TEXT,
        status INTEGER NOT NULL,
        response_time REAL,
        timestamp TIMESTAMP NOT NULL
    )
    ''')

    # PLC status table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS plc_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plc_name TEXT NOT NULL,
        plc_ip TEXT NOT NULL,
        parent_client TEXT NOT NULL,
        parent_gateway TEXT NOT NULL,
        status INTEGER NOT NULL,
        response_time REAL,
        last_checked TIMESTAMP NOT NULL,
        UNIQUE(plc_name)
    )
    ''')

    # PLC history table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS plc_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plc_name TEXT NOT NULL,
        plc_ip TEXT NOT NULL,
        parent_client TEXT NOT NULL,
        parent_gateway TEXT NOT NULL,
        status INTEGER NOT NULL,
        response_time REAL,
        timestamp TIMESTAMP NOT NULL
    )
    ''')

    # Performance metrics table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS performance_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL,
        device_ip TEXT NOT NULL,
        device_type TEXT NOT NULL,
        parent_gateway TEXT,
        response_time REAL,
        packet_loss REAL,
        timestamp TIMESTAMP NOT NULL
    )
    ''')

    # Alerts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL,
        device_ip TEXT NOT NULL, 
        device_type TEXT NOT NULL,
        parent_gateway TEXT,
        alert_type TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        resolved_at TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()


def check_port_80(ip, max_retries=3, timeout=2):
    """Check if port 80 is open on the given IP address"""
    response_time = None
    for attempt in range(max_retries):
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            end_time = time.time()

            if result == 0:
                response_time = (end_time - start_time) * 1000  # in milliseconds
                return True, response_time
            time.sleep(1)
        except:
            pass
    return False, response_time


def check_plc_with_tolerance(plc_ip, timeout=PING_TIMEOUT, count=PING_COUNT, max_retry=2):
    """
    Check PLC connectivity with tolerance for high latency and some packet loss.
    Returns:
        - status (bool): True if PLC is considered online
        - response_time (float): Average response time if available
        - packet_loss (float): Packet loss percentage
        - debug_info (str): Additional debug information
    """
    debug_info = ""

    for attempt in range(max_retry):
        try:
            # Different ping command syntax based on operating system
            if platform.system().lower() == "windows":
                ping_cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), plc_ip]
            else:
                ping_cmd = ["ping", "-c", str(count), "-W", str(timeout), plc_ip]

            # Execute ping command and capture output
            ping_output = subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
            debug_info = f"Attempt {attempt + 1} output: {ping_output[:100]}..."

            # Parse output to extract packet loss and response time
            response_time = None
            packet_loss = None
            received_any = False

            if platform.system().lower() == "windows":
                # Parse Windows ping output
                for line in ping_output.splitlines():
                    if "Average" in line:
                        time_str = line.split("=")[1].strip().replace("ms", "")
                        try:
                            response_time = float(time_str)
                        except ValueError:
                            pass
                    if "Lost" in line:
                        try:
                            loss_part = line.split("(")[1].split("%")[0]
                            packet_loss = float(loss_part)
                        except (IndexError, ValueError):
                            packet_loss = None
                    if "Reply from" in line:
                        received_any = True
            else:
                # Parse Linux/Unix ping output
                for line in ping_output.splitlines():
                    if "min/avg/max" in line:
                        parts = line.split("=")[1].strip().split("/")
                        try:
                            response_time = float(parts[1])  # avg is the second value
                        except (IndexError, ValueError):
                            pass
                    if "packet loss" in line:
                        try:
                            loss_part = line.split(",")[2].strip().split("%")[0]
                            packet_loss = float(loss_part)
                        except (IndexError, ValueError):
                            packet_loss = None
                    if "bytes from" in line:
                        received_any = True

            # Determine status based on packet loss and latency
            status = False

            # If we received any packets, check against thresholds
            if received_any:
                # Consider online if:
                # 1. Packet loss is below threshold OR
                # 2. We received any responses and don't know the packet loss
                if (packet_loss is not None and packet_loss <= PLC_ACCEPTABLE_LOSS) or \
                        (packet_loss is None and received_any):
                    status = True

                # Check latency if applicable
                if status and response_time is not None and response_time > PLC_MAX_LATENCY:
                    debug_info += f" High latency: {response_time}ms > {PLC_MAX_LATENCY}ms threshold"
                    # Still consider it online but note the high latency

            # If we got any meaningful result, return it
            if packet_loss is not None or received_any:
                return status, response_time, packet_loss, debug_info

        except subprocess.CalledProcessError:
            debug_info += f" Ping command failed on attempt {attempt + 1}"
        except Exception as e:
            debug_info += f" Error on attempt {attempt + 1}: {str(e)}"

        # Wait before retry
        time.sleep(1)

    # If all attempts failed
    return False, None, 100.0, debug_info


# Add this logging function to help debug PLC issues
def log_plc_check(plc_name, plc_ip, status, response_time, packet_loss, debug_info):
    """Log detailed information about PLC checks to help with troubleshooting"""
    with open('plc_check_log.txt', 'a') as f:
        timestamp = datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"[{timestamp}] PLC: {plc_name} ({plc_ip}) - Status: {'Online' if status else 'Offline'}, "
                f"Response: {response_time}ms, Loss: {packet_loss}%, Info: {debug_info}\n")


def ping_device(ip, count=PING_COUNT, timeout=PING_TIMEOUT):
    """Ping a device and return status and statistics"""
    try:
        # Different ping command syntax based on operating system
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
        else:
            ping_cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]

        # Execute ping command
        ping_output = subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT, universal_newlines=True)

        # Check if ping was successful
        if "100% packet loss" in ping_output:
            return False, None, 100.0

        # Extract response time (might need refinement based on OS/locale)
        response_time = None
        packet_loss = None

        if platform.system().lower() == "windows":
            # Parse Windows ping output
            for line in ping_output.splitlines():
                if "Average" in line:
                    # Extract average ping time from "Average = 12ms" format
                    time_str = line.split("=")[1].strip().replace("ms", "")
                    try:
                        response_time = float(time_str)
                    except ValueError:
                        pass
                if "Lost" in line:
                    # Extract packet loss percentage
                    try:
                        loss_part = line.split("(")[1].split("%")[0]
                        packet_loss = float(loss_part)
                    except (IndexError, ValueError):
                        packet_loss = None
        else:
            # Parse Linux/Unix ping output
            for line in ping_output.splitlines():
                if "min/avg/max" in line:
                    # Extract average from "min/avg/max" format
                    parts = line.split("=")[1].strip().split("/")
                    try:
                        response_time = float(parts[1])  # avg is the second value
                    except (IndexError, ValueError):
                        pass
                if "packet loss" in line:
                    # Extract packet loss percentage
                    try:
                        loss_part = line.split(",")[2].strip().split("%")[0]
                        packet_loss = float(loss_part)
                    except (IndexError, ValueError):
                        packet_loss = None

        return True, response_time, packet_loss
    except subprocess.CalledProcessError:
        # Ping command failed
        return False, None, 100.0
    except Exception as e:
        print(f"Error pinging {ip}: {str(e)}")
        return False, None, None


def save_status(device_name, device_ip, device_type, parent_gateway, status, response_time=None):
    """Save device status to database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Current timestamp in local timezone
    now = datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')

    # Check previous status
    cursor.execute(
        "SELECT status FROM device_status WHERE device_name = ?",
        (device_name,)
    )
    result = cursor.fetchone()

    previous_status = None
    if result:
        previous_status = result[0]

    # Update device status
    cursor.execute(
        "INSERT OR REPLACE INTO device_status (device_name, device_ip, device_type, parent_gateway, status, response_time, last_checked) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (device_name, device_ip, device_type, parent_gateway, status, response_time, now)
    )

    # Add to history if status changed
    if previous_status is None or previous_status != status:
        cursor.execute(
            "INSERT INTO status_history (device_name, device_ip, device_type, parent_gateway, status, response_time, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (device_name, device_ip, device_type, parent_gateway, status, response_time, now)
        )

        # Create alert for status change
        alert_type = "disconnect" if status == 0 else "reconnect"
        message = f"Device {'disconnected' if status == 0 else 'reconnected'}"

        cursor.execute(
            "INSERT INTO alerts (device_name, device_ip, device_type, parent_gateway, alert_type, message, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (device_name, device_ip, device_type, parent_gateway, alert_type, message,
             "active" if status == 0 else "resolved", now)
        )

        # If device reconnected, resolve any disconnect alerts
        if status == 1:
            cursor.execute(
                "UPDATE alerts SET status = 'resolved', resolved_at = ? WHERE device_name = ? AND alert_type = 'disconnect' AND status = 'active'",
                (now, device_name)
            )

    conn.commit()
    conn.close()


def save_plc_status(plc_name, plc_ip, parent_client, parent_gateway, status, response_time=None):
    """Save PLC status to database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Current timestamp in local timezone
    now = datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')

    # Check previous status
    cursor.execute(
        "SELECT status FROM plc_status WHERE plc_name = ?",
        (plc_name,)
    )
    result = cursor.fetchone()

    previous_status = None
    if result:
        previous_status = result[0]

    # Update PLC status
    cursor.execute(
        "INSERT OR REPLACE INTO plc_status (plc_name, plc_ip, parent_client, parent_gateway, status, response_time, last_checked) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (plc_name, plc_ip, parent_client, parent_gateway, status, response_time, now)
    )

    # Add to history if status changed
    if previous_status is None or previous_status != status:
        cursor.execute(
            "INSERT INTO plc_history (plc_name, plc_ip, parent_client, parent_gateway, status, response_time, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (plc_name, plc_ip, parent_client, parent_gateway, status, response_time, now)
        )

        # Create alert for PLC status change
        alert_type = "plc_disconnect" if status == 0 else "plc_reconnect"
        message = f"PLC {'disconnected' if status == 0 else 'reconnected'}"

        cursor.execute(
            "INSERT INTO alerts (device_name, device_ip, device_type, parent_gateway, alert_type, message, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (plc_name, plc_ip, "plc", parent_gateway, alert_type, message, "active" if status == 0 else "resolved", now)
        )

        # If PLC reconnected, resolve any disconnect alerts
        if status == 1:
            cursor.execute(
                "UPDATE alerts SET status = 'resolved', resolved_at = ? WHERE device_name = ? AND alert_type = 'plc_disconnect' AND status = 'active'",
                (now, plc_name)
            )

    conn.commit()
    conn.close()


def save_performance_metrics(device_name, device_ip, device_type, parent_gateway, response_time, packet_loss):
    """Save performance metrics to database"""
    if not COLLECT_PERFORMANCE_METRICS:
        return

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Current timestamp
    now = datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')

    # Save metrics
    cursor.execute(
        "INSERT INTO performance_metrics (device_name, device_ip, device_type, parent_gateway, response_time, packet_loss, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (device_name, device_ip, device_type, parent_gateway, response_time, packet_loss, now)
    )

    conn.commit()
    conn.close()


def check_all_devices():
    """Check status of all gateways, clients, and PLCs"""
    print(f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Checking all devices...")

    # Check all gateways
    for gw_name, gw_ip in GATEWAYS.items():
        status, response_time = check_port_80(gw_ip)
        save_status(gw_name, gw_ip, 'gateway', None, 1 if status else 0, response_time)

        # For performance metrics, ping the device too
        if COLLECT_PERFORMANCE_METRICS:
            ping_status, ping_time, packet_loss = ping_device(gw_ip)
            if ping_status:
                save_performance_metrics(gw_name, gw_ip, 'gateway', None, ping_time, packet_loss)

    # Check all clients and PLCs
    for gw_name, clients in CLIENTS.items():
        for client in clients:
            # Check client
            status, response_time = check_port_80(client['ip'])
            save_status(client['name'], client['ip'], 'client', gw_name, 1 if status else 0, response_time)

            # For performance metrics, ping the client
            if COLLECT_PERFORMANCE_METRICS:
                ping_status, ping_time, packet_loss = ping_device(client['ip'])
                if ping_status:
                    save_performance_metrics(client['name'], client['ip'], 'client', gw_name, ping_time, packet_loss)

            # Check associated PLC (using ping)
            if 'plc_ip' in client:
                plc_ip = client['plc_ip']
                plc_name = f"{client['name']}-plc"

                # Use the improved PLC check function
                ping_status, ping_time, packet_loss, debug_info = check_plc_with_tolerance(plc_ip)

                # Log detailed information for debugging
                log_plc_check(plc_name, plc_ip, ping_status, ping_time, packet_loss, debug_info)

                # Save status to database
                save_plc_status(plc_name, plc_ip, client['name'], gw_name, 1 if ping_status else 0, ping_time)

                # Save PLC performance metrics
                if COLLECT_PERFORMANCE_METRICS and ping_status:
                    save_performance_metrics(plc_name, plc_ip, 'plc', gw_name, ping_time, packet_loss)

    # After checking all devices, send the data to the external server
    try:
        send_data_to_external_server()
    except Exception as e:
        print(
            f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Error sending data to external server: {str(e)}")

    # Cleanup old performance metrics (keep only last 30 days)
    cleanup_old_data()


def cleanup_old_data():
    """Clean up old performance metrics data (older than 30 days)"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Calculate date 30 days ago
        thirty_days_ago = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

        # Delete old performance metrics
        cursor.execute("DELETE FROM performance_metrics WHERE timestamp < ?", (thirty_days_ago,))

        # Delete old resolved alerts
        cursor.execute("DELETE FROM alerts WHERE status = 'resolved' AND resolved_at < ?", (thirty_days_ago,))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error cleaning up old data: {str(e)}")


def send_data_to_external_server():
    """Send collected data to the external server"""
    try:
        # Get all required data
        gateways_data = get_gateways_data()
        clients_data = get_all_clients_data()
        plcs_data = get_all_plcs_data()
        history_data = get_recent_history()
        summary_data = get_summary_data()
        alerts_data = get_active_alerts()

        # Prepare payload
        payload = {
            'gateways': gateways_data,
            'clients': clients_data,
            'plcs': plcs_data,
            'history': history_data,
            'summary': summary_data,
            'alerts': alerts_data,
            'timestamp': datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')
        }

        # Send data to external server
        response = requests.post(
            f"{EXTERNAL_SERVER}/api/receive_data",
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )

        if response.status_code == 200:
            print(
                f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Data successfully sent to external server")
        else:
            print(
                f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Failed to send data: {response.status_code} - {response.text}")

    except Exception as e:
        print(
            f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Error sending data to external server: {str(e)}")


def get_gateways_data():
    """Retrieve gateways data for sending to external server"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT device_name, device_ip, status, response_time, last_checked 
    FROM device_status 
    WHERE device_type = 'gateway' 
    ORDER BY device_name
    ''')

    rows = cursor.fetchall()
    gateways = []

    for row in rows:
        gateways.append({
            'name': row[0],
            'ip': row[1],
            'status': row[2],
            'responseTime': row[3],
            'lastChecked': row[4]
        })

    conn.close()
    return gateways


def get_clients_data(gateway):
    """Retrieve clients data for a specific gateway"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT device_name, device_ip, status, response_time, last_checked 
    FROM device_status 
    WHERE device_type = 'client' AND parent_gateway = ? 
    ORDER BY device_name
    ''', (gateway,))

    rows = cursor.fetchall()
    clients = []

    for row in rows:
        clients.append({
            'name': row[0],
            'ip': row[1],
            'status': row[2],
            'responseTime': row[3],
            'lastChecked': row[4]
        })

    conn.close()
    return clients


def get_all_clients_data():
    """Retrieve all clients data grouped by gateway"""
    clients_by_gateway = {}
    for gateway in GATEWAYS.keys():
        clients_by_gateway[gateway] = get_clients_data(gateway)
    return clients_by_gateway


def get_plcs_data(gateway):
    """Retrieve PLCs data for a specific gateway"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT plc_name, plc_ip, parent_client, status, response_time, last_checked 
    FROM plc_status 
    WHERE parent_gateway = ? 
    ORDER BY plc_name
    ''', (gateway,))

    rows = cursor.fetchall()
    plcs = []

    for row in rows:
        plcs.append({
            'name': row[0],
            'ip': row[1],
            'parentClient': row[2],
            'status': row[3],
            'responseTime': row[4],
            'lastChecked': row[5]
        })

    conn.close()
    return plcs


def get_all_plcs_data():
    """Retrieve all PLCs data grouped by gateway"""
    plcs_by_gateway = {}
    for gateway in GATEWAYS.keys():
        plcs_by_gateway[gateway] = get_plcs_data(gateway)
    return plcs_by_gateway


def get_device_history(device_name, limit=20, device_type=None):
    """Retrieve history for a specific device (gateway or client)"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Check if this is a PLC
    if device_type == 'plc' or (not device_type and device_name.endswith('-plc')):
        # Get PLC history
        cursor.execute('''
        SELECT plc_name, plc_ip, parent_client, parent_gateway, status, response_time, timestamp 
        FROM plc_history 
        WHERE plc_name = ?
        ORDER BY timestamp DESC 
        LIMIT ?
        ''', (device_name, limit))

        rows = cursor.fetchall()
        history = []

        for row in rows:
            history.append({
                'name': row[0],
                'ip': row[1],
                'parentClient': row[2],
                'parentGateway': row[3],
                'type': 'plc',
                'status': row[4],
                'responseTime': row[5],
                'timestamp': row[6]
            })
    else:
        # Get device history (gateway or client)
        cursor.execute('''
        SELECT device_name, device_ip, device_type, status, response_time, timestamp 
        FROM status_history 
        WHERE device_name = ?
        ORDER BY timestamp DESC 
        LIMIT ?
        ''', (device_name, limit))

        rows = cursor.fetchall()
        history = []

        for row in rows:
            history.append({
                'name': row[0],
                'ip': row[1],
                'type': row[2],
                'status': row[3],
                'responseTime': row[4],
                'timestamp': row[5]
            })

    conn.close()
    return history


def get_active_alerts(limit=50):
    """Retrieve active alerts"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT id, device_name, device_ip, device_type, parent_gateway, alert_type, message, created_at 
    FROM alerts 
    WHERE status = 'active' 
    ORDER BY created_at DESC 
    LIMIT ?
    ''', (limit,))

    rows = cursor.fetchall()
    alerts = []

    for row in rows:
        alerts.append({
            'id': row[0],
            'device_name': row[1],
            'device_ip': row[2],
            'device_type': row[3],
            'parent_gateway': row[4],
            'alert_type': row[5],
            'message': row[6],
            'created_at': row[7]
        })

    conn.close()
    return alerts


def get_recent_history(limit=100):
    """Retrieve recent history for all devices (including PLCs)"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get device history
    cursor.execute('''
    SELECT device_name, device_ip, device_type, parent_gateway, status, response_time, timestamp 
    FROM status_history 
    ORDER BY timestamp DESC 
    LIMIT ?
    ''', (limit,))

    device_rows = cursor.fetchall()

    # Get PLC history
    cursor.execute('''
    SELECT plc_name, plc_ip, 'plc', parent_gateway, status, response_time, timestamp 
    FROM plc_history 
    ORDER BY timestamp DESC 
    LIMIT ?
    ''', (limit,))

    plc_rows = cursor.fetchall()

    # Combine and sort by timestamp
    all_rows = device_rows + plc_rows
    all_rows.sort(key=lambda x: x[6], reverse=True)
    all_rows = all_rows[:limit]  # Keep only the most recent events

    history = []

    for row in all_rows:
        history.append({
            'name': row[0],
            'ip': row[1],
            'type': row[2],
            'parent_gateway': row[3],
            'status': row[4],
            'responseTime': row[5],
            'timestamp': row[6]
        })

    conn.close()
    return history


def get_performance_data(device_name, device_type, timespan="24h"):
    """Retrieve performance data for a specific device"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Calculate time range based on timespan
    now = datetime.datetime.now(iran_timezone)
    if timespan == "24h":
        start_time = now - datetime.timedelta(hours=24)
    elif timespan == "7d":
        start_time = now - datetime.timedelta(days=7)
    elif timespan == "30d":
        start_time = now - datetime.timedelta(days=30)
    else:
        start_time = now - datetime.timedelta(hours=24)  # Default to 24 hours

    start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute('''
    SELECT response_time, packet_loss, timestamp 
    FROM performance_metrics 
    WHERE device_name = ? AND device_type = ? AND timestamp >= ? 
    ORDER BY timestamp
    ''', (device_name, device_type, start_time_str))

    rows = cursor.fetchall()
    metrics = []

    for row in rows:
        metrics.append({
            'responseTime': row[0],
            'packetLoss': row[1],
            'timestamp': row[2]
        })

    conn.close()
    return metrics


def get_summary_data():
    """Retrieve summary data including gateways, clients, and PLCs"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get total device counts
    cursor.execute("SELECT COUNT(*) FROM device_status")
    total_devices = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM plc_status")
    total_plcs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM device_status WHERE status = 1")
    online_devices = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM plc_status WHERE status = 1")
    online_plcs = cursor.fetchone()[0]

    # Get gateway status information
    cursor.execute('''
    SELECT device_name, status 
    FROM device_status 
    WHERE device_type = 'gateway'
    ''')
    gateways_status = {}
    for row in cursor.fetchall():
        gw_name, status = row
        gateways_status[gw_name] = status

    # Gateway summary with client and PLC counts
    gateways_summary = {}
    for gw_name in GATEWAYS.keys():
        # Count clients
        cursor.execute('''
        SELECT COUNT(*), SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) 
        FROM device_status 
        WHERE parent_gateway = ? AND device_type = 'client'
        ''', (gw_name,))

        result = cursor.fetchone()
        total_clients = result[0] or 0
        online_clients = result[1] or 0

        # Count PLCs
        cursor.execute('''
        SELECT COUNT(*), SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) 
        FROM plc_status 
        WHERE parent_gateway = ?
        ''', (gw_name,))

        result = cursor.fetchone()
        total_plcs_gw = result[0] or 0
        online_plcs_gw = result[1] or 0

        # Calculate response times
        cursor.execute('''
        SELECT AVG(response_time) 
        FROM device_status 
        WHERE parent_gateway = ? AND response_time IS NOT NULL
        ''', (gw_name,))
        avg_response = cursor.fetchone()[0] or 0

        # Calculate uptime percentage for this gateway's devices
        total_devices_gw = total_clients + total_plcs_gw
        online_devices_gw = online_clients + online_plcs_gw
        uptime_percent_gw = round((online_devices_gw / total_devices_gw) * 100) if total_devices_gw > 0 else 0

        gateways_summary[gw_name] = {
            'total_clients': total_clients,
            'online_clients': online_clients,
            'offline_clients': total_clients - online_clients,
            'total_plcs': total_plcs_gw,
            'online_plcs': online_plcs_gw,
            'offline_plcs': total_plcs_gw - online_plcs_gw,
            'avg_response': round(avg_response, 2) if avg_response else None,
            'uptime_percent': uptime_percent_gw,
            'status': gateways_status.get(gw_name, 0)
        }

    # Calculate overall statistics
    total_all = total_devices + total_plcs
    online_all = online_devices + online_plcs
    uptime_percent = round((online_all / total_all) * 100) if total_all > 0 else 0

    # Get recent alerts count
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'active'")
    active_alerts = cursor.fetchone()[0]

    # Get average response time across all devices
    cursor.execute('''
    SELECT AVG(response_time) 
    FROM (
        SELECT response_time FROM device_status WHERE response_time IS NOT NULL
        UNION ALL
        SELECT response_time FROM plc_status WHERE response_time IS NOT NULL
    )
    ''')
    avg_response_overall = cursor.fetchone()[0] or 0

    conn.close()

    return {
        'total_devices': total_devices,
        'online_devices': online_devices,
        'offline_devices': total_devices - online_devices,
        'total_plcs': total_plcs,
        'online_plcs': online_plcs,
        'offline_plcs': total_plcs - online_plcs,
        'total_all': total_all,
        'online_all': online_all,
        'offline_all': total_all - online_all,
        'uptime_percent': uptime_percent,
        'active_alerts': active_alerts,
        'avg_response_time': round(avg_response_overall, 2) if avg_response_overall else None,
        'gateways': gateways_summary
    }


@app.route('/')
@login_required
def index():
    """Render main dashboard page"""
    return render_template('index.html')


@app.route('/api/gateways')
@login_required
def get_gateways_route():
    """Return list of all gateways"""
    return jsonify(get_gateways_data())


@app.route('/api/clients/<gateway>')
@login_required
def get_clients_by_gateway_route(gateway):
    """Return clients for a specific gateway"""
    return jsonify(get_clients_data(gateway))


@app.route('/api/plcs/<gateway>')
@login_required
def get_plcs_by_gateway_route(gateway):
    """Return PLCs for a specific gateway"""
    return jsonify(get_plcs_data(gateway))


@app.route('/api/history/<device_name>')
@login_required
def get_device_history_route(device_name):
    """Return history for a specific device"""
    limit = request.args.get('limit', 100, type=int)
    device_type = request.args.get('type', None)
    return jsonify(get_device_history(device_name, limit, device_type))


@app.route('/api/performance/<device_name>')
@login_required
def get_performance_data_route(device_name):
    """Return performance data for a specific device"""
    device_type = request.args.get('type', 'client')
    timespan = request.args.get('timespan', '24h')
    return jsonify(get_performance_data(device_name, device_type, timespan))


@app.route('/api/summary')
@login_required
def get_summary_route():
    """Return system summary data"""
    return jsonify(get_summary_data())


@app.route('/api/alerts')
@login_required
def get_alerts_route():
    """Return active alerts"""
    return jsonify(get_active_alerts())


@app.route('/api/check_now')
@login_required
def manual_check():
    """Manually trigger a check of all devices"""
    threading.Thread(target=check_all_devices).start()
    return jsonify({"status": "success", "message": "Device check initiated"})


@app.route('/download/history/<device_name>')
@login_required
def download_device_history(device_name):
    """Download history for a specific device as CSV"""
    device_type = request.args.get('type', None)

    if device_type == 'plc' or (not device_type and device_name.endswith('-plc')):
        # Download PLC history
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute('''
        SELECT plc_name, plc_ip, parent_client, parent_gateway, status, response_time, timestamp 
        FROM plc_history 
        WHERE plc_name = ?
        ORDER BY timestamp DESC
        ''', (device_name,))

        rows = cursor.fetchall()
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(
            ['PLC Name', 'IP Address', 'Parent Client', 'Parent Gateway', 'Status', 'Response Time (ms)', 'Timestamp'])

        for row in rows:
            status_text = 'Online' if row[4] == 1 else 'Offline'
            writer.writerow([row[0], row[1], row[2], row[3], status_text, row[5], row[6]])

        output.seek(0)
        filename = f"{device_name}_history_{datetime.datetime.now(iran_timezone).strftime('%Y%m%d_%H%M%S')}.csv"

        return send_file(
            io.BytesIO(output.getvalue().encode()),
            as_attachment=True,
            download_name=filename,
            mimetype='text/csv'
        )
    else:
        # Download device history
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute('''
        SELECT device_name, device_ip, device_type, parent_gateway, status, response_time, timestamp 
        FROM status_history 
        WHERE device_name = ?
        ORDER BY timestamp DESC
        ''', (device_name,))

        rows = cursor.fetchall()
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(
            ['Device Name', 'IP Address', 'Type', 'Parent Gateway', 'Status', 'Response Time (ms)', 'Timestamp'])

        for row in rows:
            status_text = 'Online' if row[4] == 1 else 'Offline'
            writer.writerow([row[0], row[1], row[2], row[3], status_text, row[5], row[6]])

        output.seek(0)
        filename = f"{device_name}_history_{datetime.datetime.now(iran_timezone).strftime('%Y%m%d_%H%M%S')}.csv"

        return send_file(
            io.BytesIO(output.getvalue().encode()),
            as_attachment=True,
            download_name=filename,
            mimetype='text/csv'
        )


@app.route('/download/all_history')
@login_required
def download_all_history():
    """Download history for all devices as CSV"""
    history_type = request.args.get('type', 'all')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    if history_type == 'plc':
        # Download all PLC history
        cursor.execute('''
        SELECT plc_name, plc_ip, parent_client, parent_gateway, status, response_time, timestamp 
        FROM plc_history 
        ORDER BY timestamp DESC
        ''')

        rows = cursor.fetchall()
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(
            ['PLC Name', 'IP Address', 'Parent Client', 'Parent Gateway', 'Status', 'Response Time (ms)', 'Timestamp'])

        for row in rows:
            status_text = 'Online' if row[4] == 1 else 'Offline'
            writer.writerow([row[0], row[1], row[2], row[3], status_text, row[5], row[6]])

    elif history_type == 'device':
        # Download all device history
        cursor.execute('''
        SELECT device_name, device_ip, device_type, parent_gateway, status, response_time, timestamp 
        FROM status_history 
        ORDER BY timestamp DESC
        ''')

        rows = cursor.fetchall()
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(
            ['Device Name', 'IP Address', 'Type', 'Parent Gateway', 'Status', 'Response Time (ms)', 'Timestamp'])

        for row in rows:
            status_text = 'Online' if row[4] == 1 else 'Offline'
            writer.writerow([row[0], row[1], row[2], row[3], status_text, row[5], row[6]])

    else:
        # Download all history (devices and PLCs)
        # Get device history
        cursor.execute('''
        SELECT device_name, device_ip, device_type, parent_gateway, status, response_time, timestamp 
        FROM status_history 
        ORDER BY timestamp DESC
        ''')

        device_rows = cursor.fetchall()

        # Get PLC history
        cursor.execute('''
        SELECT plc_name, plc_ip, 'plc', parent_gateway, status, response_time, timestamp 
        FROM plc_history 
        ORDER BY timestamp DESC
        ''')

        plc_rows = cursor.fetchall()

        # Combine and sort by timestamp
        all_rows = device_rows + plc_rows
        all_rows.sort(key=lambda x: x[6], reverse=True)

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(
            ['Device Name', 'IP Address', 'Type', 'Parent Gateway', 'Status', 'Response Time (ms)', 'Timestamp'])

        for row in all_rows:
            status_text = 'Online' if row[4] == 1 else 'Offline'
            writer.writerow([row[0], row[1], row[2], row[3], status_text, row[5], row[6]])

    output.seek(0)
    filename = f"all_history_{datetime.datetime.now(iran_timezone).strftime('%Y%m%d_%H%M%S')}.csv"

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        as_attachment=True,
        download_name=filename,
        mimetype='text/csv'
    )


@app.route('/download/performance/<device_name>')
@login_required
def download_performance_data(device_name):
    """Download performance metrics for a specific device as CSV"""
    device_type = request.args.get('type', 'client')
    timespan = request.args.get('timespan', '7d')

    # Calculate time range based on timespan
    now = datetime.datetime.now(iran_timezone)
    if timespan == "24h":
        start_time = now - datetime.timedelta(hours=24)
        timespan_text = "24 Hours"
    elif timespan == "7d":
        start_time = now - datetime.timedelta(days=7)
        timespan_text = "7 Days"
    elif timespan == "30d":
        start_time = now - datetime.timedelta(days=30)
        timespan_text = "30 Days"
    else:
        start_time = now - datetime.timedelta(hours=24)
        timespan_text = "24 Hours"

    start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT response_time, packet_loss, timestamp 
    FROM performance_metrics 
    WHERE device_name = ? AND device_type = ? AND timestamp >= ? 
    ORDER BY timestamp DESC
    ''', (device_name, device_type, start_time_str))

    rows = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['Device Name', 'Type', 'Timespan', 'Response Time (ms)', 'Packet Loss (%)', 'Timestamp'])

    for row in rows:
        writer.writerow([device_name, device_type, timespan_text, row[0], row[1], row[2]])

    output.seek(0)
    filename = f"{device_name}_performance_{timespan}_{datetime.datetime.now(iran_timezone).strftime('%Y%m%d_%H%M%S')}.csv"

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        as_attachment=True,
        download_name=filename,
        mimetype='text/csv'
    )


# Ruta para obtener el historial reciente (agregada para completitud)
@app.route('/api/recent_history')
@login_required
def get_recent_history_route():
    """Return recent history for all devices"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(get_recent_history(limit))


def start_scheduler():
    """Start the background scheduler for periodic device checks"""
    scheduler = BackgroundScheduler(timezone=str(iran_timezone))
    scheduler.add_job(check_all_devices, 'interval', minutes=5)
    scheduler.start()
    print(f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Scheduler started!")


if __name__ == '__main__':
    # Ensure templates directory exists
    if not os.path.exists('templates'):
        os.makedirs('templates')

    # Create and initialize database
    init_db()

    # Initial device check
    check_all_devices()

    # Start background scheduler
    start_scheduler()

    # Start Flask application
    app.run(host='0.0.0.0', port=5000, debug=True)
