from flask import Flask, render_template, jsonify, request, send_file
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
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)


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
        {'name': 'gw1-c1', 'ip': '172.18.64.41'},
        {'name': 'gw1-c2', 'ip': '172.18.64.42'},
        {'name': 'gw1-c3', 'ip': '172.18.64.43'},
        {'name': 'gw1-c4', 'ip': '172.18.64.44'},
        {'name': 'gw1-c5', 'ip': '172.18.64.45'}
    ],
    'gw2': [
        {'name': 'gw2-c1', 'ip': '172.18.65.41'},
        {'name': 'gw2-c2', 'ip': '172.18.65.42'},  
        {'name': 'gw2-c3', 'ip': '172.18.65.43'},
        {'name': 'gw2-c4', 'ip': '172.18.65.44'},
        {'name': 'gw2-c5', 'ip': '172.18.65.45'}
    ],
    'gw3': [
        {'name': 'gw3-c1', 'ip': '172.18.66.41'},
        {'name': 'gw3-c2', 'ip': '172.18.66.42'},
        {'name': 'gw3-c3', 'ip': '172.18.66.43'},
        {'name': 'gw3-c4', 'ip': '172.18.66.44'},
        {'name': 'gw3-c5', 'ip': '172.18.67.45'}
    ],
    'gw4': [
        {'name': 'gw4-c1', 'ip': '172.18.67.41'},
        {'name': 'gw4-c2', 'ip': '172.18.67.42'},
        {'name': 'gw4-c3', 'ip': '172.18.67.43'},
        
    ],
    'gw5': [
        {'name': 'gw5-c1', 'ip': '172.18.68.41'},
        {'name': 'gw5-c2', 'ip': '172.18.68.42'},
        {'name': 'gw5-c3', 'ip': '172.18.68.43'}
    ],
    'gw6': [
        {'name': 'gw6-c1', 'ip': '172.18.69.41'},
        {'name': 'gw6-c2', 'ip': '172.18.69.42'},
        {'name': 'gw6-c3', 'ip': '172.18.69.43'}
    ]
}

# External server configuration
EXTERNAL_SERVER = 'http://185.80.196.129:6500'


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS device_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL,
        device_ip TEXT NOT NULL,
        device_type TEXT NOT NULL,
        parent_gateway TEXT,
        status INTEGER NOT NULL,
        last_checked TIMESTAMP NOT NULL,
        UNIQUE(device_name)
    )
    ''')
    

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS status_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL,
        device_ip TEXT NOT NULL,
        device_type TEXT NOT NULL,
        parent_gateway TEXT,
        status INTEGER NOT NULL,
        timestamp TIMESTAMP NOT NULL
    )
    ''')
    
    conn.commit()
    conn.close()


def check_port_80(ip, max_retries=3, timeout=2):
    for attempt in range(max_retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            if result == 0:  
                return True
            time.sleep(1)  
        except:
            pass
    return False  


def save_status(device_name, device_ip, device_type, parent_gateway, status):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    

    now = datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')
    
  
    cursor.execute(
        "SELECT status FROM device_status WHERE device_name = ?", 
        (device_name,)
    )
    result = cursor.fetchone()
    
    previous_status = None
    if result:
        previous_status = result[0]
    

    cursor.execute(
        "INSERT OR REPLACE INTO device_status (device_name, device_ip, device_type, parent_gateway, status, last_checked) VALUES (?, ?, ?, ?, ?, ?)",
        (device_name, device_ip, device_type, parent_gateway, status, now)
    )
    
   
    if previous_status is None or previous_status != status:
        cursor.execute(
            "INSERT INTO status_history (device_name, device_ip, device_type, parent_gateway, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (device_name, device_ip, device_type, parent_gateway, status, now)
        )
    
    conn.commit()
    conn.close()


def check_all_devices():
    print(f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Checking all devices...")
    

    for gw_name, gw_ip in GATEWAYS.items():
        status = check_port_80(gw_ip)
        save_status(gw_name, gw_ip, 'gateway', None, 1 if status else 0)
    

    for gw_name, clients in CLIENTS.items():
        for client in clients:
            status = check_port_80(client['ip'])
            save_status(client['name'], client['ip'], 'client', gw_name, 1 if status else 0)
            
    # After checking all devices, send the data to the external server
    send_data_to_external_server()


def send_data_to_external_server():
    """Send collected data to the external server"""
    try:
        # Get all required data
        gateways_data = get_gateways_data()
        clients_data = get_all_clients_data()
        history_data = get_recent_history()
        summary_data = get_summary_data()
        
        # Prepare payload
        payload = {
            'gateways': gateways_data,
            'clients': clients_data,
            'history': history_data,
            'summary': summary_data,
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
            print(f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Data successfully sent to external server")
        else:
            print(f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Failed to send data: {response.status_code} - {response.text}")
    
    except Exception as e:
        print(f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Error sending data to external server: {str(e)}")


def get_gateways_data():
    """Retrieve gateways data for sending to external server"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT device_name, device_ip, status, last_checked 
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
            'lastChecked': row[3]
        })
    
    conn.close()
    return gateways


def get_clients_data(gateway):
    """Retrieve clients data for a specific gateway"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT device_name, device_ip, status, last_checked 
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
            'lastChecked': row[3]
        })
    
    conn.close()
    return clients


def get_all_clients_data():
    """Retrieve all clients data grouped by gateway"""
    clients_by_gateway = {}
    for gateway in GATEWAYS.keys():
        clients_by_gateway[gateway] = get_clients_data(gateway)
    return clients_by_gateway


def get_device_history(device_name, limit=20):
    """Retrieve history for a specific device"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT device_name, device_ip, device_type, status, timestamp 
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
            'timestamp': row[4]
        })
    
    conn.close()
    return history


def get_recent_history(limit=100):
    """Retrieve recent history for all devices"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT device_name, device_ip, device_type, parent_gateway, status, timestamp 
    FROM status_history 
    ORDER BY timestamp DESC 
    LIMIT ?
    ''', (limit,))
    
    rows = cursor.fetchall()
    history = []
    
    for row in rows:
        history.append({
            'name': row[0],
            'ip': row[1],
            'type': row[2],
            'parent_gateway': row[3],
            'status': row[4],
            'timestamp': row[5]
        })
    
    conn.close()
    return history


def get_summary_data():
    """Retrieve summary data for sending to external server"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    

    cursor.execute("SELECT COUNT(*) FROM device_status")
    total_devices = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM device_status WHERE status = 1")
    online_devices = cursor.fetchone()[0]
    

    cursor.execute('''
    SELECT device_name, status 
    FROM device_status 
    WHERE device_type = 'gateway'
    ''')
    gateways_status = {}
    for row in cursor.fetchall():
        gw_name, status = row
        gateways_status[gw_name] = status
    

    gateways_summary = {}
    for gw_name in GATEWAYS.keys():
        cursor.execute('''
        SELECT COUNT(*), SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) 
        FROM device_status 
        WHERE parent_gateway = ?
        ''', (gw_name,))
        
        result = cursor.fetchone()
        total_clients = result[0] or 0
        online_clients = result[1] or 0
        
        gateways_summary[gw_name] = {
            'total': total_clients,
            'online': online_clients,
            'offline': total_clients - online_clients,
            'status': gateways_status.get(gw_name, 0)
        }
    
    conn.close()
    
    return {
        'total_devices': total_devices,
        'online_devices': online_devices,
        'offline_devices': total_devices - online_devices,
        'uptime_percent': round((online_devices / total_devices) * 100) if total_devices > 0 else 0,
        'gateways': gateways_summary
    }


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/gateways')
def get_gateways():
    return jsonify(get_gateways_data())

@app.route('/api/clients/<gateway>')
def get_clients_by_gateway(gateway):
    return jsonify(get_clients_data(gateway))

@app.route('/api/history/<device_name>')
def get_device_history_route(device_name):
    limit = request.args.get('limit', 100, type=int)
    return jsonify(get_device_history(device_name, limit))

@app.route('/api/summary')
def get_summary():
    return jsonify(get_summary_data())

@app.route('/download/history/<device_name>')
def download_device_history(device_name):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT device_name, device_ip, device_type, status, timestamp 
    FROM status_history 
    WHERE device_name = ?
    ORDER BY timestamp DESC
    ''', (device_name,))
    
    rows = cursor.fetchall()
    

    output = io.StringIO()
    writer = csv.writer(output)
    

    writer.writerow(['Device Name', 'IP Address', 'Type', 'Status', 'Timestamp'])
    

    for row in rows:
        status_text = 'Online' if row[3] == 1 else 'Offline'
        writer.writerow([row[0], row[1], row[2], status_text, row[4]])
    

    output.seek(0)
    

    filename = f"{device_name}_history_{datetime.datetime.now(iran_timezone).strftime('%Y%m%d_%H%M%S')}.csv"
    
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        as_attachment=True,
        download_name=filename,
        mimetype='text/csv'
    )

@app.route('/download/all_history')
def download_all_history():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT device_name, device_ip, device_type, parent_gateway, status, timestamp 
    FROM status_history 
    ORDER BY timestamp DESC
    ''')
    
    rows = cursor.fetchall()
    

    output = io.StringIO()
    writer = csv.writer(output)
    

    writer.writerow(['Device Name', 'IP Address', 'Type', 'Parent Gateway', 'Status', 'Timestamp'])
    

    for row in rows:
        status_text = 'Online' if row[4] == 1 else 'Offline'
        writer.writerow([row[0], row[1], row[2], row[3], status_text, row[5]])
    

    output.seek(0)
    

    filename = f"all_history_{datetime.datetime.now(iran_timezone).strftime('%Y%m%d_%H%M%S')}.csv"
    
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        as_attachment=True,
        download_name=filename,
        mimetype='text/csv'
    )


def start_scheduler():
    scheduler = BackgroundScheduler(timezone=str(iran_timezone))
    scheduler.add_job(check_all_devices, 'interval', minutes=1)
    scheduler.start()
    print(f"[{datetime.datetime.now(iran_timezone).strftime('%Y-%m-%d %H:%M:%S')}] Scheduler started!")

if __name__ == '__main__':

    if not os.path.exists('templates'):
        os.makedirs('templates')
    

    init_db()
    

    check_all_devices()
    

    start_scheduler()
    

    app.run(host='0.0.0.0', port=5000, debug=True)
