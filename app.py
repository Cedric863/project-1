import sqlite3
import csv
import io
from flask import Flask, jsonify, render_template, request, session, redirect, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'zetech_nids_super_secret_key_change_in_production'

def get_db_connection():
    conn = sqlite3.connect('zetech_nids.db', timeout=5)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.row_factory = sqlite3.Row 
    return conn

# --- UPDATED: Database Migration for DPI ---
def init_engine_db():
    try:
        conn = get_db_connection()
        conn.execute('CREATE TABLE IF NOT EXISTS ENGINE_CONTROL (id INTEGER PRIMARY KEY CHECK (id = 1), status TEXT NOT NULL)')
        conn.execute('INSERT OR IGNORE INTO ENGINE_CONTROL (id, status) VALUES (1, "running")')
        
        # Ensure SIGNATURE_RULE exists
        conn.execute('''CREATE TABLE IF NOT EXISTS SIGNATURE_RULE (
                        rule_id INTEGER PRIMARY KEY, threat_type TEXT, protocol TEXT, port INTEGER)''')
        
        # Safely attempt to add the new DPI payload column if it doesn't exist
        try:
            conn.execute('ALTER TABLE SIGNATURE_RULE ADD COLUMN payload_keyword TEXT')
        except sqlite3.OperationalError:
            pass # Column already exists
            
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Init Error: {e}")

init_engine_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('auth'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM ADMIN_USER LIMIT 1').fetchone()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not admin:
            hashed_pw = generate_password_hash(password)
            conn.execute('INSERT INTO ADMIN_USER (admin_id, username, password_hash) VALUES (1, ?, ?)', (username, hashed_pw))
            conn.commit()
            session['logged_in'] = True
            session['username'] = username
            conn.close()
            return redirect(url_for('index'))
        else:
            if admin['username'] == username and check_password_hash(admin['password_hash'], password):
                session['logged_in'] = True
                session['username'] = username
                conn.close()
                return redirect(url_for('index'))
            else:
                conn.close()
                return render_template('auth.html', mode='login', error='Invalid username or password!')
                
    conn.close()
    mode = 'login' if admin else 'register'
    return render_template('auth.html', mode=mode)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username'))

@app.route('/threats')
@login_required
def threats():
    return render_template('threats.html')

@app.route('/admin/add-rule')
@login_required
def admin_add_rule():
    return render_template('admin_add.html')

@app.route('/admin/remove-rule')
@login_required
def admin_remove_rule():
    return render_template('admin_remove.html')

@app.route('/admin/update-credentials')
@login_required
def admin_update_credentials():
    return render_template('admin_update.html', username=session.get('username'))

@app.route('/api/alerts')
@login_required
def get_alerts():
    try:
        conn = get_db_connection()
        alerts = conn.execute('SELECT * FROM ALERT_LOG ORDER BY time_logged DESC LIMIT 100').fetchall()
        conn.close()
        return jsonify([dict(row) for row in alerts])
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/logs')
@login_required
def get_logs():
    try:
        conn = get_db_connection()
        logs = conn.execute('SELECT * FROM LOGS ORDER BY time_logged DESC LIMIT 100').fetchall()
        conn.close()
        return jsonify([dict(row) for row in logs])
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/stats')
@login_required
def get_stats():
    try:
        conn = get_db_connection()
        common_row = conn.execute("""
            SELECT rule_id, COUNT(rule_id) as occurrence 
            FROM ALERT_LOG 
            WHERE date(time_logged) = date('now', 'localtime')
            GROUP BY rule_id 
            ORDER BY occurrence DESC 
            LIMIT 1
        """).fetchone()
        conn.close()
        most_common = f"Rule {common_row['rule_id']}" if common_row else "None"
        return jsonify({"most_common_threat": most_common})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/rules')
@login_required
def get_rules():
    try:
        conn = get_db_connection()
        rules = conn.execute('SELECT * FROM SIGNATURE_RULE').fetchall()
        conn.close()
        return jsonify([dict(row) for row in rules])
    except Exception as e:
        return jsonify({"error": str(e)})

# --- UPDATED: Add Rule API now handles payload keywords ---
@app.route('/api/rules/add', methods=['POST'])
@login_required
def add_rule():
    try:
        data = request.json
        rule_id = data.get('rule_id')
        threat_type = data.get('threat_type')
        protocol = data.get('protocol')
        port = data.get('port')
        keyword = data.get('payload_keyword', '') # Extract optional keyword
        
        if not (rule_id and threat_type and protocol and port):
            return jsonify({"error": "Rule ID, Threat Type, Protocol, and Port are required!"}), 400
            
        conn = get_db_connection()
        conn.execute('''INSERT INTO SIGNATURE_RULE (rule_id, threat_type, protocol, port, payload_keyword) 
                        VALUES (?, ?, ?, ?, ?)''', 
                     (int(rule_id), threat_type, protocol, int(port), keyword))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Signature rule saved successfully!"})
    except sqlite3.IntegrityError:
        return jsonify({"error": f"Rule ID {rule_id} already exists!"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rules/remove', methods=['POST'])
@login_required
def remove_rule():
    try:
        data = request.json
        rule_id = data.get('rule_id')
        if not rule_id:
            return jsonify({"error": "Rule ID is required!"}), 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM SIGNATURE_RULE WHERE rule_id = ?', (int(rule_id),))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": f"Rule ID {rule_id} does not exist!"}), 404
        conn.execute('DELETE FROM SIGNATURE_RULE WHERE rule_id = ?', (int(rule_id),))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"Rule {rule_id} purged!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/update', methods=['POST'])
@login_required
def update_admin():
    try:
        data = request.json
        new_username = data.get('username')
        new_password = data.get('password')
        if not new_username:
            return jsonify({"error": "Username cannot be blank!"}), 400
        conn = get_db_connection()
        if new_password:
            hashed_pw = generate_password_hash(new_password)
            conn.execute('UPDATE ADMIN_USER SET username = ?, password_hash = ? WHERE admin_id = 1', (new_username, hashed_pw))
        else:
            conn.execute('UPDATE ADMIN_USER SET username = ? WHERE admin_id = 1', (new_username,))
        conn.commit()
        conn.close()
        session['username'] = new_username 
        return jsonify({"success": True, "message": "Profile updated!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/engine/status')
@login_required
def engine_status():
    try:
        conn = get_db_connection()
        row = conn.execute('SELECT status FROM ENGINE_CONTROL WHERE id = 1').fetchone()
        conn.close()
        return jsonify({"status": row['status'] if row else "unknown"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/engine/set', methods=['POST'])
@login_required
def engine_set():
    try:
        data = request.json
        new_status = data.get('status')
        if new_status in ['running', 'stopped']:
            conn = get_db_connection()
            conn.execute('UPDATE ENGINE_CONTROL SET status = ? WHERE id = 1', (new_status,))
            conn.commit()
            conn.close()
            return jsonify({"success": True, "status": new_status})
        return jsonify({"error": "Invalid status"})
    except Exception as e:
        return jsonify({"error": str(e)})

# --- NEW: Fix for Log Retention Settings ---
@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():
    try:
        conn = get_db_connection()
        # Make sure the table exists just in case
        conn.execute('CREATE TABLE IF NOT EXISTS SYSTEM_SETTINGS (id INTEGER PRIMARY KEY CHECK (id = 1), retention_hours INTEGER)')
        conn.execute('INSERT OR IGNORE INTO SYSTEM_SETTINGS (id, retention_hours) VALUES (1, 24)')
        
        if request.method == 'POST':
            data = request.json
            new_hours = data.get('retention_hours', 24)
            conn.execute('UPDATE SYSTEM_SETTINGS SET retention_hours = ? WHERE id = 1', (int(new_hours),))
            conn.commit()
            conn.close()
            return jsonify({"success": True})
        else:
            row = conn.execute('SELECT retention_hours FROM SYSTEM_SETTINGS WHERE id = 1').fetchone()
            conn.close()
            return jsonify({"retention_hours": row['retention_hours'] if row else 24})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/export/alerts')
@login_required
def export_alerts():
    try:
        conn = get_db_connection()
        alerts = conn.execute('SELECT * FROM ALERT_LOG ORDER BY time_logged DESC').fetchall()
        conn.close()
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['Alert ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'Rule ID'])
        for row in alerts:
            cw.writerow([row['alert_id'], row['time_logged'], row['source_ip'], row['dest_ip'], row['protocol'], row['src_port'], row['dst_port'], row['rule_id']])
        return Response(si.getvalue(), mimetype="text/csv", headers={"Content-disposition": "attachment; filename=zetech_alert_logs.csv"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/export/logs')
@login_required
def export_logs():
    try:
        conn = get_db_connection()
        logs = conn.execute('SELECT * FROM LOGS ORDER BY time_logged DESC').fetchall()
        conn.close()
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['Log ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'Rule ID'])
        for row in logs:
            cw.writerow([row['log_id'], row['time_logged'], row['source_ip'], row['dest_ip'], row['protocol'], row['src_port'], row['dst_port'], row['rule_id']])
        return Response(si.getvalue(), mimetype="text/csv", headers={"Content-disposition": "attachment; filename=zetech_general_logs.csv"})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)