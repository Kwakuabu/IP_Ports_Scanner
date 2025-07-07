#!/usr/bin/env python3
"""
Flask Web Interface for IP Ports Scanner
Author: Silas Asani Abudu
Version: 1.1
"""

import os
import json
import uuid
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import ipaddress

# Import our existing scanner modules
from vuln_scan import VulnerabilityScanner, NetworkScanner, CVELookup, ReportGenerator

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

# Global variables for managing scans
active_scans = {}
scan_results = {}

# Simple user authentication (in production, use a proper database)
USERS = {
    'admin': generate_password_hash('password123'),  # Change this!
    'auditor': generate_password_hash('audit2025')
}

# Configuration
ENABLE_AUTH = os.environ.get('ENABLE_AUTH', 'false').lower() == 'true'
MAX_CONCURRENT_SCANS = 3

def require_auth(f):
    """Decorator to require authentication if enabled"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if ENABLE_AUTH and 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if not ENABLE_AUTH:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in USERS and check_password_hash(USERS[username], password):
            session['user'] = username
            flash('Successfully logged in!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.pop('user', None)
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/')
@require_auth
def index():
    """Main dashboard page"""
    return render_template('index.html', 
                         active_scans=len(active_scans),
                         enable_auth=ENABLE_AUTH,
                         user=session.get('user'))

@app.route('/start_scan', methods=['POST'])
@require_auth
def start_scan():
    """Start a new vulnerability scan"""
    try:
        data = request.get_json()
        subnets = data.get('subnets', [])
        enable_cve = data.get('enable_cve', True)
        max_threads = data.get('max_threads', 10)
        
        # Validate inputs
        if not subnets:
            return jsonify({'error': 'No subnets provided'}), 400
        
        if len(active_scans) >= MAX_CONCURRENT_SCANS:
            return jsonify({'error': 'Maximum concurrent scans reached'}), 429
        
        # Validate subnet formats
        for subnet in subnets:
            try:
                ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                return jsonify({'error': f'Invalid subnet format: {subnet}'}), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan status
        active_scans[scan_id] = {
            'status': 'initializing',
            'progress': 0,
            'current_phase': 'Starting scan...',
            'subnets': subnets,
            'start_time': datetime.now(),
            'hosts_found': 0,
            'ports_found': 0,
            'errors': []
        }
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_scan_background,
            args=(scan_id, subnets, enable_cve, max_threads)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'status': 'started'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def run_scan_background(scan_id, subnets, enable_cve, max_threads):
    """Run vulnerability scan in background thread"""
    try:
        # Update status
        active_scans[scan_id]['status'] = 'running'
        active_scans[scan_id]['current_phase'] = 'Discovering hosts...'
        active_scans[scan_id]['progress'] = 10
        
        # Initialize scanner
        scanner = VulnerabilityScanner(
            max_threads=max_threads,
            enable_cve_lookup=enable_cve
        )
        
        # Phase 1: Host Discovery
        all_hosts = []
        for i, subnet in enumerate(subnets):
            active_scans[scan_id]['current_phase'] = f'Discovering hosts in {subnet}...'
            hosts = scanner.scanner.discover_hosts(subnet)
            all_hosts.extend(hosts)
            
            # Update progress
            progress = 10 + (30 * (i + 1) / len(subnets))
            active_scans[scan_id]['progress'] = int(progress)
            active_scans[scan_id]['hosts_found'] = len(all_hosts)
        
        if not all_hosts:
            active_scans[scan_id]['status'] = 'completed'
            active_scans[scan_id]['current_phase'] = 'No hosts found'
            active_scans[scan_id]['progress'] = 100
            scan_results[scan_id] = []
            return
        
        # Phase 2: Port Scanning
        active_scans[scan_id]['current_phase'] = f'Scanning {len(all_hosts)} hosts...'
        active_scans[scan_id]['progress'] = 40
        
        results = []
        total_hosts = len(all_hosts)
        
        for i, host in enumerate(all_hosts):
            try:
                active_scans[scan_id]['current_phase'] = f'Scanning {host}...'
                result = scanner.scanner.scan_host_ports(host)
                results.append(result)
                
                # Count total ports found
                total_ports = sum(len(r['ports']) for r in results)
                active_scans[scan_id]['ports_found'] = total_ports
                
                # Update progress
                progress = 40 + (40 * (i + 1) / total_hosts)
                active_scans[scan_id]['progress'] = int(progress)
                
            except Exception as e:
                active_scans[scan_id]['errors'].append(f'Error scanning {host}: {str(e)}')
        
        # Phase 3: CVE Lookup
        if enable_cve:
            active_scans[scan_id]['current_phase'] = 'Looking up vulnerabilities...'
            active_scans[scan_id]['progress'] = 80
            scanner._enrich_with_cves(results)
        
        # Complete scan
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['current_phase'] = 'Scan completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['end_time'] = datetime.now()
        
        # Store results
        scan_results[scan_id] = results
        
    except Exception as e:
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['current_phase'] = f'Scan failed: {str(e)}'
        active_scans[scan_id]['errors'].append(str(e))

@app.route('/scan_status/<scan_id>')
@require_auth
def scan_status(scan_id):
    """Get scan status and progress"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    status = active_scans[scan_id].copy()
    
    # Add duration if scan is running or completed
    if 'start_time' in status:
        if 'end_time' in status:
            duration = status['end_time'] - status['start_time']
        else:
            duration = datetime.now() - status['start_time']
        status['duration_seconds'] = int(duration.total_seconds())
    
    # Convert datetime objects to strings for JSON serialization
    for key in ['start_time', 'end_time']:
        if key in status:
            status[key] = status[key].isoformat()
    
    return jsonify(status)

@app.route('/scan_results/<scan_id>')
@require_auth
def get_scan_results(scan_id):
    """Get scan results"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    results = scan_results[scan_id]
    
    # Format results for DataTables
    formatted_results = []
    for host in results:
        if not host['ports']:
            formatted_results.append({
                'ip': host['ip'],
                'hostname': host['hostname'],
                'os': host['os'],
                'port': '',
                'protocol': '',
                'service': 'No open ports',
                'product': '',
                'version': '',
                'cve_count': 0,
                'top_cve': '',
                'cvss_score': ''
            })
        else:
            for port in host['ports']:
                # Get CVE information
                cve_count = 0
                top_cve = ''
                cvss_score = ''
                
                if 'vulnerabilities' in port and port['vulnerabilities']:
                    cve_count = len(port['vulnerabilities'])
                    top_vuln = port['vulnerabilities'][0]
                    top_cve = top_vuln.get('cve_id', '')
                    cvss_score = top_vuln.get('cvss', '')
                
                formatted_results.append({
                    'ip': host['ip'],
                    'hostname': host['hostname'],
                    'os': host['os'],
                    'port': port['port'],
                    'protocol': port['protocol'],
                    'service': port['service'],
                    'product': port['product'],
                    'version': port['version'],
                    'cve_count': cve_count,
                    'top_cve': top_cve,
                    'cvss_score': cvss_score
                })
    
    return jsonify({'data': formatted_results})

@app.route('/export_csv/<scan_id>')
@require_auth
def export_csv(scan_id):
    """Export scan results as CSV"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    try:
        # Generate CSV file
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f'scan_results_{timestamp}.csv'
        filepath = os.path.join('/tmp', filename)
        
        reporter = ReportGenerator()
        reporter.export_csv(scan_results[scan_id], filepath)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/active_scans')
@require_auth
def active_scans_list():
    """Get list of active scans"""
    scans = []
    for scan_id, scan_info in active_scans.items():
        scan_data = scan_info.copy()
        scan_data['scan_id'] = scan_id
        
        # Convert datetime to string
        if 'start_time' in scan_data:
            scan_data['start_time'] = scan_data['start_time'].isoformat()
        if 'end_time' in scan_data:
            scan_data['end_time'] = scan_data['end_time'].isoformat()
            
        scans.append(scan_data)
    
    return jsonify(scans)

@app.route('/delete_scan/<scan_id>', methods=['DELETE'])
@require_auth
def delete_scan(scan_id):
    """Delete a completed scan"""
    try:
        if scan_id in active_scans:
            if active_scans[scan_id]['status'] == 'running':
                return jsonify({'error': 'Cannot delete running scan'}), 400
            del active_scans[scan_id]
        
        if scan_id in scan_results:
            del scan_results[scan_id]
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Internal server error"), 500

# Cleanup old scans periodically
def cleanup_old_scans():
    """Clean up old completed scans to free memory"""
    current_time = datetime.now()
    to_delete = []
    
    for scan_id, scan_info in active_scans.items():
        if scan_info['status'] in ['completed', 'failed']:
            if 'end_time' in scan_info:
                age = current_time - scan_info['end_time']
                if age.total_seconds() > 3600:  # 1 hour
                    to_delete.append(scan_id)
    
    for scan_id in to_delete:
        if scan_id in active_scans:
            del active_scans[scan_id]
        if scan_id in scan_results:
            del scan_results[scan_id]

# Schedule cleanup every 30 minutes
def schedule_cleanup():
    """Schedule periodic cleanup"""
    threading.Timer(1800, schedule_cleanup).start()  # 30 minutes
    cleanup_old_scans()

if __name__ == '__main__':
    # Start cleanup scheduler
    schedule_cleanup()
    
    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )