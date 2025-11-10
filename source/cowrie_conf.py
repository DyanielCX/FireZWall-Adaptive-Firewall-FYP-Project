''' External Library Import '''
import time, json
from collections import defaultdict
from datetime import datetime, timedelta
from dateutil import parser
import subprocess

''' Internal File Import '''
from dbModel import db, HoneypotEvent

def cowrie_start():     # Start cowrie honeypot
    cmd = ["cowrie", "start"]
    subprocess.run(cmd)

def cowrie_stop():      # Stop cowrie honeypot
    cmd = ["cowrie", "stop"]
    subprocess.run(cmd)

def cowrie_watcher():
    '''
    Monitor the cowrie log event, 
    auto block access ip addr & create report
    '''

    LOGFILE = 'cowrie/var/log/cowrie/cowrie.json'
    
    # Track failed login attempts per IP with timestamps
    failed_attempts = defaultdict(list)
    
    # Time window for brute-force detection (in minutes)
    TIME_WINDOW = 10
    
    seen = 0
    while True:
        try:
            with open(LOGFILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            new_lines = lines[seen:]
            seen = len(lines)
            
            current_time = datetime.now()
            
            for line in new_lines:
                try:
                    obj = json.loads(line)
                except:
                    continue
                    
                ip = obj.get('src_ip') or obj.get('peerIP') or obj.get('peer')
                eventid = obj.get('eventid')
                
                # Brute-Force Session
                if eventid == 'cowrie.login.failed' and ip:
                    # Add timestamp for this failed attempt
                    failed_attempts[ip].append(current_time)
                    
                    # Clean old attempts outside the time window
                    failed_attempts[ip] = [
                        ts for ts in failed_attempts[ip] 
                        if current_time - ts < timedelta(minutes=TIME_WINDOW)
                    ]
                    
                    print(f"Failed login attempt #{len(failed_attempts[ip])} from {ip} (last {TIME_WINDOW} min)")
                    
                    # Check for brute-force pattern
                    if len(failed_attempts[ip]) >= 6:
                        print(f"🚨 BRUTE-FORCE ATTACK DETECTED from {ip} - {len(failed_attempts[ip])} failed attempts in {TIME_WINDOW} minutes!")

                        # Auto block IP addr & Create Honeypot Report
                        # _ip_auto_block(ip)

                        event = HoneypotEvent(
                            timestamp = parser.isoparse(obj.get('timestamp')),
                            eventid = eventid,
                            event_type = "brute-force attack",
                            src_ip = ip,
                            protocol = obj.get('protocol'),
                            username = obj.get('username'),
                            password = obj.get('password'),
                            message = obj.get('message')
                        )
                        db.session.add(event)
                        db.session.commit()
                        
                        # Reset after detection
                        failed_attempts[ip] = []
                
                # Connected Session
                elif eventid == 'cowrie.login.success' and ip:
                    print(f"🚨 UNAUTHORIZED ACCESS ATTEMPT from {ip}")
                    
                    # Auto block IP addr & Create Honeypot Report
                    # _ip_auto_block(ip)

                    event = HoneypotEvent(
                            timestamp = parser.isoparse(obj.get('timestamp')),
                            eventid = eventid,
                            event_type = "unauthorized access attemp",
                            src_ip = ip,
                            protocol = obj.get('protocol'),
                            username = obj.get('username'),
                            password = obj.get('password'),
                            message = obj.get('message')
                    )
                    db.session.add(event)
                    db.session.commit()

            time.sleep(10)
            
        except:
            break

def _ip_auto_block(ip):
        """
        Block given ip using ufw.
        """
        cmd = ["sudo", "/usr/sbin/ufw", "deny", "from", ip, "to", "any"]
        subprocess.run(cmd)