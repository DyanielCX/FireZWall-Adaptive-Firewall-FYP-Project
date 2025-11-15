''' External Library Import '''
import time, json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
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

    # Dictionary to track active sessions
    active_sessions = {}

    # Dictionary to track tty code
    tty_codes = {}
    
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
                    
                # Get data from log file
                ip = obj.get('src_ip')
                event_id = obj.get('eventid')
                session = obj.get('session')
                

                #=====================================#
                #-------  Brute-Force Session  -------#
                #=====================================#
                if event_id == 'cowrie.login.failed' and ip:

                    # Add timestamp for this failed attempt
                    failed_attempts[ip].append(current_time)
                    
                    # Clean old attempts outside the time window
                    failed_attempts[ip] = [
                        ts for ts in failed_attempts[ip] 
                        if current_time - ts < timedelta(minutes=TIME_WINDOW)
                    ]
                    
                    # Check for brute-force pattern
                    if len(failed_attempts[ip]) >= 6:

                        # Convert datetime format of timestamp
                        parsed_ts = parser.isoparse(obj.get('timestamp'))
                        parsed_ts = parsed_ts.astimezone(timezone.utc).replace(tzinfo=None)
                        
                        event = HoneypotEvent(
                            timestamp = parsed_ts,
                            event_id = event_id,
                            event_type = "brute-force attack",
                            src_ip = ip,
                            protocol = obj.get('protocol'),
                            username = obj.get('username'),
                            password = obj.get('password'),
                            duration = None,
                            tty_code = None,
                            message = obj.get('message')
                        )

                        # Check if event exist in database (prevent duplicate)
                        commit_flag = _check_event(event)
                        if commit_flag:
                            db.session.add(event)
                            db.session.commit()

                        # Auto block IP addr & Create Honeypot Report
                        _ip_auto_block(ip)
                        
                        # Reset after detection
                        failed_attempts[ip] = []


                #===================================#
                #-------  Connected Session  -------#
                #===================================#
                # Login Success Session - track the connected session info #
                elif event_id == 'cowrie.login.success' and ip and session:
                    
                    # Store the active login session in dictionary
                    active_sessions[session] = {
                        'timestamp': obj.get('timestamp'),
                        'login_time': current_time,
                        'src_ip': obj.get('src_ip'),
                        'protocol': obj.get('protocol'),
                        'username': obj.get('username'),
                        'password': obj.get('password'),
                        'message': obj.get('message'),
                        'success_event_stored': False
                    }

                    active_sessions[session]['success_event_stored'] = True


                # Lod Closed Session - retrieve the tty code for the session #
                elif event_id == 'cowrie.log.closed' and session:
                    if session in active_sessions:
                        # Store the tty code into tty dictionary
                        tty_codes[session] = {obj.get('shasum')}


                # Session Closed - submit data into DB & block the src IP Addr #
                elif event_id == 'cowrie.session.closed' and session:
                    if session in active_sessions:
                        session_data = active_sessions[session]
                        
                        # Get duration and tty code
                        duration = obj.get('duration')
                        tty_code = tty_codes.get(session)
                        tty_code = next(iter(tty_code))

                        # Convert datetime format of timestamp
                        parsed_ts = parser.isoparse(obj.get('timestamp'))
                        parsed_ts = parsed_ts.astimezone(timezone.utc).replace(tzinfo=None)

                        event = HoneypotEvent(
                                timestamp = parsed_ts,
                                event_id = "cowrie.session.completed",
                                event_type = "unauthorized access attemp",
                                src_ip = ip,
                                protocol = session_data.get('protocol'),
                                username = session_data.get('username'),
                                password = session_data.get('password'),
                                duration = duration + " seconds",
                                tty_code = tty_code,
                                message = session_data.get('message')
                        )

                        # Check if event exist in database (prevent duplicate)
                        commit_flag = _check_event(event)
                        if commit_flag:
                            db.session.add(event)
                            db.session.commit()
                        
                        # Block the source IP address
                        _ip_auto_block(ip)

            # Session cleanup (remove sessions older than 24 hours)
            current_time = datetime.now()
            expired_sessions = [
                session for session, data in active_sessions.items()
                if current_time - data['login_time'] > timedelta(hours=24)
            ]

            for session in expired_sessions:
                del active_sessions[session]


            time.sleep(10)
            
        except:
            break

def _check_event(event):
    """
    Compare & check the current honetpot event info
    with all events that are stored in database
    """
    event_query = HoneypotEvent.query
    for e in event_query:
        if all([
            e.timestamp == event.timestamp,
            e.event_id == event.event_id,
            e.event_type == event.event_type,
            e.src_ip == event.src_ip,
            e.protocol == event.protocol,
            e.username == event.username,
            e.password == event.password,
            e.duration == event.duration,
            e.tty_code == event.tty_code,
            e.message == event.message,
        ]):
            return False
    return True

def _ip_auto_block(ip):
    """
    Block given ip using ufw
    """
    cmd = ["sudo", "/usr/sbin/ufw", "deny", "from", ip, "to", "any"]
    subprocess.run(cmd, capture_output=True, text=True)