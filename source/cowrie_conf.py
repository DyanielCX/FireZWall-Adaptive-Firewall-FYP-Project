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
    
    #=====  Reconnaissance Detection Variables  ======#  
    
    # Reconnaissance Flag (determine whether is )
    rateDetect = False
    signDetect = False
    isRecon = False

    # Nmap signature keywords
    NMAP_KEYWORDS = ["GET ", "OPTIONS ", "RTSP", "/ HTTP", "/ RTSP", "OPTIONS", "Contact", "\\"]

    # Track connection attempts per IP
    connection_attempts = defaultdict(list) 

    # Time window for reconnaissance detection (in seconds)
    NMAP_TIME_WINDOW = 120
    
    # Typical number of rapid nmap probes
    NMAP_THRESHOLD = 8


    #=====  Brute-Force Detection Variables  ======#    
    
    # Track failed login attempts per IP with timestamps
    failed_attempts = defaultdict(list)
    
    # Time window for brute-force detection (in minutes)
    BRUTE_FORCE_TIME_WINDOW = 5

    # Typical number of failed login attempts
    BRUTE_FORCE_THRESHOLD = 6


    #=====  Session Tracking Variables  ======#    
    
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
                
                #==========================================#
                #-------  Reconnaissance Detection  -------#
                #==========================================#
                # Rate-based Detection #
                if event_id == "cowrie.session.connect":
                    ts = datetime.now()
                    connection_attempts[ip].append(ts)

                    # keep only recent attempts
                    connection_attempts[ip] = [
                        t for t in connection_attempts[ip]
                        if (ts - t).total_seconds() < NMAP_TIME_WINDOW
                    ]

                    # If reach the threshold within window time
                    if len(connection_attempts[ip]) >= NMAP_THRESHOLD:
                        rateDetect = True

                # Signature-based Detection #
                if event_id == "cowrie.login.failed":
                    if is_nmap_failed_login(obj, NMAP_KEYWORDS):
                        signDetect = True

                # Only rateDetect & signDetect both trigger, only know as recon
                if rateDetect & signDetect:
                    isRecon = True
                        
                if isRecon:

                    # Auto block IP addr & Create Honeypot Report
                    event = HoneypotEvent(
                        timestamp = parser.isoparse(obj.get('timestamp')),
                        event_id = "cowrie.recon.scan",
                        event_type = "reconnaissance",
                        src_ip = ip,
                        protocol = None,
                        username = None,
                        password = None,
                        duration = None,
                        tty_code = None,
                        message = "Possible Nmap scan detected"
                    )

                    # Check if event exist in database (prevent duplicate)
                    commit_flag = _check_event(event)
                    if commit_flag:
                        db.session.add(event)
                        db.session.commit()

                    # Block the source IP address
                    _ip_auto_block(ip)

                    # Reset after detection
                    connection_attempts[ip] = []
                    rateDetect = False
                    signDetect = False
                    isRecon = False


                #=====================================#
                #-------  Brute-Force Session  -------#
                #=====================================#
                if event_id == 'cowrie.login.failed' and ip and not is_nmap_failed_login(obj, NMAP_KEYWORDS):

                    # Add timestamp for this failed attempt
                    failed_attempts[ip].append(current_time)
                    
                    # Clean old attempts outside the time window
                    failed_attempts[ip] = [
                        ts for ts in failed_attempts[ip] 
                        if current_time - ts < timedelta(minutes=BRUTE_FORCE_TIME_WINDOW)
                    ]
                    
                    # Check for brute-force pattern
                    if len(failed_attempts[ip]) >= BRUTE_FORCE_THRESHOLD:

                        # Convert datetime format of timestamp
                        parsed_ts = parser.isoparse(obj.get('timestamp'))
                        parsed_ts = parsed_ts.astimezone(timezone.utc).replace(tzinfo=None)
                        
                        # Auto block IP addr & Create Honeypot Report
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

                        # Block the source IP address
                        _ip_auto_block(ip)
                        
                        # Reset after detection
                        failed_attempts[ip] = []


                #============================================#
                #-------  Connected Session Tracking  -------#
                #============================================#
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


                # Log Closed Session - retrieve the tty code for the session #
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
                                event_type = "unauthorized access attempt",
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

def is_nmap_failed_login(obj, NMAP_KEYWORDS):
    """
    Detect failed login events caused by Nmap scan
    """
    username = obj.get("username", "")
    password = obj.get("password", "")

    # Signature 1: completely empty username + password
    if username == "" and password == "":
        return True

    # Signature 2: username contains HTTP / RTSP requests
    for key in NMAP_KEYWORDS:
        if key in username:
            return True

    return False

def _check_event(event):
    """
    Compare & check the current honetpot event info
    with all events that are stored in database
    """
    event_query = HoneypotEvent.query
    for e in event_query:
        if all([
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
    # First check if rule already exists
    status_cmd = ["sudo", "/usr/sbin/ufw", "status", "numbered"]
    status = subprocess.run(status_cmd, capture_output=True, text=True).stdout

    if ip in status:
        return

    # Insert at the top
    cmd = ["sudo", "/usr/sbin/ufw", "insert", "1", "deny", "from", ip, "to", "any"]
    subprocess.run(cmd, capture_output=True, text=True)
