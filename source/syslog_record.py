''' External Library Import '''
from datetime import datetime, timezone
from dateutil import parser
import datetime

''' Internal File Import '''
from dbModel import db, User, OAuth2Token, SystemLog

def syslog_create(Level, Event_type, Module, Message, Username, IP_addr, Method, Endpoint, Details):
    # Convert datetime format of timestamp
    parsed_ts = parser.isoparse(datetime.now())
    parsed_ts = parsed_ts.astimezone(timezone.utc).replace(tzinfo=None)

    # Logs Record
    syslog = SystemLog(
        timestamp = parsed_ts,
        level = Level,
        event_type = Event_type,
        module = Module,
        message = Message,
        username = Username,
        ip_addr = IP_addr,
        method = Method,
        endpoint = Endpoint,
        details = Details
    )

    db.session.add(syslog)
    db.session.commit()

def get_username_with_token (OAuth_token):
    # Get User ID
    token = OAuth2Token.query.filter_by(access_token=OAuth_token).first()
    user_ID = token.user_id

    # Get username
    user = User.query.filter_by(id=user_ID).first()
    username = user.username

    return username