''' External Library Import '''
import datetime

''' Internal File Import '''
from dbModel import db, User, OAuth2Client


# Create default client and user
def init_database():
    try:
        # Create all tables
        db.create_all()
        print("Database tables created successfully!")
        
        # Create a default OAuth client
        if not OAuth2Client.query.first():
            client = OAuth2Client(
                client_id='default-client',
                client_secret='default-secret',
                client_id_issued_at=int(datetime.datetime.utcnow().timestamp()),
                client_metadata='{"scope": "firewall", "grant_types": ["password"]}'
            )
            db.session.add(client)
            
            # Create a default admin user
            if not User.query.filter_by(username='admin').first():
                admin_user = User(
                    username='admin'
                )
                admin_user.set_password('admin123')
                db.session.add(admin_user)
            
            db.session.commit()
            print("Default client and user created successfully!")
        else:
            print("Default client and user already exist!")
            
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.session.rollback()