from app import app, db 
with app.app_context():
        try:
            db.drop_all()
            print("All tables dropped")
            
            # db.create_all()
            # print("Database initialized successfully.")
        except Exception as e:
            print(f"Error initializing database: {e}")