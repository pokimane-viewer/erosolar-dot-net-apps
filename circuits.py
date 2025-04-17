app.secret_key = os.environ.get('FLASK_SECRET_KEY', ''.join(random.choices(string.ascii_letters + string.digits, k=32)))
