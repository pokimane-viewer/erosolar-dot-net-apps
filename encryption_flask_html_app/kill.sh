ps aux | grep gunicorn | grep encryption | awk '{print $2}' | xargs kill -9
