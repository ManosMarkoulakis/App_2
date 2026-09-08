from waitress import serve
import os

if __package__:
    from .app import app
else:
    from app import app


if __name__ == "__main__":
    serve(app, host="0.0.0.0" if os.getenv("RENDER") else "127.0.0.1",
          port=int(os.getenv("PORT", "5000")), threads=1)
