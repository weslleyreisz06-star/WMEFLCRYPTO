import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "troqueseu_secret_key_aqui"

    # Pega DATABASE_URL do Render, se não existir usa SQLite local
    uri = os.environ.get("DATABASE_URL") or "sqlite:///" + os.path.join(BASE_DIR, "app.db")

    # Corrige prefixo para compatibilidade com SQLAlchemy
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = uri
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Gerencianet (exemplo) - deve definir no ambiente
    GN_CLIENT_ID = os.environ.get("GN_CLIENT_ID")
    GN_CLIENT_SECRET = os.environ.get("GN_CLIENT_SECRET")
    GN_SANDBOX = os.environ.get("GN_SANDBOX", "true")  # "true" para testar
