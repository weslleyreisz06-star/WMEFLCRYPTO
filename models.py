from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

# Hierarquia de cargos
ROLES = {
    0: "Usuário",
    1: "Moderador de Site",
    2: "Moderador Global",
    3: "Administrador",
    4: "Supremo",
}

# Permissões por cargo
ROLE_PERMISSIONS = {
    "Usuário": ["deposit", "withdraw"],
    "Moderador de Site": ["view_users", "view_txs"],
    "Moderador Global": ["view_users", "view_txs", "warn_users"],
    "Administrador": ["add_balance", "grant_roles", "view_users", "view_txs"],
    "Supremo": ["full_access"],  # acesso total
}


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    balance = db.Column(db.Float, default=0.0, nullable=False)

    # Cargo do usuário (0 = comum, 4 = supremo)
    role = db.Column(db.Integer, default=0, nullable=False)

    has_deposited = db.Column(db.Boolean, default=False, nullable=False)

    # Informações PIX para saque e depósito
    pix_key = db.Column(db.String(200), nullable=True)
    pix_holder = db.Column(db.String(120), nullable=True)  # nome do titular PIX
    phone_number = db.Column(db.String(20), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw, method="pbkdf2:sha256", salt_length=16)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

    @property
    def role_name(self) -> str:
        return ROLES.get(self.role, "Usuário")

    @property
    def is_admin(self) -> bool:
        return self.role in [3, 4]

    @is_admin.setter
    def is_admin(self, value: bool):
        if value:
            if self.role < 3:
                self.role = 3
        else:
            if self.role in [3, 4]:
                self.role = 0

    def has_permission(self, permission: str) -> bool:
        if self.role_name == "Supremo":
            return True
        return permission in ROLE_PERMISSIONS.get(self.role_name, [])


class Transaction(db.Model):
    __tablename__ = "transaction"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # deposit, withdraw, admin_credit
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending, paid, failed, under_review
    external_id = db.Column(db.String(200), nullable=True)  # ID retornado pelo provedor
    extra = db.Column(db.Text, nullable=True)  # dados adicionais (ex: payload PIX, QR Code)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", backref="transactions")
