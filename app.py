import os
import base64
import qrcode
import io
import requests
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort, send_file
from flask_socketio import SocketIO
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from models import db, User, Transaction
from config import Config

# ---------- CONFIGURAÇÃO DO APP ----------
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
from flask_migrate import Migrate
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---------- USER LOADER ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- DECORADOR ADMIN ----------
def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not (
            getattr(current_user, "role", None) in [3, 4]  # 3=Administrador, 4=Supremo
        ):
            abort(403)
        return f(*args, **kwargs)
    return wrapped

# ---------- FUNÇÃO PARA GARANTIR SUPREMO ----------
def ensure_supreme_admin():
    admin_email = "cryptobrutal@gmail.com"
    try:
        user = User.query.filter_by(email=admin_email).first()
        if not user:
            hashed_password = generate_password_hash("123456", method="pbkdf2:sha256", salt_length=16)
            sup_user = User(
                name="Supremo",
                email=admin_email,
                password_hash=hashed_password,
                role=4,  # Supremo
                balance=0.0,
                has_deposited=True
            )
            db.session.add(sup_user)
            db.session.commit()
        else:
            user.role = 4  # Supremo
            db.session.commit()
    except Exception as e:
        print("ensure_supreme_admin error:", e)

# ---------- ROTAS PRINCIPAIS ----------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Preencha todos os campos", "warning")
            return render_template("login.html")

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash(f"Bem-vindo {user.email}!", "success")

            if user.email == "cryptobrutal@gmail.com":
                user.role = 4  # Supremo
                db.session.commit()

            return redirect(url_for("dashboard"))

        flash("Login inválido!", "danger")

    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not name or not email or not password or not confirm_password:
            flash("Preencha todos os campos.", "error")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("As senhas não coincidem.", "error")
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("E-mail já cadastrado.", "error")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        new_user = User(name=name, email=email, password_hash=hashed_password)

        if email == "cryptobrutal@gmail.com":
            new_user.role = 4  # Supremo

        db.session.add(new_user)
        db.session.commit()

        flash("Cadastro realizado com sucesso!", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# ---------- DASHBOARD ----------
@app.route("/dashboard")
@login_required
def dashboard():
    txs = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.created_at.desc()).all()
    coins = {
        "bitcoin": "Bitcoin",
        "ethereum": "Ethereum",
        "tether": "Tether",
        "binancecoin": "Binance Coin",
        "cardano": "Cardano"
    }

    prices = {}
    try:
        ids = ','.join(coins.keys())
        url = f"https://api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=brl"
        resp = requests.get(url, timeout=10).json()
        for cid in coins.keys():
            prices[cid] = resp.get(cid, {}).get("brl", 0.0)
    except Exception as e:
        print("Erro ao buscar preços:", e)
        for cid in coins.keys():
            prices[cid] = 0.0

    return render_template("dashboard.html", user=current_user, txs=txs, coins=coins, prices=prices)

# ---------- ROTA ADMIN ----------
@app.route("/admin")
@login_required
@admin_required
def admin_index():
    users = User.query.order_by(User.created_at.desc()).all()
    txs = Transaction.query.order_by(Transaction.created_at.desc()).limit(50).all()
    roles = ["Supremo", "Administrador", "Moderador Global", "Moderador de Site", "User"]
    return render_template("admin.html", users=users, txs=txs, roles=roles)

@app.route("/admin/add_balance", methods=["POST"])
@login_required
@admin_required
def admin_add_balance():
    user_id = request.form.get("user_id")
    amount = request.form.get("amount")
    try:
        amount = float(amount)
    except:
        flash("Valor inválido", "danger")
        return redirect(url_for("admin_index"))

    user = User.query.get(user_id)
    if not user:
        flash("Usuário não encontrado", "danger")
        return redirect(url_for("admin_index"))

    user.balance += amount
    if amount > 0:
        user.has_deposited = True
    tx = Transaction(user_id=user.id, amount=amount, type="admin_credit", status="paid", extra="Crédito manual pelo admin")
    db.session.add(tx)
    db.session.commit()
    flash(f"R$ {amount:.2f} creditados para {user.email} com sucesso!", "success")
    return redirect(url_for("admin_index"))

@app.route("/admin/grant_admin", methods=["POST"])
@login_required
@admin_required
def admin_grant_admin():
    user_id = request.form.get("user_id")
    user = User.query.get(user_id)
    if not user:
        flash("Usuário não encontrado", "danger")
        return redirect(url_for("admin_index"))

    user.role = 3  # Administrador
    db.session.commit()
    flash(f"{user.email} agora é admin!", "success")
    return redirect(url_for("admin_index"))

@app.route("/admin/set_role", methods=["POST"])
@login_required
@admin_required
def admin_set_role():
    user_id = request.form.get("user_id")
    role = request.form.get("role")
    allowed_roles = ["Supremo", "Administrador", "Moderador Global", "Moderador de Site", "User"]
    if role not in allowed_roles:
        flash("Cargo inválido", "danger")
        return redirect(url_for("admin_index"))

    user = User.query.get(user_id)
    if not user:
        flash("Usuário não encontrado", "danger")
        return redirect(url_for("admin_index"))

    current_role_name = getattr(current_user, "role", None)
    if role == "Supremo" and current_role_name != 4:
        flash("Apenas um usuário Supremo pode atribuir o cargo Supremo.", "danger")
        return redirect(url_for("admin_index"))

    mapping = {"User":0,"Moderador de Site":1,"Moderador Global":2,"Administrador":3,"Supremo":4}
    user.role = mapping.get(role, 0)
    db.session.commit()
    flash(f"Cargo de {user.email} alterado para {role}.", "success")
    return redirect(url_for("admin_index"))

# ---------- PROFILE ----------
@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    if request.method == "POST":
        pix_key = request.form.get("pix_key")
        pix_holder = request.form.get("pix_holder")
        phone = request.form.get("phone")
        if pix_key:
            current_user.pix_key = pix_key.strip()
        if pix_holder:
            current_user.pix_holder = pix_holder.strip()
        if phone:
            current_user.phone_number = phone.strip()
        db.session.commit()
        flash("Dados de pagamento atualizados.","success")
        return redirect(url_for("profile"))

    txs = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.created_at.desc()).limit(10).all()
    return render_template("profile.html", user=current_user, txs=txs)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Você saiu da conta.","info")
    return redirect(url_for("login"))

# ---------- DEPOSITO PIX / QR CODE ----------
PIX_KEY = "0a02a292-39ae-4b7c-89fc-b889fb970a05"  # SUA CHAVE PIX MANTIDA

def generate_pix_payload(amount: float):
    """
    Gera payload PIX funcional compatível com todos os bancos.
    """
    merchant_name = "WMEFL CRYPTO"
    city = "SAO PAULO"
    valor_str = f"{amount:.2f}"

    # Payload EMV
    payload = (
        "000201" +
        "26580014BR.GOV.BCB.PIX" +
        f"01{len(PIX_KEY):02d}{PIX_KEY}" +
        "52040000" +
        "5303986" +
        f"54{valor_str}" +
        "5802BR" +
        f"59{len(merchant_name):02d}{merchant_name}" +
        f"60{len(city):02d}{city}" +
        "62290525REC" +  # Additional Data
        "6304"
    )

    # CRC16 CCITT
    def crc16_ccitt(data: bytes, poly=0x1021, init_val=0xFFFF):
        crc = init_val
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ poly) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc

    crc = crc16_ccitt(payload.encode("utf-8"))
    payload += f"{crc:04X}"
    return payload

@app.route("/deposito", methods=["GET","POST"])
@login_required
def deposito():
    qr_img = None
    payload = None
    amount = None

    if request.method == "POST":
        try:
            amount = float(request.form.get("amount",0))
        except:
            flash("Valor inválido","danger")
            return redirect(url_for("deposito"))

        if amount < 22.90:
            flash("O depósito mínimo é de R$22,90.","warning")
            return redirect(url_for("deposito"))

        payload = generate_pix_payload(amount)

        # Salvar transação
        tx = Transaction(user_id=current_user.id, amount=amount, type="deposit", status="pending", extra="PIX aguardando pagamento")
        db.session.add(tx)
        db.session.commit()

        # QR code Premium
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#FF5A5F", back_color="#1E1E2F")
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_img = base64.b64encode(buffered.getvalue()).decode("utf-8")

        return render_template("deposito_confirm.html", pix_key=PIX_KEY, qr_img=qr_img, payload=payload, amount=amount)

    # GET: valor mínimo
    payload = generate_pix_payload(22.90)
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#FF5A5F", back_color="#1E1E2F")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_img = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return render_template("deposito.html", pix_key=PIX_KEY, qr_img=qr_img, payload=payload, amount=22.90)

# ---------- SAQUE ----------
@app.route("/wallet/withdraw", methods=["POST"])
@login_required
def wallet_withdraw():
    try:
        amount=float(request.form.get("amount",0))
    except:
        amount=0
    if not getattr(current_user,"has_deposited",False):
        flash("Você precisa realizar um depósito (mínimo R$22,90) antes de solicitar saque.","danger")
        return redirect(url_for("profile"))
    if amount<=0 or amount>current_user.balance:
        flash("Valor inválido ou saldo insuficiente.","danger")
        return redirect(url_for("profile"))
    tx = Transaction(user_id=current_user.id, amount=amount, type="withdraw", status="under_review", extra="Solicitação em análise")
    db.session.add(tx)
    db.session.commit()
    flash("Solicitação de saque enviada. Aguarde a análise.","info")
    return redirect(url_for("profile"))

# ---------- RUN ----------
if __name__ == "__main__":
    try:
        with app.app_context():
            ensure_supreme_admin()
    except Exception as e:
        print("Erro ao garantir supremo admin no startup:", e)

    # Para Render, use host padrão e debug=False
    port = int(os.environ.get("PORT", 5000))
    with app.app_context():
        db.create_all()  # Cria as tabelas no PostgreSQL do Render
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
