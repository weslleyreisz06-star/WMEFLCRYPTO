from app import app
from models import db, User

with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="teste@local").first():
        u = User(email="teste@local", name="Usuário Teste")
        u.set_password("123456")
        u.balance = 43549.00
        db.session.add(u)
        db.session.commit()
        print("Usuário teste criado: teste@local / 123456")
    else:
        print("Usuário já existe")
