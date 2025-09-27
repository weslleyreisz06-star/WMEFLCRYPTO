import psycopg2

# Substitua pelos seus dados do Render
DATABASE_URL = "postgresql://usuario:senha@host:5432/wmefl_crypto_db"

try:
    # Conecta ao banco
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    print("Conexão bem-sucedida!")

    # Solicita o ID da conta que deseja apagar
    conta_id = int(input("Digite o ID da conta que deseja apagar: "))

    # Confirmação antes de apagar
    confirm = input(f"Tem certeza que deseja apagar a conta {conta_id}? (s/n): ")
    if confirm.lower() == 's':
        cur.execute("DELETE FROM contas WHERE id = %s", (conta_id,))
        conn.commit()
        print(f"Conta {conta_id} apagada com sucesso!")
    else:
        print("Operação cancelada.")

    cur.close()
    conn.close()
except Exception as e:
    print("Erro:", e)
