# Escolhe a versão do Python
FROM python:3.12-slim

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia o requirements.txt para dentro do container
COPY requirements.txt .

# Instala dependências do sistema necessárias
RUN apt-get update && apt-get install -y \
    libpq-dev build-essential \
 && rm -rf /var/lib/apt/lists/*

# Atualiza pip e instala os pacotes do requirements
RUN pip install --upgrade pip setuptools wheel
RUN pip install -r requirements.txt

# Copia todo o restante do projeto
COPY . .

# Expõe a porta que o Flask vai rodar
EXPOSE 5000

# Comando para iniciar o app
CMD ["python", "app.py"]
