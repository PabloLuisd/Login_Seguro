import os
import sqlite3
import time
import secrets
import hashlib
from functools import wraps
from flask import Flask, request, redirect, session, flash, render_template_string, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "chave-local-troque-antes-de-publicar")
DB_PATH = os.environ.get("DATABASE_PATH", "/data/login.db")

MAX_TENTATIVAS = 5
BLOQUEIO_SEGUNDOS = 15 * 60
TOKEN_SEGUNDOS = 15 * 60

# Páginas HTML simples, mantidas dentro deste arquivo para facilitar o projeto.
HTML = """
<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login Seguro</title>
<style>
body{font-family:Arial,sans-serif;background:#f2f5f9;margin:0;padding:24px}
main{max-width:420px;margin:45px auto;background:white;padding:28px;border-radius:10px;box-shadow:0 4px 15px #0001}
h1,h2{text-align:center;color:#1769aa}
label{display:block;margin:14px 0 6px}
input{box-sizing:border-box;width:100%;padding:11px;border:1px solid #ccc;border-radius:5px}
button{width:100%;padding:12px;margin-top:18px;background:#1769aa;color:white;border:0;border-radius:5px;cursor:pointer}
a{color:#1769aa}
.msg{background:#eaf3ff;padding:10px;border-radius:5px;margin:10px 0}
</style>
</head>
<body><main>
<h1>Login Seguro</h1>
{% for m in get_flashed_messages() %}<div class="msg">{{m}}</div>{% endfor %}
{{ conteudo|safe }}
</main></body></html>
"""

def conectar():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def inicializar_banco():
    with conectar() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS usuarios(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                senha_hash TEXT NOT NULL,
                token_hash TEXT,
                token_expira REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tentativas(
                email TEXT PRIMARY KEY,
                quantidade INTEGER NOT NULL DEFAULT 0,
                bloqueado_ate REAL NOT NULL DEFAULT 0
            )
        """)

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

def validar_csrf():
    enviado = request.form.get("csrf_token", "")
    salvo = session.get("csrf_token", "")
    return bool(enviado and salvo and secrets.compare_digest(enviado, salvo))

def formulario(campos, botao, abaixo=""):
    # O conteúdo do formulário é inserido como HTML pronto (safe),
    # então o token precisa ser colocado aqui diretamente.
    html = (
        '<form method="post">'
        f'<input type="hidden" name="csrf_token" value="{csrf_token()}">'
    )
    for nome, rotulo, tipo in campos:
        html += f'<label>{rotulo}</label><input name="{nome}" type="{tipo}" required>'
    html += f'<button type="submit">{botao}</button></form>{abaixo}'
    return html

@app.context_processor
def disponibilizar_csrf():
    return {"csrf": csrf_token()}

@app.route("/")
def inicio():
    return redirect(url_for("login"))

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    abaixo = '<p>Já tem conta? <a href="/login">Entrar</a></p>'
    conteudo = "<h2>Criar conta</h2>" + formulario(
        [("nome", "Nome", "text"), ("email", "E-mail", "email"), ("senha", "Senha (mínimo 8 caracteres)", "password")],
        "Cadastrar", abaixo
    )
    if request.method == "POST":
        if not validar_csrf():
            flash("Formulário inválido. Atualize a página e tente novamente.")
            return redirect(url_for("cadastro"))
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        if not nome or not email or len(senha) < 8:
            flash("Informe nome, e-mail válido e senha com pelo menos 8 caracteres.")
        else:
            try:
                with conectar() as conn:
                    conn.execute(
                        "INSERT INTO usuarios(nome,email,senha_hash) VALUES(?,?,?)",
                        (nome, email, generate_password_hash(senha, method="scrypt"))
                    )
                flash("Cadastro realizado! Faça login.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Este e-mail já está cadastrado.")
    return render_template_string(HTML, conteudo=conteudo)

@app.route("/login", methods=["GET", "POST"])
def login():
    abaixo = '<p><a href="/cadastro">Criar conta</a></p><p><a href="/recuperar">Esqueci minha senha</a></p>'
    conteudo = "<h2>Entrar</h2>" + formulario(
        [("email", "E-mail", "email"), ("senha", "Senha", "password")],
        "Entrar", abaixo
    )
    if request.method == "POST":
        if not validar_csrf():
            flash("Formulário inválido. Atualize a página e tente novamente.")
            return redirect(url_for("login"))
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        agora = time.time()

        with conectar() as conn:
            tentativa = conn.execute(
                "SELECT quantidade,bloqueado_ate FROM tentativas WHERE email=?", (email,)
            ).fetchone()
            if tentativa and tentativa["bloqueado_ate"] > agora:
                flash("Muitas tentativas. Aguarde 15 minutos.")
                return redirect(url_for("login"))

            usuario = conn.execute("SELECT * FROM usuarios WHERE email=?", (email,)).fetchone()
            if usuario and check_password_hash(usuario["senha_hash"], senha):
                conn.execute("DELETE FROM tentativas WHERE email=?", (email,))
                session.clear()
                session["usuario_id"] = usuario["id"]
                session["usuario_nome"] = usuario["nome"]
                return redirect(url_for("painel"))

            qtd = (tentativa["quantidade"] if tentativa else 0) + 1
            bloqueado_ate = agora + BLOQUEIO_SEGUNDOS if qtd >= MAX_TENTATIVAS else 0
            conn.execute("""
                INSERT INTO tentativas(email,quantidade,bloqueado_ate) VALUES(?,?,?)
                ON CONFLICT(email) DO UPDATE SET
                quantidade=excluded.quantidade,bloqueado_ate=excluded.bloqueado_ate
            """, (email, qtd, bloqueado_ate))
        flash("E-mail ou senha inválidos.")
    return render_template_string(HTML, conteudo=conteudo)

@app.route("/painel")
def painel():
    if "usuario_id" not in session:
        flash("Faça login para acessar.")
        return redirect(url_for("login"))
    conteudo = f"""
    <h2>Área protegida</h2>
    <p>Bem-vindo, {session.get('usuario_nome', 'usuário')}!</p>
    <p>Você entrou no sistema com sucesso.</p>
    <p><a href="/sair">Sair</a></p>
    """
    return render_template_string(HTML, conteudo=conteudo)

@app.route("/sair")
def sair():
    session.clear()
    flash("Você saiu do sistema.")
    return redirect(url_for("login"))

@app.route("/recuperar", methods=["GET", "POST"])
def recuperar():
    abaixo = '<p><a href="/login">Voltar ao login</a></p>'
    conteudo = "<h2>Recuperar senha</h2>" + formulario(
        [("email", "E-mail cadastrado", "email")], "Gerar link de recuperação", abaixo
    )
    if request.method == "POST":
        if not validar_csrf():
            flash("Formulário inválido. Atualize a página.")
            return redirect(url_for("recuperar"))
        email = request.form.get("email", "").strip().lower()
        with conectar() as conn:
            usuario = conn.execute("SELECT id FROM usuarios WHERE email=?", (email,)).fetchone()
            # Mensagem genérica para não revelar se o e-mail existe.
            flash("Se o e-mail estiver cadastrado, o link de recuperação foi gerado.")
            if usuario:
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                conn.execute(
                    "UPDATE usuarios SET token_hash=?,token_expira=? WHERE id=?",
                    (token_hash, time.time() + TOKEN_SEGUNDOS, usuario["id"])
                )
                # Demonstração acadêmica: o link aparece na tela.
                # Em produção, envie o link ao e-mail do usuário.
                conteudo += f'<p><strong>Link de demonstração:</strong><br><a href="/redefinir/{token}">Redefinir senha</a></p>'
    return render_template_string(HTML, conteudo=conteudo)

@app.route("/redefinir/<token>", methods=["GET", "POST"])
def redefinir(token):
    conteudo = "<h2>Definir nova senha</h2>" + formulario(
        [("senha", "Nova senha (mínimo 8 caracteres)", "password")],
        "Alterar senha",
        '<p><a href="/login">Voltar ao login</a></p>'
    )
    if request.method == "POST":
        if not validar_csrf():
            flash("Formulário inválido. Atualize a página.")
            return redirect(url_for("redefinir", token=token))
        senha = request.form.get("senha", "")
        if len(senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.")
        else:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            with conectar() as conn:
                usuario = conn.execute(
                    "SELECT id FROM usuarios WHERE token_hash=? AND token_expira>?",
                    (token_hash, time.time())
                ).fetchone()
                if usuario:
                    conn.execute(
                        "UPDATE usuarios SET senha_hash=?,token_hash=NULL,token_expira=NULL WHERE id=?",
                        (generate_password_hash(senha, method="scrypt"), usuario["id"])
                    )
                    flash("Senha alterada com sucesso. Faça login.")
                    return redirect(url_for("login"))
            flash("Token inválido ou expirado.")
    return render_template_string(HTML, conteudo=conteudo)

if __name__ == "__main__":
    inicializar_banco()
    app.run(host="0.0.0.0", port=5000, debug=False)
