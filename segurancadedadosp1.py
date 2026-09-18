import os
import hashlib
import hmac
import math
import tkinter as tk
from tkinter import messagebox, filedialog

BLOCO = 32
TSALT = 16
TRAIZ = 32
TAUT = 32

class No:
    def __init__(self, valor):
        self.valor = valor
        self.esquerda = None
        self.direita = None

def inserir(raiz, valor):
    if raiz is None:
        return No(valor)
    if valor < raiz.valor:
        raiz.esquerda = inserir(raiz.esquerda, valor)
    elif valor > raiz.valor:
        raiz.direita = inserir(raiz.direita, valor)
    # Se o valor for igual, ele apenas retorna o nó existente, evitando duplicatas e falhas
    return raiz

def montar_arvore(chave):
    raiz = None
    for valor in chave:
        raiz = inserir(raiz, valor)
    return raiz

def fluxo_bloco(raiz, tamanho):
    fluxo = bytearray()
    for i in range(tamanho):
        no = raiz
        bits = bin(i)[2:].zfill(5)
        for b in bits:
            if no is not None:
                no = no.esquerda if b == "0" else no.direita
        if no is None:
            no = raiz
        fluxo.append(no.valor & 0xFF)
    return bytes(fluxo)

def derivar_master(senha, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        100000
    )

def gerar_fluxo(tamanho, senha, salt):
    master = derivar_master(senha, salt)
    fluxo = bytearray()
    contador = 0
    while len(fluxo) < tamanho:
        chave_bloco = list(
            hashlib.sha256(
                master + contador.to_bytes(4, "big")
            ).digest()
        )
        raiz = montar_arvore(chave_bloco)
        restante = min(BLOCO, tamanho - len(fluxo))
        fluxo += fluxo_bloco(raiz, restante)
        contador += 1
    return bytes(fluxo)

def xor_bytes(dados, senha, salt):
    ks = gerar_fluxo(len(dados), senha, salt)
    return bytes(
        b ^ k
        for b, k in zip(dados, ks)
    )

def raiz_merkle(dados):
    n_blocos = max(
        1,
        math.ceil(len(dados) / BLOCO)
    )
    nivel = [
        hashlib.sha256(
            dados[i * BLOCO:(i + 1) * BLOCO]
        ).digest()
        for i in range(n_blocos)
    ]
    while len(nivel) > 1:
        proximo = []
        for i in range(0, len(nivel), 2):
            esq = nivel[i]
            dir_val = (
                nivel[i + 1]
                if i + 1 < len(nivel)
                else esq
            )
            proximo.append(
                hashlib.sha256(
                    esq + dir_val
                ).digest()
            )
        nivel = proximo
    return nivel[0]

def gerar_autenticacao(cifrado, senha, salt):
    chave = derivar_master(senha, salt)
    return hmac.new(
        chave,
        salt + raiz_merkle(cifrado) + cifrado,
        hashlib.sha256
    ).digest()

def criptografar(dados, senha):
    salt = os.urandom(TSALT)
    cifrado = xor_bytes(
        dados,
        senha,
        salt
    )
    raiz = raiz_merkle(cifrado)
    aut = gerar_autenticacao(
        cifrado,
        senha,
        salt
    )
    return salt + raiz + aut + cifrado

def descriptografar(pacote, senha):
    tamanho_minimo = TSALT + TRAIZ + TAUT
    if len(pacote) < tamanho_minimo:
        raise ValueError(
            "O arquivo parece incompleto ou corrompido."
        )
    salt = pacote[:TSALT]
    inicio_raiz = TSALT
    fim_raiz = inicio_raiz + TRAIZ
    raiz_salva = pacote[inicio_raiz:fim_raiz]
    inicio_aut = fim_raiz
    fim_aut = inicio_aut + TAUT
    aut_salva = pacote[inicio_aut:fim_aut]
    cifrado = pacote[fim_aut:]
    raiz_calculada = raiz_merkle(cifrado)
    if not hmac.compare_digest(
        raiz_calculada,
        raiz_salva
    ):
        raise ValueError(
            "O arquivo foi alterado ou corrompido."
        )
    aut_calculada = gerar_autenticacao(
        cifrado,
        senha,
        salt
    )
    if not hmac.compare_digest(
        aut_calculada,
        aut_salva
    ):
        raise ValueError(
            "Senha incorreta ou arquivo inválido."
        )
    return xor_bytes(
        cifrado,
        senha,
        salt
    )

class JanelaApp:
    def __init__(self, raiz):
        self.raiz = raiz
        self.raiz.title("Tree Crypt — Cofre Digital Seguro")
        self.raiz.geometry("540x600")
        self.raiz.config(bg="#1e293b")

        titulo_topo = tk.Label(
            raiz,
            text="🔒 Sistema de Segurança de Dados",
            bg="#1e293b",
            fg="#f8fafc",
            font=("Segoe UI", 14, "bold")
        )
        titulo_topo.pack(pady=(15, 5))

        sub_topo = tk.Label(
            raiz,
            text="Transporte Seguro entre Maricá e Niterói",
            bg="#1e293b",
            fg="#94a3b8",
            font=("Segoe UI", 9)
        )
        sub_topo.pack(pady=(0, 15))

        frame_principal = tk.Frame(raiz, bg="#0f172a", bd=2, relief="flat")
        frame_principal.pack(padx=20, pady=5, fill="both", expand=True)

        rotulo_mensagem = tk.Label(
            frame_principal,
            text="Mensagem Confidencial:",
            bg="#0f172a",
            fg="#e2e8f0",
            font=("Segoe UI", 10, "bold")
        )
        rotulo_mensagem.pack(anchor="w", padx=15, pady=(15, 5))

        self.campo_mensagem = tk.Text(
            frame_principal,
            height=7,
            width=50,
            font=("Segoe UI", 10),
            bg="#1e293b",
            fg="#f8fafc",
            insertbackground="white",
            relief="flat",
            bd=5
        )
        self.campo_mensagem.pack(padx=15, pady=5)

        rotulo_senha = tk.Label(
            frame_principal,
            text="Senha Mestre do Cofre:",
            bg="#0f172a",
            fg="#e2e8f0",
            font=("Segoe UI", 10, "bold")
        )
        rotulo_senha.pack(anchor="w", padx=15, pady=(15, 5))

        self.campo_senha = tk.Entry(
            frame_principal,
            show="*",
            width=42,
            font=("Segoe UI", 11),
            bg="#1e293b",
            fg="#f8fafc",
            insertbackground="white",
            relief="flat",
            bd=5
        )
        self.campo_senha.pack(anchor="w", padx=15, pady=5)

        botao_cripto = tk.Button(
            frame_principal,
            text="🔒 Criptografar e Salvar no Pendrive",
            bg="#10b981",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            activebackground="#059669",
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            command=self.acao_criptografar
        )
        botao_cripto.pack(fill="x", padx=15, pady=(20, 10))

        botao_decripto = tk.Button(
            frame_principal,
            text="📂 Abrir Arquivo Seguro (.enc)",
            bg="#3b82f6",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            activebackground="#2563eb",
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            command=self.acao_descriptografar
        )
        botao_decripto.pack(fill="x", padx=15, pady=(0, 20))

    def acao_criptografar(self):
        texto = self.campo_mensagem.get(
            "1.0",
            tk.END
        ).strip()
        senha = self.campo_senha.get()

        if not texto:
            messagebox.showerror(
                "Atenção",
                "Escreva alguma mensagem para criptografar."
            )
            return

        if not senha:
            messagebox.showerror(
                "Atenção",
                "Digite uma senha mestre para proteger os dados."
            )
            return

        destino = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[
                (
                    "Arquivo Criptografado",
                    "*.enc"
                )
            ],
            title="Salvar arquivo no pendrive"
        )

        if destino:
            try:
                pacote = criptografar(
                    texto.encode("utf-8"),
                    senha
                )
                with open(
                    destino,
                    "wb"
                ) as arquivo:
                    arquivo.write(pacote)
                messagebox.showinfo(
                    "Sucesso",
                    f"Mensagem protegida salva com sucesso em:\n{destino}"
                )
                self.campo_mensagem.delete(
                    "1.0",
                    tk.END
                )
                self.campo_senha.delete(
                    0,
                    tk.END
                )
            except Exception as e:
                messagebox.showerror(
                    "Erro",
                    f"Não foi possível salvar: {e}"
                )

    def acao_descriptografar(self):
        senha = self.campo_senha.get()
        if not senha:
            messagebox.showerror(
                "Atenção",
                "Digite a senha mestre para abrir o arquivo."
            )
            return

        origem = filedialog.askopenfilename(
            filetypes=[
                (
                    "Arquivo Criptografado",
                    "*.enc"
                )
            ],
            title="Selecionar arquivo no pendrive"
        )

        if origem:
            try:
                with open(
                    origem,
                    "rb"
                ) as arquivo:
                    pacote = arquivo.read()
                dados = descriptografar(
                    pacote,
                    senha
                )
                self.campo_mensagem.delete(
                    "1.0",
                    tk.END
                )
                self.campo_mensagem.insert(
                    "1.0",
                    dados.decode("utf-8")
                )
                messagebox.showinfo(
                    "Sucesso",
                    "Mensagem aberta e recuperada com sucesso!"
                )
            except Exception as e:
                messagebox.showerror(
                    "Erro de Abertura",
                    f"Falha ao descriptografar:\n{e}"
                )

def principal():
    raiz = tk.Tk()
    app = JanelaApp(raiz)
    raiz.mainloop()

if __name__ == "__main__":
    principal()