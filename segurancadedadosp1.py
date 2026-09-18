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

