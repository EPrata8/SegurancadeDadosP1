# Sistema Seguro de Transporte de Dados

Aplicação desenvolvida para garantir a confidencialidade e a integridade no transporte de informações sensíveis entre Maricá e Niterói para o cliente Márcio. O sistema funciona como um "cofre digital" portátil baseado em árvores de busca binária e hashes criptográficos, permitindo uso offline direto de um pen drive.

---

## Equipe do Projeto

* Erick Prata: Project Manager (Gerente de Projeto) e Desenvolvedor.
* Daniel Tozato de Siqueira: Desenvolvedor e Tester.

---

## Gerenciamento do Projeto
Quadro de tarefas no Trello: https://trello.com/b/rwF0tjEK/sistema-seguro-de-transporte-de-dados-por-%C3%A1rvore-de-criptografia

---

## Tecnologias Utilizadas

* Python: Linguagem base para toda a lógica de criptografia e interface.
* Tkinter: Biblioteca nativa para a criação da interface gráfica corporativa.
* PyInstaller: Ferramenta de empacotamento para gerar o executável portátil (`.exe`), dispensando a instalação do Python na máquina de destino.
* Criptografia Baseada em Árvore (BST) & Merkle Trees: Lógica estruturada para geração de fluxos de bytes e validação de integridade.

---

## Como Executar e Compilar

Como o projeto utiliza exclusivamente bibliotecas nativas do Python (`os`, `hashlib`, `hmac`, `math`, `tkinter`), não é necessário instalar dependências externas (`requirements.txt`).

### 1. Rodar diretamente via código fonte:
```bash
python segurancadedadosp1.py