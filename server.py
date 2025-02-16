# server.py
from flask import Flask, request, jsonify
import threading
import os
import datetime

app = Flask(__name__)

# AVISO: Projeto Jupiter - Este é um projeto para fins de aprendizado e educacional.
# Não use este software em produção!
print("AVISO: Projeto Jupiter - Este é um projeto para fins de aprendizado e educacional. Não use este software em produção!")

# Configuração da tarefa:
TASK_SIZE = 10000  # 10.000 candidatos por tarefa (ajustado para testes)
MAX_RANGE = 2**40  # Espaço total para o candidato (5 bytes): 1,099,511,627,776

# Ponteiro global para o próximo intervalo a ser distribuído
current_range_start = 0

# Arquivos para persistência
COMPLETED_TASKS_FILE = "tasks_completed.txt"
ASSIGNED_TASKS_FILE = "last_assigned_task.txt"
RESULTS_FILE = "resultados.txt"

# Lock para sincronização de acesso
task_lock = threading.Lock()

def load_last_assigned():
    global current_range_start
    if os.path.exists(ASSIGNED_TASKS_FILE):
        with open(ASSIGNED_TASKS_FILE, "r") as f:
            line = f.read().strip()
            if line:
                try:
                    current_range_start = int(line)
                except Exception as e:
                    print(f"Erro ao ler last_assigned_task.txt: {e}")
                    current_range_start = 0
    else:
        current_range_start = 0

def save_last_assigned(value):
    with open(ASSIGNED_TASKS_FILE, "w") as f:
        f.write(str(value))

# Carrega o último valor atribuído ao iniciar o servidor
load_last_assigned()

@app.route('/')
def index():
    return "Projeto Jupiter - Servidor online para processamento de carteiras. Use /get_task para obter uma tarefa."

@app.route('/get_task', methods=['GET'])
def get_task():
    """
    Distribui um intervalo (range) de tarefas para um worker.
    """
    global current_range_start
    with task_lock:
        if current_range_start >= MAX_RANGE:
            return jsonify({"message": "No more tasks available"}), 404
        start = current_range_start
        end = start + TASK_SIZE
        current_range_start = end
        save_last_assigned(current_range_start)
    print(f"Assigned task range: {start} to {end}")
    return jsonify({"start": str(start), "end": str(end)})

@app.route('/task_complete', methods=['POST'])
def task_complete():
    """
    Recebe e registra um intervalo concluído pelo worker.
    """
    data = request.json
    with open(COMPLETED_TASKS_FILE, "a") as f:
        f.write(f"{data['range']['start']},{data['range']['end']}\n")
    print("Completed task:", data)
    return jsonify({"message": "Task completion recorded"})

@app.route('/found', methods=['POST'])
def found():
    """
    Recebe os dados de uma carteira encontrada (ou quase encontrada) e grava os resultados
    no arquivo 'resultados.txt' com os campos alinhados.
    Se o arquivo não existir, cria-o com um cabeçalho.
    """
    data = request.json
    if not os.path.exists(RESULTS_FILE):
        header = (
            "#################### CABEÇALHO DE EXEMPLO ####################\n\n"
            "Exemplo de registro para Wallet Found!:\n"
            "*********************************************************************************************************************************************************\n"
            "*********************************************************************************************************************************************************\n"
            "*********************************************************************************************************************************************************\n"
            "*********************************************************************************************************************************************************\n"
            "*********************************************************************************************************************************************************\n\n"
            "########  #######  ##     ## ##    ## ########  \n"
            "##       ##     ## ##     ## ###   ## ##     ## \n"
            "##       ##     ## ##     ## ####  ## ##     ## \n"
            "######   ##     ## ##     ## ## ## ## ##     ## \n"
            "##       ##     ## ##     ## ##  #### ##     ## \n"
            "##       ##     ## ##     ## ##   ### ##     ## \n"
            "##        #######   #######  ##    ## ######## \n\n"
            "hex private key:      05A96B74204279A8A3D0F5A546EC04B578292C992C40078395030B0000001DC9\n"
            "WIF private key:      5HrnCp9FbfpHeLSXGbMNP22LLGDtF2k7yxcAdm9bzk5ighPxgKM\n"
            "public key:           042A67B2352A1A57269BA94BEAB8BAF799D5C76DF3A5AC5DEE2B108254BD1481761452D68473028AC7DDECE16D5ACBB131AECC072CF434A854D21D96C8B3959DFF\n"
            "Generated address:    1JRo3dhU2X5iisG1CacsvGx8AGa26fhD3p\n"
            "Database address:     1JRo3dhU2X5iisG1CacsvGx8AGa26fhD3p\n"
            "Wallet Found!\n"
            "*********************************************************************************************************************************************************\n\n"
            "Exemplo de registro para Almost there!:\n"
            "hex private key:      05A96B74204279A8A3D0F5A546EC04B578292C992C40078395030B0000001DC9\n"
            "WIF private key:      5HrnCp9FbfpHeLSXGbMNP22LLGDtF2k7yxcAdm9bzk5ighPxgKM\n"
            "public key:           042A67B2352A1A57269BA94BEAB8BAF799D5C76DF3A5AC5DEE2B108254BD1481761452D68473028AC7DDECE16D5ACBB131AECC072CF434A854D21D96C8B3959DFF\n"
            "Generated address:    1JRo3dhU2X5iisG1CacsvGx8AGa26fhD3p\n"
            "Database address:     1JRo3dhU2X5iisG1CacsvGx8AGa26fh999\n"
            "Almost there!\n\n"
        )
        with open(RESULTS_FILE, "w") as f:
            f.write(header)
    print(">>> Carteira encontrada:")
    generated_address = data.get("uncompressed address", "None")
    full_db_address = data.get("full_db_address", "None")
    print("Generated address:".ljust(22) + generated_address)
    print("Database address: ".ljust(22) + full_db_address)
    
    with open(RESULTS_FILE, "a") as f:
        if data.get("status") == "Wallet Found!":
            banner = (
                "\n" + "*" * 150 + "\n" +
                "*" * 150 + "\n" +
                "*" * 150 + "\n" +
                "*" * 150 + "\n" +
                "*" * 150 + "\n\n"
            )
            record = (
                f"hex private key:      {data.get('hex private key')}\n"
                f"WIF private key:      {data.get('WIF private key')}\n"
                f"public key:           {data.get('public key')}\n"
                f"Generated address:    {generated_address}\n"
                f"Database address:     {full_db_address}\n"
                f"{data.get('status')}\n"
            )
            f.write(banner + record + "*" * 150 + "\n")
        else:
            record = (
                "hex private key:      05A96B74204279A8A3D0F5A546EC04B578292C992C40078395030B0000001DC9\n"
                "WIF private key:      5HrnCp9FbfpHeLSXGbMNP22LLGDtF2k7yxcAdm9bzk5ighPxgKM\n"
                "public key:           042A67B2352A1A57269BA94BEAB8BAF799D5C76DF3A5AC5DEE2B108254BD1481761452D68473028AC7DDECE16D5ACBB131AECC072CF434A854D21D96C8B3959DFF\n"
                "Generated address:    1JRo3dhU2X5iisG1CacsvGx8AGa26fhD3p\n"
                "Database address:     1JRo3dhU2X5iisG1CacsvGx8AGa26fh999\n"
                "Almost there!\n\n"
            )
            f.write(record)
    return jsonify({"message": "Wallet result recorded"})

if __name__ == '__main__':
    app.run(debug=True)
