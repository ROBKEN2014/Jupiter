# worker.py
from fastecdsa import keys, curve
from ellipticcurve.privateKey import PrivateKey
import platform
import multiprocessing
import hashlib
import binascii
import os
import sys
import time
import datetime
import requests

# Exibe o aviso apenas no processo principal
if __name__ == '__main__':
    if multiprocessing.current_process().name == "MainProcess":
        print("AVISO: Projeto Jupiter - Este é um projeto para fins de aprendizado e educacional. Não use este software em produção!")

# Configurações
DATABASE = r'database/11_13_2022/'  # Caminho para o banco de dados
SERVER_URL = "https://jupiter-55e84f25b2dc.herokuapp.com"  # URL do servidor

def generate_private_key_with_task(candidate):
    """
    Gera uma chave privada de 32 bytes (256 bits):
    27 bytes aleatórios + 5 bytes representando o candidate (big-endian).
    """
    suffix = candidate.to_bytes(5, 'big')
    random_part = os.urandom(27)
    return binascii.hexlify(random_part + suffix).decode('utf-8').upper()

def private_key_to_public_key(private_key, use_fastecdsa):
    if use_fastecdsa:
        key = keys.get_public_key(int('0x' + private_key, 0), curve.secp256k1)
        x_str = hex(key.x)[2:].zfill(64)
        y_str = hex(key.y)[2:].zfill(64)
        return '04' + x_str + y_str
    else:
        pk = PrivateKey().fromString(private_key)
        return '04' + pk.publicKey().toString().upper()

def public_key_to_address(public_key):
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    ripemd160 = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    ripemd160.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + ripemd160.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + ripemd160.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count):
        output.append(alphabet[0])
    return ''.join(output[::-1])

def private_key_to_wif(private_key):
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = 0
    result = ''
    for i, c in enumerate(var[::-1]):
        value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result = alphabet[mod] + result
        value = div
    result = alphabet[value] + result
    pad = 0
    for c in var:
        if c == 0:
            pad += 1
        else:
            break
    return alphabet[0] * pad + result

def load_database(substring_length):
    """
    Carrega o banco de dados e retorna um dicionário com as últimas 'substring_length' letras de cada endereço.
    Se o diretório não existir ou o banco estiver vazio, o programa é encerrado.
    """
    database = {}
    if not os.path.isdir(DATABASE):
        print(f"Diretório do banco de dados não encontrado: {DATABASE}")
        return database
    for filename in os.listdir(DATABASE):
        file_path = os.path.join(DATABASE, filename)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r') as file:
                    for addr in file:
                        addr = addr.strip()
                        if addr.startswith('1'):
                            key = addr[-substring_length:]
                            database[key] = addr
            except Exception as e:
                print(f"Erro ao ler {file_path}: {e}")
    print(f"Banco de dados carregado: {len(database)} entradas.")
    return database

def process_subrange(sub_start, sub_end, processed_counter, substring, database, verbose):
    """
    Processa os candidatos no subrange:
      - Gera chave privada, converte para chave pública e endereço.
      - Verifica se os últimos caracteres do endereço estão no banco de dados.
      - Se houver correspondência, envia os dados para o servidor (endpoint /found).
    """
    for candidate in range(sub_start, sub_end):
        priv_key = generate_private_key_with_task(candidate)
        pub_key = private_key_to_public_key(priv_key, True)
        addr = public_key_to_address(pub_key)
        key = addr[-substring:]
        if key in database:
            full_db_address = database[key]
            status = "Wallet Found!" if full_db_address == addr else "Almost there!"
            print(f"\n{status} - Candidate: {candidate} - Address: {addr}")
            data = {
                "hex private key": priv_key,
                "WIF private key": private_key_to_wif(priv_key),
                "public key": pub_key,
                "uncompressed address": addr,
                "status": status,
                "tested_candidate": candidate,
                "substring": key,
                "full_db_address": full_db_address
            }
            try:
                requests.post(SERVER_URL + "/found", json=data)
            except Exception as e:
                print("Erro ao reportar resultado:", e)
        with processed_counter.get_lock():
            processed_counter.value += 1
        # Sem delay para manter a eficiência

def display_progress(processed_counter, total, step=5):
    """
    Exibe uma barra de progresso que atualiza a cada 'step' por cento, verificando a cada 0.5 segundos.
    """
    print("Monitor de progresso iniciado...")
    current_pct = 0
    while True:
        with processed_counter.get_lock():
            count = processed_counter.value
        pct = int((count / total) * 100)
        if pct >= current_pct + step:
            current_pct = pct - (pct % step)
            if current_pct > 100:
                current_pct = 100
            bar = "[" + "#" * (current_pct // step) + " " * ((100 - current_pct) // step) + "]"
            print(f"Progresso: {current_pct}% {bar}")
        if count >= total:
            break
        time.sleep(0.5)

def process_task(task, database, args):
    """
    Recebe uma tarefa (range) do servidor, divide o range entre os núcleos e processa cada subrange em paralelo.
    Exibe uma barra de progresso durante o processamento.
    """
    task_start = int(task["start"])
    task_end = int(task["end"])
    total_range = task_end - task_start
    print(f"Processando tarefa de {task_start} até {task_end} (total: {total_range} candidatos)")
    num_workers = args["cpu_count"]
    processed_counter = multiprocessing.Value('i', 0)
    subranges = []
    subrange_size = total_range // num_workers
    for i in range(num_workers):
        sub_start = task_start + i * subrange_size
        sub_end = task_end if i == num_workers - 1 else sub_start + subrange_size
        subranges.append((sub_start, sub_end))
    pool = multiprocessing.Pool(processes=num_workers)
    progress_proc = multiprocessing.Process(target=display_progress, args=(processed_counter, total_range))
    progress_proc.start()
    for sub in subranges:
        pool.apply_async(process_subrange, args=(sub[0], sub[1], processed_counter, args["substring"], database, args["verbose"]))
    pool.close()
    pool.join()
    progress_proc.join()
    print("Tarefa completa.")

def worker_main(database, args):
    """
    Loop principal do worker:
      - Obtém uma tarefa do servidor (via GET /get_task).
      - Processa o range recebido.
      - Reporta a conclusão da tarefa (via POST /task_complete).
      - Repete o processo.
    """
    while True:
        try:
            r = requests.get(SERVER_URL + "/get_task")
            if r.status_code != 200:
                print("Nenhuma tarefa recebida, aguardando...")
                time.sleep(5)
                continue
            task = r.json()
            print("Nova tarefa recebida:", task)
        except Exception as e:
            print("Erro ao obter tarefa:", e)
            time.sleep(5)
            continue
        process_task(task, database, args)
        try:
            payload = {"range": {"start": task["start"], "end": task["end"]}, "timestamp": datetime.datetime.now().isoformat()}
            requests.post(SERVER_URL + "/task_complete", json=payload)
            print("Tarefa reportada como concluída.")
        except Exception as e:
            print("Erro ao reportar conclusão de tarefa:", e)

def print_help():
    help_text = """
Jupiter Worker - Distributed Wallet Generation (Educational)
Usage:
    python worker.py [verbose=0|1] [substring=<n>] [cpu_count=<n>]

verbose: 0 or 1 (default 0) - If 1, prints detailed info.
substring: number of characters (from the end of the address) for database lookup (default 8).
cpu_count: number of processes to use (default: number of CPU cores).
"""
    print(help_text)
    sys.exit(0)

if __name__ == '__main__':
    args = {
        "verbose": 0,
        "substring": 8,
        "fastecdsa": platform.system() in ["Linux", "Darwin"],
        "cpu_count": multiprocessing.cpu_count()
    }
    for arg in sys.argv[1:]:
        key = arg.split('=')[0]
        value = arg.split('=')[1] if '=' in arg else None
        if key == "help":
            print_help()
        elif key == "verbose":
            if value in ["0", "1"]:
                args["verbose"] = int(value)
            else:
                print("Invalid input for verbose. Must be 0 or 1.")
                sys.exit(-1)
        elif key == "substring":
            try:
                substring = int(value)
                if 0 < substring < 27:
                    args["substring"] = substring
                else:
                    print("Invalid input for substring. Must be >0 and less than 27.")
                    sys.exit(-1)
            except:
                print("Invalid input for substring.")
                sys.exit(-1)
        elif key == "cpu_count":
            try:
                cpu_count = int(value)
                if 0 < cpu_count <= multiprocessing.cpu_count():
                    args["cpu_count"] = cpu_count
                else:
                    print("Invalid input for cpu_count. Must be >0 and <= " + str(multiprocessing.cpu_count()))
                    sys.exit(-1)
            except:
                print("Invalid input for cpu_count.")
                sys.exit(-1)
        else:
            print("Invalid input:", key, "\nRun 'python worker.py help' for usage")
            sys.exit(-1)
    
    print("Lendo arquivos do banco de dados...")
    database = load_database(args["substring"])
    if not database or len(database) == 0:
        print("Erro: Banco de dados não encontrado ou vazio. Encerrando o worker.")
        sys.exit(1)
    print("DONE")
    print("Database size:", len(database))
    print("Processos iniciados:", args["cpu_count"])
    
    # Executa o loop principal do worker
    worker_main(database, args)
