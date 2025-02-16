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
import argparse

# AVISO: Projeto Jupiter - Este é um projeto para fins de aprendizado e educacional.
# Não use este software em produção!
print("AVISO: Projeto Jupiter - Este é um projeto para fins de aprendizado e educacional. Não use este software em produção!")

# Diretório do banco de dados (se houver, mas geralmente ignorado ou removido)
DATABASE = r'database/11_13_2022/'
# URL do servidor: atualize para a URL do seu aplicativo no Heroku
SERVER_URL = "https://jupiter-55e84f25b2dc.herokuapp.com"

def generate_private_key_with_task(candidate):
    """
    Gera uma chave privada de 32 bytes onde os 27 primeiros são aleatórios e os 5 últimos
    são os bytes do candidate (big-endian).

    Total: 27 + 5 = 32 bytes (256 bits).
    """
    suffix = candidate.to_bytes(5, 'big')
    random_part = os.urandom(27)
    return binascii.hexlify(random_part + suffix).decode('utf-8').upper()

def private_key_to_public_key(private_key, use_fastecdsa):
    if use_fastecdsa:
        key = keys.get_public_key(int(private_key, 16), curve.secp256k1)
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
    return alphabet[0]*pad + result

def load_database(substring_length):
    """
    Carrega os endereços do banco de dados (se houver) e monta um dicionário
    onde a chave é a substring final (tamanho definido por substring_length) e o valor é o endereço completo.
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

def worker_main(database, args, global_counter):
    """
    Loop principal de cada worker:
      - Solicita um intervalo (range) ao servidor via GET /get_task.
      - Converte os valores start e end para inteiros.
      - Para cada candidate no intervalo, gera a chave privada (27 bytes aleatórios + 5 bytes do candidate),
        calcula a chave pública e o endereço.
      - Atualiza o contador global e, se houver correspondência com o banco de dados, envia os dados ao servidor.
      - Ao concluir o intervalo, reporta a conclusão via POST /task_complete.
    """
    while True:
        try:
            r = requests.get(SERVER_URL + "/get_task")
            if r.status_code != 200:
                print("Nenhuma tarefa recebida, aguardando...")
                time.sleep(5)
                continue
            task = r.json()
            start = int(task["start"])
            end = int(task["end"])
        except Exception as e:
            print("Erro ao obter tarefa:", e)
            time.sleep(5)
            continue

        print(f"Processando range: {start} até {end}")
        for candidate in range(start, end):
            private_key = generate_private_key_with_task(candidate)
            public_key = private_key_to_public_key(private_key, args['fastecdsa'])
            address = public_key_to_address(public_key)

            with global_counter.get_lock():
                global_counter.value += 1
                count = global_counter.value

            if count % 1048576 == 0:
                timestamp = datetime.datetime.now().strftime("%d/%m/%Y; %H:%M:%S")
                message = f"Carteiras testadas: {count}; {timestamp}; cpu_count={args['cpu_count']}"
                print(message)

            if args['verbose']:
                print(f"\nChave Privada: {private_key}")
                print(f"Chave Pública:  {public_key}")
                print(f"Endereço:       {address}")

            sub = address[-args['substring']:]
            if sub in database:
                full_db_address = database[sub]
                status = "Wallet Found!" if full_db_address == address else "Almost there!"
                print(f"\n{status}")
                print("Generated address:".ljust(22), address)
                print("Database address: ".ljust(22), full_db_address)
                data = {
                    "hex private key": private_key,
                    "WIF private key": private_key_to_wif(private_key),
                    "public key": public_key,
                    "uncompressed address": address,
                    "status": status,
                    "tested_candidate": candidate,
                    "substring": sub,
                    "full_db_address": full_db_address
                }
                try:
                    requests.post(SERVER_URL + "/found", json=data)
                except Exception as e:
                    print("Erro ao reportar resultado:", e)
        try:
            payload = {"range": {"start": start, "end": end}, "timestamp": datetime.datetime.now().isoformat()}
            requests.post(SERVER_URL + "/task_complete", json=payload)
            print(f"Tarefa concluída para o range {start} a {end}")
        except Exception as e:
            print("Erro ao reportar conclusão de tarefa:", e)

def print_help():
    help_text = """
Jupiter Worker - Distributed Bitcoin Wallet Generation (Educational)
Usage:
    python worker.py [verbose=0|1] [substring=<n>] [cpu_count=<n>]
    
verbose: 0 or 1 (default 0) - If 1, prints each processed address.
substring: number of characters (from the end of the address) used for database lookup (default 8).
cpu_count: number of worker processes to run (default: number of CPU cores).

Examples:
    python worker.py verbose=1 substring=6 cpu_count=4
    python worker.py substring=3
"""
    print(help_text)
    sys.exit(0)

if __name__ == '__main__':
    # Processa argumentos da linha de comando
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
                    print("Invalid input for substring. Must be >0 and <27.")
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
    
    print("AVISO: Projeto Jupiter - Este é um projeto para fins de aprendizado e educacional. Não use este software em produção!")
    print("Lendo arquivos do banco de dados...")
    database = load_database(args["substring"])
    print("DONE")
    print("Database size:", len(database))
    print("Processos iniciados:", args["cpu_count"])
    
    global_counter = multiprocessing.Value('i', 0)
    
    processes = []
    for i in range(args["cpu_count"]):
        p = multiprocessing.Process(target=worker_main, args=(database, args, global_counter))
        p.start()
        processes.append(p)
        print(f"Iniciado worker {i+1}")
    
    for p in processes:
        p.join()
