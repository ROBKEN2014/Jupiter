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
DATABASE = r'database/11_13_2022/'  # Caminho correto para o banco de dados
SERVER_URL = "https://jupiter-55e84f25b2dc.herokuapp.com"  # URL do servidor

def generate_private_key():
    # Gera 32 bytes aleatórios (256 bits) e os converte para uma string hexadecimal
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key, use_fastecdsa):
    if use_fastecdsa:
        key = keys.get_public_key(int('0x' + private_key, 0), curve.secp256k1)
        return '04' + (hex(key.x)[2:] + hex(key.y)[2:]).zfill(128)
    else:
        pk = PrivateKey().fromString(private_key)
        return '04' + pk.publicKey().toString().upper()

def public_key_to_address(public_key):
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
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
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]):
        value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for c in var:
        if c == 0:
            pad += 1
        else:
            break
    return chars[0] * pad + result

def main(database, args, global_counter):
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key, args['fastecdsa'])
        address = public_key_to_address(public_key)

        # Incrementa o contador global de forma segura
        with global_counter.get_lock():
            global_counter.value += 1
            count = global_counter.value

        # Imprime e grava progresso a cada 1.048.576 chaves
        if count % 1048576 == 0:
            timestamp = datetime.datetime.now().strftime("%d/%m/%Y; %H:%M:%S")
            message = f"Carteiras testadas: {count}; {timestamp}; cpu_count={args['cpu_count']}"
            print(message)
            with open("processamento.txt", "a") as proc_file:
                proc_file.write(message + "\n")

        if args['verbose']:
            print(f"\nChave Privada: {private_key}")
            print(f"Chave Pública:  {public_key}")
            print(f"Endereço:       {address}")

        sub = address[-args['substring']:]
        if sub in database:
            full_db_address = database[sub]
            if full_db_address == address:
                with open('resultados.txt', 'a') as f:
                    f.write('hex private key: ' + private_key + '\n' +
                            'WIF private key: ' + private_key_to_wif(private_key) + '\n' +
                            'public key: ' + public_key + '\n' +
                            'uncompressed address: ' + address + '\n' +
                            'Wallet Found!\n\n')
                print("\nWallet Found! Database address: " + full_db_address)
            else:
                with open('resultados.txt', 'a') as f:
                    f.write('hex private key: ' + private_key + '\n' +
                            'WIF private key: ' + private_key_to_wif(private_key) + '\n' +
                            'public key: ' + public_key + '\n' +
                            'uncompressed address: ' + address + '\n' +
                            'Almost there!\n\n')
                print("\nAlmost there! Generated address: " + address + "\nDatabase address: " + full_db_address)

if __name__ == '__main__':
    # Configuração dos parâmetros padrão
    args = {
        'verbose': 0,
        'substring': 8,
        'fastecdsa': platform.system() in ['Linux', 'Darwin'],
        'cpu_count': multiprocessing.cpu_count()
    }
    
    for arg in sys.argv[1:]:
        command = arg.split('=')[0]
        if command == 'help':
            print("Usage: python worker.py [verbose=0|1] [substring=<n>] [cpu_count=<n>]")
            sys.exit(0)
        elif command == 'cpu_count':
            cpu_count = int(arg.split('=')[1])
            if cpu_count > 0 and cpu_count <= multiprocessing.cpu_count():
                args['cpu_count'] = cpu_count
            else:
                print('invalid input. cpu_count must be greater than 0 and less than or equal to ' + str(multiprocessing.cpu_count()))
                sys.exit(-1)
        elif command == 'verbose':
            verbose = arg.split('=')[1]
            if verbose in ['0', '1']:
                args['verbose'] = int(verbose)
            else:
                print('invalid input. verbose must be 0 (false) or 1 (true)')
                sys.exit(-1)
        elif command == 'substring':
            substring = int(arg.split('=')[1])
            if substring > 0 and substring < 27:
                args['substring'] = substring
            else:
                print('invalid input. substring must be greater than 0 and less than 27')
                sys.exit(-1)
        else:
            print('invalid input: ' + command + '\nrun `python worker.py help` for help')
            sys.exit(-1)
    
    print("Lendo arquivos do banco de dados...")
    database = {}
    for filename in os.listdir(DATABASE):
        with open(os.path.join(DATABASE, filename)) as file:
            for address in file:
                address = address.strip()
                if address.startswith('1'):
                    key = address[-args['substring']:]
                    database[key] = address
    print("DONE")
    print("database size: " + str(len(database)))
    print("processos iniciados: " + str(args['cpu_count']))
    
    global_counter = multiprocessing.Value('i', 0)
    for cpu in range(args['cpu_count']):
        multiprocessing.Process(target=main, args=(database, args, global_counter)).start()
