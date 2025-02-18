import os
import datetime
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)

# Obtém a URL do banco a partir da variável de ambiente (definida pelo Heroku)
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# MODELOS
class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    range_start = Column(String, nullable=False)
    range_end = Column(String, nullable=False)
    assigned_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, default="pending")

class Metadata(Base):
    __tablename__ = "metadata"
    key = Column(String, primary_key=True, index=True)
    value = Column(String)

class FoundWallet(Base):
    __tablename__ = "found_wallets"
    id = Column(Integer, primary_key=True, index=True)
    hex_private_key = Column(String)
    wif_private_key = Column(String)
    public_key = Column(String)
    uncompressed_address = Column(String)
    full_db_address = Column(String)
    status = Column(String)
    tested_candidate = Column(Integer)
    substring = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

# Cria as tabelas, se não existirem
Base.metadata.create_all(bind=engine)

# Funções auxiliares para conversão
def hex_to_int(hex_str):
    return int(hex_str, 16)

def int_to_hex(value):
    return hex(value)[2:].upper().zfill(64)

# Recupera o último valor atribuído (se não existir, inicializa com 64 zeros)
def get_last_assigned(db):
    meta = db.query(Metadata).filter(Metadata.key == "last_assigned").first()
    if meta is None:
        meta = Metadata(key="last_assigned", value="0" * 64)
        db.add(meta)
        db.commit()
        db.refresh(meta)
    return meta.value

def update_last_assigned(db, new_value):
    meta = db.query(Metadata).filter(Metadata.key == "last_assigned").first()
    if meta:
        meta.value = new_value
        db.commit()

# Constantes
TASK_SIZE = 100         # Para testes; ajuste conforme necessário.
TIMEOUT_SECONDS = 60    # Tempo limite para reatribuição de tarefas.
MAX_VALUE = 2 ** 256

def get_next_task():
    db = SessionLocal()
    now = datetime.datetime.utcnow()
    # Procura tarefas em "processing" que excederam o timeout
    task = (
        db.query(Task)
        .filter(Task.status == "processing", Task.assigned_at <= (now - datetime.timedelta(seconds=TIMEOUT_SECONDS)))
        .first()
    )
    if task:
        task.assigned_at = now
        db.commit()
        task_data = {"id": task.id, "start": task.range_start, "end": task.range_end}
        db.close()
        return task_data

    # Caso não haja tarefa pendente para reatribuição, cria uma nova tarefa
    last_assigned = get_last_assigned(db)
    last_int = hex_to_int(last_assigned)
    new_end_int = last_int + TASK_SIZE
    if new_end_int > MAX_VALUE:
        db.close()
        return None
    range_start = int_to_hex(last_int)
    range_end = int_to_hex(new_end_int)
    new_task = Task(range_start=range_start, range_end=range_end, assigned_at=now, status="processing")
    db.add(new_task)
    db.commit()
    task_id = new_task.id
    update_last_assigned(db, range_end)
    db.close()
    return {"id": task_id, "start": range_start, "end": range_end}

# Endpoints
@app.route('/')
def index():
    return "Servidor do Projeto Jupiter com Heroku Postgres"

@app.route('/get_task', methods=["GET"])
def get_task():
    task = get_next_task()
    if task is None:
        return jsonify({"message": "No more tasks available"}), 404
    return jsonify({"task_id": task["id"], "start": task["start"], "end": task["end"]})

@app.route('/task_complete', methods=["POST"])
def task_complete():
    data = request.get_json()
    task_id = data.get("task_id")
    if not task_id:
        return jsonify({"error": "task_id is required"}), 400
    db = SessionLocal()
    task = db.query(Task).filter(Task.id == task_id).first()
    if task:
        task.status = "completed"
        task.completed_at = datetime.datetime.utcnow()
        db.commit()
    db.close()
    return jsonify({"message": "Task marked as completed", "task_id": task_id})

@app.route('/tasks_status', methods=["GET"])
def tasks_status():
    db = SessionLocal()
    tasks = db.query(Task).order_by(Task.id).all()
    tasks_list = []
    for t in tasks:
        tasks_list.append({
            "id": t.id,
            "range_start": t.range_start,
            "range_end": t.range_end,
            "status": t.status,
            "assigned_at": t.assigned_at.isoformat() if t.assigned_at else None,
            "completed_at": t.completed_at.isoformat() if t.completed_at else None
        })
    db.close()
    return jsonify(tasks_list)

@app.route('/found', methods=["POST"])
def found():
    data = request.get_json()
    db = SessionLocal()
    new_found = FoundWallet(
        hex_private_key=data.get("hex private key"),
        wif_private_key=data.get("WIF private key"),
        public_key=data.get("public key"),
        uncompressed_address=data.get("uncompressed address"),
        full_db_address=data.get("full_db_address"),
        status=data.get("status"),
        tested_candidate=data.get("tested_candidate"),
        substring=data.get("substring"),
        timestamp=datetime.datetime.utcnow()
    )
    db.add(new_found)
    db.commit()
    db.close()
    return jsonify({"message": "Wallet result recorded"})

if __name__ == '__main__':
    app.run(debug=True)
