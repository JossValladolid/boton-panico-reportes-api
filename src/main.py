from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import sqlite3
import zoneinfo

DATABASE_URL = "tasks.db"

class Task(BaseModel):
    id: Optional[int] = None
    codigoEstudiante: Optional[str] = None
    nombre: Optional[str] = None
    descripcion: Optional[str] = None
    estado: Optional[str] = "Activo"
    fecha: Optional[str] = None  # dd/mm/yyyy
    hora: Optional[str] = None   # HH:MM

def get_current_local_date_time():
    tz = zoneinfo.ZoneInfo("America/Mexico_City")
    now = datetime.now(tz)
    fecha = now.strftime("%d/%m/%Y")
    hora = now.strftime("%H:%M")
    return fecha, hora

def create_connection():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = create_connection()
    cursor = conn.cursor()

    # Verificamos si la tabla existe
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'")
    table_exists = cursor.fetchone()

    if not table_exists:
        # Creamos tabla con fecha y hora separadas
        cursor.execute("""
            CREATE TABLE tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                codigoEstudiante TEXT NOT NULL,
                nombre TEXT,
                descripcion TEXT NOT NULL,
                estado TEXT DEFAULT 'Activo',
                fecha TEXT,
                hora TEXT
            )
        """)
    else:
        # Verificamos columnas existentes
        cursor.execute("PRAGMA table_info(tasks)")
        columns = [col[1] for col in cursor.fetchall()]

        # Si no existen las columnas fecha y hora, agregarlas
        if "fecha" not in columns:
            cursor.execute("ALTER TABLE tasks ADD COLUMN fecha TEXT")
        if "hora" not in columns:
            cursor.execute("ALTER TABLE tasks ADD COLUMN hora TEXT")

    conn.commit()
    conn.close()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    init_db()

@app.post("/tasks/", response_model=Task, status_code=201)
async def create_task(task: Task):
    fecha, hora = get_current_local_date_time()
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO tasks (codigoEstudiante, nombre, descripcion, estado, fecha, hora) VALUES (?, ?, ?, ?, ?, ?)",
        (task.codigoEstudiante, task.nombre, task.descripcion, task.estado, fecha, hora)
    )
    conn.commit()
    task_id = cursor.lastrowid
    cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
    new_task = cursor.fetchone()
    conn.close()
    return Task(**new_task)

@app.get("/tasks/", response_model=List[Task])
async def read_tasks():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks")
    tasks = cursor.fetchall()
    conn.close()
    return [Task(**task) for task in tasks]

@app.get("/tasks/{task_id}", response_model=Task)
async def read_task(task_id: int):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
    task = cursor.fetchone()
    conn.close()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return Task(**task)

@app.put("/tasks/{task_id}", response_model=Task)
async def update_task(task_id: int, updated_task: Task):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE tasks SET codigoEstudiante=?, nombre=?, descripcion=?, estado=? WHERE id=?",
        (updated_task.codigoEstudiante, updated_task.nombre, updated_task.descripcion, updated_task.estado, task_id)
    )
    conn.commit()
    cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
    updated_task_from_db = cursor.fetchone()
    conn.close()
    if updated_task_from_db is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return Task(**updated_task_from_db)

@app.delete("/tasks/{task_id}", status_code=204)
async def delete_task(task_id: int):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return None
