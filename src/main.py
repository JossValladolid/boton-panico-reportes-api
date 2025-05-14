from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware  # Importa el middleware CORS
from pydantic import BaseModel
import sqlite3

DATABASE_URL = "tasks.db"

class Task(BaseModel):
    id: Optional[int] = None
    codigoEstudiante: int
    nombre: Optional[str] = None
    descripcion: Optional[str] = None

def create_connection():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row  # Para acceder a las columnas por nombre
    return conn

def init_db():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigoEstudiante INTEGER NOT NULL,
            nombre TEXT,
            descripcion TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

app = FastAPI()

# Agrega el middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite todas las origenes (ajústalo en producción)
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos los métodos HTTP
    allow_headers=["*"],  # Permite todas las cabeceras
)

@app.on_event("startup")
async def startup_event():
    init_db()

@app.post("/tasks/", response_model=Task, status_code=201)
async def create_task(task: Task):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO tasks (codigoEstudiante, nombre, descripcion) VALUES (?, ?, ?)",
                   (task.codigoEstudiante, task.nombre, task.descripcion))
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
    cursor.execute("UPDATE tasks SET codigoEstudiante=?, nombre=?, descripcion=? WHERE id=?",
                   (updated_task.codigoEstudiante, updated_task.nombre, updated_task.descripcion, task_id))
    conn.commit()
    cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id))
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