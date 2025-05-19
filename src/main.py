from typing import List, Optional, Dict, Any, Union
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import os
from datetime import datetime
import zoneinfo

DATABASE_URL = "db/tasks.db"

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
    conn.row_factory = sqlite3.Row  # Para acceder a las columnas por nombre
    return conn

def init_db():
    os.makedirs("db", exist_ok=True)
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

        # Si no existen las columnas, agregarlas
        if "estado" not in columns:
            cursor.execute("ALTER TABLE tasks ADD COLUMN estado TEXT DEFAULT 'Activo'")
        if "fecha" not in columns:
            cursor.execute("ALTER TABLE tasks ADD COLUMN fecha TEXT")
        if "hora" not in columns:
            cursor.execute("ALTER TABLE tasks ADD COLUMN hora TEXT")

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

#########################################

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

#########################################

# Nuevo endpoint para búsquedas avanzadas
@app.get("/search-advanced")
async def search_advanced(
    nom: Optional[List[str]] = Query(None),
    cod: Optional[List[str]] = Query(None),
    id: Optional[List[Union[int, str]]] = Query(None),
    des: Optional[List[str]] = Query(None),
    combinado: Optional[List[str]] = Query(None),
):
    conn = create_connection()
    cursor = conn.cursor()
    
    # Lista para almacenar cada condición OR
    or_conditions = []
    valores = []
    
    # 1. Procesar cada campo simple (OR dentro del mismo campo)
    def procesar_campo_simple(parametros, campo_db, like=False):
        if not parametros:
            return None, []
        
        sub_conditions = []
        sub_values = []
        
        for valor in parametros:
            if like:
                sub_conditions.append(f"{campo_db} LIKE ?")
                sub_values.append(f"%{valor}%")
            else:
                sub_conditions.append(f"{campo_db} = ?")
                sub_values.append(valor)
        
        return " OR ".join(sub_conditions), sub_values
    
    # Procesar campos simples
    if nom:
        nom_condition, nom_values = procesar_campo_simple(nom, "nombre")
        if nom_condition:
            or_conditions.append(f"({nom_condition})")
            valores.extend(nom_values)
    
    if cod:
        cod_condition, cod_values = procesar_campo_simple(cod, "codigoEstudiante")
        if cod_condition:
            or_conditions.append(f"({cod_condition})")
            valores.extend(cod_values)
    
    if id:
        # Convertir id a enteros si son strings
        id_parsed = []
        for i in id:
            try:
                id_parsed.append(int(i))
            except (ValueError, TypeError):
                continue
        
        id_condition, id_values = procesar_campo_simple(id_parsed, "id")
        if id_condition:
            or_conditions.append(f"({id_condition})")
            valores.extend(id_values)
    
    if des:
        des_condition, des_values = procesar_campo_simple(des, "descripcion", like=True)
        if des_condition:
            or_conditions.append(f"({des_condition})")
            valores.extend(des_values)
    
    # 2. Procesar combinaciones AND
    if combinado:
        for combo in combinado:
            and_parts = combo.split(":")
            and_conditions = []
            and_values = []
            
            for part in and_parts:
                if "=" not in part:
                    continue
                
                campo, valor = part.split("=", 1)
                if campo not in ["nom", "cod", "id", "des"]:
                    continue
                
                # Manejar múltiples valores separados por coma dentro de un campo
                valores_campo = valor.split(",")
                
                if campo == "nom":
                    cond, vals = procesar_campo_simple(valores_campo, "nombre")
                    if cond:
                        and_conditions.append(f"({cond})")
                        and_values.extend(vals)
                
                elif campo == "cod":
                    cond, vals = procesar_campo_simple(valores_campo, "codigoEstudiante")
                    if cond:
                        and_conditions.append(f"({cond})")
                        and_values.extend(vals)
                
                elif campo == "id":
                    # Convertir a enteros
                    id_parsed = []
                    for i in valores_campo:
                        try:
                            id_parsed.append(int(i))
                        except (ValueError, TypeError):
                            continue
                    
                    cond, vals = procesar_campo_simple(id_parsed, "id")
                    if cond:
                        and_conditions.append(f"({cond})")
                        and_values.extend(vals)
                
                elif campo == "des":
                    cond, vals = procesar_campo_simple(valores_campo, "descripcion", like=True)
                    if cond:
                        and_conditions.append(f"({cond})")
                        and_values.extend(vals)
            
            if and_conditions:
                or_conditions.append("(" + " AND ".join(and_conditions) + ")")
                valores.extend(and_values)
    
    # Construir la consulta SQL final
    if or_conditions:
        query = "SELECT * FROM tasks WHERE " + " OR ".join(or_conditions)
    else:
        query = "SELECT * FROM tasks"
    
    try:
        cursor.execute(query, valores)
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except sqlite3.Error as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Error en la consulta SQL: {str(e)}")