from typing import List, Optional, Dict, Any, Union, Annotated
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Query, Depends, status, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, validator, Field, EmailStr
import sqlite3
import os
from datetime import datetime, timedelta
import zoneinfo
import jwt
from passlib.context import CryptContext
import logging
from enum import Enum

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# Constantes y configuración
DATABASE_URL = "db/isaa.db"
SECRET_KEY = "pene"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configuración de seguridad
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Enumeraciones para valores fijos
class EstadoTarea(str, Enum):
    ACTIVO = "Activo"
    COMPLETADO = "Completado"
    PENDIENTE = "Pendiente"
    CANCELADO = "Cancelado"

# Modelos Pydantic
class Usuario(BaseModel):
    id: Optional[int] = None
    codigo: str
    correo: str  # Cambio de nombre a correo
    contrasena: Optional[str] = None
    rol: str = "usuario"
    
    @validator('codigo')
    def codigo_no_vacio(cls, v):
        if not v or not v.strip():
            raise ValueError('El código no puede estar vacío')
        return v.strip()
    
    @validator('correo')
    def correo_valido(cls, v):
        if not v or not v.strip():
            raise ValueError('El correo no puede estar vacío')
        # Validación básica de formato de email
        if '@' not in v or '.' not in v.split('@')[1]:
            raise ValueError('El formato del correo no es válido')
        return v.strip().lower()

class UsuarioResponse(BaseModel):
    id: int
    codigo: str
    correo: str

class Task(BaseModel):
    id: Optional[int] = None
    usuario_id: Optional[int] = None
    descripcion: Optional[str] = Field(None, min_length=1)
    estado: Optional[EstadoTarea] = EstadoTarea.ACTIVO
    fecha: Optional[str] = None  # dd/mm/yyyy
    hora: Optional[str] = None   # HH:MM
    
    @validator('descripcion')
    def descripcion_no_vacia(cls, v):
        if v is not None and not v.strip():
            raise ValueError('La descripción no puede estar vacía')
        return v.strip() if v else None

class TaskResponse(BaseModel):
    id: Optional[int] = None
    usuario_id: Optional[int] = None
    codigo_estudiante: Optional[str] = None
    correo_estudiante: Optional[str] = None
    descripcion: Optional[str] = None
    estado: Optional[str] = EstadoTarea.ACTIVO
    fecha: Optional[str] = None
    hora: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    codigo: Optional[str] = None

# Funciones de utilidad
@contextmanager
def get_db_connection():
    """Context manager para manejar conexiones a la base de datos de forma segura."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_URL)
        conn.row_factory = sqlite3.Row
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Error de base de datos: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de conexión a la base de datos"
        )
    finally:
        if conn:
            conn.close()

def get_current_local_date_time():
    """Obtiene la fecha y hora local en el formato requerido."""
    try:
        tz = zoneinfo.ZoneInfo("America/Mexico_City")
        now = datetime.now(tz)
        fecha = now.strftime("%d/%m/%Y")
        hora = now.strftime("%H:%M")
        return fecha, hora
    except Exception as e:
        logger.error(f"Error al obtener fecha y hora: {e}")
        # Fallback a UTC si hay error
        now = datetime.utcnow()
        fecha = now.strftime("%d/%m/%Y")
        hora = now.strftime("%H:%M")
        return fecha, hora

def verify_password(plain_password, hashed_password):
    """Verifica que una contraseña coincida con su hash.""" 
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Error verificando contraseña: {e}")
        return False

def get_password_hash(password):
    """Genera un hash seguro para una contraseña."""
    return pwd_context.hash(password)

def get_user(codigo: str):
    """Obtiene un usuario por su código."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM usuarios WHERE codigo = ?", (codigo,))
            user = cursor.fetchone()
            return dict(user) if user else None
    except Exception as e:
        logger.error(f"Error al obtener usuario: {e}")
        return None

def authenticate_user(codigo: str, password: str):
    """Autentica un usuario verificando su código y contraseña."""
    user = get_user(codigo)
    if not user:
        return False
    if not verify_password(password, user["contrasena"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Crea un token JWT de acceso."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creando token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear token de acceso"
        )

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Obtiene el usuario actual a partir del token JWT."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        codigo: str = payload.get("sub")
        if codigo is None:
            raise credentials_exception
        token_data = TokenData(codigo=codigo)
    except jwt.PyJWTError as e:
        logger.error(f"Error decodificando token: {e}")
        raise credentials_exception
    
    user = get_user(codigo=token_data.codigo)
    if user is None:
        raise credentials_exception
    return user

def init_db():
    """Inicializa la base de datos si no existe."""
    try:
        os.makedirs("db", exist_ok=True)
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Verificamos si la tabla de usuarios existe
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
            users_table_exists = cursor.fetchone()

            if not users_table_exists:
                # Creamos tabla de usuarios con correo en lugar de nombre
                cursor.execute("""
                    CREATE TABLE usuarios (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rol TEXT 'usuario',
                        codigo TEXT UNIQUE NOT NULL,
                        correo TEXT NOT NULL,
                        contrasena TEXT NOT NULL
                    )
                """)
            
            # Verificamos si la tabla de tareas existe
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'")
            tasks_table_exists = cursor.fetchone()

            if not tasks_table_exists:
                # Creamos tabla con referencia a usuarios
                cursor.execute("""
                    CREATE TABLE tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        usuario_id INTEGER NOT NULL,
                        descripcion TEXT NOT NULL,
                        estado TEXT DEFAULT 'Activo',
                        fecha TEXT,
                        hora TEXT,
                        FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
                    )
                """)
                
            # Añadir índices para mejorar rendimiento
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_tasks_usuario_id'")
            if not cursor.fetchone():
                cursor.execute("CREATE INDEX idx_tasks_usuario_id ON tasks(usuario_id)")
                
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_usuarios_codigo'")
            if not cursor.fetchone():
                cursor.execute("CREATE INDEX idx_usuarios_codigo ON usuarios(codigo)")
                
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_usuarios_correo'")
            if not cursor.fetchone():
                cursor.execute("CREATE INDEX idx_usuarios_correo ON usuarios(correo)")
            
            conn.commit()
            logger.info("Base de datos inicializada correctamente")
    except Exception as e:
        logger.error(f"Error al inicializar la base de datos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al inicializar la base de datos"
        )

# Inicialización de FastAPI
app = FastAPI(title="Task Manager API", version="1.2.0")

# Middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://127.0.0.1:5501", ],  # Permite todas las origenes (ajústalo en producción)
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos los métodos HTTP
    allow_headers=["*"],  # Permite todas las cabeceras
)

def get_current_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("rol") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso restringido a administradores"
        )
    return current_user


@app.on_event("startup")
async def startup_event():
    """Evento de inicio de la aplicación."""
    try:
        init_db()
    except Exception as e:
        logger.critical(f"Error crítico al iniciar la aplicación: {e}")

#########################################
# Endpoints de autenticación

@app.post("/token", response_model=Token)
async def login_for_access_token(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """Endpoint para obtener un token de acceso mediante credenciales."""
    try:
        user = authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario o contraseña incorrectos",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["codigo"], "rol": user["rol"]},
            expires_delta=access_token_expires
        )

        # Añadir cabecera de caché para evitar almacenamiento del token
        response.headers["Cache-Control"] = "no-store"
        
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        # Re-lanzar las excepciones HTTP ya formateadas
        raise
    except Exception as e:
        logger.error(f"Error inesperado en login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor al procesar la solicitud de login"
        )

#########################################
# Endpoints de usuarios

@app.post("/usuarios/", response_model=UsuarioResponse, status_code=201)
async def create_user(usuario: Usuario):
    """Crea un nuevo usuario."""
    try:
        # Validación adicional
        if not usuario.codigo or not usuario.correo or not usuario.contrasena:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Todos los campos son obligatorios"
            )
        
        if get_user(usuario.codigo):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El código de usuario ya está en uso"
            )
        
        # Verificar si el correo ya está en uso
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM usuarios WHERE correo = ?", (usuario.correo,))
            if cursor.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="El correo ya está en uso"
                )
        
        hashed_password = get_password_hash(usuario.contrasena)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO usuarios (codigo, correo, contrasena, rol) VALUES (?, ?, ?, ?)",
                (usuario.codigo, usuario.correo, hashed_password, "usuario")
            )
            conn.commit()
            user_id = cursor.lastrowid
            
            cursor.execute("SELECT id, codigo, correo FROM usuarios WHERE id = ?", (user_id,))
            new_user = cursor.fetchone()
            
            if not new_user:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al crear usuario"
                )
                
            return UsuarioResponse(**dict(new_user))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al crear usuario: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno al procesar la solicitud"
        )

@app.get("/usuarios/", response_model=List[UsuarioResponse])
async def read_users(current_user: dict = Depends(get_current_user)):
    """Obtiene todos los usuarios."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, codigo, correo FROM usuarios")
            users = cursor.fetchall()
            return [UsuarioResponse(**dict(user)) for user in users]
    except Exception as e:
        logger.error(f"Error al obtener usuarios: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al recuperar la lista de usuarios"
        )

@app.get("/usuarios/{user_id}", response_model=UsuarioResponse)
async def read_user(user_id: int, current_user: dict = Depends(get_current_user)):
    """Obtiene un usuario por su ID."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, codigo, correo FROM usuarios WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Usuario no encontrado"
            )
        return UsuarioResponse(**dict(user))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al obtener usuario {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al recuperar información del usuario"
        )

@app.put("/usuarios/{user_id}", response_model=UsuarioResponse)
async def update_user(
    user_id: int, 
    updated_user: Usuario, 
    current_user: dict = Depends(get_current_user)
):
    """Actualiza un usuario existente."""
    try:
        # Verificar si el usuario tiene permisos para actualizar este usuario
        if current_user["id"] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permiso para actualizar este usuario"
            )
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verificar que el usuario existe
            cursor.execute("SELECT id FROM usuarios WHERE id = ?", (user_id,))
            if not cursor.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Usuario no encontrado"
                )
            
            # Si se quiere cambiar el código, verificar que no esté en uso
            if updated_user.codigo != current_user["codigo"]:
                cursor.execute("SELECT id FROM usuarios WHERE codigo = ? AND id != ?", 
                              (updated_user.codigo, user_id))
                if cursor.fetchone():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="El código de usuario ya está en uso por otro usuario"
                    )
            
            # Si se quiere cambiar el correo, verificar que no esté en uso
            if updated_user.correo != current_user["correo"]:
                cursor.execute("SELECT id FROM usuarios WHERE correo = ? AND id != ?", 
                              (updated_user.correo, user_id))
                if cursor.fetchone():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="El correo ya está en uso por otro usuario"
                    )
            
            # Si se proporciona una contraseña, actualizarla
            if updated_user.contrasena:
                hashed_password = get_password_hash(updated_user.contrasena)
                cursor.execute(
                    "UPDATE usuarios SET codigo=?, correo=?, contrasena=? WHERE id=?",
                    (updated_user.codigo, updated_user.correo, hashed_password, user_id)
                )
            else:
                cursor.execute(
                    "UPDATE usuarios SET codigo=?, correo=? WHERE id=?",
                    (updated_user.codigo, updated_user.correo, user_id)
                )
            
            conn.commit()
            
            cursor.execute("SELECT id, codigo, correo FROM usuarios WHERE id = ?", (user_id,))
            updated_user_from_db = cursor.fetchone()
            
            if updated_user_from_db is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, 
                    detail="Usuario no encontrado después de la actualización"
                )
            
            return UsuarioResponse(**dict(updated_user_from_db))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al actualizar usuario {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar el usuario"
        )

#########################################
# Endpoints de tareas

@app.get("/tasks/{task_id}", response_model=TaskResponse)
async def read_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Obtiene una tarea específica por su ID."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.id = ?
            """, (task_id,))
            task = cursor.fetchone()
            
        if task is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Tarea no encontrada"
            )
        return TaskResponse(**dict(task))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al obtener tarea {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al recuperar la tarea"
        )

@app.put("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(
    task_id: int, 
    updated_task: Task, 
    current_user: dict = Depends(get_current_user)
):
    """Actualiza una tarea existente."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verificar si la tarea existe y pertenece al usuario
            cursor.execute("SELECT usuario_id FROM tasks WHERE id = ?", (task_id,))
            task = cursor.fetchone()
            
            if task is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, 
                    detail="Tarea no encontrada"
                )
            
            if task["usuario_id"] != current_user["id"] and current_user.get("rol") != "admin":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No tienes permiso para modificar esta tarea"
                )
            
            # Validación adicional
            if not updated_task.descripcion:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La descripción es obligatoria"
                )
            
            # Actualizar la tarea
            cursor.execute(
                "UPDATE tasks SET descripcion=?, estado=? WHERE id=?",
                (updated_task.descripcion, 
                 updated_task.estado.value if updated_task.estado else EstadoTarea.ACTIVO, 
                 task_id)
            )
            conn.commit()
            
            # Obtener la tarea actualizada con la información del usuario
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.id = ?
            """, (task_id,))
            updated_task_from_db = cursor.fetchone()
            
            if not updated_task_from_db:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al actualizar la tarea"
                )
            
            return TaskResponse(**dict(updated_task_from_db))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al actualizar tarea {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar la tarea"
        )

@app.delete("/tasks/{task_id}", status_code=204)
async def delete_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Elimina una tarea existente."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verificar si la tarea existe y pertenece al usuario
            cursor.execute("SELECT usuario_id FROM tasks WHERE id = ?", (task_id,))
            task = cursor.fetchone()
            
            if task is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, 
                    detail="Tarea no encontrada"
                )
            
            if task["usuario_id"] != current_user["id"] and current_user.get("rol") != "admin":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No tienes permiso para eliminar esta tarea"
                )
            
            cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.commit()
            
            return Response(status_code=status.HTTP_204_NO_CONTENT)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al eliminar tarea {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar la tarea"
        )

#########################################
# Endpoint para búsquedas avanzadas (mejorado)

@app.get("/search-advanced", response_model=List[TaskResponse])
async def search_advanced(
    cor: Optional[List[str]] = Query(None, description="Buscar por correo"),
    cod: Optional[List[str]] = Query(None, description="Buscar por código"),
    id: Optional[List[Union[int, str]]] = Query(None, description="Buscar por ID"),
    des: Optional[List[str]] = Query(None, description="Buscar por descripción"),
    combinado: Optional[List[str]] = Query(None, description="Búsqueda combinada (cor=val:cod=val:id=val:des=val)"),
    limit: int = Query(100, ge=1, le=500, description="Límite de resultados"),
    offset: int = Query(0, ge=0, description="Inicio de la paginación"),
    current_user: dict = Depends(get_current_user)
):
    """
    Realiza una búsqueda avanzada de tareas con filtros flexibles.
    
    Ejemplos:
    - /search-advanced?correo=juan@email.com&cod=E001&des=Proyecto
    - /search-advanced?combinado=correo=juan@email.com:cod=E001
    """
    try:
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
                if not valor:  # Ignorar valores vacíos
                    continue
                    
                if like:
                    sub_conditions.append(f"{campo_db} LIKE ?")
                    sub_values.append(f"%{valor}%")
                else:
                    sub_conditions.append(f"{campo_db} = ?")
                    sub_values.append(valor)
            
            if not sub_conditions:
                return None, []
                
            return " OR ".join(sub_conditions), sub_values
        
        # Procesar campos simples
        if cor:
            correo_condition, correo_values = procesar_campo_simple(cor, "u.correo", like=True)
            if correo_condition:
                or_conditions.append(f"({correo_condition})")
                valores.extend(correo_values)
        
        if cod:
            cod_condition, cod_values = procesar_campo_simple(cod, "u.codigo")
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
            
            if id_parsed:  # Solo procesar si hay IDs válidos
                id_condition, id_values = procesar_campo_simple(id_parsed, "t.id")
                if id_condition:
                    or_conditions.append(f"({id_condition})")
                    valores.extend(id_values)
        
        if des:
            des_condition, des_values = procesar_campo_simple(des, "t.descripcion", like=True)
            if des_condition:
                or_conditions.append(f"({des_condition})")
                valores.extend(des_values)
        
        # 2. Procesar combinaciones AND
        if combinado:
            for combo in combinado:
                if not combo or "=" not in combo:  # Validar formato
                    continue
                    
                and_parts = combo.split(":")
                and_conditions = []
                and_values = []
                
                for part in and_parts:
                    if "=" not in part:
                        continue
                    
                    try:
                        campo, valor = part.split("=", 1)
                        if not campo or not valor or campo not in ["cor", "cod", "id", "des"]:
                            continue
                        
                        # Manejar múltiples valores separados por coma dentro de un campo
                        valores_campo = valor.split(",") if valor else []
                        
                        if campo == "cor":
                            cond, vals = procesar_campo_simple(valores_campo, "u.cor", like=True)
                            if cond:
                                and_conditions.append(f"({cond})")
                                and_values.extend(vals)
                        
                        elif campo == "cod":
                            cond, vals = procesar_campo_simple(valores_campo, "u.codigo")
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
                            
                            if id_parsed:  # Solo procesar si hay IDs válidos
                                cond, vals = procesar_campo_simple(id_parsed, "t.id")
                                if cond:
                                    and_conditions.append(f"({cond})")
                                    and_values.extend(vals)
                        
                        elif campo == "des":
                            cond, vals = procesar_campo_simple(valores_campo, "t.descripcion", like=True)
                            if cond:
                                and_conditions.append(f"({cond})")
                                and_values.extend(vals)
                    except Exception as e:
                        logger.warning(f"Error procesando parte combinada {part}: {e}")
                        continue
                
                if and_conditions:
                    or_conditions.append("(" + " AND ".join(and_conditions) + ")")
                    valores.extend(and_values)
        
        # Construir la consulta SQL final
        base_query = """
            SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                   t.descripcion, t.estado, t.fecha, t.hora
            FROM tasks t
            JOIN usuarios u ON t.usuario_id = u.id
        """
        
        if or_conditions:
            query = base_query + " WHERE " + " OR ".join(or_conditions)
        else:
            query = base_query
            
        # Añadir paginación
        query += " LIMIT ? OFFSET ?"
        valores.extend([limit, offset])
        
        # Ejecutar consulta
        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, valores)
                rows = cursor.fetchall()
                return [TaskResponse(**dict(row)) for row in rows]
            except sqlite3.Error as e:
                logger.error(f"Error en consulta SQL: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                    detail=f"Error en la consulta de búsqueda: {str(e)}"
                )
    except Exception as e:
        logger.error(f"Error en búsqueda avanzada: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al procesar la búsqueda avanzada"
        )

#########################################
# Endpoint para tareas del usuario actual

@app.post("/my-tasks/", response_model=TaskResponse, status_code=201)
async def create_my_task(task: Task, current_user: dict = Depends(get_current_user)):
    """Crea una nueva tarea para el usuario actual."""
    try:
        # Validaciones adicionales
        if not task.descripcion:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La descripción es obligatoria"
            )
        
        fecha, hora = get_current_local_date_time()
        
        # Usar el ID del usuario autenticado (no permitir especificar usuario_id)
        usuario_id = current_user["id"]
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO tasks (usuario_id, descripcion, estado, fecha, hora) VALUES (?, ?, ?, ?, ?)",
                (usuario_id, task.descripcion, task.estado.value if task.estado else EstadoTarea.ACTIVO, fecha, hora)
            )
            conn.commit()
            task_id = cursor.lastrowid
            
            # Obtener la tarea creada con la información del usuario
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.id = ? AND t.usuario_id = ?
            """, (task_id, usuario_id))
            new_task = cursor.fetchone()
            
            if not new_task:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al crear la tarea"
                )
                
            return TaskResponse(**dict(new_task))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al crear tarea del usuario {current_user['id']}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear la tarea"
        )

@app.get("/my-tasks/{task_id}", response_model=TaskResponse)
async def read_my_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Obtiene una tarea específica del usuario actual por su ID."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.id = ? AND t.usuario_id = ?
            """, (task_id, current_user["id"]))
            task = cursor.fetchone()
            
        if task is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Tarea no encontrada o no tienes permiso para acceder a ella"
            )
        return TaskResponse(**dict(task))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al obtener tarea {task_id} del usuario {current_user['id']}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al recuperar la tarea"
        )

@app.get("/my-tasks/", response_model=List[TaskResponse])
async def read_my_tasks(
    estado: Optional[EstadoTarea] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """Obtiene las tareas del usuario actual con filtro opcional por estado."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.usuario_id = ?
            """
            params = [current_user["id"]]
            
            if estado:
                query += " AND t.estado = ?"
                params.append(estado.value)
                
            query += " ORDER BY t.fecha DESC, t.hora DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            tasks = cursor.fetchall()
            return [TaskResponse(**dict(task)) for task in tasks]
    except Exception as e:
        logger.error(f"Error al obtener tareas del usuario: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al recuperar las tareas del usuario"
        )
    
@app.put("/my-tasks/{task_id}", response_model=TaskResponse)
async def update_my_task(
    task_id: int, 
    updated_task: Task, 
    current_user: dict = Depends(get_current_user)
):
    """Actualiza una tarea específica del usuario actual."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verificar si la tarea existe y pertenece al usuario actual
            cursor.execute("SELECT usuario_id FROM tasks WHERE id = ? AND usuario_id = ?", 
                          (task_id, current_user["id"]))
            task = cursor.fetchone()
            
            if task is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, 
                    detail="Tarea no encontrada o no tienes permiso para modificarla"
                )
            
            # Validación adicional
            if not updated_task.descripcion:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La descripción es obligatoria"
                )
            
            # Actualizar la tarea
            cursor.execute(
                "UPDATE tasks SET descripcion=?, estado=? WHERE id=? AND usuario_id=?",
                (updated_task.descripcion, 
                 updated_task.estado.value if updated_task.estado else EstadoTarea.ACTIVO, 
                 task_id,
                 current_user["id"])
            )
            conn.commit()
            
            # Obtener la tarea actualizada con la información del usuario
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.id = ? AND t.usuario_id = ?
            """, (task_id, current_user["id"]))
            updated_task_from_db = cursor.fetchone()
            
            if not updated_task_from_db:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al actualizar la tarea"
                )
            
            return TaskResponse(**dict(updated_task_from_db))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al actualizar tarea propia {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar la tarea"
        )

#########################################
# Token del usuario actual

@app.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "codigo": current_user["codigo"],
        "correo": current_user["correo"],
        "rol": current_user["rol"]
    }

#########################################
# Endpoint para verificar estado del sistema

@app.get("/health")
async def health_check():
    """Verifica el estado del sistema."""
    try:
        # Verificar conexión a la base de datos
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            
        return {
            "status": "ok",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error en health check: {e}")
        return {
            "status": "error",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
#8====D---- isaac
#{|}jose miguel
#(.)(.)saul
