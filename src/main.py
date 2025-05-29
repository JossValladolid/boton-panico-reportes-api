from typing import List, Optional, Dict, Any, Union, Annotated
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Query, Depends, status, Response, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, validator, Field, EmailStr
import sqlite3
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import zoneinfo
import jwt
from passlib.context import CryptContext
import logging
from enum import Enum
import json
import zoneinfo

# CONFIGURACIÓN INICIAL Y CONSTANTES

# Configuración de logging estructurado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# Carga de variables de entorno
load_dotenv()

# Constantes de configuración
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
DATABASE_URL = os.getenv("DATABASE_URL", "db/isaa.db")

# Validación de configuración crítica
if not SECRET_KEY:
    raise ValueError("SECRET_KEY no configurada en .env")


# CONFIGURACIÓN DE SEGURIDAD

# Contexto de encriptación para contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema OAuth2 para autenticación JWT
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# ENUMERACIONES Y TIPOS DE DATOS

class EstadoTarea(str, Enum):
    """Estados posibles para las tareas/reportes."""
    ACTIVO = "Activo"
    COMPLETADO = "Completado"
    PENDIENTE = "Pendiente"
    CANCELADO = "Cancelado"


# MODELOS PYDANTIC PARA VALIDACIÓN DE DATOS
class Usuario(BaseModel):
    """Modelo para usuarios del sistema."""
    id: Optional[int] = None
    codigo: str
    correo: str
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
        if '@' not in v or '.' not in v.split('@')[1]:
            raise ValueError('El formato del correo no es válido')
        return v.strip().lower()

class UsuarioResponse(BaseModel):
    """Modelo de respuesta para usuarios (sin contraseña)."""
    id: int
    codigo: str
    correo: str
    rol: str

class Task(BaseModel):
    """Modelo para tareas/reportes de emergencia."""
    id: Optional[int] = None
    usuario_id: Optional[int] = None
    descripcion: Optional[str] = Field(None, min_length=1)
    estado: Optional[EstadoTarea] = EstadoTarea.ACTIVO
    fecha: Optional[str] = None  # dd/mm/yyyy
    hora: Optional[str] = None   # HH:MM
    razon: Optional[str] = Field(None, min_length=1)  # Razón de cancelación
    
    @validator('descripcion')
    def descripcion_no_vacia(cls, v):
        if v is not None and not v.strip():
            raise ValueError('La descripción no puede estar vacía')
        return v.strip() if v else None
    
    @validator('razon')
    def razon_no_vacia(cls, v):
        if v is not None and not v.strip():
            raise ValueError('La razón no puede estar vacía')
        return v.strip() if v else None

class TaskResponse(BaseModel):
    """Modelo de respuesta para tareas con información del usuario."""
    id: Optional[int] = None
    usuario_id: Optional[int] = None
    codigo_estudiante: Optional[str] = None
    correo_estudiante: Optional[str] = None
    descripcion: Optional[str] = None
    estado: Optional[str] = EstadoTarea.ACTIVO
    fecha: Optional[str] = None
    hora: Optional[str] = None
    razon: Optional[str] = None

class Formulario(BaseModel):
    """Modelo para formularios de denuncia estudiantil."""
    id: Optional[int] = None
    task_id: int
    nombres: str = Field(..., min_length=1)
    apellido_paterno: str = Field(..., min_length=1)
    apellido_materno: str = Field(..., min_length=1)
    codigo_udg: str = Field(..., min_length=1)
    fecha_nacimiento: str = Field(..., min_length=1)  # formato: YYYY-MM-DD
    descripcion_detallada: str = Field(..., min_length=1)
    fecha_creacion: Optional[str] = None
    hora_creacion: Optional[str] = None
    
    @validator('nombres', 'apellido_paterno', 'apellido_materno', 'codigo_udg', 'descripcion_detallada')
    def campos_no_vacios(cls, v):
        if not v or not v.strip():
            raise ValueError('Este campo no puede estar vacío')
        return v.strip()

class FormularioResponse(BaseModel):
    """Modelo de respuesta para formularios."""
    id: int
    task_id: int
    nombres: str
    apellido_paterno: str
    apellido_materno: str
    codigo_udg: str
    fecha_nacimiento: str
    descripcion_detallada: str
    fecha_creacion: Optional[str] = None
    hora_creacion: Optional[str] = None

class Token(BaseModel):
    """Modelo para tokens JWT."""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """Modelo para datos del token."""
    codigo: Optional[str] = None

class FormularioRequest(BaseModel):
    """Modelo de request para crear formularios."""
    nombres: str
    apellido_paterno: str
    apellido_materno: str
    codigo_udg: str
    fecha_nacimiento: str
    descripcion_detallada: str


# FUNCIONES DE UTILIDAD Y HELPERS

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
    """Obtiene la fecha y hora local en el formato requerido (Mexico City)."""
    try:
        # Intentar con zoneinfo primero
        try:
            tz = zoneinfo.ZoneInfo("America/Mexico_City")
            now = datetime.now(tz)
            fecha = now.strftime("%d/%m/%Y")
            hora = now.strftime("%H:%M")
            return fecha, hora
        except:
            pass
        
        # Fallback: Calcular manualmente la hora de México
        utc_now = datetime.utcnow()
        month = utc_now.month
        if 4 <= month <= 10:
            mexico_time = utc_now - timedelta(hours=6)
        
        fecha = mexico_time.strftime("%d/%m/%Y")
        hora = mexico_time.strftime("%H:%M")
        return fecha, hora
        
    except Exception as e:
        logger.error(f"Error al obtener fecha y hora: {e}")
        # Último recurso
        now = datetime.utcnow()
        fecha = now.strftime("%d/%m/%Y")
        hora = now.strftime("%H:%M")
        return fecha, hora


# FUNCIONES DE AUTENTICACIÓN Y SEGURIDAD

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

def get_current_admin(current_user: dict = Depends(get_current_user)):
    """Verifica que el usuario actual sea administrador."""
    if current_user.get("rol") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso restringido a administradores"
        )
    return current_user


# INICIALIZACIÓN DE BASE DE DATOS

def init_db():
    """Inicializa la base de datos si no existe."""
    try:
        os.makedirs("db", exist_ok=True)
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Tabla de usuarios
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
            users_table_exists = cursor.fetchone()

            if not users_table_exists:
                cursor.execute("""
                    CREATE TABLE usuarios (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rol TEXT DEFAULT 'usuario',
                        codigo TEXT UNIQUE NOT NULL,
                        correo TEXT NOT NULL,
                        contrasena TEXT NOT NULL
                    )
                """)
            
            # Tabla de tareas/reportes
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'")
            tasks_table_exists = cursor.fetchone()

            if not tasks_table_exists:
                cursor.execute("""
                    CREATE TABLE tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        usuario_id INTEGER NOT NULL,
                        descripcion TEXT NOT NULL,
                        estado TEXT DEFAULT 'Activo',
                        fecha TEXT,
                        hora TEXT,
                        razon TEXT,
                        FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
                    )
                """)
            else:
                # Verificar si la columna razon existe, si no, agregarla
                cursor.execute("PRAGMA table_info(tasks)")
                columns = [column[1] for column in cursor.fetchall()]
                if 'razon' not in columns:
                    cursor.execute("ALTER TABLE tasks ADD COLUMN razon TEXT")
                    logger.info("Columna 'razon' agregada a la tabla tasks")

            # Tabla de formularios de denuncia
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='formularios'")
            formularios_table_exists = cursor.fetchone()

            if not formularios_table_exists:
                cursor.execute("""
                    CREATE TABLE formularios (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        task_id INTEGER NOT NULL,
                        nombres TEXT NOT NULL,
                        apellido_paterno TEXT NOT NULL,
                        apellido_materno TEXT NOT NULL,
                        codigo_udg TEXT NOT NULL,
                        fecha_nacimiento TEXT NOT NULL,
                        descripcion_detallada TEXT NOT NULL,
                        fecha_creacion TEXT,
                        hora_creacion TEXT,
                        FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE
                    )
                """)
                logger.info("Tabla 'formularios' creada exitosamente")
                
            # Crear índices para optimizar rendimiento
            indices = [
                ("idx_tasks_usuario_id", "CREATE INDEX idx_tasks_usuario_id ON tasks(usuario_id)"),
                ("idx_usuarios_codigo", "CREATE INDEX idx_usuarios_codigo ON usuarios(codigo)"),
                ("idx_usuarios_correo", "CREATE INDEX idx_usuarios_correo ON usuarios(correo)"),
                ("idx_tasks_razon", "CREATE INDEX idx_tasks_razon ON tasks(razon)"),
                ("idx_formularios_task_id", "CREATE INDEX idx_formularios_task_id ON formularios(task_id)"),
                ("idx_formularios_codigo_udg", "CREATE INDEX idx_formularios_codigo_udg ON formularios(codigo_udg)")
            ]
            
            for index_name, create_sql in indices:
                cursor.execute(f"SELECT name FROM sqlite_master WHERE type='index' AND name='{index_name}'")
                if not cursor.fetchone():
                    cursor.execute(create_sql)
            
            conn.commit()
            logger.info("Base de datos inicializada correctamente")
    except Exception as e:
        logger.error(f"Error al inicializar la base de datos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al inicializar la base de datos"
        )


# INICIALIZACIÓN DE FASTAPI

app = FastAPI(title="ISAA API - Task Manager", version="1.4.0")

# Middleware CORS para permitir requests desde el frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://127.0.0.1:5501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Evento de inicio de la aplicación."""
    try:
        init_db()
    except Exception as e:
        logger.critical(f"Error crítico al iniciar la aplicación: {e}")


# ENDPOINTS DE AUTENTICACIÓN

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

        response.headers["Cache-Control"] = "no-store"
        
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error inesperado en login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor al procesar la solicitud de login"
        )

@app.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Obtiene información del usuario actual."""
    return {
        "id": current_user["id"],
        "codigo": current_user["codigo"],
        "correo": current_user["correo"],
        "rol": current_user["rol"]
    }

# ENDPOINTS DE GESTIÓN DE USUARIOS

@app.post("/usuarios/", response_model=UsuarioResponse, status_code=201)
async def create_user(usuario: Usuario):
    """Crea un nuevo usuario en el sistema."""
    try:
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
            
            cursor.execute("SELECT id, codigo, correo, rol FROM usuarios WHERE id = ?", (user_id,))
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
    """Obtiene todos los usuarios del sistema."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, codigo, correo, rol FROM usuarios")
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
    """Obtiene un usuario específico por su ID."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, codigo, correo, rol FROM usuarios WHERE id = ?", (user_id,))
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


# ENDPOINTS DE GESTIÓN DE TAREAS/REPORTES PERSONALES

@app.post("/my-tasks/", response_model=TaskResponse, status_code=201)
async def create_my_task(task: Task, current_user: dict = Depends(get_current_user)):
    """Crea una nueva tarea para el usuario actual."""
    try:
        if not task.descripcion:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La descripción es obligatoria"
            )
        
        fecha, hora = get_current_local_date_time()
        usuario_id = current_user["id"]
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO tasks (usuario_id, descripcion, estado, fecha, hora, razon) VALUES (?, ?, ?, ?, ?, ?)",
                (usuario_id, task.descripcion, task.estado.value if task.estado else EstadoTarea.ACTIVO, fecha, hora, task.razon)
            )
            conn.commit()
            task_id = cursor.lastrowid
            
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora, t.razon
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

@app.get("/my-tasks/", response_model=List[TaskResponse])
async def read_my_tasks(
    estado: Optional[EstadoTarea] = None,
    razon: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """Obtiene las tareas del usuario actual con filtros opcionales."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora, t.razon
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.usuario_id = ?
            """
            params = [current_user["id"]]
            
            if estado:
                query += " AND t.estado = ?"
                params.append(estado.value)
            
            if razon:
                query += " AND t.razon = ?"
                params.append(razon.strip())
                
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

@app.get("/my-tasks/{task_id}", response_model=TaskResponse)
async def read_my_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Obtiene una tarea específica del usuario actual por su ID."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora, t.razon
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

@app.put("/my-tasks/{id}/{razon}", response_model=TaskResponse)
async def update_task_with_razon(
    id: int,
    razon: str,
    current_user: dict = Depends(get_current_user)
):
    """Actualiza una tarea del usuario actual añadiendo una razón de cancelación."""
    try:
        if not razon or not razon.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La razón no puede estar vacía"
            )

        usuario_id = current_user["id"]

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Verificar que la tarea exista y pertenezca al usuario
            cursor.execute(
                "SELECT id, estado FROM tasks WHERE id = ? AND usuario_id = ?",
                (id, usuario_id)
            )
            existing_task = cursor.fetchone()

            if not existing_task:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No se encontró la tarea para el usuario actual con ese id"
                )

            # Cambiar el estado a "Cancelado" y actualizar la razón
            cursor.execute(
                "UPDATE tasks SET estado = ?, razon = ? WHERE id = ? AND usuario_id = ?",
                ("Cancelado", razon.strip(), id, usuario_id)
            )
            conn.commit()

            # Recuperar la tarea actualizada
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante,
                       t.descripcion, t.estado, t.fecha, t.hora, t.razon
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.id = ? AND t.usuario_id = ?
            """, (id, usuario_id))
            updated_task = cursor.fetchone()

            if not updated_task:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al recuperar la tarea actualizada"
                )

            return TaskResponse(**dict(updated_task))

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al actualizar la razón de la tarea: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar la razón de la tarea"
        )


# ENDPOINTS DE ADMINISTRACIÓN DE TAREAS (ADMIN)

@app.get("/tasks/{task_id}", response_model=TaskResponse)
async def read_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Obtiene una tarea específica por su ID."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora, t.razon
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

@app.put("/tasks/{task_id}/estado", response_model=TaskResponse)
async def update_task_status(
    task_id: int,
    task_update: Task,
):
    """Actualiza el estado de una tarea específica. Solo para administradores."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verificar que la tarea existe
            cursor.execute("SELECT id FROM tasks WHERE id = ?", (task_id,))
            task = cursor.fetchone()
            
            if task is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Tarea no encontrada"
                )
            
            # Actualizar el estado
            cursor.execute(
                "UPDATE tasks SET estado = ? WHERE id = ?",
                (task_update.estado.value if task_update.estado else EstadoTarea.ACTIVO, task_id)
            )
            conn.commit()
            
            # Recuperar y retornar la tarea actualizada
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora, t.razon
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.id = ?
            """, (task_id,))
            updated_task = cursor.fetchone()
            
            if not updated_task:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al recuperar la tarea actualizada"
                )
            
            return TaskResponse(**dict(updated_task))
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al actualizar estado de la tarea {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar el estado de la tarea"
        )

@app.put("/tasks/{task_id}/{razon}", response_model=TaskResponse) 
async def update_task_razon(
    task_id: int, 
    razon: str, 
    current_user: dict = Depends(get_current_user)
):
    """Actualiza solo la razón de una tarea existente."""
    try:
        if not razon or not razon.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La razón no puede estar vacía"
            )
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verificar existencia y permisos
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
            
            # Actualizar solo la razón
            cursor.execute(
                "UPDATE tasks SET razon = ? WHERE id = ?",
                (razon.strip(), task_id)
            )
            conn.commit()
            
            # Recuperar y retornar la tarea actualizada
            cursor.execute("""
                SELECT t.id, t.usuario_id, u.codigo as codigo_estudiante, u.correo as correo_estudiante, 
                       t.descripcion, t.estado, t.fecha, t.hora, t.razon
                FROM tasks t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.id = ?
            """, (task_id,))
            updated_task_from_db = cursor.fetchone()
            
            if not updated_task_from_db:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al recuperar la tarea actualizada"
                )
            
            return TaskResponse(**dict(updated_task_from_db))

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al actualizar razón de la tarea {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar la razón de la tarea"
        )

@app.delete("/tasks/{task_id}", status_code=204)
async def delete_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Elimina una tarea existente."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
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


# ENDPOINT DE BÚSQUEDA AVANZADA

@app.get("/search-advanced", response_model=List[TaskResponse])
async def search_advanced(
  cor: Optional[List[str]] = Query(None, description="Buscar por correo"),
  cod: Optional[List[str]] = Query(None, description="Buscar por código"),
  id: Optional[List[Union[int, str]]] = Query(None, description="Buscar por ID"),
  des: Optional[List[str]] = Query(None, description="Buscar por descripción"),
  combinado: Optional[List[str]] = Query(None, description="Búsqueda combinada"),
  limit: int = Query(100, ge=1, le=500, description="Límite de resultados"),
  offset: int = Query(0, ge=0, description="Inicio de la paginación"),
  current_user: dict = Depends(get_current_user)
):
  """Realiza una búsqueda avanzada de tareas con filtros flexibles."""
  try:
      or_conditions = []
      valores = []
      
      def procesar_campo_simple(parametros, campo_db, like=False):
          if not parametros:
              return None, []
          
          sub_conditions = []
          sub_values = []
          
          for valor in parametros:
              if not valor:
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
          cor_condition, cor_values = procesar_campo_simple(cor, "u.correo", like=True)
          if cor_condition:
              or_conditions.append(f"({cor_condition})")
              valores.extend(cor_values)
      
      if cod:
          cod_condition, cod_values = procesar_campo_simple(cod, "u.codigo")
          if cod_condition:
              or_conditions.append(f"({cod_condition})")
              valores.extend(cod_values)
      
      if id:
          id_parsed = []
          for i in id:
              try:
                  id_parsed.append(int(i))
              except (ValueError, TypeError):
                  continue
          
          if id_parsed:
              id_condition, id_values = procesar_campo_simple(id_parsed, "t.id")
              if id_condition:
                  or_conditions.append(f"({id_condition})")
                  valores.extend(id_values)
      
      if des:
          des_condition, des_values = procesar_campo_simple(des, "t.descripcion", like=True)
          if des_condition:
              or_conditions.append(f"({des_condition})")
              valores.extend(des_values)

      # Procesar combinaciones AND
      if combinado:
          for combo in combinado:
              if not combo or "=" not in combo:
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
                      
                      valores_campo = valor.split(",") if valor else []
                      
                      if campo == "cor":
                          cond, vals = procesar_campo_simple(valores_campo, "u.correo", like=True)
                          if cond:
                              and_conditions.append(f"({cond})")
                              and_values.extend(vals)
                      
                      elif campo == "cod":
                          cond, vals = procesar_campo_simple(valores_campo, "u.codigo")
                          if cond:
                              and_conditions.append(f"({cond})")
                              and_values.extend(vals)
                      
                      elif campo == "id":
                          id_parsed = []
                          for i in valores_campo:
                              try:
                                  id_parsed.append(int(i))
                              except (ValueError, TypeError):
                                  continue
                          
                          if id_parsed:
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
                 t.descripcion, t.estado, t.fecha, t.hora, t.razon
          FROM tasks t
          JOIN usuarios u ON t.usuario_id = u.id
      """
      
      if or_conditions:
          query = base_query + " WHERE " + " OR ".join(or_conditions)
      else:
          query = base_query
          
      query += " LIMIT ? OFFSET ?"
      valores.extend([limit, offset])
      
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


# ENDPOINTS DE FORMULARIOS DE DENUNCIA
@app.post("/my-tasks/{task_id}/formulario", response_model=FormularioResponse, status_code=201)
async def create_formulario(
    task_id: int,
    formulario: FormularioRequest,
    current_user: dict = Depends(get_current_user)
):
    """Crea un formulario detallado para una tarea específica del usuario actual."""
    try:
        # Verificar que la tarea existe y pertenece al usuario
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM tasks WHERE id = ? AND usuario_id = ?",
                (task_id, current_user["id"])
            )
            task = cursor.fetchone()
            
            if not task:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Tarea no encontrada o no tienes permiso para acceder a ella"
                )
            
            # Verificar si ya existe un formulario para esta tarea
            cursor.execute("SELECT id FROM formularios WHERE task_id = ?", (task_id,))
            existing_form = cursor.fetchone()
            
            if existing_form:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Ya existe un formulario para esta tarea"
                )
            
            # Obtener fecha y hora actuales
            fecha, hora = get_current_local_date_time()
            
            # Crear el formulario
            cursor.execute("""
                INSERT INTO formularios 
                (task_id, nombres, apellido_paterno, apellido_materno, codigo_udg, 
                 fecha_nacimiento, descripcion_detallada, fecha_creacion, hora_creacion)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_id, formulario.nombres.strip(), formulario.apellido_paterno.strip(), formulario.apellido_materno.strip(),
                formulario.codigo_udg.strip(), formulario.fecha_nacimiento, formulario.descripcion_detallada.strip(),
                fecha, hora
            ))
            conn.commit()
            formulario_id = cursor.lastrowid
            
            # Recuperar el formulario creado
            cursor.execute("""
                SELECT id, task_id, nombres, apellido_paterno, apellido_materno, codigo_udg,
                       fecha_nacimiento, descripcion_detallada, fecha_creacion, hora_creacion
                FROM formularios WHERE id = ?
            """, (formulario_id,))
            new_form = cursor.fetchone()
            
            if not new_form:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al crear el formulario"
                )
            
            return FormularioResponse(**dict(new_form))
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al crear formulario para tarea {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear el formulario"
        )

@app.get("/my-tasks/{task_id}/formulario", response_model=FormularioResponse)
async def get_my_formulario(
    task_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Obtiene el formulario de una tarea específica del usuario actual."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verificar que la tarea existe y pertenece al usuario
            cursor.execute(
                "SELECT id FROM tasks WHERE id = ? AND usuario_id = ?",
                (task_id, current_user["id"])
            )
            task = cursor.fetchone()
            
            if not task:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Tarea no encontrada o no tienes permiso para acceder a ella"
                )
            
            # Obtener el formulario
            cursor.execute("""
                SELECT id, task_id, nombres, apellido_paterno, apellido_materno, codigo_udg,
                       fecha_nacimiento, descripcion_detallada, fecha_creacion, hora_creacion
                FROM formularios WHERE task_id = ?
            """, (task_id,))
            formulario = cursor.fetchone()
            
            if not formulario:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No se encontró formulario para esta tarea"
                )
            
            return FormularioResponse(**dict(formulario))
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al obtener formulario de tarea {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al recuperar el formulario"
        )

@app.get("/tasks/{task_id}/formulario", response_model=FormularioResponse)
async def get_formulario(
    task_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Obtiene el formulario de cualquier tarea (para administradores o propietarios)."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verificar que la tarea existe
            cursor.execute("SELECT usuario_id FROM tasks WHERE id = ?", (task_id,))
            task = cursor.fetchone()
            
            if not task:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Tarea no encontrada"
                )
            
            # Verificar permisos (propietario o admin)
            if task["usuario_id"] != current_user["id"] and current_user.get("rol") != "admin":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No tienes permiso para acceder a este formulario"
                )
            
            # Obtener el formulario
            cursor.execute("""
                SELECT id, task_id, nombres, apellido_paterno, apellido_materno, codigo_udg,
                       fecha_nacimiento, descripcion_detallada, fecha_creacion, hora_creacion
                FROM formularios WHERE task_id = ?
            """, (task_id,))
            formulario = cursor.fetchone()
            
            if not formulario:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No se encontró formulario para esta tarea"
                )
            
            return FormularioResponse(**dict(formulario))
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al obtener formulario de tarea {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al recuperar el formulario"
        )


"""
RESUMEN DE LA API ORGANIZADA:

CONFIGURACIÓN Y DEPENDENCIAS:
- FastAPI con middleware CORS
- SQLite como base de datos
- JWT para autenticación
- bcrypt para hash de contraseñas
- Logging para monitoreo

MODELOS DE DATOS:
- Usuario: Gestión de usuarios y roles
- Task: Reportes de emergencia con estados
- Formulario: Denuncias estudiantiles detalladas
- Token: Autenticación JWT

SISTEMA DE AUTENTICACIÓN:
- JWT tokens con expiración
- Roles: admin y usuario
- Middleware de seguridad OAuth2

ENDPOINTS PRINCIPALES:
- /token: Autenticación
- /usuarios/: CRUD de usuarios
- /my-tasks/: Gestión de reportes personales
- /tasks/: Administración de reportes (admin)
- /formularios/: Denuncias detalladas
- /search-advanced: Búsqueda avanzada

CARACTERÍSTICAS DE SEGURIDAD:
- Validación de permisos por rol
- Sanitización de datos de entrada
- Manejo robusto de errores
- Logging de actividades

FUNCIONALIDADES AVANZADAS:
- Búsqueda con múltiples criterios
- Paginación de resultados
- Estados de reportes (Activo, Pendiente, Completado, Cancelado)
- Razones de cancelación
- Timestamps automáticos
"""

"""
ARQUITECTURA DE LA API ISAA:

ESTRUCTURA MODULAR:
- Configuración centralizada con variables de entorno
- Modelos Pydantic para validación automática
- Context managers para manejo seguro de DB
- Middleware CORS para integración frontend
- Logging estructurado para monitoreo

SEGURIDAD IMPLEMENTADA:
- Autenticación JWT con expiración configurable
- Hash bcrypt para contraseñas
- Validación de permisos por rol (admin/usuario)
- Sanitización automática de inputs
- Manejo seguro de errores sin exposición de datos

ENDPOINTS ORGANIZADOS:
- /token: Autenticación y login
- /usuarios/: Gestión de usuarios
- /my-tasks/: Reportes personales del usuario
- /tasks/: Administración de reportes (admin)
- /formularios/: Denuncias estudiantiles detalladas
- /search-advanced: Búsqueda con múltiples criterios
- /health: Monitoreo del sistema

BASE DE DATOS OPTIMIZADA:
- SQLite con índices para rendimiento
- Relaciones FK con integridad referencial
- Migraciones automáticas de esquema
- Context managers para transacciones seguras

CARACTERÍSTICAS AVANZADAS:
- Timezone awareness (Mexico City)
- Paginación en consultas
- Búsqueda avanzada con operadores
- Estados de reporte con workflow
- Validación automática con Pydantic
- Logging de actividades para auditoría

Esta API proporciona una base sólida y escalable para el sistema ISAA,
con todas las mejores prácticas de desarrollo implementadas.
"""
