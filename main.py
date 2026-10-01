import os
import re
import bcrypt
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt
from dotenv import load_dotenv

# 1. Cargar claves secretas desde el archivo .env
load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET", "clave_super_secreta_novapay_2026")

# 2. Inicializar la aplicación FastAPI
app = FastAPI(title="NovaPay Secure API Gateway")

# Base de datos temporal en memoria
db_usuarios = {}

# --- MODELOS DE DATOS ---
class UsuarioRegistro(BaseModel):
    nombre: str
    email: str
    password: str
    consentimiento_gdpr: bool  # Cumplimiento GDPR / Ley 1581

class UsuarioLogin(BaseModel):
    email: str
    password: str

# --- FUNCIONES DE SEGURIDAD Y VALIDACIÓN ---
def encriptar_password(password: str) -> str:
    # Usamos bcrypt directo sin depender del wrapper passlib
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verificar_password(password_plano: str, password_encriptado: str) -> bool:
    try:
        return bcrypt.checkpw(password_plano.encode('utf-8'), password_encriptado.encode('utf-8'))
    except Exception:
        return False

def validar_regex_nombre(nombre: str) -> bool:
    # Solo letras y espacios (bloquea inyecciones XSS)
    return bool(re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ ]+$", nombre))

def validar_regex_password(password: str) -> bool:
    # Mínimo 8 caracteres, al menos una mayúscula y un número
    return bool(re.match(r"^(?=.*[A-Z])(?=.*\d).{8,}$", password))

# --- ENDPOINTS (PUNTOS DE ENTRADA) ---

# Endpoint 1: Registro de Usuarios (/register)
@app.post("/register")
def registrar_usuario(datos: UsuarioRegistro):
    # A. Validar cumplimiento GDPR
    if not datos.consentimiento_gdpr:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error GDPR: Debe aceptar el consentimiento explicito de datos."
        )

    # B. Validar Regex en el Nombre
    if not validar_regex_nombre(datos.nombre):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error: El nombre solo puede contener letras y espacios."
        )

    # C. Validar Regex en la Contraseña
    if not validar_regex_password(datos.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error: La contrasena debe tener al menos 8 caracteres, una mayuscula y un numero."
        )

    # D. Verificar si el correo ya existe
    if datos.email in db_usuarios:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario ya se encuentra registrado."
        )

    # E. Encriptar contraseña con bcrypt y guardar registro
    password_hash = encriptar_password(datos.password)
    db_usuarios[datos.email] = {
        "nombre": datos.nombre,
        "email": datos.email,
        "password_hash": password_hash,
        "gdpr_consent": datos.consentimiento_gdpr
    }
    return {"mensaje": "Usuario registrado exitosamente de forma segura en NovaPay."}

# Endpoint 2: Inicio de Sesión (/login)
@app.post("/login")
def login_usuario(datos: UsuarioLogin):
    usuario = db_usuarios.get(datos.email)
    
    # Verificar si existe el usuario y la contraseña coincide
    if not usuario or not verificar_password(datos.password, usuario["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas."
        )
    
    # Generar el Token JWT firmado
    token_payload = {"sub": usuario["email"], "nombre": usuario["nombre"]}
    token = jwt.encode(token_payload, JWT_SECRET, algorithm="HS256")
    return {
        "access_token": token,
        "token_type": "bearer",
        "mensaje": "Inicio de sesion exitoso."
    }
