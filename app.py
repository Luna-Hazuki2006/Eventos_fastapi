from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from typing import List, Union, Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "27A0D7C4CCCE76E6BE39225B7EEE8BD0EF890DE82D49E459F4C405C583080AB0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Evento(BaseModel): 
    ID : str
    titulo : str
    descripcion : str
    fechaHora : datetime
    notas : List[str]
    fue_realizado : bool

class Usuario(BaseModel): 
    usuario : str
    nombre_real : str
    contraseña : str
    color_favorito : str

class UsuarioEnBD(Usuario): 
    contraseñaHasheada : str

class Token(BaseModel): 
    usuario : str
    token_acceso : str
    tipo_token : str

class DataToken(BaseModel): 
    usuario : Union[str, None] = None

usuarios : list[Usuario] = []
eventos : list[Evento] = []
basedatos : list[UsuarioEnBD] = []

def crear_token_acceso(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def dumb_decode_token(usuarioReal : Usuario, token):
    return Usuario(usuario=token + "dummydecoded", color_favorito=usuarioReal.color_favorito, nombre_real=usuarioReal.nombre_real)

def obtener_usuario(usuario: str):
    for esto in usuarios: 
        if esto.usuario == usuario: 
            return UsuarioEnBD(usuario=esto.usuario, nombre_real=esto.nombre_real, color_favorito=esto.color_favorito, contraseña=esto.contraseña, contraseñaHasheada='dsd')

def get_password_hash(password):
    return pwd_context.hash(password)

# async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
#     user = dumb_decode_token(token)
#     credentials_exception = HTTPException(
#             status_code= status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid authentication credentials",
#             headers={"WWW-Authenticate": "Bearer"}
#         )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         token_data = DataToken(usuario=username)
#     except JWTError:
#         raise credentials_exception
#     user = obtener_usuario(usuario=token_data.username)
#     if user is None:
#         raise credentials_exception
#     return user

def verify_password(plain_password, contraseñaHasheada):
    return pwd_context.verify(plain_password, contraseñaHasheada)

def autenticar_usuario(username: str, password: str):
    user = obtener_usuario(username)
    print(user)
    if not user:
        return False
    contraseñaHasheada = get_password_hash(user.contraseñaHasheada)
    if not verify_password(password, contraseñaHasheada):
        return False
    return user

@app.post('/registrar')
async def registrar(usuario : Usuario): 
    for esto in usuarios:
        if esto.usuario == usuario.usuario: 
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE, 
                detail='Ya existe un usuario con el mismo nombre'
            )
    usuarios.append(usuario)
    return usuario

@app.post('/inciarsesion')
async def iniciar_sesion(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token: 
    usuario = autenticar_usuario(form_data.username, form_data.password)
    if not usuario: 
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = crear_token_acceso(
        data={"sub": usuario.username}, expires_delta=access_token_expires
    )
    return Token(token_acceso=access_token, tipo_token= "bearer")

@app.post('/cerrarsesion')
async def cerrar_sesion(): 
    return 'chaito :3'

@app.get('/eventos')
async def listar_eventos(): 
    return eventos

@app.post('/evento', status_code=status.HTTP_201_CREATED)
async def crear_evento(evento : Evento): 
    for esto in eventos: 
        if esto.ID == evento.ID: 
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE, 
                detail='No se puede tener un evento con una id que ya exista'
            )
    eventos.append(evento)
    return evento

@app.get('/evento/{id}')
async def buscar_evento(id : str): 
    for esto in eventos: 
        if esto.ID == id: return esto
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, 
        detail="No se pudo encontrar ese evento"
    )

@app.get('/eventos_hechos')
async def listar_eventos_hechos(): 
    hechos = filter(lambda x: x.fue_realizado == True, eventos)
    if hechos == None: 
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="No se pudieron encontrar eventos hechos"
        )
    else: return hechos

@app.get('/eventos_no_hechos')
async def listar_eventos_no_hechos(): 
    no_hechos = filter(lambda x: x.fue_realizado == False, eventos)
    if no_hechos == None: 
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="No se pudieron encontrar eventos no hechos"
        )
    else: return no_hechos

@app.put('/evento/{id}')
async def modificar_evento(id : str, evento : Evento): 
    if id != evento.ID: 
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE, 
            detail='El id del parámetro y la del evento deben ser iguales'
        )
    for i in range(len(eventos)): 
        if eventos[i].ID == id: 
            eventos[i] = evento
            return evento
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, 
        detail='No se pudo encontrar un evento con tal id'
    )

@app.put('/evento_notas/{id}')
async def añadir_notas(id : str, notas : str): 
    for i in range(len(eventos)): 
        if eventos[i].ID == id: 
            eventos[i].notas.append(notas)
            return eventos[i]
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, 
        detail='No se pudo encontrar un evento con tal id'
    )

@app.delete('/evento/{id}')
async def eliminar_evento(id : str): 
    for i in range(len(eventos)): 
        if eventos[i].ID == id: 
            evento = eventos[i]
            eventos.remove(evento)
            return evento 
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, 
        detail='No se pudo encontrar un evento con tal id'
    )