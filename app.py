from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from typing import List, Union
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "27A0D7C4CCCE76E6BE39225B7EEE8BD0EF890DE82D49E459F4C405C583080AB0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Evento(BaseModel): 
    ID : int
    titulo : str
    descripcion : str
    fechaHora : datetime
    notas : List[str]
    fue_realizado : bool

class Usuario(BaseModel): 
    usuario : str
    nombre_real : str
    contraseña : str

usuarios : list[Usuario] = []
eventos : list[Evento] = []

@app.post('/registrar')
async def registrar(usuario : Usuario): 
    for esto in usuarios:
        if esto.usuario == usuario.usuario: 
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE, 
                detail='Ya existe un usuario con el mismo nombre'
            )
    usuarios.append(usuario)

@app.post('/inciarsesion')
async def iniciar_sesion(): 
    return 'holis :3'

@app.post('/cerrarsesion')
async def cerrar_sesion(): 
    return 'chaito :3'

@app.get('/eventos')
async def listar_eventos(): 
    return eventos

@app.post('/evento', status_code=status.HTTP_201_CREATED)
async def crear_evento(evento : Evento): 
    estos = filter(lambda x: x.ID == evento.ID, eventos)
    if estos != None: 
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE, 
            detail='No se puede tener un evento con una id que ya exista'
        )
    else: 
        eventos.append(evento)
        return evento

@app.get('/evento/{id}')
async def buscar_evento(id : int): 
    for esto in eventos: 
        if esto.ID == id: return esto
    else: 
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
async def modificar_evento(id : int, evento : Evento): 
    if id != evento.ID: 
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE, 
            detail='El id del parámetro y la del evento deben ser iguales'
        )
    real = filter(lambda x: x.ID == id, eventos)
    if real == None: 
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail='No se pudo encontrar un evento con tal id'
        )
    eventos[eventos.index(real)] = evento
    return evento

@app.put('/evento_notas/{id}')
async def añadir_notas(id, notas): 
    return f'Un evento {id} con estas notas {notas}'

@app.delete('/evento/{id}')
async def eliminar_evento(id : int): 
    evento = filter(lambda x: x.ID == id, eventos)
    if evento == None: 
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail='No se pudo encontrar un evento con tal id'
        )
    eventos.remove(evento)
    return evento