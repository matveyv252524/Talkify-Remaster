from fastapi import FastAPI, Request, WebSocket, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.future import select
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, func
from sqlalchemy.orm import relationship
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import List, Optional, Dict
import os
import secrets
from dotenv import load_dotenv


# Загрузка переменных окружения
load_dotenv()

# Конфигурация
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    # Для PostgreSQL на Render
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")
else:
    # Для локальной разработки - SQLite
    DATABASE_URL = "sqlite+aiosqlite:///./messenger.db"

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-for-development")
IS_RENDER = os.getenv("RENDER", "false").lower() == "true"
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",")

# Инициализация FastAPI
app = FastAPI(title="Messenger", docs_url="/api/docs", redoc_url="/api/redoc")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# База данных
engine = create_async_engine(DATABASE_URL, echo=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
Base = declarative_base()

# Templates
templates = Jinja2Templates(directory="templates")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Модели базы данных
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_online = Column(Boolean, default=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now())

    contacts = relationship("Contact", foreign_keys="[Contact.user_id]", back_populates="user")
    contact_of = relationship("Contact", foreign_keys="[Contact.contact_id]", back_populates="contact")
    chat_members = relationship("ChatMember", back_populates="user")
    messages = relationship("Message", back_populates="user")


class Contact(Base):
    __tablename__ = "contacts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    contact_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    added_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", foreign_keys=[user_id], back_populates="contacts")
    contact = relationship("User", foreign_keys=[contact_id], back_populates="contact_of")


class Chat(Base):
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=True)
    is_group = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    members = relationship("ChatMember", back_populates="chat")
    messages = relationship("Message", back_populates="chat")


class ChatMember(Base):
    __tablename__ = "chat_members"
    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    joined_at = Column(DateTime(timezone=True), server_default=func.now())

    chat = relationship("Chat", back_populates="members")
    user = relationship("User", back_populates="chat_members")


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    is_read = Column(Boolean, default=False)

    chat = relationship("Chat", back_populates="messages")
    user = relationship("User", back_populates="messages")


# Утилиты
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_simple_token(user_id: int) -> str:
    """Простая реализация токена"""
    payload = {
        "sub": str(user_id),
        "exp": (datetime.utcnow() + timedelta(minutes=60)).timestamp()
    }
    return f"user_{user_id}_{payload['exp']}"


def verify_simple_token(token: str) -> Optional[int]:
    """Проверка простого токена"""
    try:
        if token.startswith("user_"):
            parts = token.split("_")
            if len(parts) >= 3:
                user_id = int(parts[1])
                exp_timestamp = float(parts[2])
                if datetime.utcnow().timestamp() < exp_timestamp:
                    return user_id
    except (ValueError, IndexError):
        return None
    return None


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None

    user_id = verify_simple_token(token)
    if not user_id:
        return None

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    return user


# WebSocket менеджер
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, WebSocket] = {}
        self.user_chats: Dict[int, List[int]] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, message: dict, user_id: int):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_json(message)

    async def broadcast_to_chat(self, message: dict, chat_id: int, exclude_user_id: int = None):
        for user_id, websocket in self.active_connections.items():
            if user_id != exclude_user_id and user_id in self.user_chats.get(chat_id, []):
                await websocket.send_json(message)

    def join_chat(self, user_id: int, chat_id: int):
        if chat_id not in self.user_chats:
            self.user_chats[chat_id] = []
        if user_id not in self.user_chats[chat_id]:
            self.user_chats[chat_id].append(user_id)

    def leave_chat(self, user_id: int, chat_id: int):
        if chat_id in self.user_chats and user_id in self.user_chats[chat_id]:
            self.user_chats[chat_id].remove(user_id)


manager = ConnectionManager()


# Создание таблиц при запуске
@app.on_event("startup")
async def startup():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("Database tables created successfully")
    except Exception as e:
        print(f"Database connection error: {e}")
        # Для Render, если PostgreSQL ещё не готов, ждём немного
        if IS_RENDER:
            import time
            time.sleep(2)
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)


# Роуты
@app.get("/", response_class=HTMLResponse)
async def root(request: Request, current_user: User = Depends(get_current_user)):
    if current_user:
        return RedirectResponse("/chat")
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login(
        request: Request,
        email: str = Form(...),
        password: str = Form(...),
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()

    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверный email или пароль"
        })

    user.is_online = True
    user.last_seen = datetime.utcnow()
    await db.commit()

    access_token = create_simple_token(user.id)
    response = RedirectResponse("/chat", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=3600)
    return response


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@app.post("/register")
async def register(
        request: Request,
        email: str = Form(...),
        username: str = Form(...),
        password: str = Form(...),
        password_confirm: str = Form(...),
        db: AsyncSession = Depends(get_db)
):
    if password != password_confirm:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пароли не совпадают"
        })

    result = await db.execute(select(User).where(User.email == email))
    if result.scalars().first():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Email уже зарегистрирован"
        })

    result = await db.execute(select(User).where(User.username == username))
    if result.scalars().first():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Имя пользователя уже занято"
        })

    hashed_password = get_password_hash(password)
    user = User(email=email, username=username, password_hash=hashed_password)

    db.add(user)
    await db.commit()
    await db.refresh(user)

    access_token = create_simple_token(user.id)
    response = RedirectResponse("/chat", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=3600)
    return response


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
):
    if not current_user:
        return RedirectResponse("/login")

    result = await db.execute(
        select(Chat).join(ChatMember).where(ChatMember.user_id == current_user.id)
    )
    chats = result.scalars().all()

    result = await db.execute(
        select(Contact).where(Contact.user_id == current_user.id)
    )
    contacts = result.scalars().all()

    for chat in chats:
        result = await db.execute(
            select(ChatMember).where(ChatMember.chat_id == chat.id)
        )
        chat.members = result.scalars().all()
        for member in chat.members:
            await db.refresh(member.user)

    for contact in contacts:
        await db.refresh(contact.contact)

    return templates.TemplateResponse("chat.html", {
        "request": request,
        "current_user": current_user,
        "chats": chats,
        "contacts": contacts,
        "current_chat": None,
        "messages": [],
        "token": create_simple_token(current_user.id)
    })


@app.get("/logout")
async def logout():
    response = RedirectResponse("/")
    response.delete_cookie("access_token")
    return response


# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}


# API endpoints
@app.get("/api/users/me")
async def get_current_user_api(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.username,
        "is_online": current_user.is_online,
        "created_at": current_user.created_at
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
