from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates
from app import models, schemas, crud, auth
from .database import SessionLocal, engine
from datetime import timedelta
from fastapi.staticfiles import StaticFiles

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI()

# Mount static files directory for serving CSS and JavaScript
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Set up Jinja2 templates directory
templates = Jinja2Templates(directory="app/templates")

# Define OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    Authenticate user and return access token.
    """
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    response = RedirectResponse(url='/todos', status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.post("/register", response_model=schemas.User)
async def register_user(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Register a new user.
    """
    user = schemas.UserCreate(username=username, password=password)
    db_user = crud.get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    crud.create_user(db=db, user=user)
    response = RedirectResponse(url='/login', status_code=302)
    return response

@app.post("/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Log in and return an access token.
    """
    user = crud.authenticate_user(db, username=username, password=password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    response = RedirectResponse(url='/todos', status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """
    Serve the home page.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/todos/", response_class=HTMLResponse)
async def read_todos(request: Request, db: Session = Depends(get_db)):
    """
    Retrieve and display all TODO items for the current user.
    """
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    current_user = await auth.get_current_user(db, token)
    todos = crud.get_todo_items(db, user_id=current_user.id)
    return templates.TemplateResponse("todo.html", {"request": request, "todos": todos, "user": current_user})

@app.post("/todos/create", response_class=HTMLResponse)
async def create_todo(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Create a new TODO item.
    """
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    current_user = await auth.get_current_user(db, token)
    todo = schemas.TodoItemCreate(title=title, description=description)
    crud.create_todo_item(db=db, todo=todo, user_id=current_user.id)
    todos = crud.get_todo_items(db, user_id=current_user.id)
    return templates.TemplateResponse("todo.html", {"request": request, "todos": todos, "user": current_user})

@app.post("/todos/{todo_id}/update", response_class=HTMLResponse)
async def update_todo(
    request: Request,
    todo_id: int,
    title: str = Form(...),
    description: str = Form(...),
    completed: bool = Form(False),
    db: Session = Depends(get_db)
):
    """
    Update an existing TODO item.
    """
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    current_user = await auth.get_current_user(db, token)
    todo = schemas.TodoItemCreate(title=title, description=description)
    crud.update_todo_item(db=db, todo_id=todo_id, todo=todo, user_id=current_user.id)
    todos = crud.get_todo_items(db, user_id=current_user.id)
    return templates.TemplateResponse("todo.html", {"request": request, "todos": todos, "user": current_user})

@app.post("/todos/{todo_id}/delete", response_class=HTMLResponse)
async def delete_todo(
    request: Request,
    todo_id: int,
    db: Session = Depends(get_db)
):
    """
    Delete a TODO item.
    """
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    current_user = await auth.get_current_user(db, token)
    crud.delete_todo_item(db=db, todo_id=todo_id, user_id=current_user.id)
    todos = crud.get_todo_items(db, user_id=current_user.id)
    return templates.TemplateResponse("todo.html", {"request": request, "todos": todos, "user": current_user})

@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    """
    Serve the login page.
    """
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    """
    Serve the registration page.
    """
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/users/me")
async def read_users_me(request: Request, db: Session = Depends(get_db)):
    """
    Get the current user's information.
    """
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    current_user = await auth.get_current_user(db, token)
    return current_user

@app.post("/logout")
async def logout(request: Request):
    """
    Log out the user by deleting the access token cookie.
    """
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("access_token")
    return response
