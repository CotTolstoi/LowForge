@echo off
setlocal
cd /d "%~dp0"
if exist "router\__pycache__" (rmdir /s /q "router\__pycache__")
if exist "router\__pycache__" (echo Failed to clear Python cache.& pause & exit /b 1)
python main.py
pause
