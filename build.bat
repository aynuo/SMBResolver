@echo off
python -m PyInstaller --noconfirm --onefile --console --name SMBResolver ^
  --collect-submodules uvicorn ^
  --collect-submodules websockets ^
  --collect-submodules smbresolver ^
  --add-data "smbresolver\plugins;smbresolver\plugins" ^
  --add-data "config.example.yaml;." ^
  run.py