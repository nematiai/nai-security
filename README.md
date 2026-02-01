## General Instruction: Creating a Shared Django Package

### Step 1: Create Package Structure

```
D:\NAI_Project\{package-name}\
├── pyproject.toml
├── README.md
├── .gitignore
└── {package_name}\          # underscore, not hyphen
    ├── __init__.py
    ├── apps.py
    ├── models\
    │   ├── __init__.py
    │   └── ... (model files)
    ├── services\
    ├── admin.py
    ├── views.py
    ├── urls.py
    └── migrations\
        └── __init__.py      # Keep empty, no migration files
```

### Step 2: Key Files Content

**pyproject.toml:**
```toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "{package-name}"
version = "1.0.0"
description = "Description here"
requires-python = ">=3.11"
dependencies = ["django>=4.2"]

[tool.setuptools.packages.find]
where = ["."]
include = ["{package_name}*"]
```

**{package_name}/\_\_init\_\_.py:**
```python
default_app_config = '{package_name}.apps.{AppName}Config'
__version__ = '1.0.0'
```

**{package_name}/apps.py:**
```python
from django.apps import AppConfig

class {AppName}Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = '{package_name}'
    verbose_name = '{App Name}'
```

### Step 3: Copy Code from Existing App

```powershell
# Copy folder
Copy-Item -Path "D:\NAI_Project\{PROJECT}\{backend}\apps\{app}\" -Destination "D:\NAI_Project\{package-name}\{package_name}\" -Recurse

# Fix imports
$files = Get-ChildItem -Path ".\{package_name}" -Filter "*.py" -Recurse
foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw
    $content = $content -replace "apps\.{app}", "{package_name}"
    Set-Content -Path $file.FullName -Value $content -NoNewline
}

# Remove migrations (except __init__.py)
Remove-Item -Path ".\{package_name}\migrations\*.py" -Exclude "__init__.py"

# Remove __pycache__
Get-ChildItem -Path ".\{package_name}" -Directory -Recurse -Filter "__pycache__" | Remove-Item -Recurse -Force
```

### Step 4: Test Locally

```powershell
cd D:\NAI_Project\{package-name}
pip install -e .
python -c "import {package_name}; print({package_name}.__version__)"
```

### Step 5: Push to GitHub

```powershell
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/{username}/{package-name}.git
git push -u origin main
```

### Step 6: Use in Projects

**requirements.txt:**
```
git+https://github.com/{username}/{package-name}.git@main#egg={package-name}
```

**settings.py:**
```python
INSTALLED_APPS = [
    ...
    "{package_name}",
]
```

**Dockerfile (add git):**
```dockerfile
apt-get install -y --no-install-recommends ... git
```

### Step 7: Update Original Project

1. Remove old `apps/{app}/` folder
2. Update `settings.py`: `apps.{app}` → `{package_name}`
3. Update all imports in other files
4. Rebuild Docker

---

**That's it.** Same process every time.

Now show me your build output.
