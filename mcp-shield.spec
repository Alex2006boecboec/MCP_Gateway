# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the `mcp-shield` standalone proxy binary.

Builds a one-file executable that bundles the proxy core + its lightweight
deps (pyyaml, jsonschema) and the bundled default policy. Heavy optional
deps (torch, scikit-learn, sentence-transformers, fastapi, uvicorn, jinja2,
psycopg2, httpx) are EXCLUDED on purpose — they belong to the optional ML
detector layers and the cloud dashboard (which runs separately). This keeps
the binary small (~15-25 MB) and lets no-code users run it without Python.

Build (run from repo root):
    pip install pyinstaller pyyaml jsonschema
    pyinstaller mcp-shield.spec --noconfirm --clean

The binary is emitted to dist/mcp-shield (macOS/Linux) or dist/mcp-shield.exe
(Windows). CI builds all three platforms via .github/workflows/release-binaries.yml.
"""

from PyInstaller.utils.hooks import collect_submodules

# Heavy optional deps we never want in the proxy binary.
excludes = [
    # Optional ML detector layers (Layer 2/3).
    "torch", "torchvision", "torchaudio",
    "sklearn", "scikit_learn",
    "sentence_transformers",
    "transformers", "tokenizers", "huggingface_hub",
    "numpy", "scipy", "pandas",
    # Cloud dashboard (runs as a separate service / Railway deploy).
    "fastapi", "uvicorn", "starlette",
    "jinja2", "itsdangerous", "multipart", "python_multipart",
    "psycopg2", "psycopg",
    "httpx", "httpcore",
    # Test deps.
    "pytest", "_pytest",
]

# All mcp_shield submodules must be picked up (graph/, detector/, approval/).
hiddenimports = collect_submodules("mcp_shield")

a = Analysis(
    ["mcp_shield/cli.py"],
    pathex=["."],
    binaries=[],
    datas=[
        # Bundle the default policy so `mcp-shield -- <srv>` works with no args.
        ("policies/default.yaml", "policies"),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="mcp-shield",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # stdio proxy must keep stdin/stdout/stderr attached.
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
