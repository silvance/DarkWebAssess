# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the mini threat-intelligence platform.

Build with:
    pip install -r requirements-build.txt
    python -m PyInstaller --clean --noconfirm mini-threat-intel.spec
    # or:
    python scripts/build_exe.py

Output: dist/mini-threat-intel/mini-threat-intel(.exe)

The build is a "onedir" bundle (executable + sidecar libs/data). Onefile is
not recommended here because Streamlit unpacks slowly from a tar archive on
first run.
"""
from PyInstaller.utils.hooks import collect_all, copy_metadata

datas = []
binaries = []
hiddenimports = []

# Pull in everything from the heaviest deps so PyInstaller's static analysis
# doesn't miss data files / hidden imports.
for pkg in (
    "streamlit",
    "feedparser",
    "tldextract",
    "apscheduler",
    "pydantic",
    "anthropic",
    "yaml",
    "socks",  # pysocks — needed by requests for Tor SOCKS5 routing
):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# Streamlit and Pydantic both rely on package metadata at runtime.
for pkg in ("streamlit", "pydantic", "anthropic"):
    datas += copy_metadata(pkg)

# Bundle our own data files so they end up alongside the executable.
datas += [
    ("sources.yaml", "."),
    ("watchlist.yaml", "."),
    ("suppression.yaml", "."),
    ("app/extractors/named_entities.yaml", "app/extractors"),
    ("app/ui/streamlit_app.py", "app/ui"),
]

# Hidden imports that PyInstaller's analyzer can't see (mostly because we
# import lazily inside CLI handlers).
hiddenimports += [
    "app.main",
    "app.pipeline",
    "app.config_models",
    # CLI subcommand modules — registered by parser.py but loaded via importlib
    "app.cli.parser",
    "app.cli._helpers",
    "app.cli.cmd_alerts",
    "app.cli.cmd_backup",
    "app.cli.cmd_cases",
    "app.cli.cmd_collection",
    "app.cli.cmd_enrich",
    "app.cli.cmd_pivot",
    "app.cli.cmd_reports",
    "app.cli.cmd_scheduler",
    "app.cli.cmd_score",
    "app.cli.cmd_search",
    "app.cli.cmd_summarize",
    "app.cli.cmd_tor",
    "app.cli.cmd_users",
    # Auth + collectors + extractors + matching + enrichment + cases + reports
    "app.auth.audit",
    "app.auth.middleware",
    "app.auth.passwords",
    "app.auth.users",
    "app.collectors.onion_collector",
    "app.collectors.rss_collector",
    "app.extractors.entities",
    "app.extractors.handles",
    "app.extractors.named_entities",
    "app.extractors.onion",
    "app.extractors.wallets",
    "app.matching.watchlist_matcher",
    "app.matching.scoring",
    "app.matching.suppression",
    "app.enrichment.runner",
    "app.enrichment.cisa_kev",
    "app.enrichment.epss",
    "app.enrichment.urlhaus",
    "app.enrichment.malware_bazaar",
    "app.enrichment.virustotal",
    "app.enrichment.abuseipdb",
    "app.alerts.telegram",
    "app.jobs.scheduler",
    "app.jobs.runner",
    "app.search",
    "app.llm.summarizer",
    "app.llm.prompts",
    "app.llm.schemas",
    "app.cases.repository",
    "app.cases.exporter",
    "app.graph.relationships",
    "app.reports.runner",
    "app.reports.templates",
    "app.reports.renderers",
    "streamlit.web.cli",
    "streamlit.runtime.scriptrunner",
]


block_cipher = None

a = Analysis(
    ["app/entry.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tests"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="mini-threat-intel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="mini-threat-intel",
)
