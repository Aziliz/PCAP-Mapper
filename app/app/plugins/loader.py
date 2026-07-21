import importlib.util
from pathlib import Path
from app.config import PLUGIN_DIR


def load_plugins():
    plugins=[]
    for path in PLUGIN_DIR.glob('*.py'):
        try:
            spec = importlib.util.spec_from_file_location(path.stem, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            if hasattr(mod, 'analyze_event'):
                plugins.append(mod)
        except Exception as e:
            print(f'plugin load failed {path}: {e}')
    return plugins


def run_plugins(event, context, plugins):
    findings=[]
    for p in plugins:
        try:
            res = p.analyze_event(event, context) or []
            findings.extend(res)
        except Exception as e:
            findings.append({'title':'Plugin Error','severity':'low','description':str(e),'plugin':getattr(p,'__name__','unknown')})
    return findings
