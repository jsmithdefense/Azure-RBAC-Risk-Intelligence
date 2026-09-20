from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


@dataclass(frozen=True)
class RiskConfig:
    role_weights: Dict[str, int]
    scope_weights: Dict[str, int]
    principal_modifiers: Dict[str, int]
    severity_thresholds: Dict[str, int]
    role_taxonomy: Dict[str, str]


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_llm_defaults(project_root: Path | None = None) -> Dict[str, Any]:
    """
    Read the LLM endpoint settings from config/llm.json. These are not secrets.

    The file is optional. You can set LLM_BASE_URL, LLM_MODEL and LLM_API_KEY in
    the environment instead. Thus, if the file is absent, this function returns
    an empty result. It does not raise an error.

    A key that starts with an underscore is a comment in the JSON file. The key
    "presets" is a list of example endpoints. Neither is a setting. Thus this
    function removes both. This function never reads an API key from the file.
    """
    root = project_root or Path(__file__).resolve().parents[1]
    llm_path = root / "config" / "llm.json"

    if not llm_path.exists():
        return {}

    raw = _load_json(llm_path)
    if not isinstance(raw, dict):
        raise ValueError(f"{llm_path} must be a JSON object")

    return {
        key: value
        for key, value in raw.items()
        if not key.startswith("_") and key != "presets"
    }


def load_risk_config(project_root: Path | None = None) -> RiskConfig:
    """
    Loads risk scoring weights and optional taxonomy mapping from config/.

    The taxonomy file is optional. If missing, roles will be classified
    dynamically using permission inspection.
    """
    root = project_root or Path(__file__).resolve().parents[1]
    cfg_dir = root / "config"

    weights_path = cfg_dir / "risk_weights.json"
    taxonomy_path = cfg_dir / "role_taxonomy.json"

    weights = _load_json(weights_path)

    # Taxonomy file is optional
    if taxonomy_path.exists():
        taxonomy = _load_json(taxonomy_path)

        if not isinstance(taxonomy, dict):
            raise ValueError(
                f"{taxonomy_path} must be a JSON object mapping role_name -> bucket"
            )

        taxonomy_map = {k: str(v) for k, v in taxonomy.items()}
    else:
        taxonomy_map = {}

    # Validate weights structure
    required_keys = [
        "role_weights",
        "scope_weights",
        "principal_modifiers",
        "severity_thresholds",
    ]

    for k in required_keys:
        if k not in weights or not isinstance(weights[k], dict):
            raise ValueError(f"{weights_path} missing or invalid key: {k}")

    return RiskConfig(
        role_weights={k: int(v) for k, v in weights["role_weights"].items()},
        scope_weights={k: int(v) for k, v in weights["scope_weights"].items()},
        principal_modifiers={k: int(v) for k, v in weights["principal_modifiers"].items()},
        severity_thresholds={k: int(v) for k, v in weights["severity_thresholds"].items()},
        role_taxonomy=taxonomy_map,
    )