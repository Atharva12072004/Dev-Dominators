#!/usr/bin/env sh
set -eu

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -c "from services.yara_engine import compile_rules_or_raise; compile_rules_or_raise(); print('YARA rules compiled successfully')"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

