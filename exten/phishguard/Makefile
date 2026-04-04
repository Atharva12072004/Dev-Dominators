PYTHON ?= python
APP ?= main:app

.PHONY: install check-yara run

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt

check-yara:
	$(PYTHON) -c "from services.yara_engine import compile_rules_or_raise; compile_rules_or_raise(); print('YARA rules compiled successfully')"

run:
	$(PYTHON) -m uvicorn $(APP) --host 0.0.0.0 --port 8000 --reload

