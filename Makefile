.PHONY: install sample train test smoke run lint

install:
	python -m pip install -r requirements.txt

sample:
	python scripts/generate_sample_data.py

train:
	python train_models.py --data-dir data --model-dir models --allow-overwrite

test:
	pytest -q

smoke:
	python scripts/smoke_test.py

run:
	python app.py

lint:
	python -m ruff check src tests app.py train_models.py evaluate_models.py
