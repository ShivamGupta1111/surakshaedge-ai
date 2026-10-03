# Local model artifacts

Files such as `sms_model.joblib` are written by `python train_models.py`.

- Only load artifacts produced on this machine from trusted CSVs.
- `joblib` can execute code during unpickle. Never place downloaded models here.
- `model_metadata.json` records SHA-256 checksums, library versions, and a `demo: true` flag when sample data was used.
- Missing files are OK: detectors fall back to deterministic rules.
