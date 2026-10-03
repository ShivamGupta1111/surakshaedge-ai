# SurakshaEdge AI — Web Frontend Interface

This directory contains the user-facing web dashboard interface for SurakshaEdge AI.

## Structure
- `index.html`: Responsive single-page application (SPA) with Threat Analyzer tabs, Risk Score progress gauge, Extracted Evidence tag cloud, Llama Advisor accordion, Alert History log table, and Metrics dashboard.
- `style.css`: Modern Dark Mode glassmorphism stylesheet (`#070A12` dark background, `#00F2FE` cyan accents, glassmorphism cards, risk color coding).
- `app.js`: Interactive frontend logic connecting user input to local backend REST API endpoints (`/api/v1/analyze/message`, `/api/v1/analyze/url`, `/api/v1/analyze/network-flow`, `/api/v1/analyze/telemetry`, `/api/v1/alerts`, `/api/v1/info`).

## Integration
The frontend is served directly by the FastAPI backend server (`src/api.py`). Running `python app.py` serves both the backend API and this frontend dashboard at `http://127.0.0.1:8080/`.
