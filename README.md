# CyberShield AI

> **Hackathon Submission** · Team **Dev Dominators**

CyberShield AI is an Android-first cybersecurity application that protects users from phishing, malicious URLs, and suspicious content in real time. It combines a FastAPI backend with an Expo React Native mobile client and uses offline heuristics with optional AI-powered enrichment.

---

## Team

**Dev Dominators**

| Name | Role |
|---|---|
| Atharva Harane | Backend & AI Integration |
| Altamash Chougle | Mobile Development |
| Darsh Kamble | Android Native & Security |
| Lokesh Patil | UI/UX & Frontend |

---

## Project Overview

CyberShield AI scans SMS messages, Gmail content, push notifications, pasted text, and suspicious URLs to detect threats before they cause harm. Detection is offline-first with explainable risk scores, and an optional backend layer adds AI-powered enrichment using providers like OpenAI, Gemini, VirusTotal, and Google Safe Browsing.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python · FastAPI · Uvicorn · SQLite |
| Mobile | React Native · Expo · TypeScript |
| AI Enrichment | OpenAI · Google Gemini · Grok |
| Threat Intel | VirusTotal · Google Safe Browsing · Falcon Sandbox |
| Auth | Google OAuth 2.0 (Android + Web) |
| Real-time | Google Cloud Pub/Sub · Gmail Watch API |

---

## Features

### Mobile (Android-first)
- Real-time SMS and notification monitoring
- Manual text and URL scanning
- Browser security check flow
- Gmail connect and sync
- Local protection logs with threat details
- In-app suspicious content alerts

### Backend
- Offline heuristic detection engine
- Explainable results: `label`, `risk_score`, `reasons`, `should_block`
- Gmail Pub/Sub push integration
- Block / ignore event logging
- REST API with Swagger docs

---

## Repository Structure

```
app/                  # FastAPI backend
  api/
  core/
  models/
  routes/
  services/
  utils/
  main.py
mobile/               # Expo React Native app
  app/
  components/
  hooks/
  navigation/
  screens/
  services/
  storage/
  utils/
  android/
  package.json
.env.example          # Backend environment template
requirements.txt      # Python dependencies
README.md
```

---

## Getting Started

### Prerequisites

**Backend**
- Python 3.11+

**Mobile**
- Node.js 20+
- npm
- Android Studio + Android SDK
- Expo development build *(Expo Go is not supported — native features require a dev build)*

---

### 1 · Clone & Configure Environment

```bash
# Copy the backend env template
cp .env.example .env
```

Fill in any AI / threat-intel API keys you want to enable (all are optional — the app works offline without them).

Create `mobile/.env` and add:

```env
EXPO_PUBLIC_API_BASE_URL=http://<YOUR_LOCAL_IP>:8000
EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID=<android_client_id>.apps.googleusercontent.com
EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID=<web_client_id>.apps.googleusercontent.com
```

---

### 2 · Run the Backend

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

### 3 · Run the Mobile App

```powershell
cd mobile
npm install
npm run start:lan
```

To build or reinstall the Android dev app:

```powershell
cd mobile
npm run android:dev
```

To forward Metro ports over USB:

```powershell
adb reverse tcp:8081 tcp:8081
adb reverse tcp:19000 tcp:19000
adb reverse tcp:19001 tcp:19001
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/scan/text` | Scan plain text |
| `POST` | `/scan/url` | Scan a URL |
| `POST` | `/scan/unified` | Unified scan (text + URL) |
| `POST` | `/gmail/connect` | Connect Gmail account |
| `POST` | `/gmail/sync` | Sync Gmail messages |
| `POST` | `/gmail/watch/setup` | Set up Pub/Sub watch |
| `POST` | `/gmail/watch/notify` | Receive Pub/Sub push |
| `POST` | `/events/block` | Log a blocked event |
| `POST` | `/events/ignore` | Log an ignored event |
| `GET` | `/logs` | Retrieve scan logs |
| `GET` | `/health` | Health check |

---

## Notes

- `scan_logs.db` and `mobile/.env` are git-ignored and should never be committed
- Gmail real-time Pub/Sub requires a publicly reachable backend URL; local development can use polling instead
- See `mobile/README.md` for additional mobile-specific setup details

---

*Built by Dev Dominators*
