# CyberShield AI Mobile

CyberShield AI Mobile is the Expo React Native client for the CyberShield AI phishing-protection platform. It targets Expo development builds, with Android providing the full native-capable feature set.

## Current Feature Set

- Dashboard with protection status
- Manual scan
- Threat details screen
- Protection logs
- Browser security flow
- Gmail connect and Gmail sync
- Android SMS event pipeline
- Android notification ingestion pipeline
- Local suspicious-content alert notifications

## Project Structure

```text
mobile/
  app/
  api/
  components/
  docs/
  features/
  hooks/
  native/
  navigation/
  repositories/
  screens/
  services/
  storage/
  utils/
  android/
  app.json
  babel.config.js
  package.json
  tsconfig.json
```

## Required Environment Variables

Create `mobile/.env`:

```env
EXPO_PUBLIC_API_BASE_URL=http://YOUR_PC_LAN_IP:8000
EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID=your_android_google_client_id.apps.googleusercontent.com
EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID=your_web_google_client_id.apps.googleusercontent.com
```

## Start The Backend

From the repo root:

```powershell
cd c:\Users\ATHARVA\OneDrive\Desktop\secai
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Install Mobile Dependencies

```powershell
cd c:\Users\ATHARVA\OneDrive\Desktop\secai\mobile
npm install
```

## Start Metro For The Development Build

```powershell
cd c:\Users\ATHARVA\OneDrive\Desktop\secai\mobile
$env:NODE_ENV="development"
npm run start:lan
```

## Build Or Reinstall The Android Dev App

```powershell
cd c:\Users\ATHARVA\OneDrive\Desktop\secai\mobile
npm run android:dev
```

## USB Device Workflow

If your Android device is connected with USB debugging:

```powershell
& 'C:\Users\ATHARVA\AppData\Local\Android\Sdk\platform-tools\adb.exe' devices
& 'C:\Users\ATHARVA\AppData\Local\Android\Sdk\platform-tools\adb.exe' reverse tcp:8081 tcp:8081
& 'C:\Users\ATHARVA\AppData\Local\Android\Sdk\platform-tools\adb.exe' reverse tcp:19000 tcp:19000
& 'C:\Users\ATHARVA\AppData\Local\Android\Sdk\platform-tools\adb.exe' reverse tcp:19001 tcp:19001
& 'C:\Users\ATHARVA\AppData\Local\Android\Sdk\platform-tools\adb.exe' shell monkey -p com.anonymous.cybershieldai -c android.intent.category.LAUNCHER 1
```

## Gmail Notes

- Gmail detection and Gmail-triggered phishing alerts are integrated through the mobile Gmail connect/sync flow plus backend Gmail endpoints
- Android auth uses the Android Google client ID
- Web auth uses the web client ID
- This project does not use Expo Go for Gmail, SMS, or notification-native features

## Important Notes

- Use Expo development build, not Expo Go
- `mobile/.env` is intentionally ignored
- Native Android functionality depends on your local Android SDK and a connected device or emulator
