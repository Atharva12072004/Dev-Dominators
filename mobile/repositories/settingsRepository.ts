import { storage } from "@/utils/storage";

export class SettingsRepository {
  getSelectedApps() {
    return storage.getSelectedApps();
  }

  setSelectedApps(appIds: string[]) {
    return storage.setSelectedApps(appIds);
  }

  getPermissions() {
    return storage.getPermissions();
  }

  setPermissions(permissions: Awaited<ReturnType<typeof storage.getPermissions>>) {
    return storage.setPermissions(permissions);
  }
}

export const settingsRepository = new SettingsRepository();

