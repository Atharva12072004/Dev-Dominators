import {
  GoogleSignin,
  isErrorWithCode,
  statusCodes,
} from "@react-native-google-signin/google-signin";

import { gmailRepository } from "@/repositories/gmailRepository";
import { appConfig } from "@/utils/config";
import { GmailConnection } from "@/utils/types";

const scopes = [
  "openid",
  "email",
  "profile",
  "https://www.googleapis.com/auth/gmail.readonly",
];

let configured = false;

export function configureGoogleSignin() {
  if (configured) {
    return;
  }
  GoogleSignin.configure({
    scopes,
    webClientId: appConfig.googleWebClientId,
    offlineAccess: true,
    forceCodeForRefreshToken: true,
    profileImageSize: 120,
  });
  configured = true;
}

function resolveEmail(user: unknown) {
  if (
    user &&
    typeof user === "object" &&
    "type" in user &&
    (user as { type?: string }).type === "success" &&
    "data" in user
  ) {
    return resolveEmail((user as { data?: unknown }).data);
  }
  if (!user || typeof user !== "object") {
    return null;
  }
  const nestedUser = (user as { user?: { email?: string } }).user;
  return nestedUser?.email || null;
}

async function getAccessToken() {
  const tokens = await GoogleSignin.getTokens();
  return tokens.accessToken;
}

export async function resetInteractiveGoogleSession() {
  try {
    await GoogleSignin.revokeAccess();
  } catch {
    // Continue even if revoke fails. Sign-out below still helps clear the local session.
  }

  try {
    const accessToken = await getAccessToken();
    if (accessToken) {
      await GoogleSignin.clearCachedAccessToken(accessToken);
    }
  } catch {
    // Best-effort cleanup only. We still want to continue to account selection.
  }

  try {
    await GoogleSignin.signOut();
  } catch {
    // Ignore sign-out failures and continue to the chooser attempt.
  }
}

export async function disconnectGoogleSession() {
  await resetInteractiveGoogleSession();
}

export async function refreshBackendGmailSession(
  gmailConnection: GmailConnection,
  mode: "interactive" | "silent" = "silent"
): Promise<GmailConnection> {
  configureGoogleSignin();

  if (mode === "interactive") {
    await GoogleSignin.hasPlayServices({ showPlayServicesUpdateDialog: true });
    await resetInteractiveGoogleSession();
    const signInResponse = await GoogleSignin.signIn();
    if (signInResponse.type !== "success") {
      throw new Error("Google sign-in was cancelled.");
    }
    const accessToken = await getAccessToken();
    const email = resolveEmail(signInResponse.data);
    return gmailRepository.connect({
      access_token: accessToken,
      email,
    });
  }

  try {
    const user = await GoogleSignin.signInSilently();
    const accessToken = await getAccessToken();
    const email = resolveEmail(user);
    return gmailRepository.connect({
      access_token: accessToken,
      email: email || gmailConnection.email,
    });
  } catch (error) {
    if (isErrorWithCode(error) && error.code === statusCodes.SIGN_IN_REQUIRED) {
      throw new Error("Gmail session expired or access was denied. Reconnect Gmail and try again.");
    }
    throw error;
  }
}
