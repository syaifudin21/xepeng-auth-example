// @ts-nocheck
// src/config.ts
var DEFAULT_CONFIG = {
  baseUrl: "https://staging-app.xepeng.com",
  apiBaseUrl: "https://staging-api.xepeng.com",
  scopes: ["profile", "email"],
  storage: "memory",
  autoRefresh: true,
  refreshBuffer: 300,
};

// src/types.ts
var OAuthError = class extends Error {
  constructor(message, code, statusCode) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.name = "OAuthError";
  }
};

// src/storage.ts
var MemoryStorage = class {
  constructor() {
    this.tokens = null;
  }
  get() {
    return this.tokens;
  }
  set(tokens) {
    this.tokens = tokens;
  }
  clear() {
    this.tokens = null;
  }
};
var LocalStorageAdapter = class {
  constructor() {
    this.key = "xepeng_oauth_tokens";
  }
  get() {
    if (typeof window === "undefined") return null;
    try {
      const data = localStorage.getItem(this.key);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  }
  set(tokens) {
    if (typeof window === "undefined") return;
    try {
      localStorage.setItem(this.key, JSON.stringify(tokens));
    } catch (e) {
      console.warn("Failed to store tokens in localStorage:", e);
    }
  }
  clear() {
    if (typeof window === "undefined") return;
    try {
      localStorage.removeItem(this.key);
    } catch (e) {
      console.warn("Failed to clear tokens from localStorage:", e);
    }
  }
};
var SessionStorageAdapter = class {
  constructor() {
    this.key = "xepeng_oauth_tokens";
  }
  get() {
    if (typeof window === "undefined") return null;
    try {
      const data = sessionStorage.getItem(this.key);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  }
  set(tokens) {
    if (typeof window === "undefined") return;
    try {
      sessionStorage.setItem(this.key, JSON.stringify(tokens));
    } catch (e) {
      console.warn("Failed to store tokens in sessionStorage:", e);
    }
  }
  clear() {
    if (typeof window === "undefined") return;
    try {
      sessionStorage.removeItem(this.key);
    } catch (e) {
      console.warn("Failed to clear tokens from sessionStorage:", e);
    }
  }
};
function createStorage(type) {
  switch (type) {
    case "localStorage":
      return new LocalStorageAdapter();
    case "sessionStorage":
      return new SessionStorageAdapter();
    default:
      return new MemoryStorage();
  }
}

// src/pkce.ts
var CHARSET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
var CODE_VERIFIER_MIN_LENGTH = 43;
var CODE_VERIFIER_MAX_LENGTH = 128;
var DEFAULT_CODE_VERIFIER_LENGTH = 64;
function generateCodeVerifier(length = DEFAULT_CODE_VERIFIER_LENGTH) {
  if (length < CODE_VERIFIER_MIN_LENGTH || length > CODE_VERIFIER_MAX_LENGTH) {
    throw new Error(
      `Code verifier length must be between ${CODE_VERIFIER_MIN_LENGTH} and ${CODE_VERIFIER_MAX_LENGTH}`,
    );
  }
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  return Array.from(values, (byte) => CHARSET[byte % CHARSET.length]).join("");
}
async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}
function generateState() {
  return generateCodeVerifier(43);
}

// src/oauth-client.ts
var OAuthClient = class {
  constructor(config) {
    this.refreshTimer = null;
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.storage = createStorage(this.config.storage);
  }
  /**
   * Get the authorization URL to redirect the user to
   */
  async getAuthorizationUrl() {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    this.storeOAuthState(state, codeVerifier, codeChallenge);
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: "code",
      scope: this.config.scopes.join(" "),
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    return `${this.config.baseUrl}/oauth/authorize?${params.toString()}`;
  }
  /**
   * Handle the OAuth callback and exchange code for tokens
   */
  async handleCallback(callbackUrl) {
    const url = new URL(callbackUrl);
    console.log("[Debug] Raw callback URL:", callbackUrl);
    console.log("[Debug] URL Search Params:", url.search);

    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    console.log("[Debug] Parsed code:", code);
    console.log("[Debug] Parsed state:", state);

    if (code) {
      console.log("Storing callback code to localStorage:", code);
      localStorage.setItem("xepeng_oauth_code", code);
    }
    if (state) {
      console.log("Storing callback state to localStorage:", state);
      localStorage.setItem("xepeng_oauth_callback_state", state);
    }

    if (error) {
      throw new OAuthError(
        url.searchParams.get("error_description") || error,
        error,
      );
    }
    if (!code) {
      throw new OAuthError(
        "No authorization code found in callback",
        "missing_code",
      );
    }
    if (!state) {
      throw new OAuthError(
        "No state parameter found in callback",
        "missing_state",
      );
    }
    const storedState = this.retrieveOAuthState();
    console.log("[Debug] Stored state object:", storedState);

    if (!storedState) {
      console.error("[Debug] No stored state found!");
      throw new OAuthError("Invalid state parameter", "invalid_state");
    }

    if (storedState.state !== state) {
      const errorMessage = `State mismatch! Storage state: ${storedState.state} vs Callback state: ${state}`;
      console.error("[Debug] " + errorMessage);
      alert(errorMessage); // Alert user immediately as requested
      throw new OAuthError(errorMessage, "invalid_state");
    }
    const result = await this.exchangeCodeForToken(
      code,
      storedState.codeVerifier,
    );

    // Cleanup temporary storage after successful exchange
    localStorage.removeItem("xepeng_oauth_code");
    localStorage.removeItem("xepeng_oauth_callback_state");
    console.log("[Debug] Temporary OAuth keys cleaned up from localStorage.");

    return result;
  }
  /**
   * Exchange authorization code for access token
   */
  async exchangeCodeForToken(code, codeVerifier) {
    const response = await this.fetchToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code_verifier: codeVerifier,
    });
    await this.storeTokens(response);
    return response;
  }
  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken() {
    const tokens = this.storage.get();
    if (!tokens?.refreshToken) {
      throw new OAuthError("No refresh token available", "no_refresh_token");
    }
    const response = await this.fetchToken({
      grant_type: "refresh_token",
      refresh_token: tokens.refreshToken,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });
    await this.storeTokens(response);
    return response;
  }
  /**
   * Get user info from the userinfo endpoint
   */
  async getUserInfo() {
    const tokens = this.getTokens();
    if (!tokens) {
      throw new OAuthError("Not authenticated", "not_authenticated");
    }
    const baseUrl = this.config.apiBaseUrl || this.config.baseUrl;
    const response = await fetch(`${baseUrl}/oauth/userinfo`, {
      headers: {
        Authorization: `Bearer ${tokens.accessToken}`,
      },
    });
    if (!response.ok) {
      throw new OAuthError(
        "Failed to fetch user info",
        "userinfo_failed",
        response.status,
      );
    }
    return response.json();
  }
  /**
   * Revoke all tokens for the client
   */
  async revokeTokens() {
    const tokens = this.getTokens();
    if (!tokens) return;
    const baseUrl = this.config.apiBaseUrl || this.config.baseUrl;
    await fetch(`${baseUrl}/oauth/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokens.accessToken}`,
      },
      body: JSON.stringify({
        client_id: this.config.clientId,
      }),
    });
    this.logout();
  }
  /**
   * Check if user is authenticated
   */
  isAuthenticated() {
    const tokens = this.storage.get();
    if (!tokens) return false;
    return Date.now() < tokens.expiresAt;
  }
  /**
   * Get stored tokens
   */
  getTokens() {
    const tokens = this.storage.get();
    if (!tokens) return null;
    return {
      ...tokens,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: tokens.expiresAt,
    };
  }
  /**
   * Get access token (refreshing if necessary)
   */
  async getAccessToken() {
    const tokens = this.getTokens();
    if (!tokens) {
      throw new OAuthError("Not authenticated", "not_authenticated");
    }
    if (this.shouldRefreshToken(tokens)) {
      await this.refreshAccessToken();
      return this.getAccessToken();
    }
    return tokens.accessToken;
  }
  /**
   * Logout and clear tokens
   */
  logout() {
    this.storage.clear();
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.clearOAuthState();
  }
  /**
   * Fetch token from token endpoint
   */
  async fetchToken(params) {
    const body = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== void 0) {
        body.append(key, value);
      }
    }
    const baseUrl = this.config.apiBaseUrl || this.config.baseUrl;
    const response = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });

    console.log("[Debug] Token Request Body:", body.toString());
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new OAuthError(
        error.message || "Token request failed",
        error.error || "token_error",
        response.status,
      );
    }
    return response.json();
  }
  /**
   * Store tokens and setup auto-refresh
   */
  async storeTokens(response) {
    const expiresAt = Date.now() + response.expires_in * 1e3;
    const tokens = {
      accessToken: response.access_token,
      refreshToken: response.refresh_token,
      expiresAt,
    };
    this.storage.set(tokens);
    if (this.config.autoRefresh && response.refresh_token) {
      this.setupAutoRefresh(tokens);
    }
  }
  /**
   * Setup auto-refresh timer
   */
  setupAutoRefresh(tokens) {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    const refreshTime =
      tokens.expiresAt - Date.now() - this.config.refreshBuffer * 1e3;
    if (refreshTime > 0) {
      this.refreshTimer = setTimeout(() => {
        this.refreshAccessToken().catch(console.error);
      }, refreshTime);
    }
  }
  /**
   * Check if token should be refreshed
   */
  shouldRefreshToken(tokens) {
    const bufferTime = this.config.refreshBuffer * 1e3;
    return Date.now() >= tokens.expiresAt - bufferTime;
  }
  /**
   * Store OAuth state for callback verification
   */
  storeOAuthState(state, codeVerifier, codeChallenge) {
    if (typeof window === "undefined") return;
    const key = "xepeng_oauth_state";
    const data = {
      state,
      codeVerifier,
      codeChallenge,
      redirectUri: this.config.redirectUri,
    };
    console.log("Storing OAuth state to localStorage:", data);
    localStorage.setItem(key, JSON.stringify(data));
  }
  /**
   * Retrieve and clear OAuth state
   */
  retrieveOAuthState() {
    if (typeof window === "undefined") return null;
    const key = "xepeng_oauth_state";
    const data = localStorage.getItem(key);
    console.log("Retrieved OAuth state from localStorage:", data);
    localStorage.removeItem(key);
    return data ? JSON.parse(data) : null;
  }
  /**
   * Clear OAuth state
   */
  clearOAuthState() {
    if (typeof window === "undefined") return;
    localStorage.removeItem("xepeng_oauth_state");
  }
};

// src/composables/useOAuth.ts
import { ref, computed, readonly } from "vue";
function useOAuth(config) {
  const client = new OAuthClient(config);
  const isLoading = ref(false);
  const user = ref(null);
  const error = ref(null);
  const tokens = ref(client.getTokens());

  const isAuthenticated = computed(() => {
    return !!tokens.value && Date.now() < tokens.value.expiresAt;
  });
  async function login() {
    isLoading.value = true;
    error.value = null;
    try {
      const url = await client.getAuthorizationUrl();
      window.location.href = url;
    } catch (e) {
      error.value = e;
      isLoading.value = false;
    }
  }
  async function handleCallback() {
    isLoading.value = true;
    error.value = null;
    try {
      await client.handleCallback(window.location.href);
      tokens.value = client.getTokens(); // Update reactive state
      console.log(
        "[Debug] Login process complete. User is authenticated (skipping userinfo).",
      );
    } catch (e) {
      error.value = e;
    } finally {
      isLoading.value = false;
    }
  }
  async function logout() {
    isLoading.value = true;
    error.value = null;
    try {
      // Skipping revokeTokens hit as requested
      // await client.revokeTokens();
    } catch (e) {
      console.warn("Failed to revoke tokens:", e);
    } finally {
      client.logout();
      tokens.value = null; // Update reactive state
      user.value = null;
      isLoading.value = false;
    }
  }
  async function getAccessToken() {
    return client.getAccessToken();
  }
  async function refreshAccessToken() {
    isLoading.value = true;
    error.value = null;
    try {
      await client.refreshAccessToken();
      tokens.value = client.getTokens(); // Update reactive state
      await getUserInfo();
    } catch (e) {
      error.value = e;
    } finally {
      isLoading.value = false;
    }
  }
  async function revokeTokens() {
    isLoading.value = true;
    error.value = null;
    try {
      await client.revokeTokens();
    } catch (e) {
      error.value = e;
    } finally {
      isLoading.value = false;
    }
  }
  async function getUserInfo() {
    isLoading.value = true;
    error.value = null;
    try {
      const userInfo = await client.getUserInfo();
      user.value = userInfo;
    } catch (e) {
      error.value = e;
    } finally {
      isLoading.value = false;
    }
  }
  return {
    isAuthenticated,
    isLoading: readonly(isLoading),
    user: readonly(user),
    error: readonly(error),
    login,
    handleCallback,
    logout,
    getAccessToken,
    refreshAccessToken,
    revokeTokens,
    getUserInfo,
    client,
  };
}
export {
  DEFAULT_CONFIG,
  LocalStorageAdapter,
  MemoryStorage,
  OAuthClient,
  OAuthError,
  SessionStorageAdapter,
  createStorage,
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
  useOAuth,
};
