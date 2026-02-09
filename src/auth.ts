import { useOAuth } from "./lib/oauth";

export const auth = useOAuth({
  clientId: import.meta.env.VITE_OAUTH_CLIENT_ID,
  clientSecret: import.meta.env.VITE_OAUTH_SECRET,
  redirectUri: import.meta.env.VITE_OAUTH_REDIRECT_URI,
  baseUrl: import.meta.env.VITE_OAUTH_BASE_URL,
  apiBaseUrl: import.meta.env.VITE_OAUTH_API_BASE_URL,
  storage: "localStorage",
  scopes: import.meta.env.VITE_OAUTH_SCOPES
    ? import.meta.env.VITE_OAUTH_SCOPES.split(",")
    : undefined,
});
