# OAuth Authentication Setup for ThermoWorks Cloud

This integration supports three authentication methods:
- **Email/Password**: Traditional authentication (simple, works immediately)
- **Sign in with Google**: OAuth authentication via Google
- **Sign in with Apple**: OAuth authentication via Apple

## Why Use OAuth?

- Better security (no password storage in Home Assistant)
- Automatic token refresh
- Can revoke access from Google/Apple account settings

## Email/Password Setup (Easiest)

1. Add the ThermoWorks Cloud integration in Home Assistant
2. Select "Email/Password" as the authentication method
3. Enter your ThermoWorks email and password
4. Done!

## Google OAuth Setup

### Step 1: Create Google OAuth 2.0 Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth client ID**
5. If prompted, configure the OAuth consent screen:
   - User Type: **External**
   - App name: `ThermoWorks HomeAssistant`
   - User support email: Your email
   - Developer contact: Your email
   - Scopes: Add `openid`, `email`, and `profile`
   - Test users: Add your email address
6. Application type: **Web application**
7. Name: `ThermoWorks HomeAssistant Integration`
8. **Authorized redirect URIs**: Add your Home Assistant OAuth callback URL:
   ```
   https://YOUR-HA-INSTANCE/auth/external/callback
   ```
   Replace `YOUR-HA-INSTANCE` with your actual Home Assistant URL (e.g., `https://homeassistant.local:8123`)

9. Click **Create**
10. **Save the Client ID and Client Secret** - you'll need these next

### Step 2: Configure Integration in Home Assistant

1. Go to **Settings** → **Devices & Services**
2. Click **Add Integration**
3. Search for "ThermoWorks Cloud"
4. Select **Sign in with Google**
5. Enter the **Client ID** and **Client Secret** from Step 1
6. You'll be redirected to Google to authorize access
7. Sign in with the Google account linked to your ThermoWorks account
8. Grant permissions
9. You'll be redirected back to Home Assistant
10. Done!

### Finding Your Home Assistant OAuth Callback URL

Your redirect URI follows this pattern:
```
https://{your-ha-domain}/auth/external/callback
```

Examples:
- Local: `http://homeassistant.local:8123/auth/external/callback`
- Nabu Casa: `https://abcdef1234.ui.nabu.casa/auth/external/callback`
- Custom domain: `https://ha.yourdomain.com/auth/external/callback`

## Apple Sign In Setup

### Step 1: Create Apple Sign In Service ID

1. Go to [Apple Developer Account](https://developer.apple.com/account/)
2. Navigate to **Certificates, Identifiers & Profiles**
3. Click **Identifiers** → **+** (plus button)
4. Select **App IDs** and click **Continue**
5. Select **App** and click **Continue**
6. Configure your App ID:
   - Description: `ThermoWorks HomeAssistant App`
   - Bundle ID: `com.yourname.thermoworks` (must be unique)
   - Capabilities: Enable **Sign in with Apple**
7. Click **Continue** then **Register**

### Step 2: Create Service ID

1. Click **Identifiers** → **+** (plus button) again
2. Select **Services IDs** and click **Continue**
3. Configure:
   - Description: `ThermoWorks HomeAssistant Service`
   - Identifier: `com.yourname.thermoworks.service` (this is your Client ID)
   - Enable **Sign in with Apple**
4. Click **Configure** next to Sign in with Apple
5. **Primary App ID**: Select the App ID you created in Step 1
6. **Domains and Subdomains**: Add your Home Assistant domain (e.g., `homeassistant.local` or `yourdomain.com`)
7. **Return URLs**: Add your Home Assistant OAuth callback URL:
   ```
   https://YOUR-HA-INSTANCE/auth/external/callback
   ```
8. Click **Save**, then **Continue**, then **Register**

### Step 3: Create Private Key

1. Click **Keys** → **+** (plus button)
2. Key Name: `ThermoWorks HomeAssistant Key`
3. Enable **Sign in with Apple**
4. Click **Configure** and select your App ID
5. Click **Save**, then **Continue**, then **Register**
6. **Download the .p8 key file** (you can only download this once!)
7. Note the **Key ID** shown

### Step 4: Generate Client Secret (JWT)

Apple requires a JWT token as the client secret. You need to generate this using your private key.

**Using Python script:**

```python
import jwt
import time

# Your details from Apple Developer Console
team_id = "YOUR_TEAM_ID"  # Find in top right of developer.apple.com
client_id = "com.yourname.thermoworks.service"  # Service ID from Step 2
key_id = "YOUR_KEY_ID"  # From Step 3
key_file = "path/to/AuthKey_KEYID.p8"  # Downloaded in Step 3

# Read private key
with open(key_file, 'r') as f:
    private_key = f.read()

# Create JWT
headers = {
    "kid": key_id,
    "alg": "ES256"
}

payload = {
    "iss": team_id,
    "iat": int(time.time()),
    "exp": int(time.time()) + 15777000,  # 6 months
    "aud": "https://appleid.apple.com",
    "sub": client_id
}

client_secret = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)
print(f"Client Secret: {client_secret}")
```

**Install dependencies:**
```bash
pip install PyJWT cryptography
```

**Run the script:**
```bash
python generate_apple_secret.py
```

Copy the generated client secret.

### Step 5: Configure Integration in Home Assistant

1. Go to **Settings** → **Devices & Services**
2. Click **Add Integration**
3. Search for "ThermoWorks Cloud"
4. Select **Sign in with Apple**
5. Enter:
   - **Client ID**: Your Service ID from Step 2 (e.g., `com.yourname.thermoworks.service`)
   - **Client Secret**: The JWT token you generated in Step 4
6. You'll be redirected to Apple to authorize access
7. Sign in with the Apple ID linked to your ThermoWorks account
8. Grant permissions
9. You'll be redirected back to Home Assistant
10. Done!

## Troubleshooting

### Google OAuth

**Error: "redirect_uri_mismatch"**
- The redirect URI in Home Assistant doesn't match what you configured in Google Cloud Console
- Double-check the URL exactly matches (including http vs https, port numbers, etc.)

**Error: "invalid_client"**
- Client ID or Client Secret is incorrect
- Regenerate credentials in Google Cloud Console

**Error: "access_denied"**
- You denied permission during OAuth flow
- Restart the integration setup and grant permissions

### Apple Sign In

**Error: "invalid_client"**
- Client ID (Service ID) is incorrect
- Or Client Secret (JWT) is expired or invalid
- Regenerate the JWT using the Python script

**Error: "invalid_grant"**
- The JWT token has expired (they last 6 months)
- Regenerate a new client secret

**Error: "redirect_uri_mismatch"**
- The return URL doesn't match what you configured in Apple Developer Console
- Check domains and return URLs in your Service ID configuration

### General Issues

**"No ID token received"**
- The OAuth provider didn't return an ID token
- This usually means the scope `openid` wasn't requested
- Try removing and re-adding the integration

**"Authentication failed with ThermoWorks"**
- The OAuth account doesn't match a ThermoWorks account
- Make sure you're using the same email/account for both OAuth and ThermoWorks

## Security Notes

- OAuth tokens are stored securely in Home Assistant's configuration
- Tokens are automatically refreshed when they expire
- You can revoke access anytime from your Google/Apple account settings
- Client secrets should be kept private (don't share them publicly)

## Support

For issues or questions:
- GitHub Issues: [https://github.com/a2hill/ha-thermoworks-cloud/issues](https://github.com/a2hill/ha-thermoworks-cloud/issues)

## Sources

- [Firebase signInWithIdp API](https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithIdp)
- [Home Assistant OAuth Documentation](https://developers.home-assistant.io/docs/core/platform/application_credentials/)
- [Google OAuth Setup](https://www.home-assistant.io/integrations/application_credentials/)
