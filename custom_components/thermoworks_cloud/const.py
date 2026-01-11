"""Constants for the Thermoworks Cloud integration."""

DOMAIN = "thermoworks_cloud"
# Setting to 30 minutes to be nice to their servers
DEFAULT_SCAN_INTERVAL_SECONDS = 1800
# Just an arbitrary value
MIN_SCAN_INTERVAL_SECONDS = 5

# Authentication methods
CONF_AUTH_METHOD = "auth_method"
AUTH_METHOD_EMAIL = "email"
AUTH_METHOD_GOOGLE = "google"
AUTH_METHOD_APPLE = "apple"

# OAuth provider IDs for Firebase
GOOGLE_PROVIDER_ID = "google.com"
APPLE_PROVIDER_ID = "apple.com"

# OAuth URLs (for user reference in setup instructions)
GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
APPLE_AUTHORIZE_URL = "https://appleid.apple.com/auth/authorize"
