"""Config flow for Thermoworks Cloud integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components.http import KEY_HASS, HomeAssistantView
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_SCAN_INTERVAL
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from thermoworks_cloud import AuthenticationError, AuthFactory, ThermoworksCloud

from .const import (
    APPLE_AUTHORIZE_URL,
    APPLE_PROVIDER_ID,
    APPLE_TOKEN_URL,
    AUTH_METHOD_APPLE,
    AUTH_METHOD_EMAIL,
    AUTH_METHOD_GOOGLE,
    CONF_AUTH_METHOD,
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    DEFAULT_SCAN_INTERVAL_SECONDS,
    DOMAIN,
    GOOGLE_AUTHORIZE_URL,
    GOOGLE_PROVIDER_ID,
    GOOGLE_TOKEN_URL,
    MIN_SCAN_INTERVAL_SECONDS,
)

_LOGGER: logging.Logger = logging.getLogger(__package__)

AUTH_METHOD_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_AUTH_METHOD): vol.In(
            [AUTH_METHOD_EMAIL, AUTH_METHOD_GOOGLE, AUTH_METHOD_APPLE]
        ),
    }
)

EMAIL_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

OAUTH_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CLIENT_ID): str,
        vol.Required(CONF_CLIENT_SECRET): str,
    }
)


async def validate_email_password(
    hass: HomeAssistant, data: dict[str, Any]
) -> dict[str, Any]:
    """Validate email/password authentication."""
    client_session = async_get_clientsession(hass)
    auth_factory = AuthFactory(client_session)
    try:
        auth = await auth_factory.build_auth(
            data[CONF_EMAIL], password=data[CONF_PASSWORD]
        )
        thermoworks_cloud = ThermoworksCloud(auth)
        await thermoworks_cloud.get_user()

    except AuthenticationError as e:
        raise InvalidAuth from e
    except ConnectionError as e:
        raise CannotConnect from e

    return {"title": "ThermoWorks Cloud", "user": auth.user_id}


async def validate_oauth(
    hass: HomeAssistant, id_token: str, provider_id: str
) -> dict[str, Any]:
    """Validate OAuth authentication."""
    client_session = async_get_clientsession(hass)
    auth_factory = AuthFactory(client_session)
    try:
        auth = await auth_factory.build_auth_with_oauth(id_token, provider_id)
        thermoworks_cloud = ThermoworksCloud(auth)
        await thermoworks_cloud.get_user()

    except AuthenticationError as e:
        raise InvalidAuth from e
    except ConnectionError as e:
        raise CannotConnect from e

    return {"title": "ThermoWorks Cloud", "user": auth.user_id}


class ThermoworksOAuth2Implementation(config_entry_oauth2_flow.LocalOAuth2Implementation):
    """Custom OAuth2 implementation for ThermoWorks."""

    def __init__(
        self,
        hass: HomeAssistant,
        domain: str,
        client_id: str,
        client_secret: str,
        authorize_url: str,
        token_url: str,
    ) -> None:
        """Initialize the OAuth2 implementation."""
        super().__init__(
            hass,
            domain,
            client_id,
            client_secret,
            authorize_url,
            token_url,
        )

    @property
    def extra_authorize_data(self) -> dict[str, Any]:
        """Extra data for authorization request."""
        return {
            "scope": "openid email profile",
        }


class ConfigFlow(
    config_entries.ConfigFlow, config_entry_oauth2_flow.AbstractOAuth2FlowHandler, domain=DOMAIN
):
    """Handle a config flow for ThermoWorks Cloud."""

    VERSION = 1
    DOMAIN = DOMAIN

    _auth_method: str | None = None
    _oauth_data: dict[str, Any] = {}

    @property
    def logger(self) -> logging.Logger:
        """Return logger."""
        return _LOGGER

    @property
    def extra_authorize_data(self) -> dict[str, Any]:
        """Extra data for OAuth authorization."""
        return {"scope": "openid email profile"}

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> OptionsFlowHandler:
        """Get the options flow for this handler."""
        return OptionsFlowHandler()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle the initial step - choose auth method."""
        if user_input is not None:
            self._auth_method = user_input[CONF_AUTH_METHOD]

            if self._auth_method == AUTH_METHOD_EMAIL:
                return await self.async_step_email()
            elif self._auth_method == AUTH_METHOD_GOOGLE:
                return await self.async_step_google_credentials()
            elif self._auth_method == AUTH_METHOD_APPLE:
                return await self.async_step_apple_credentials()

        return self.async_show_form(
            step_id="user",
            data_schema=AUTH_METHOD_SCHEMA,
            description_placeholders={
                "auth_method": "Choose your authentication method"
            },
        )

    async def async_step_email(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle email/password authentication."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await validate_email_password(self.hass, user_input)
                await self.async_set_unique_id(info.get("user"))
                self._abort_if_unique_id_configured()

                data = user_input.copy()
                data[CONF_AUTH_METHOD] = AUTH_METHOD_EMAIL
                return self.async_create_entry(title=info["title"], data=data)

            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception as e:
                _LOGGER.exception(f"Unexpected exception: {e}")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="email", data_schema=EMAIL_SCHEMA, errors=errors
        )

    async def async_step_google_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle Google OAuth credentials input."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._oauth_data = {
                CONF_CLIENT_ID: user_input[CONF_CLIENT_ID],
                CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET],
                "provider_id": GOOGLE_PROVIDER_ID,
                "provider_name": "Google",
            }

            # Create OAuth implementation
            self.async_register_implementation(
                self.hass,
                ThermoworksOAuth2Implementation(
                    self.hass,
                    DOMAIN,
                    user_input[CONF_CLIENT_ID],
                    user_input[CONF_CLIENT_SECRET],
                    GOOGLE_AUTHORIZE_URL,
                    GOOGLE_TOKEN_URL,
                ),
            )

            return await self.async_step_oauth()

        return self.async_show_form(
            step_id="google_credentials",
            data_schema=OAUTH_SCHEMA,
            errors=errors,
            description_placeholders={
                "setup_url": "https://console.cloud.google.com/apis/credentials"
            },
        )

    async def async_step_apple_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle Apple OAuth credentials input."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._oauth_data = {
                CONF_CLIENT_ID: user_input[CONF_CLIENT_ID],
                CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET],
                "provider_id": APPLE_PROVIDER_ID,
                "provider_name": "Apple",
            }

            # Create OAuth implementation
            self.async_register_implementation(
                self.hass,
                ThermoworksOAuth2Implementation(
                    self.hass,
                    DOMAIN,
                    user_input[CONF_CLIENT_ID],
                    user_input[CONF_CLIENT_SECRET],
                    APPLE_AUTHORIZE_URL,
                    APPLE_TOKEN_URL,
                ),
            )

            return await self.async_step_oauth()

        return self.async_show_form(
            step_id="apple_credentials",
            data_schema=OAUTH_SCHEMA,
            errors=errors,
            description_placeholders={
                "setup_url": "https://developer.apple.com/account/resources/identifiers/list/serviceId"
            },
        )

    async def async_oauth_create_entry(self, data: dict[str, Any]) -> config_entries.ConfigFlowResult:
        """Create entry from OAuth callback."""
        try:
            # Extract ID token from OAuth token response
            token_data = data.get("token", {})
            id_token = token_data.get("id_token")

            if not id_token:
                _LOGGER.error("No ID token in OAuth response")
                return self.async_abort(reason="no_id_token")

            # Validate with Firebase
            info = await validate_oauth(
                self.hass, id_token, self._oauth_data["provider_id"]
            )

            await self.async_set_unique_id(info.get("user"))
            self._abort_if_unique_id_configured()

            # Store auth method and OAuth data
            entry_data = {
                CONF_AUTH_METHOD: AUTH_METHOD_GOOGLE if self._oauth_data["provider_id"] == GOOGLE_PROVIDER_ID else AUTH_METHOD_APPLE,
                CONF_CLIENT_ID: self._oauth_data[CONF_CLIENT_ID],
                CONF_CLIENT_SECRET: self._oauth_data[CONF_CLIENT_SECRET],
                "token": token_data,
            }

            return self.async_create_entry(
                title=f"ThermoWorks Cloud ({self._oauth_data['provider_name']})",
                data=entry_data,
            )

        except InvalidAuth:
            return self.async_abort(reason="invalid_auth")
        except CannotConnect:
            return self.async_abort(reason="cannot_connect")
        except Exception as e:
            _LOGGER.exception(f"Error creating OAuth entry: {e}")
            return self.async_abort(reason="unknown")


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handles the options flow."""

    async def async_step_init(
        self, user_input=None
    ) -> config_entries.ConfigFlowResult:
        """Handle options flow."""
        if user_input is not None:
            options = self.config_entry.options | user_input
            return self.async_create_entry(data=options)

        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=self.config_entry.options.get(
                        CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL_SECONDS
                    ),
                ): vol.All(vol.Coerce(int), vol.Clamp(min=MIN_SCAN_INTERVAL_SECONDS)),
            }
        )

        return self.async_show_form(
            step_id="init",
            data_schema=data_schema,
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
