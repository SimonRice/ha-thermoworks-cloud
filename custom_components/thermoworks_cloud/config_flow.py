"""Config flow for Thermoworks Cloud integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_SCAN_INTERVAL
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from thermoworks_cloud import AuthenticationError, AuthFactory, ThermoworksCloud

from .const import (
    APPLE_AUTHORIZE_URL,
    APPLE_PROVIDER_ID,
    AUTH_METHOD_APPLE,
    AUTH_METHOD_EMAIL,
    AUTH_METHOD_GOOGLE,
    CONF_AUTH_METHOD,
    DEFAULT_SCAN_INTERVAL_SECONDS,
    DOMAIN,
    GOOGLE_AUTHORIZE_URL,
    GOOGLE_PROVIDER_ID,
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


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for ThermoWorks Cloud."""

    VERSION = 1

    _auth_method: str | None = None

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
                return await self.async_step_google_oauth()
            elif self._auth_method == AUTH_METHOD_APPLE:
                return await self.async_step_apple_oauth()

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

    async def async_step_google_oauth(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle Google OAuth ID token input."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                id_token = user_input["id_token"]
                info = await validate_oauth(self.hass, id_token, GOOGLE_PROVIDER_ID)

                await self.async_set_unique_id(info.get("user"))
                self._abort_if_unique_id_configured()

                data = {
                    CONF_AUTH_METHOD: AUTH_METHOD_GOOGLE,
                    "id_token": id_token,
                    "provider_id": GOOGLE_PROVIDER_ID,
                }
                return self.async_create_entry(
                    title="ThermoWorks Cloud (Google)", data=data
                )

            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception as e:
                _LOGGER.exception(f"Unexpected exception: {e}")
                errors["base"] = "unknown"

        schema = vol.Schema({vol.Required("id_token"): str})

        return self.async_show_form(
            step_id="google_oauth",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "auth_url": f"{GOOGLE_AUTHORIZE_URL}?client_id=YOUR_CLIENT_ID&redirect_uri=https://your-ha-instance/&response_type=id_token&scope=openid email profile&nonce=123"
            },
        )

    async def async_step_apple_oauth(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle Apple OAuth ID token input."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                id_token = user_input["id_token"]
                info = await validate_oauth(self.hass, id_token, APPLE_PROVIDER_ID)

                await self.async_set_unique_id(info.get("user"))
                self._abort_if_unique_id_configured()

                data = {
                    CONF_AUTH_METHOD: AUTH_METHOD_APPLE,
                    "id_token": id_token,
                    "provider_id": APPLE_PROVIDER_ID,
                }
                return self.async_create_entry(
                    title="ThermoWorks Cloud (Apple)", data=data
                )

            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception as e:
                _LOGGER.exception(f"Unexpected exception: {e}")
                errors["base"] = "unknown"

        schema = vol.Schema({vol.Required("id_token"): str})

        return self.async_show_form(
            step_id="apple_oauth",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "auth_url": f"{APPLE_AUTHORIZE_URL}?client_id=YOUR_CLIENT_ID&redirect_uri=https://your-ha-instance/&response_type=id_token&scope=openid email&nonce=123"
            },
        )


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
