"""Coordinates data updates from the Thermoworks Cloud API."""

from dataclasses import dataclass
from datetime import timedelta
import logging
from typing import Any

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_SCAN_INTERVAL
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from thermoworks_cloud import AuthFactory, ThermoworksCloud, ResourceNotFoundError

from .const import (
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
    GOOGLE_PROVIDER_ID,
    GOOGLE_TOKEN_URL,
)
from .exceptions import MissingRequiredAttributeError
from .models import ThermoworksDevice, ThermoworksChannel

_LOGGER: logging.Logger = logging.getLogger(__package__)


@dataclass
class ThermoworksData:
    """Class to hold data retrieved from the Thermoworks Cloud API."""

    # List of devices retreived for the user
    devices: list[ThermoworksDevice]
    # Map of DeviceChannel's indexed by device id
    device_channels: dict[str, list[ThermoworksChannel]]


class ThermoworksCoordinator(DataUpdateCoordinator[ThermoworksData]):
    """Coordinate device updates from Thermoworks Cloud."""

    auth_factory: AuthFactory
    api: ThermoworksCloud | None
    data: ThermoworksData
    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant, config_entry: ConfigEntry) -> None:
        """Initialize coordinator."""

        self.config_entry = config_entry
        auth_method = config_entry.data.get(CONF_AUTH_METHOD, AUTH_METHOD_EMAIL)

        # Set variables based on auth method
        if auth_method == AUTH_METHOD_EMAIL:
            self.email = config_entry.data[CONF_EMAIL]
            self.password = config_entry.data[CONF_PASSWORD]
            self.auth_method = AUTH_METHOD_EMAIL
        elif auth_method in [AUTH_METHOD_GOOGLE, AUTH_METHOD_APPLE]:
            self.auth_method = auth_method
            self.oauth_client_id = config_entry.data[CONF_CLIENT_ID]
            self.oauth_client_secret = config_entry.data[CONF_CLIENT_SECRET]
            self.oauth_token = config_entry.data.get("token", {})
        else:
            raise ValueError(f"Unknown auth method: {auth_method}")

        # set variables from options
        self.poll_interval = config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL_SECONDS
        )

        # Initialise DataUpdateCoordinator
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} ({config_entry.unique_id})",
            update_method=self.async_update_data,
            update_interval=timedelta(seconds=self.poll_interval),
        )
        client_session = async_get_clientsession(hass)
        self.auth_factory = AuthFactory(client_session)
        self.api = None

    async def _get_oauth_id_token(self) -> str:
        """Get a valid OAuth ID token, refreshing if necessary."""
        # Check if we have a valid ID token
        id_token = self.oauth_token.get("id_token")

        if not id_token:
            # Need to refresh the OAuth token
            _LOGGER.debug("No ID token found, refreshing OAuth token")
            await self._refresh_oauth_token()
            id_token = self.oauth_token.get("id_token")

        return id_token

    async def _refresh_oauth_token(self) -> None:
        """Refresh the OAuth access token using the refresh token."""
        refresh_token = self.oauth_token.get("refresh_token")

        if not refresh_token:
            raise UpdateFailed("No refresh token available for OAuth")

        # Determine token URL based on provider
        if self.auth_method == AUTH_METHOD_GOOGLE:
            token_url = GOOGLE_TOKEN_URL
        elif self.auth_method == AUTH_METHOD_APPLE:
            token_url = APPLE_TOKEN_URL
        else:
            raise UpdateFailed(f"Unknown OAuth provider: {self.auth_method}")

        # Refresh the token
        client_session = async_get_clientsession(self.hass)

        try:
            async with client_session.post(
                token_url,
                data={
                    "client_id": self.oauth_client_id,
                    "client_secret": self.oauth_client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
            ) as response:
                response.raise_for_status()
                token_data = await response.json()

                # Update stored token data
                self.oauth_token.update(token_data)

                # Update config entry with new token data
                new_data = dict(self.config_entry.data)
                new_data["token"] = self.oauth_token
                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=new_data
                )

                _LOGGER.debug("Successfully refreshed OAuth token")

        except aiohttp.ClientError as err:
            raise UpdateFailed(f"Failed to refresh OAuth token: {err}") from err

    async def async_update_data(self) -> ThermoworksData:
        """Fetch data from API endpoint."""

        try:
            if self.api is None:
                # Initialize API connection based on auth method
                if self.auth_method == AUTH_METHOD_EMAIL:
                    _LOGGER.debug(
                        "Initializing Thermoworks Cloud API connection with email/password for %s",
                        self.email,
                    )
                    auth = await self.auth_factory.build_auth(
                        self.email, password=self.password
                    )
                elif self.auth_method in [AUTH_METHOD_GOOGLE, AUTH_METHOD_APPLE]:
                    _LOGGER.debug(
                        "Initializing Thermoworks Cloud API connection with %s OAuth",
                        self.auth_method,
                    )
                    id_token = await self._get_oauth_id_token()
                    provider_id = (
                        GOOGLE_PROVIDER_ID
                        if self.auth_method == AUTH_METHOD_GOOGLE
                        else APPLE_PROVIDER_ID
                    )
                    auth = await self.auth_factory.build_auth_with_oauth(
                        id_token, provider_id
                    )
                else:
                    raise UpdateFailed(f"Unknown auth method: {self.auth_method}")

                self.api = ThermoworksCloud(auth)
                _LOGGER.debug("Successfully authenticated with Thermoworks Cloud API")

            devices: list[ThermoworksDevice] = []
            device_channels_by_device: dict[str, list[ThermoworksChannel]] = {}

            user = await self.api.get_user()
            _LOGGER.debug("Retrieved user data: %s", user)

            if user.account_id is None:
                raise UpdateFailed("No account ID found for user")

            api_devices = await self.api.get_devices(user.account_id)
            _LOGGER.debug("Retrieved %d devices for user", len(api_devices))

            for api_device in api_devices:
                try:
                    device = ThermoworksDevice.from_api_device(api_device)
                    devices.append(device)
                    _LOGGER.debug("Retrieved device %s", device.display_name())
                except MissingRequiredAttributeError as err:
                    _LOGGER.error("Device %s: %s", api_device, err)
                    continue

                device_channels = []
                for channel in range(1, 10):
                    try:
                        api_channel = await self.api.get_device_channel(
                            device_serial=device.serial, channel=str(channel)
                        )
                        try:
                            channel_data = ThermoworksChannel.from_api_channel(
                                api_channel
                            )
                            device_channels.append(channel_data)
                            _LOGGER.debug(
                                "Retrieved channel %s for device %s",
                                channel_data.display_name(),
                                device.display_name(),
                            )
                        except MissingRequiredAttributeError as err:
                            _LOGGER.error(
                                "Channel %s for device %s: %s",
                                channel,
                                device.display_name(),
                                err,
                            )
                    except ResourceNotFoundError:
                        _LOGGER.debug(
                            "No more channels found for device %s after channel %s",
                            device.display_name(),
                            channel - 1,
                        )
                        break
                    except Exception as channel_err:
                        _LOGGER.error(
                            "Error fetching channel %s for device %s: %s",
                            channel,
                            device.display_name(),
                            channel_err,
                        )
                        continue

                device_channels_by_device[device.get_identifier()] = device_channels
                _LOGGER.debug(
                    "Found %d channels for device %s",
                    len(device_channels),
                    device.display_name(),
                )

        except Exception as err:
            raise UpdateFailed(f"Error communicating with API: {err}") from err

        _LOGGER.debug("Update completed: %d devices with data retrieved", len(devices))

        return ThermoworksData(
            devices=devices,
            device_channels=device_channels_by_device,
        )

    def get_device_by_id(self, device_id: str) -> ThermoworksDevice | None:
        """Return device by device id or serial."""
        for device in self.data.devices:
            if device.get_identifier() == device_id:
                return device

        return None

    def get_device_channel_by_id(
        self, device_id: str, channel_id: str
    ) -> ThermoworksChannel | None:
        """Return device channel by device id and channel id."""
        for device_channel in self.data.device_channels.get(device_id, []):
            if device_channel.number == channel_id:
                return device_channel

        return None
