import json
import logging
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pprint import pprint as pp
from typing import Tuple, Optional, Any

import requests
from dotenv import dotenv_values

from octo.comdirect.exceptions import ComdirectAuthenticationFailed

logger = logging.getLogger(__name__)

CONFIG_FILENAME = ".env"


class ComdirectAccount(Enum):
    GEMEINSCHAFT = 1
    BOGDAN = 2


@dataclass
class Config:
    client_id: str
    client_secret: str
    username: str
    password: str
    base_url: str
    base_api_url: str


@dataclass
class TokenResponse:
    access_token: str
    token_type: str
    refresh_token: str
    expires_in: int
    scope: str
    kdnr: str
    bpid: int
    kontaktId: str


@dataclass
class Session:
    session_id: str
    request_id: str


@dataclass
class SessionStatusResponse:
    identifier: str
    sessionTanActive: bool
    activated2FA: bool


class ComdirectAuth:
    base_headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    def __init__(self, tan_wait_time=60, account=ComdirectAccount.GEMEINSCHAFT):
        self.account = account
        self._session = Session(str(uuid.uuid4()), str(uuid.uuid4()))
        self._config = None
        self._token: Optional[TokenResponse] = None
        self._session_response: Optional[SessionStatusResponse] = None
        self._tan_challenge_id = None
        self.tan_wait_time = tan_wait_time

    @property
    def config(self) -> Config:
        if not self._config:
            self._config = self._parse_config(dotenv_values())
        return self._config

    @property
    def token(self) -> Optional[TokenResponse]:
        return self._token

    @property
    def session(self) -> Session:
        return self._session

    @property
    def session_response(self) -> Optional[SessionStatusResponse]:
        return self._session_response

    def _parse_config(self, config: dict) -> Config:
        return Config(
            client_id=config.get("COMDIRECT_CLIENT_ID"),
            client_secret=config.get("COMDIRECT_CLIENT_SECRET"),
            username=config.get(f"COMDIRECT_ZUGANGSNUMMER_{self.account.name}"),
            password=config.get(f"COMDIRECT_PIN_{self.account.name}"),
            base_url=config.get("COMDIRECT_BASE_URL"),
            base_api_url=config.get("COMDIRECT_BASE_API_URL"),
        )

    def oauth_flow(self) -> None:
        self._token = self.auth_resource_owner_password_flow()
        self._session_response = self.fetch_session_status()
        if not self.session_response.sessionTanActive:
            logger.info("Requesting TAN-Challenge")
            self._session_response, self._tan_challenge_id = self.request_tan_challenge()
            logger.info("Sleeping for 60sec while the PhotoTAN app is used for TAN-Challenge")
            time.sleep(self.tan_wait_time)
            self._session_response = self.activate_tan()
            pp(self.session_response)

    def _make_request(
        self,
        url: str,
        headers: dict,
        method: str = "GET",
        data: Optional[str] = None,
    ) -> Any:
        try:
            response = requests.request(method, url, headers=headers, data=data)
            if not response.ok:
                raise ComdirectAuthenticationFailed(response.text)
            return response.json()
        except Exception as e:
            raise ComdirectAuthenticationFailed(e.args[0])

    def cd_secondary_flow(self, token: str) -> None:
        oauth_url = f"{self.config.base_url}oauth/token"
        payload = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "token": token,
            "grant_type": "cd_secondary",
        }
        response = requests.request("POST", oauth_url, headers=self.base_headers, data=payload)

    def auth_resource_owner_password_flow(self) -> TokenResponse:
        oauth_url = f"{self.config.base_url}oauth/token"
        payload = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "username": self.config.username,
            "password": self.config.password,
            "grant_type": "password",
        }

        response = requests.request("POST", oauth_url, headers=self.base_headers, data=payload)

        if not response.ok:
            raise ComdirectAuthenticationFailed(response.text)

        data = response.json()
        return TokenResponse(**data)

    def _make_token_header(self):
        return f"Bearer {self.token.access_token}"

    def fetch_session_status(self) -> SessionStatusResponse:
        session_url = f"{self.config.base_api_url}session/clients/user/v1/sessions"
        request_info = {"clientRequestId": {"sessionId": self.session.session_id, "requestId": self.session.request_id}}
        headers = {
            **self.base_headers,
            "Content-Type": "application/json",
            "Authorization": self._make_token_header(),
            "x-http-request-info": json.dumps(request_info),
        }
        data = self._make_request(session_url, headers)
        return SessionStatusResponse(**data[0])

    def request_tan_challenge(self) -> Tuple[SessionStatusResponse, str]:
        url = f"{self.config.base_api_url}session/clients/user/v1/sessions/{self.session_response.identifier}/validate"
        request_info = {"clientRequestId": {"sessionId": self.session.session_id, "requestId": self.session.request_id}}
        headers = {
            **self.base_headers,
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token.access_token}",
            "x-http-request-info": json.dumps(request_info),
        }
        payload = {"identifier": self.session_response.identifier, "sessionTanActive": True, "activated2FA": True}
        response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
        if not response.ok:
            raise ComdirectAuthenticationFailed(response.text)

        header = json.loads(response.headers.get("x-once-authentication-info"))
        data = response.json()
        return SessionStatusResponse(**data), header["id"]

    def activate_tan(self) -> SessionStatusResponse:
        url = f"{self.config.base_api_url}session/clients/user/v1/sessions/{self.session_response.identifier}"
        request_info = {"clientRequestId": {"sessionId": self.session.session_id, "requestId": self.session.request_id}}
        auth_info = {"id": self._tan_challenge_id}
        headers = {
            **self.base_headers,
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token.access_token}",
            "x-http-request-info": json.dumps(request_info),
            "x-once-authentication-info": json.dumps(auth_info),
            "x-once-authentication": "000000",
        }
        payload = {"identifier": self.session_response.identifier, "sessionTanActive": True, "activated2FA": True}
        data = self._make_request(url, headers, method="PATCH", data=json.dumps(payload))
        return SessionStatusResponse(**data)
