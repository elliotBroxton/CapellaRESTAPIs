# -*- coding: utf-8 -*-
# Generic/Built-in
from threading import Lock

import requests
import logging
import pprint


from .APIAuth import APIAuth
from .APIExceptions import (
    MissingAccessKeyError,
    MissingSecretKeyError,
    GenericHTTPError,
    CbcAPIError
)
import base64
import json


class APIRequests(object):

    def __init__(self, url, secret=None, access=None, token=None,
                 tls_ca=None, tls_client_cert=None, tls_client_key=None,
                 tls_verify=None):
        # handles http requests - GET , PUT, POST, DELETE
        # to the Couchbase Cloud APIs
        # Read the values from the environmental variables
        self.API_BASE_URL = url
        self.SECRET = secret
        self.ACCESS = access
        self.bearer_token = token

        self._log = logging.getLogger(__name__)
        self._log.propagate = True

        # TLS / mTLS configuration
        # Determine verification behavior: explicit tls_verify overrides, then tls_ca, else default False (preserve prior behavior)
        if tls_verify is not None:
            self.tls_verify = tls_verify
        elif tls_ca is not None:
            self.tls_verify = tls_ca
        else:
            # Existing code used verify=False everywhere; keep backward compatible default
            self.tls_verify = False

        # Prepare client certificate chain
        if tls_client_cert is not None and tls_client_key is not None:
            self.tls_client_cert = (tls_client_cert, tls_client_key)
        else:
            self.tls_client_cert = tls_client_cert

        # We will re-use the first session we setup to avoid
        # the overhead of creating new sessions for each request
        self.network_session = requests.Session()
        # Apply TLS config to the session
        self.network_session.verify = self.tls_verify
        if self.tls_client_cert is not None:
            self.network_session.cert = self.tls_client_cert
        self.jwt = None
        self.lock = Lock()

    def set_logging_level(self, level):
        self._log.setLevel(level)

    # --- Logging helpers (avoid leaking secrets) ---
    def _truncate(self, text, limit=800):
        try:
            s = str(text)
        except Exception:
            return "<unserializable>"
        if len(s) <= limit:
            return s
        return s[:limit] + "...<truncated>"

    def _summarize_auth_header(self, value):
        try:
            if not isinstance(value, str):
                return "<non-string auth>"
            parts = value.split(" ", 1)
            scheme = parts[0] if parts else "<unknown>"
            token_len = len(parts[1]) if len(parts) > 1 else 0
            return "%s <redacted len=%s>" % (scheme, token_len)
        except Exception:
            return "<auth redacted>"

    def _safe_headers(self, headers):
        if not headers:
            return {}
        safe = {}
        try:
            for k, v in headers.items():
                if isinstance(k, str) and k.lower() == "authorization":
                    safe[k] = self._summarize_auth_header(v)
                else:
                    safe[k] = v
        except Exception:
            return {"<headers>": "<error building headers snapshot>"}
        return safe

    def _preview_obj(self, obj, limit=1200):
        if obj is None:
            return None
        try:
            return self._truncate(json.dumps(obj, sort_keys=True), limit)
        except Exception:
            return self._truncate(obj, limit)

    def _cert_key_paths(self):
        cert_path = None
        key_path = None
        if isinstance(self.tls_client_cert, tuple):
            cert_path, key_path = self.tls_client_cert
        elif isinstance(self.tls_client_cert, str):
            cert_path = self.tls_client_cert
        return cert_path, key_path

    def _verify_description(self, verify_value):
        if isinstance(verify_value, str):
            return "custom:%s" % verify_value
        return "true" if verify_value else "false"

    def _auth_scheme_from_headers(self, headers):
        try:
            if not headers:
                return None
            for k, v in headers.items():
                if isinstance(k, str) and k.lower() == "authorization" and isinstance(v, str):
                    return v.split(" ", 1)[0]
        except Exception:
            return None
        return None

    def _log_http_error(self, response):
        try:
            req = getattr(response, 'request', None)
            method = getattr(req, 'method', None)
            url = getattr(req, 'url', None)
            request_headers = self._safe_headers(getattr(req, 'headers', {}))
            request_body = None
            try:
                body = getattr(req, 'body', None)
                if body is not None and isinstance(body, (bytes, bytearray)):
                    try:
                        request_body = self._truncate(body.decode('utf-8', errors='replace'))
                    except Exception:
                        request_body = "<bytes len=%s>" % len(body)
                else:
                    request_body = self._preview_obj(body)
            except Exception:
                request_body = "<unavailable>"

            status = getattr(response, 'status_code', None)
            reason = getattr(response, 'reason', None)
            resp_headers = self._safe_headers(getattr(response, 'headers', {}))
            try:
                text = getattr(response, 'text', '')
            except Exception:
                text = ''
            resp_text = self._truncate(text)
            auth_scheme = self._auth_scheme_from_headers(getattr(req, 'headers', {}))
            self._log.error(
                "HTTP failure: method=%s url=%s status=%s reason=%s auth_scheme=%s request_headers=%s request_body=%s response_headers=%s response_body=%s",
                method, url, status, reason, auth_scheme, request_headers, request_body, resp_headers, resp_text
            )
        except Exception as e:
            self._log.error("Failed to log HTTP error context: %s", e)

    def get_authorization_internal(self):
        if self.jwt is None:
            self.lock.acquire()
            if self.jwt is None:
                if self.tls_client_cert is not None:
                    # mTLS-only mode: do not perform BASIC /sessions; avoid any Authorization
                    self._log.info("mTLS enabled: skipping internal BASIC /sessions auth and JWT fetch")
                    self.jwt = ""
                else:
                    self._log.debug("refreshing token")
                    basic = base64.b64encode(
                        '{}:{}'.format(
                            self.user,
                            self.pwd).encode()).decode()
                    header = {'Authorization': 'Basic %s' % basic}
                    # Log BASIC auth usage with redacted password
                    try:
                        pwd_len = len(self.pwd) if self.pwd is not None else 0
                    except Exception:
                        pwd_len = -1
                    self._log.info(
                        "Auth mode: method=POST url=%s/sessions BASIC username=%s password=<redacted len=%s>",
                        self.internal_url, self.user, pwd_len
                    )
                    resp = self._urllib_request(
                        "{}/sessions".format(self.internal_url), method="POST",
                        headers=header)
                    if resp.status_code != 200:
                        self._log.warning("Response: {}".format(resp.status_code))
                        self._log.error("Error : {}".format(resp.content))
                    self.jwt = json.loads(resp.content).get("jwt") or ""
            self.lock.release()
        # Build headers; omit Authorization entirely when JWT is empty (mTLS-only mode)
        cbc_api_request_headers = {'Content-Type': 'application/json'}
        if self.jwt:
            cbc_api_request_headers['Authorization'] = 'Bearer %s' % self.jwt
        return cbc_api_request_headers

    def do_internal_request(self, url, method, params='', headers={}):
        header = self.get_authorization_internal()
        header.update(headers or {})
        mtls_enabled = self.tls_client_cert is not None
        secrets_present = self.SECRET is not None and self.ACCESS is not None
        # Strip Authorization header under mTLS
        effective_headers = dict(header) if header else {}
        if mtls_enabled and 'Authorization' in effective_headers:
            del effective_headers['Authorization']

        # Decide path: mTLS + HMAC (no bearer) vs legacy path
        if mtls_enabled and secrets_present:
            # Attach HMAC signer
            safe_before = self._safe_headers(header)
            safe_after = self._safe_headers(effective_headers)
            self._log.info(
                "Auth mode: method=%s url=%s mtls_enabled=%s hmac_applied=%s headers_before=%s headers_after=%s",
                method, url, mtls_enabled, True, safe_before, safe_after
            )
            try:
                if method == "GET":
                    query = params if isinstance(params, dict) else None
                    resp = self.network_session.get(
                        url, params=query,
                        auth=APIAuth(self.SECRET, self.ACCESS, self.bearer_token),
                        headers=effective_headers)
                elif method == "POST":
                    resp = self.network_session.post(
                        url, data=params,
                        auth=APIAuth(self.SECRET, self.ACCESS, self.bearer_token),
                        headers=effective_headers)
                elif method == "DELETE":
                    resp = self.network_session.delete(
                        url, data=params,
                        auth=APIAuth(self.SECRET, self.ACCESS, self.bearer_token),
                        headers=effective_headers)
                elif method == "PUT":
                    resp = self.network_session.put(
                        url, data=params,
                        auth=APIAuth(self.SECRET, self.ACCESS, self.bearer_token),
                        headers=effective_headers)
                elif method == "PATCH":
                    resp = self.network_session.patch(
                        url, data=params,
                        auth=APIAuth(self.SECRET, self.ACCESS, self.bearer_token),
                        headers=effective_headers)
                else:
                    resp = self._urllib_request(url, method, params=params, headers=effective_headers)
            except Exception as e:
                raise CbcAPIError(e)
        else:
            # Bearer (if any) or anonymous path
            self._log.info(
                "Auth mode: method=%s url=%s mtls_enabled=%s hmac_applied=%s headers=%s",
                method, url, mtls_enabled, False, self._safe_headers(effective_headers)
            )
            resp = self._urllib_request(
                url, method, params=params, headers=effective_headers)

        if resp is not None and resp.status_code == 401:
            self.jwt = None
            return self.do_internal_request(url, method, params)
        return resp

    # Methods
    def api_get(self, api_endpoint, params=None, headers=None):
        cbc_api_response = None
        self._log.info(api_endpoint)

        try:
            mtls_enabled = self.tls_client_cert is not None
            authorization_header_present = bool(headers and "Authorization" in headers)
            hmac_should_attach = (not authorization_header_present) and ((not mtls_enabled) or (mtls_enabled and self.SECRET and self.ACCESS))
            verify_mode = (
                "custom" if isinstance(self.tls_verify, str) else (
                    "true" if self.tls_verify else "false"
                )
            )
            cert_path, key_path = self._cert_key_paths()
            safe_headers_before = self._safe_headers(headers)
            # Enforce mTLS-only: strip Authorization header if client cert is configured
            effective_headers = dict(headers) if headers else None
            auth_header_stripped = False
            if mtls_enabled and effective_headers and "Authorization" in effective_headers:
                del effective_headers["Authorization"]
                auth_header_stripped = True
            safe_headers_after = self._safe_headers(effective_headers)
            params_preview = self._preview_obj(params)
            self._log.info(
                "Auth mode: method=GET endpoint=%s mtls_enabled=%s authorization_header_present=%s hmac_applied=%s verify=%s cert=%s key=%s secret_present=%s access_present=%s bearer_token_present=%s auth_header_stripped=%s headers_before=%s headers_after=%s params=%s"
                % (
                    api_endpoint,
                    mtls_enabled,
                    authorization_header_present,
                    hmac_should_attach,
                    verify_mode,
                    cert_path,
                    key_path,
                    self.SECRET is not None,
                    self.ACCESS is not None,
                    self.bearer_token is not None,
                    auth_header_stripped,
                    safe_headers_before,
                    safe_headers_after,
                    params_preview,
                )
            )
            if effective_headers and "Authorization" in (effective_headers or {}):
                cbc_api_response = self.network_session.get(
                    self.API_BASE_URL + api_endpoint,
                    params=params,
                    headers=effective_headers)
            else:
                if hmac_should_attach:
                    cbc_api_response = self.network_session.get(
                        self.API_BASE_URL + api_endpoint,
                        auth=APIAuth(
                            self.SECRET, self.ACCESS, self.bearer_token),
                        params=params,
                        headers=effective_headers)
                else:
                    # mTLS client cert present: omit APIAuth to ensure only mTLS is used
                    cbc_api_response = self.network_session.get(
                        self.API_BASE_URL + api_endpoint,
                        params=params,
                        headers=effective_headers)
            # Always log response status
            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code'):
                self._log.info("HTTP response: method=GET endpoint=%s status=%s", api_endpoint, cbc_api_response.status_code)
            self._log.info(cbc_api_response.content)
            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code') and cbc_api_response.status_code >= 400:
                self._log_http_error(cbc_api_response)

        except requests.exceptions.HTTPError:
            error = pprint.pformat(cbc_api_response.json())
            raise GenericHTTPError(error)

        except MissingAccessKeyError:
            self._log.debug("Missing Access Key environment variable")
            print("Missing Access Key environment variable")

        except MissingSecretKeyError:
            self._log.debug("Missing Access Key environment variable")
            print("Missing Access Key environment variable")

        # Grab any other exception and send to our generic exception
        # handler
        except Exception as e:
            raise CbcAPIError(e)

        return (cbc_api_response)

    def api_post(self, api_endpoint, request_body, headers=None):
        cbc_api_response = None

        self._log.info(api_endpoint)
        self._log.debug("Request body: " + str(request_body))

        try:
            mtls_enabled = self.tls_client_cert is not None
            authorization_header_present = bool(headers and "Authorization" in headers)
            hmac_should_attach = (not authorization_header_present) and ((not mtls_enabled) or (mtls_enabled and self.SECRET and self.ACCESS))
            verify_mode = (
                "custom" if isinstance(self.tls_verify, str) else (
                    "true" if self.tls_verify else "false"
                )
            )
            cert_path, key_path = self._cert_key_paths()
            safe_headers_before = self._safe_headers(headers)
            effective_headers = dict(headers) if headers else None
            auth_header_stripped = False
            if mtls_enabled and effective_headers and "Authorization" in effective_headers:
                del effective_headers["Authorization"]
                auth_header_stripped = True
            safe_headers_after = self._safe_headers(effective_headers)
            body_preview = self._preview_obj(request_body)
            self._log.info(
                "Auth mode: method=POST endpoint=%s mtls_enabled=%s authorization_header_present=%s hmac_applied=%s verify=%s cert=%s key=%s secret_present=%s access_present=%s bearer_token_present=%s auth_header_stripped=%s headers_before=%s headers_after=%s body=%s"
                % (
                    api_endpoint,
                    mtls_enabled,
                    authorization_header_present,
                    hmac_should_attach,
                    verify_mode,
                    cert_path,
                    key_path,
                    self.SECRET is not None,
                    self.ACCESS is not None,
                    self.bearer_token is not None,
                    auth_header_stripped,
                    safe_headers_before,
                    safe_headers_after,
                    body_preview,
                )
            )
            if effective_headers and "Authorization" in (effective_headers or {}):
                cbc_api_response = self.network_session.post(
                    self.API_BASE_URL + api_endpoint,
                    json=request_body,
                    headers=effective_headers)
            else:
                if hmac_should_attach:
                    cbc_api_response = self.network_session.post(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        auth=APIAuth(
                            self.SECRET, self.ACCESS, self.bearer_token),
                        headers=effective_headers)
                else:
                    cbc_api_response = self.network_session.post(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        headers=effective_headers)
            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code'):
                self._log.info("HTTP response: method=POST endpoint=%s status=%s", api_endpoint, cbc_api_response.status_code)
            self._log.debug(cbc_api_response.content)
            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code') and cbc_api_response.status_code >= 400:
                self._log_http_error(cbc_api_response)

        except requests.exceptions.HTTPError:
            error = pprint.pformat(cbc_api_response.json())
            raise GenericHTTPError(error)

        except MissingAccessKeyError:
            print("Missing Access Key environment variable")

        except MissingSecretKeyError:
            print("Missing Access Key environment variable")

        # Grab any other exception and send to our generic exception
        # handler
        except Exception as e:
            raise CbcAPIError(e)

        return (cbc_api_response)

    def api_put(self, api_endpoint, json_request_body=None, headers=None,
                data_request_body=None):
        cbc_api_response = None

        self._log.info(api_endpoint)
        if json_request_body:
            self._log.debug("Request body: " + str(json_request_body))
        if data_request_body:
            self._log.debug("Request body: " + str(data_request_body))
        try:
            mtls_enabled = self.tls_client_cert is not None
            authorization_header_present = bool(headers and "Authorization" in headers)
            hmac_should_attach = (not authorization_header_present) and ((not mtls_enabled) or (mtls_enabled and self.SECRET and self.ACCESS))
            verify_mode = (
                "custom" if isinstance(self.tls_verify, str) else (
                    "true" if self.tls_verify else "false"
                )
            )
            cert_path, key_path = self._cert_key_paths()
            safe_headers_before = self._safe_headers(headers)
            effective_headers = dict(headers) if headers else None
            auth_header_stripped = False
            if mtls_enabled and effective_headers and "Authorization" in effective_headers:
                del effective_headers["Authorization"]
                auth_header_stripped = True
            safe_headers_after = self._safe_headers(effective_headers)
            body_preview_json = self._preview_obj(json_request_body)
            body_preview_data = self._preview_obj(data_request_body)
            self._log.info(
                "Auth mode: method=PUT endpoint=%s mtls_enabled=%s authorization_header_present=%s hmac_applied=%s verify=%s cert=%s key=%s secret_present=%s access_present=%s bearer_token_present=%s auth_header_stripped=%s headers_before=%s headers_after=%s json=%s data=%s"
                % (
                    api_endpoint,
                    mtls_enabled,
                    authorization_header_present,
                    hmac_should_attach,
                    verify_mode,
                    cert_path,
                    key_path,
                    self.SECRET is not None,
                    self.ACCESS is not None,
                    self.bearer_token is not None,
                    auth_header_stripped,
                    safe_headers_before,
                    safe_headers_after,
                    body_preview_json,
                    body_preview_data,
                )
            )
            if effective_headers and "Authorization" in (effective_headers or {}):
                cbc_api_response = self.network_session.put(
                    self.API_BASE_URL + api_endpoint,
                    json=json_request_body,
                    data=data_request_body,
                    headers=effective_headers)
            else:
                if hmac_should_attach:
                    cbc_api_response = self.network_session.put(
                        self.API_BASE_URL + api_endpoint,
                        json=json_request_body,
                        data=data_request_body,
                        auth=APIAuth(
                            self.SECRET, self.ACCESS, self.bearer_token),
                        headers=effective_headers)
                else:
                    cbc_api_response = self.network_session.put(
                        self.API_BASE_URL + api_endpoint,
                        json=json_request_body,
                        data=data_request_body,
                        headers=effective_headers)
            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code'):
                self._log.info("HTTP response: method=PUT endpoint=%s status=%s", api_endpoint, cbc_api_response.status_code)
            self._log.debug(cbc_api_response.content)
            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code') and cbc_api_response.status_code >= 400:
                self._log_http_error(cbc_api_response)

        except requests.exceptions.HTTPError:
            error = pprint.pformat(cbc_api_response.json())
            raise GenericHTTPError(error)

        except MissingAccessKeyError:
            print("Missing Access Key environment variable")

        except MissingSecretKeyError:
            print("Missing Access Key environment variable")

        return (cbc_api_response)

    def api_patch(self, api_endpoint, request_body, headers=None):
        cbc_api_response = None

        self._log.info(api_endpoint)
        self._log.debug("Request body: " + str(request_body))

        try:
            mtls_enabled = self.tls_client_cert is not None
            authorization_header_present = bool(headers and "Authorization" in headers)
            hmac_should_attach = (not authorization_header_present) and ((not mtls_enabled) or (mtls_enabled and self.SECRET and self.ACCESS))
            verify_mode = (
                "custom" if isinstance(self.tls_verify, str) else (
                    "true" if self.tls_verify else "false"
                )
            )
            cert_path, key_path = self._cert_key_paths()
            safe_headers_before = self._safe_headers(headers)
            effective_headers = dict(headers) if headers else None
            auth_header_stripped = False
            if mtls_enabled and effective_headers and "Authorization" in effective_headers:
                del effective_headers["Authorization"]
                auth_header_stripped = True
            safe_headers_after = self._safe_headers(effective_headers)
            body_preview = self._preview_obj(request_body)
            self._log.info(
                "Auth mode: method=PATCH endpoint=%s mtls_enabled=%s authorization_header_present=%s hmac_applied=%s verify=%s cert=%s key=%s secret_present=%s access_present=%s bearer_token_present=%s auth_header_stripped=%s headers_before=%s headers_after=%s body=%s"
                % (
                    api_endpoint,
                    mtls_enabled,
                    authorization_header_present,
                    hmac_should_attach,
                    verify_mode,
                    cert_path,
                    key_path,
                    self.SECRET is not None,
                    self.ACCESS is not None,
                    self.bearer_token is not None,
                    auth_header_stripped,
                    safe_headers_before,
                    safe_headers_after,
                    body_preview,
                )
            )
            if effective_headers and "Authorization" in (effective_headers or {}):
                cbc_api_response = self.network_session.patch(
                    self.API_BASE_URL + api_endpoint,
                    json=request_body,
                    headers=effective_headers)
            else:
                if hmac_should_attach:
                    cbc_api_response = self.network_session.patch(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        auth=APIAuth(
                            self.SECRET, self.ACCESS, self.bearer_token),
                        headers=effective_headers)
                else:
                    cbc_api_response = self.network_session.patch(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        headers=effective_headers)
            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code'):
                self._log.info("HTTP response: method=PATCH endpoint=%s status=%s", api_endpoint, cbc_api_response.status_code)
            self._log.debug(cbc_api_response.content)
            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code') and cbc_api_response.status_code >= 400:
                self._log_http_error(cbc_api_response)

        except requests.exceptions.HTTPError:
            error = pprint.pformat(cbc_api_response.json())
            raise GenericHTTPError(error)

        except MissingAccessKeyError:
            print("Missing Access Key environment variable")

        except MissingSecretKeyError:
            print("Missing Access Key environment variable")

        return (cbc_api_response)

    def api_del(self, api_endpoint, request_body=None, headers=None):
        cbc_api_response = None

        self._log.info(api_endpoint)
        self._log.debug("Request body: " + str(request_body))

        try:
            mtls_enabled = self.tls_client_cert is not None
            authorization_header_present = bool(headers and "Authorization" in headers)
            hmac_should_attach = (not authorization_header_present) and ((not mtls_enabled) or (mtls_enabled and self.SECRET and self.ACCESS))
            verify_mode = (
                "custom" if isinstance(self.tls_verify, str) else (
                    "true" if self.tls_verify else "false"
                )
            )
            cert_path, key_path = self._cert_key_paths()
            safe_headers_before = self._safe_headers(headers)
            effective_headers = dict(headers) if headers else None
            auth_header_stripped = False
            if mtls_enabled and effective_headers and "Authorization" in effective_headers:
                del effective_headers["Authorization"]
                auth_header_stripped = True
            safe_headers_after = self._safe_headers(effective_headers)
            body_preview = self._preview_obj(request_body)
            self._log.info(
                "Auth mode: method=DELETE endpoint=%s mtls_enabled=%s authorization_header_present=%s hmac_applied=%s verify=%s cert=%s key=%s secret_present=%s access_present=%s bearer_token_present=%s auth_header_stripped=%s headers_before=%s headers_after=%s body=%s"
                % (
                    api_endpoint,
                    mtls_enabled,
                    authorization_header_present,
                    hmac_should_attach,
                    verify_mode,
                    cert_path,
                    key_path,
                    self.SECRET is not None,
                    self.ACCESS is not None,
                    self.bearer_token is not None,
                    auth_header_stripped,
                    safe_headers_before,
                    safe_headers_after,
                    body_preview,
                )
            )
            if effective_headers and "Authorization" in (effective_headers or {}):
                if request_body is None:
                    cbc_api_response = self.network_session.delete(
                        self.API_BASE_URL + api_endpoint,
                        headers=effective_headers)
                else:
                    cbc_api_response = self.network_session.delete(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        headers=effective_headers)
            else:
                if hmac_should_attach:
                    if request_body is None:
                        cbc_api_response = self.network_session.delete(
                            self.API_BASE_URL + api_endpoint,
                            auth=APIAuth(
                                self.SECRET, self.ACCESS, self.bearer_token),
                            headers=effective_headers)
                    else:
                        cbc_api_response = self.network_session.delete(
                            self.API_BASE_URL + api_endpoint,
                            json=request_body,
                            auth=APIAuth(
                                self.SECRET, self.ACCESS, self.bearer_token),
                            headers=effective_headers)
                else:
                    if request_body is None:
                        cbc_api_response = self.network_session.delete(
                            self.API_BASE_URL + api_endpoint,
                            headers=effective_headers)
                    else:
                        cbc_api_response = self.network_session.delete(
                            self.API_BASE_URL + api_endpoint,
                            json=request_body,
                            headers=effective_headers)

            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code'):
                self._log.info("HTTP response: method=DELETE endpoint=%s status=%s", api_endpoint, cbc_api_response.status_code)
            self._log.debug(cbc_api_response.content)
            if cbc_api_response is not None and hasattr(cbc_api_response, 'status_code') and cbc_api_response.status_code >= 400:
                self._log_http_error(cbc_api_response)

        except requests.exceptions.HTTPError:
            error = pprint.pformat(cbc_api_response.json())
            raise GenericHTTPError(error)

        except MissingAccessKeyError:
            print("Missing Access Key environment variable")

        except MissingSecretKeyError:
            print("Missing Access Key environment variable")

        # Grab any other exception and send to our generic exception
        # handler
        except Exception as e:
            raise CbcAPIError(e)

        return (cbc_api_response)

    def _urllib_request(self, api, method='GET', headers=None,
                        params='', timeout=300, verify=None):
        session = requests.Session()
        # Apply TLS config to the ad-hoc session
        effective_verify = self.tls_verify if verify is None else verify
        session.verify = effective_verify
        if self.tls_client_cert is not None:
            session.cert = self.tls_client_cert
        mtls_enabled = self.tls_client_cert is not None
        authorization_header_present = bool(headers and "Authorization" in headers)
        # Enforce mTLS-only for ad-hoc requests too: strip Authorization header
        effective_headers = dict(headers) if headers else None
        auth_header_stripped = False
        if mtls_enabled and effective_headers and "Authorization" in effective_headers:
            del effective_headers["Authorization"]
            auth_header_stripped = True
        verify_mode = (
            "custom" if isinstance(effective_verify, str) else (
                "true" if effective_verify else "false"
            )
        )
        cert_path = None
        key_path = None
        if isinstance(self.tls_client_cert, tuple):
            cert_path, key_path = self.tls_client_cert
        elif isinstance(self.tls_client_cert, str):
            cert_path = self.tls_client_cert
        safe_headers_before = self._safe_headers(headers)
        safe_headers_after = self._safe_headers(effective_headers)
        params_preview = self._preview_obj(params)
        self._log.info(
            "Auth mode: method=%s url=%s mtls_enabled=%s authorization_header_present=%s auth_header_stripped=%s verify=%s cert=%s key=%s secret_present=%s access_present=%s bearer_token_present=%s headers_before=%s headers_after=%s params=%s"
            % (
                method,
                api,
                mtls_enabled,
                authorization_header_present,
                auth_header_stripped,
                verify_mode,
                cert_path,
                key_path,
                self.SECRET is not None,
                self.ACCESS is not None,
                self.bearer_token is not None,
                safe_headers_before,
                safe_headers_after,
                params_preview,
            )
        )
        try:
            if method == "GET":
                resp = session.get(api, params=params, headers=effective_headers,
                                   timeout=timeout, verify=effective_verify)
            elif method == "POST":
                resp = session.post(api, data=params, headers=effective_headers,
                                    timeout=timeout, verify=effective_verify)
            elif method == "DELETE":
                resp = session.delete(api, data=params, headers=effective_headers,
                                      timeout=timeout, verify=effective_verify)
            elif method == "PUT":
                resp = session.put(api, data=params, headers=effective_headers,
                                   timeout=timeout, verify=effective_verify)
            elif method == "PATCH":
                resp = session.patch(api, data=params, headers=effective_headers,
                                     timeout=timeout, verify=effective_verify)
            if resp is not None and resp.status_code >= 400:
                self._log_http_error(resp)
            return resp
        except requests.exceptions.HTTPError as errh:
            self._log.error("HTTP Error {0}".format(errh))
        except requests.exceptions.ConnectionError as errc:
            self._log.error("Error Connecting {0}".format(errc))
        except requests.exceptions.Timeout as errt:
            self._log.error("Timeout Error: {0}".format(errt))
        except requests.exceptions.RequestException as err:
            self._log.error("Something else: {0}".format(err))
