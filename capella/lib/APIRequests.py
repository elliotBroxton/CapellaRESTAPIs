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

    def get_authorization_internal(self):
        if self.jwt is None:
            self.lock.acquire()
            if self.jwt is None:
                self._log.debug("refreshing token")
                basic = base64.b64encode(
                    '{}:{}'.format(
                        self.user,
                        self.pwd).encode()).decode()
                header = {'Authorization': 'Basic %s' % basic}
                resp = self._urllib_request(
                    "{}/sessions".format(self.internal_url), method="POST",
                    headers=header)
                if resp.status_code != 200:
                    self._log.warning("Response: {}".format(resp.status_code))
                    self._log.error("Error : {}".format(resp.content))
                self.jwt = json.loads(resp.content).get("jwt")
            self.lock.release()
        cbc_api_request_headers = {
            'Authorization': 'Bearer %s' % self.jwt,
            'Content-Type': 'application/json'
        }
        return cbc_api_request_headers

    def do_internal_request(self, url, method, params='', headers={}):
        header = self.get_authorization_internal()
        header.update(headers)
        resp = self._urllib_request(
            url, method, params=params, headers=header)
        if resp.status_code == 401:
            self.jwt = None
            return self.do_internal_request(url, method, params)
        return resp

    # Methods
    def api_get(self, api_endpoint, params=None, headers=None):
        cbc_api_response = None
        self._log.info(api_endpoint)

        try:
            if headers and "Authorization" in headers:
                cbc_api_response = self.network_session.get(
                    self.API_BASE_URL + api_endpoint,
                    params=params,
                    headers=headers)
            else:
                if self.tls_client_cert is None:
                    cbc_api_response = self.network_session.get(
                        self.API_BASE_URL + api_endpoint,
                        auth=APIAuth(
                            self.SECRET, self.ACCESS, self.bearer_token),
                        params=params,
                        headers=headers)
                else:
                    # mTLS client cert present: omit APIAuth to ensure only mTLS is used
                    cbc_api_response = self.network_session.get(
                        self.API_BASE_URL + api_endpoint,
                        params=params,
                        headers=headers)
            self._log.info(cbc_api_response.content)

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
            if headers and "Authorization" in headers:
                cbc_api_response = self.network_session.post(
                    self.API_BASE_URL + api_endpoint,
                    json=request_body,
                    headers=headers)
            else:
                if self.tls_client_cert is None:
                    cbc_api_response = self.network_session.post(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        auth=APIAuth(
                            self.SECRET, self.ACCESS, self.bearer_token),
                        headers=headers)
                else:
                    cbc_api_response = self.network_session.post(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        headers=headers)
            self._log.debug(cbc_api_response.content)

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
            if headers and "Authorization" in headers:
                cbc_api_response = self.network_session.put(
                    self.API_BASE_URL + api_endpoint,
                    json=json_request_body,
                    data=data_request_body,
                    headers=headers)
            else:
                if self.tls_client_cert is None:
                    cbc_api_response = self.network_session.put(
                        self.API_BASE_URL + api_endpoint,
                        json=json_request_body,
                        data=data_request_body,
                        auth=APIAuth(
                            self.SECRET, self.ACCESS, self.bearer_token),
                        headers=headers)
                else:
                    cbc_api_response = self.network_session.put(
                        self.API_BASE_URL + api_endpoint,
                        json=json_request_body,
                        data=data_request_body,
                        headers=headers)
            self._log.debug(cbc_api_response.content)

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
            if headers and "Authorization" in headers:
                cbc_api_response = self.network_session.patch(
                    self.API_BASE_URL + api_endpoint,
                    json=request_body,
                    headers=headers)
            else:
                if self.tls_client_cert is None:
                    cbc_api_response = self.network_session.patch(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        auth=APIAuth(
                            self.SECRET, self.ACCESS, self.bearer_token),
                        headers=headers)
                else:
                    cbc_api_response = self.network_session.patch(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        headers=headers)
            self._log.debug(cbc_api_response.content)

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
            if headers and "Authorization" in headers:
                if request_body is None:
                    cbc_api_response = self.network_session.delete(
                        self.API_BASE_URL + api_endpoint,
                        headers=headers)
                else:
                    cbc_api_response = self.network_session.delete(
                        self.API_BASE_URL + api_endpoint,
                        json=request_body,
                        headers=headers)
            else:
                if self.tls_client_cert is None:
                    if request_body is None:
                        cbc_api_response = self.network_session.delete(
                            self.API_BASE_URL + api_endpoint,
                            auth=APIAuth(
                                self.SECRET, self.ACCESS, self.bearer_token),
                            headers=headers)
                    else:
                        cbc_api_response = self.network_session.delete(
                            self.API_BASE_URL + api_endpoint,
                            json=request_body,
                            auth=APIAuth(
                                self.SECRET, self.ACCESS, self.bearer_token),
                            headers=headers)
                else:
                    if request_body is None:
                        cbc_api_response = self.network_session.delete(
                            self.API_BASE_URL + api_endpoint,
                            headers=headers)
                    else:
                        cbc_api_response = self.network_session.delete(
                            self.API_BASE_URL + api_endpoint,
                            json=request_body,
                            headers=headers)

            self._log.debug(cbc_api_response.content)

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
        try:
            if method == "GET":
                resp = session.get(api, params=params, headers=headers,
                                   timeout=timeout, verify=effective_verify)
            elif method == "POST":
                resp = session.post(api, data=params, headers=headers,
                                    timeout=timeout, verify=effective_verify)
            elif method == "DELETE":
                resp = session.delete(api, data=params, headers=headers,
                                      timeout=timeout, verify=effective_verify)
            elif method == "PUT":
                resp = session.put(api, data=params, headers=headers,
                                   timeout=timeout, verify=effective_verify)
            elif method == "PATCH":
                resp = session.patch(api, data=params, headers=headers,
                                     timeout=timeout, verify=effective_verify)
            return resp
        except requests.exceptions.HTTPError as errh:
            self._log.error("HTTP Error {0}".format(errh))
        except requests.exceptions.ConnectionError as errc:
            self._log.error("Error Connecting {0}".format(errc))
        except requests.exceptions.Timeout as errt:
            self._log.error("Timeout Error: {0}".format(errt))
        except requests.exceptions.RequestException as err:
            self._log.error("Something else: {0}".format(err))
