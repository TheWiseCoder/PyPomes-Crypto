import base64
import jwt
import requests
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK
from jwt.algorithms import RSAPublicKey
from logging import Logger
from pypomes_core import exc_format
from typing import Any, Literal


def jwt_convert(jwk: dict[str, str],
                fmt: Literal["DER", "PEM"]) -> bytes | str | None:
    """
    Convert the *JWK* (JSON Web Key) given in *jwk* to the format *fmt*.

    The supported target formats are:
        - *DER*: Distinguished Encoding Rules (bytes)
        - *PEM*: Privacy-Enhanced Mail (str)

    A typical JWK has the following format (for simplicity, 'n' and 'x5c' are truncated):
    {
        "kid": "5vrDgXBKmE-7EorvkE5Mu9VlId_ISgl2v7Af23nDvDU",
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": "2lfctxbCT2UWsBMC1rlpmWRcmDRS-EN0opirHzUsgHf7VJCyN0beKchy3biKQeXhgoirWR-f9uufn6Wl...",
        "e": "AQAB",
        "x5c": [
            "MIIClTCCAX0CBgFxx6eIWjANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANwamUwHhcNMjAwNDI5MjAzNDM3..."
        ],
        "x5t": "Bq0yqAX_D4aFA0eX9HSBVZxVW3A",
        "x5t#S256": "OGHvtCjTBasA9uHivO1_cNJXKExc0w1-1yhTPEK2CPM"
    }

    :param jwk: the JSON web key to be converted
    :param fmt: the target format
    :return: *jwt* in *DER* (bytes) or *PEM* (str) format, or *None* if error
    """
    # retrieve and decode the base64url values
    n_b64: str = jwk["n"]
    e_b64: str = jwk["e"]
    n_int: int = int.from_bytes(base64.urlsafe_b64decode(n_b64 + "=="), "big")
    e_int: int = int.from_bytes(base64.urlsafe_b64decode(e_b64 + "=="), "big")

    # construct the RSA public key
    public_numbers = rsa.RSAPublicNumbers(e=e_int,
                                          n=n_int)
    public_key = public_numbers.public_key(backend=default_backend())

    result: bytes | str | None = None
    if fmt == "DER":
        # export to DER format
        result: bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    elif fmt == "PEM":
        # export to PEM format
        pem_bytes: bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        result: str = pem_bytes.decode("utf-8")

    return result


def jwt_get_header(token: str,
                   errors: list[str] = None,
                   logger: Logger = None) -> dict[str, Any] | None:
    """
    Retrieve the data in the header a JWT *token*.

    Any well-constructed JWT token may be provided in *token*.
    Note that neither the token's signature nor its expiration is verified.

    Structure of the returned data:
        {
            "alg": "RS256",
            "typ": "JWT",
            "kid": "A1234"
        }

    :param token: the reference token
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the data in the token's header, or *None* if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(msg="Retrieve header for token")

    try:
        result = jwt.get_unverified_header(jwt=token)
    except Exception as e:
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=f"Error retrieving the token's header: {exc_err}")
        if isinstance(errors, list):
            errors.append(exc_err)

    return result


def jwt_get_payload(token: str,
                    errors: list[str] = None,
                    logger: Logger = None) -> dict[str, dict[str, Any]] | None:
    """
    Retrieve the data in the payload of a JWT *token*.

    Any well-constructed JWT token may be provided in *token*.
    Note that neither the token's signature nor its expiration is verified.

    Structure of the returned data:
        {
            "birthdate": "1980-01-01",
            "email": "jdoe@mail.com",
            "exp": 1516640454,
            "iat": 1516239022,
            "iss": "my_jwt_provider.com",
            "jti": "Uhsdfgr67FGH567qwSDF33er89retert",
            "gender": "M",
            "name": "John Doe",
            "nbt": 1516249022
            "sub": "11111111111",
            "roles": [
                "administrator",
                "operator"
            ]
      }

    :param token: the reference token
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the data in the token's payload, or *None* if error
    """
    # initialize the return variable
    result: dict[str, dict[str, Any]] | None = None

    if logger:
        logger.debug(msg="Retrieve payload for token")

    try:
        result = jwt.decode(jwt=token,
                            options={"verify_signature": False})
    except Exception as e:
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=f"Error retrieving the token's payload: {exc_err}")
        if isinstance(errors, list):
            errors.append(exc_err)

    return result


def jwt_get_claim(token: str,
                  key: str,
                  errors: list[str] = None,
                  logger: Logger = None) -> str | None:
    """
    Retrieve the claim associated with *key* in *token*'s header or payload.

    :param token: the reference token
    :param key: the name of the claim whose values are to be returned
    :param errors: incidental errors
    :param logger: optiona logger
    :return: the requested claim, or *None* if error or not found
    """
    # initialize the return variable:
    result: str | None = None

    header: dict[str, Any] = jwt_get_header(token=token,
                                            errors=errors,
                                            logger=logger)
    if not errors:
        result = header.get(key)
        if not result:
            payload: dict[str, Any] = jwt_get_payload(token=token,
                                                      errors=errors,
                                                      logger=logger)
            if not errors:
                result = payload.get(key)

    return result


def jwt_get_claims(token: str,
                   keys: tuple[str, ...],
                   errors: list[str] = None,
                   logger: Logger = None) -> tuple | None:
    """
    Retrieve the claims associated with *keys* in *token*'s header or payload.

    The claims are returned in the same order as requested in *keys*.
    For a claim not found, *None* is returned in its position.

    :param token: the reference token
    :param keys: the names of the claims whose values are to be returned
    :param errors: incidental errors
    :param logger: optiona logger
    :return: a tuple containing the respective values of *keys* in *token*'s payload, or *None* if error
    """
    # initialize the return variable:
    result: tuple | None = None

    header: dict[str, Any] = jwt_get_header(token=token,
                                            errors=errors,
                                            logger=logger)
    if not errors:
        payload: dict[str, Any] = jwt_get_payload(token=token,
                                                  errors=errors,
                                                  logger=logger)
        if not errors:
            result = tuple([header.get(key) or payload.get(key) for key in keys])

    return result


def jwt_get_public_key(issuer: str = None,
                       token: str = None,
                       fmt: Literal["PEM", "DER", "JWK"] = "PEM",
                       errors: list[str] = None,
                       logger: Logger = None) -> dict[str, str] | bytes | str | None:
    """
    Obtain the public key used to sign the token.

    The token's issuer may be provided in one of these two parameters:
        - *issuer*: the content of the token claim *iss*
        - *token*: the token itself, from which the *issuer* is extracted

    This is accomplished by requesting the token issuer for its *JWKS* (JSON Web Key Set),
    containing the public keys used for various purposes, as indicated in the attribute *use*:
        - *enc*: the key is intended for encryption
        - *sig*: the key is intended for digital signature
        - *wrap*: the key is intended for key wrapping

    A typical JWKS set has the following format (for simplicity, 'n' and 'x5c' are truncated):
        {
            "keys": [
                {
                    "kid": "X2QEcSQ4Tg2M2EK6s2nhRHZH_GwD_zxZtiWVwP4S0tg",
                    "kty": "RSA",
                    "alg": "RSA256",
                    "use": "sig",
                    "n": "tQmDmyM3tMFt5FMVMbqbQYpaDPf6A5l4e_kTVDBiHrK_bRlGfkk8hYm5SNzNzCZ...",
                    "e": "AQAB",
                    "x5c": [
                        "MIIClzCCAX8CBgGZY0bqrTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARpanVk..."
                    ],
                    "x5t": "MHfVp4kBjEZuYOtiaaGsfLCL15Q",
                    "x5t#S256": "QADezSLgD8emuonBz8hn8ghTnxo7AHX4NVNkr4luEhk"
                },
                ...
            ]
        }

    The signature key is returned in its original *JWK* (JSON Web Key) format, or converted to
    either *DER* (Distinguished Encoding Rules) or *PEM* (Privacy-Enhanced Mail) format, as per *ftm*.

    :param issuer: the token's issuer, as presented in the token's *iss* claim (required, if *token* is not provided)
    :param token: the reference token (required, if *issuer* is not provided)
    :param fmt: the returning key's format (defaults to *PEM*)
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the public key in *JWT*, *DER*, or *PEM* format, or *None* if error
    """
    # initialize the return variable
    result: dict[str, str] | bytes | str | None = None

    if not issuer and token:
        issuer: str = jwt_get_claim(token=token,
                                    key="iss",
                                    errors=errors,
                                    logger=logger)
    if issuer:
        # obtain the JWKS (JSON Web Key Set) from the token issuer
        url: str = f"{issuer}/protocol/openid-connect/certs"
        if logger:
            logger.debug(msg=f"GET {url}")
        try:
            response: requests.Response = requests.get(url=url)
            if response.status_code == 200:
                # request succeeded
                if logger:
                    logger.debug(msg="GET success")
                # select the appropriate JWK
                reply: dict[str, list[dict[str, str]]] = response.json()
                jwk: dict[str, str] | None = None
                for key in reply["keys"]:
                    if key.get("use") == "sig":
                        jwk = key
                        break
                if jwk:
                    # convert from 'JWK' to 'PEM' and save it for further use
                    if fmt in ["DER", "PEM"]:
                        # noinspection PyTypeChecker
                        result = jwt_convert(jwk=jwk,
                                             fmt=fmt)
                    else:
                        result = jwk
                    if result and logger:
                        logger.debug(f"Public key obtained for issuer '{issuer}'")
                else:
                    msg: str = (f"Signature public key missing from the JWKS "
                                f"returned by the token issuer '{issuer}'")
                    if logger:
                        logger.error(msg=msg)
                    if isinstance(errors, list):
                        errors.append(msg)
            elif logger:
                msg: str = f"GET failure, status {response.status_code}, reason {response.reason}"
                if hasattr(response, "content") and response.content:
                    msg += f", content {response.content}"
                logger.error(msg=msg)
                if isinstance(errors, list):
                    errors.append(msg)
        except Exception as e:
            # the operation raised an exception
            msg = exc_format(exc=e,
                             exc_info=sys.exc_info())
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    elif not errors:
        msg = "Token/issuer not provided"
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    return result


def jwt_validate(token: str,
                 issuer: str = None,
                 recipient_id: str = None,
                 recipient_attr: str = None,
                 public_key: str | bytes | PyJWK | RSAPublicKey = None,
                 errors: list[str] = None,
                 logger: Logger = None) -> dict[str, dict[str, Any]] | None:
    """
    Verify whether *token* is a valid JWT token, and return its claims (sections *header* and *payload*).

    The supported public key types are:
        - *DER*: Distinguished Encoding Rules (bytes)
        - *PEM*: Privacy-Enhanced Mail (str)
        - *PyJWK*: a formar from the *PyJWT* package
        - *RSAPublicKey*: a format from the *PyJWT* package

    If an asymmetric algorithm was used to sign the token and *public_key* is provided, then
    the token's signature is validated, by using the data in its *signature* section.

    The parameters *recipient_id* and *recipient_attr* refer the token's expected subject, respectively,
    the subject's identification and the attribute in the token's payload data identifying its subject.
    If both are provided, *recipient_id* is validated.

    On failure, *errors* will contain the reason(s) for rejecting *token*.
    On success, return the token's claims (*header* and *payload*).

    :param token: the token to be validated
    :param public_key: optional public key used to sign the token, in *PEM* format
    :param issuer: optional value to compare with the token's *iss* (issuer) attribute in its *payload*
    :param recipient_id: identification of the expected token subject
    :param recipient_attr: attribute in the token's payload holding the expected subject's identification
    :param errors: incidental error messages
    :param logger: optional logger
    :return: The token's claims (*header* and *payload*), or *None* if error
    """
    # initialize the return variable
    result: dict[str, dict[str, Any]] | None = None

    if logger:
        logger.debug(msg="Validate JWT token")

    # make sure to have an errors list
    if not isinstance(errors, list):
        errors = []

    # extract needed data from token header
    token_header: dict[str, Any] | None = None
    try:
        token_header: dict[str, Any] = jwt.get_unverified_header(jwt=token)
    except Exception as e:
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=f"Error retrieving the token's header: {exc_err}")
        errors.append(exc_err)

    # validate the token
    if not errors:
        token_alg: str = token_header.get("alg")
        require: list[str] = ["exp", "iat"]
        if issuer:
            require.append("iss")
        options: dict[str, Any] = {
            "require": require,
            "verify_aud": False,
            "verify_exp": True,
            "verify_iat": True,
            "verify_iss": issuer is not None,
            "verify_nbf": False,
            "verify_signature": token_alg in ["RS256", "RS512"] and public_key is not None
        }
        try:
            # raises:
            #   InvalidTokenError: token is invalid
            #   InvalidKeyError: authentication key is not in the proper format
            #   ExpiredSignatureError: token and refresh period have expired
            #   InvalidSignatureError: signature does not match the one provided as part of the token
            #   ImmatureSignatureError: 'nbf' or 'iat' claim represents a timestamp in the future
            #   InvalidAlgorithmError: the specified algorithm is not recognized
            #   InvalidIssuedAtError: 'iat' claim is non-numeric
            #   MissingRequiredClaimError: a required claim is not contained in the claimset
            payload: dict[str, Any] = jwt.decode(jwt=token,
                                                 key=public_key,
                                                 algorithms=[token_alg],
                                                 options=options,
                                                 issuer=issuer)
            if recipient_id and recipient_attr and \
                    payload.get(recipient_attr) and recipient_id != payload.get(recipient_attr):
                msg: str = f"Token was issued to '{payload.get(recipient_attr)}', not to '{recipient_id}'"
                if logger:
                    logger.error(msg=msg)
                errors.append(msg)
            else:
                result = {
                    "header": token_header,
                    "payload": payload
                }
        except Exception as e:
            exc_err: str = exc_format(exc=e,
                                      exc_info=sys.exc_info())
            if logger:
                logger.error(msg=f"Error decoding the token: {exc_err}")
            errors.append(exc_err)

    if logger:
        if errors:
            logger.debug(msg=f"Token is invalid: {token}")
        else:
            logger.debug(msg="Token is valid")

    return result
