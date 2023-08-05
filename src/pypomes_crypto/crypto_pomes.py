import hashlib
from pathlib import Path
from typing import Final
from pypomes_core import APP_PREFIX, env_get_str

CRYPTO_HASH_ALGORITHM: Final[str] = env_get_str(f"{APP_PREFIX}_DEFAULT_HASH_ALGORITHM", "sha256")


def crypto_hash(msg: Path | str | bytes, alg: str = CRYPTO_HASH_ALGORITHM) -> bytes:
    """
    Compute the hash of *msg*, using the algorithm specified in *alg*.

    Return *None* if computing the hash not possible.
    Supported algorithms: md5, blake2b, blake2s, sha1, sha224, sha256, sha384 sha512,
    sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256.

    :param msg: The message to calculate the hash for, or a path to a file.
    :param alg: The algorithm to use, or a default value (either 'sha256', or an environment-defined value).
    :return: The hash value obtained, or None if the hash could not be computed.
    """
    hasher = hashlib.new(alg.lower())

    # what is the type of the argument ?
    if isinstance(msg, bytes):
        # argument is type 'bytes'
        hasher.update(msg)

    elif Path.is_file(Path(msg)):
        # argument is the path to a file
        buf_size: int = 128 * 1024
        with Path.open(Path(msg), "rb") as f:
            while True:
                file_bytes: bytes = f.read(buf_size)
                if not file_bytes:
                    break
                hasher.update(file_bytes)

    return hasher.digest()
