"""
Shared validation constants used across schemas and configuration.
"""
import re


class ValidationConstants:
    """
    Regular expression constants for validating configuration values.

    Covers host/domain names, URLs, file paths, passwords, secret keys,
    and MySQL identifiers.
    """

    #: hostname / domain / localhost / IPv4 (optional port)
    HOST_REGEX: re.Pattern = re.compile(
        r"^(localhost|((\d{1,3}\.){3}\d{1,3}(:\d{1,5})?)"
        r"|([A-Za-z0-9-]+\.[A-Za-z0-9-.]+)|([A-Za-z0-9-_]+))$"
    )
    #: HTTP/HTTPS URL with a valid host and optional port
    HTTP_HOST_REGEX: re.Pattern = re.compile(
        r"^https?:\/\/(?:localhost|(?:\d{1,3}\.){3}\d{1,3}"
        r"|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?::\d{1,5})?$"
    )
    #: URL path starting with / containing allowed characters
    URL_PATH_STR_REGEX: re.Pattern = re.compile(r"^\/?[A-Za-z0-9\-._~\/]*$")
    #: Alphanumeric key (letters, digits, underscores, hyphens)
    KEY_REGEX: re.Pattern = re.compile(r"^[A-Za-z0-9_-]+$")
    #: Slug: lowercase letters, digits, hyphens
    SLUG_REGEX: re.Pattern = re.compile(r"^[a-z0-9-]+$")
    #: Unix absolute path
    UNIX_PATH_REGEX: re.Pattern = re.compile(r"^\/[A-Za-z0-9_\-\/]+$")
    #: Absolute path (Unix or Windows)
    FILE_PATH_REGEX: re.Pattern = re.compile(
        r"^(?:\/|(?:[A-Z]:))[A-Za-z0-9_\-\/\\:]+$"
    )
    #: Password: 8+ chars, upper, lower, digit, special, no spaces
    PASSWORD_REGEX: re.Pattern = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])(?!.*\s).{8,}$"
    )
    #: Secret key: 32+ chars, mixed case, digits, hyphens/underscores
    SECRET_KEY_REGEX: re.Pattern = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[-_])[A-Za-z\d\-_]{32,}$"
    )
    #: MySQL database / user name
    MYSQL_NAME_REGEX: re.Pattern = re.compile(r"^[A-Za-z0-9_]+$")
    # Built with chr() so the source file contains only printable ASCII
    # while the runtime string correctly encodes the char ranges.
    # Preserves tab (U+0009), LF (U+000A), CR (U+000D).
    CONTROL_CHAR_PATTERN: re.Pattern = re.compile(
        "["
        + chr(0x0000) + "-" + chr(0x0008)
        + chr(0x000B) + "-" + chr(0x000C)
        + chr(0x000E) + "-" + chr(0x001F)
        + chr(0x007F) + "-" + chr(0x009F)
        + chr(0x200B) + "-" + chr(0x200D)
        + chr(0xFEFF)
        + "]"
    )

    @classmethod
    def remove_invisible_chars(cls, text: str) -> str:
        """
        Strip invisible or control Unicode characters from a string,
        preserving line breaks and tabs.
        """
        return cls.CONTROL_CHAR_PATTERN.sub("", text)
