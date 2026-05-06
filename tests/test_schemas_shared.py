"""Tests for auth_sdk_m8.schemas.shared."""

from auth_sdk_m8.schemas.shared import ValidationConstants


def test_host_regex_localhost() -> None:
    assert ValidationConstants.HOST_REGEX.match("localhost")


def test_host_regex_ipv4() -> None:
    assert ValidationConstants.HOST_REGEX.match("192.168.1.1")


def test_host_regex_domain() -> None:
    assert ValidationConstants.HOST_REGEX.match("example.com")


def test_host_regex_invalid() -> None:
    assert not ValidationConstants.HOST_REGEX.match("http://example.com")


def test_http_host_regex_valid() -> None:
    assert ValidationConstants.HTTP_HOST_REGEX.match("http://localhost")
    assert ValidationConstants.HTTP_HOST_REGEX.match("https://example.com")
    assert ValidationConstants.HTTP_HOST_REGEX.match("http://192.168.1.1:8080")


def test_http_host_regex_invalid() -> None:
    assert not ValidationConstants.HTTP_HOST_REGEX.match("ftp://example.com")
    assert not ValidationConstants.HTTP_HOST_REGEX.match("example.com")


def test_url_path_regex_valid() -> None:
    assert ValidationConstants.URL_PATH_STR_REGEX.match("/api/v1")
    assert ValidationConstants.URL_PATH_STR_REGEX.match("api")
    assert ValidationConstants.URL_PATH_STR_REGEX.match("")


def test_url_path_regex_invalid() -> None:
    assert not ValidationConstants.URL_PATH_STR_REGEX.match("/api v1")


def test_key_regex_valid() -> None:
    assert ValidationConstants.KEY_REGEX.match("my_key-123")


def test_key_regex_invalid() -> None:
    assert not ValidationConstants.KEY_REGEX.match("my key")


def test_slug_regex_valid() -> None:
    assert ValidationConstants.SLUG_REGEX.match("my-stack-123")


def test_slug_regex_invalid() -> None:
    assert not ValidationConstants.SLUG_REGEX.match("My-Stack")


def test_unix_path_regex_valid() -> None:
    assert ValidationConstants.UNIX_PATH_REGEX.match("/static/assets")


def test_unix_path_regex_invalid() -> None:
    assert not ValidationConstants.UNIX_PATH_REGEX.match("relative/path")


def test_file_path_regex_unix() -> None:
    assert ValidationConstants.FILE_PATH_REGEX.match("/static/path")


def test_file_path_regex_windows() -> None:
    assert ValidationConstants.FILE_PATH_REGEX.match("C:/Users/project/static")


def test_file_path_regex_invalid() -> None:
    assert not ValidationConstants.FILE_PATH_REGEX.match("relative/path")


def test_password_regex_valid() -> None:
    assert ValidationConstants.PASSWORD_REGEX.match("MyPassw0rd!")


def test_password_regex_invalid_too_short() -> None:
    assert not ValidationConstants.PASSWORD_REGEX.match("Ab1!")


def test_password_regex_invalid_no_special() -> None:
    assert not ValidationConstants.PASSWORD_REGEX.match("MyPassword1")


def test_secret_key_regex_valid() -> None:
    assert ValidationConstants.SECRET_KEY_REGEX.match(
        "Abcdef-1234_XYZ-abcdef-ghijkl-mn"
    )


def test_secret_key_regex_invalid_too_short() -> None:
    assert not ValidationConstants.SECRET_KEY_REGEX.match("Abc-1d")


def test_secret_key_regex_invalid_no_digit() -> None:
    assert not ValidationConstants.SECRET_KEY_REGEX.match(
        "Abcdef-WXYZ_abcdef-ghijkl-mnopqr"
    )


def test_mysql_name_regex_valid() -> None:
    assert ValidationConstants.MYSQL_NAME_REGEX.match("my_db_1")


def test_mysql_name_regex_invalid() -> None:
    assert not ValidationConstants.MYSQL_NAME_REGEX.match("my-db")


def test_control_char_pattern_matches_control_chars() -> None:
    assert ValidationConstants.CONTROL_CHAR_PATTERN.search("\x01")
    assert ValidationConstants.CONTROL_CHAR_PATTERN.search("\x7f")
    assert ValidationConstants.CONTROL_CHAR_PATTERN.search("​")
    assert ValidationConstants.CONTROL_CHAR_PATTERN.search("﻿")


def test_control_char_pattern_preserves_tab_lf_cr() -> None:
    assert not ValidationConstants.CONTROL_CHAR_PATTERN.search("\t")
    assert not ValidationConstants.CONTROL_CHAR_PATTERN.search("\n")
    assert not ValidationConstants.CONTROL_CHAR_PATTERN.search("\r")


def test_remove_invisible_chars_strips_control() -> None:
    dirty = "hello\x01world​!"
    assert ValidationConstants.remove_invisible_chars(dirty) == "helloworld!"


def test_remove_invisible_chars_preserves_printable() -> None:
    text = "hello\tworld\n"
    assert ValidationConstants.remove_invisible_chars(text) == text


def test_remove_invisible_chars_empty() -> None:
    assert ValidationConstants.remove_invisible_chars("") == ""
