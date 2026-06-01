"""Email normalisation utilities."""


def normalize_email(email: str) -> str:
    """Normalize an email address for storage and comparison.

    Strips leading/trailing whitespace and lowercases the address.
    Applied at schema-validation time so all stored emails are
    in a canonical form regardless of how they were entered.

    Args:
        email: Raw email string from user input or an OAuth provider.

    Returns:
        Normalised email string.
    """
    return email.strip().lower()
