def is_query_malicious(query: str) -> bool:
    """
    Checks whether the input string contains SQL injection patterns.

    Args:
        query (str): The input string to validate.

    Returns:
        bool: True if an injection pattern is detected, False otherwise.

    Example:
        >>> import injectdb
        >>> injectdb.is_query_malicious("' OR 1=1 --")
        True
        >>> injectdb.is_query_malicious("SELECT id FROM users WHERE id = 1")
        False
    """
    ...
