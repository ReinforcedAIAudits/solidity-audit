import requests


__all__ = ['create_session', 'preprocess_text', 'ROLES']


class ROLES(object):
    SYSTEM = "system"
    ASSISTANT = "assistant"
    USER = "user"


def create_session():
    retries = requests.adapters.Retry(total=10, status_forcelist=[500, 503, 504])
    session = requests.Session()
    session.mount("https://", requests.adapters.HTTPAdapter(max_retries=retries))
    session.mount("http://", requests.adapters.HTTPAdapter(max_retries=retries))
    return session


def preprocess_text(text: str):
    """
    We want LLM to provide correct line numbers, as it is bad at counting - we provide line numbers ourself.

    Good implementation of this function should also process whitespace, remove empty lines, format comments, etc.
    """
    lines = text.splitlines()
    numbered_lines = [f"Line {i + 1}: {line}" for i, line in enumerate(lines)]
    return "\n".join(numbered_lines)
