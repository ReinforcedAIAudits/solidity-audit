import requests


__all__ = ['create_session', 'preprocess_text', 'ROLES', 'is_synonyms']


class ROLES(object):
    SYSTEM = "system"
    ASSISTANT = "assistant"
    USER = "user"


class SynonymsSingleton(object):
    SYNONYMS = (
        ('Missing Check on Signature Recovery', 'Signature replay'),
        ('Gas griefing', 'Gas grief', 'unchecked call'),
        (
            'Unguarded function', 'Missed access check', '(un?)intentional backdoor',
            'Unprotected function', 'Unexpected privilege grants'
        ),
        ('Invalid code', 'Invalid')
    )

    def __init__(self):
        self._synonyms = None

    @property
    def synonyms(self) -> dict:
        if self._synonyms is None:
            self._synonyms = self.load_synonyms()
        return self._synonyms

    def load_synonyms(self) -> dict:
        prepared = {}
        for pairs in self.SYNONYMS:
            prepared_pairs = [x.lower().strip() for x in pairs]
            for variant in prepared_pairs:
                for other in prepared_pairs:
                    prepared.setdefault(variant, set()).add(other)
        return prepared


synonyms_instance = SynonymsSingleton()


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


def is_synonyms(expected_result: str, answer: str) -> bool:
    expected_result = expected_result.strip().lower()
    answer = answer.strip().lower()
    if answer == expected_result:
        return True
    return answer in synonyms_instance.synonyms.get(expected_result, set())
