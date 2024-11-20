import json
import os
import random
import re
import time
import typing

from pydantic import AliasChoices, BaseModel, Field

from .protocol import ReferenceReport


__all__ = ['FilePair', 'TemplatePair', 'FileContractProvider', 'ValidatorTemplate', 'ValidatorTemplateError']


class FilePair:
    __slots__ = ["base_path", "name"]
    base_path: str
    name: str

    def __init__(self, name: str, base_path: str):
        self.base_path = base_path
        self.name = name

        if not os.path.exists(self.as_contract()):
            raise FileNotFoundError(f"Contract file {self.as_contract()} not found")
        if not os.path.exists(self.as_json()):
            raise FileNotFoundError(f" Report file {self.as_json()} not found")

    def as_contract(self):
        return f"{self.base_path}.sol.tpl"

    def as_json(self):
        return f"{self.base_path}.json"


class ValidatorTemplateError(Exception):
    pass


class ValidatorTemplate(object):
    REPLACEMENT_RE = re.compile(r'<\|([^<>]+)\|>')

    def __init__(self):
        self.replacement_methods = {}
        self.register_replacement_method('timestamp', lambda x: f'{int(time.time())}')
        self.register_replacement_method('random', lambda x: random.choice(x))

    def register_replacement_method(self, method_name: str, method_handler: typing.Callable[[list[str]], str]):
        self.replacement_methods[method_name] = method_handler

    def find_replacements(self, text: str) -> list[dict]:
        replacements = []
        for match in set(self.REPLACEMENT_RE.findall(text)):
            replacement = {'arguments': [], 'pattern': f'<|{match}|>'}
            if ':' in match:
                method, arguments = match.split(':')
                replacement['arguments'] = arguments.split('|')
            else:
                method = match
            if '|' in method:
                raise ValidatorTemplateError(f'Invalid character "|" inside template variable {method}')
            if method not in self.replacement_methods:
                raise ValidatorTemplateError(f'Unknown template variable method: {method}')
            replacement['method'] = method
            replacement['replacement'] = self.replacement_methods[method](replacement['arguments'])
            replacements.append(replacement)

        return replacements

    @classmethod
    def apply_replacements(cls, text: str, replacements: list[dict]) -> str:
        for r in replacements:
            text = text.replace(r['pattern'], r['replacement'])
        return text

    def find_and_apply_replacements(self, text: str) -> str:
        replacements = self.find_replacements(text)
        return self.apply_replacements(text, replacements)


VALIDATOR_TEMPLATE_SINGLETON = ValidatorTemplate()


class TemplatePair(BaseModel):
    contract: str = Field(...)
    reference_report: list[ReferenceReport] = Field(
        ...,
        serialization_alias="vulnerabilityReport",
        validation_alias=AliasChoices("vulnerability_report", "vulnerabilityReport"),
    )

    def normalize(self):
        self.contract = VALIDATOR_TEMPLATE_SINGLETON.find_and_apply_replacements(self.contract)


class FileContractProvider:
    _path: str
    _pairs: list[FilePair]

    def __init__(self, path_to_contract_folder: str) -> None:
        self._path = path_to_contract_folder
        self._pairs = self.find_pairs(self._path)

    @classmethod
    def find_pairs(cls, path_to_folder: str):
        base_files = {}

        for filename in os.listdir(path_to_folder):
            if filename.endswith(".json"):
                name = filename[:-5]
                base_files[name] = os.path.join(path_to_folder, name)

        return [FilePair(name, base_files[name]) for name in base_files.keys()]

    def read_files(self, pair: FilePair):
        with open(pair.as_contract(), "r") as contract_file:
            contract = contract_file.read()

        with open(pair.as_json(), "r") as json_file:
            report = json_file.read()

        json_list = json.loads(report)

        template = TemplatePair(
            contract=contract,
            vulnerability_report=[ReferenceReport(**data) for data in json_list],
        )
        template.normalize()

        return template

    def get_random_pair(self) -> TemplatePair:
        random_pair = random.choice(self._pairs)

        return self.read_files(random_pair)
    
    def get_reentrancy(self) -> TemplatePair:
        return self.read_files(next(pair for pair in self._pairs if 'wallet' in pair.base_path))
