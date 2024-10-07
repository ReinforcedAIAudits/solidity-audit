import json
import os
import random
import time

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, ValidationError
from .protocol import VulnerabilityReport


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


class TemplatePair(BaseModel):
    contract: str = Field(...)
    vulnerability_report: list[VulnerabilityReport] = Field(
        ...,
        serialization_alias="vulnerabilityReport",
        validation_alias=AliasChoices("vulnerability_report", "vulnerabilityReport"),
    )

    def normalize(self):
        self.contract = self.contract.replace("<|timsestamp|>", f"{int(time.time())}")


class FileContractProvdier:
    _path: str
    _pairs: list[FilePair]

    def __init__(self, path_to_contract_folder: str) -> None:
        self._path = path_to_contract_folder
        self._pairs = FileContractProvdier.find_pairs(self._path)

    def find_pairs(path_to_folder: str):
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
            vulnerability_report=[VulnerabilityReport(**data) for data in json_list],
        )
        template.normalize()

        return template

    def get_random_pair(self) -> TemplatePair:
        random_pair = random.choice(self._pairs)

        return self.read_files(random_pair)
