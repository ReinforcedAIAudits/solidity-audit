from enum import Enum
import json
import os
import random
from typing import Tuple, Union, Mapping, List, Optional
from dataclasses import dataclass

from pydantic import ValidationError
import regex
from solc_ast_parser import parse_ast_to_solidity
from solc_ast_parser.models.ast_models import (
    SourceUnit,
    VariableDeclaration,
    FunctionDefinition,
    Identifier,
    Block,
    ExpressionStatement,
    Assignment,
    BinaryOperation,
    UnaryOperation,
    FunctionCall,
    MemberAccess,
    IndexAccess,
    TupleExpression,
    VariableDeclarationStatement,
    Return,
)
from solc_ast_parser.models.base_ast_models import NodeType
import solcx

from ai_audits.protocol import ValidatorTask, VulnerabilityReport

FILE_NAME = "contract.example.sol"


def compile_contract_from_source(source: str):
    suggested_version = solcx.install.select_pragma_version(
        source, solcx.get_installable_solc_versions()
    )
    json_compiled = solcx.compile_source(source, solc_version=suggested_version)
    with open("compiled.json", "w+") as f:
        f.write(json.dumps(json_compiled, indent=2))
    return json_compiled[list(json_compiled.keys())[0]]["ast"]


def get_contract_variables(ast: SourceUnit) -> List[VariableDeclaration]:
    variables = []

    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for contract_node in node.nodes:
                if contract_node.node_type == NodeType.VARIABLE_DECLARATION:
                    variables.append(contract_node)

    return variables


def get_contract_functions(ast: SourceUnit) -> List[FunctionDefinition]:
    functions = []

    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for contract_node in node.nodes:
                if contract_node.node_type == NodeType.FUNCTION_DEFINITION:
                    functions.append(contract_node)

    return functions

def change_function_in_contract(ast: SourceUnit, new_function: FunctionDefinition):
    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for idx, contract_node in enumerate(node.nodes):
                if contract_node.node_type == NodeType.FUNCTION_DEFINITION:
                    if (
                        contract_node.kind == new_function.kind
                        and contract_node.name == new_function.name
                    ):
                        node.nodes[idx] = new_function
                        return ast
    raise ValueError("Function not found in contract")


def check_function_in_contract(ast: SourceUnit, function_name: str):
    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for contract_node in node.nodes:
                if contract_node.node_type == NodeType.FUNCTION_DEFINITION:
                    if contract_node.name == function_name:
                        return True
    return False


def check_storage_in_contract(ast: SourceUnit, storage_name: str):
    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for contract_node in node.nodes:
                if contract_node.node_type == NodeType.VARIABLE_DECLARATION:
                    if contract_node.name == storage_name:
                        return True
    return False


def append_node_to_contract(
    ast: SourceUnit, node: Union[FunctionDefinition, VariableDeclaration]
):
    for ast_node in ast.nodes:
        if ast_node.node_type == NodeType.CONTRACT_DEFINITION:
            if node.node_type == NodeType.FUNCTION_DEFINITION:
                if node.kind == "constructor":
                    source_constructor = next(
                        func for func in ast_node.nodes if func.kind == "constructor"
                    )
                    if source_constructor:
                        source_constructor.body.statements += node.body.statements
                        continue

            else:
                last_var_declaration = next(
                    (
                        idx
                        for idx, contract_node in enumerate(reversed(ast_node.nodes))
                        if contract_node.node_type == NodeType.VARIABLE_DECLARATION
                    ),
                    None,
                )
                if last_var_declaration:
                    ast_node.nodes.insert(last_var_declaration, node)
                    continue

            ast_node.nodes.append(node)

    return ast


def find_function_in_contract(
    contract_ast: SourceUnit, function_name: str
) -> Optional[FunctionDefinition]:
    for node in contract_ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for contract_node in node.nodes:
                if contract_node.node_type == NodeType.FUNCTION_DEFINITION:
                    if contract_node.name == function_name:
                        return contract_node
    return None


def find_function_name_in_source(
    contract_source: str, from_line: int, to_line: int
) -> str:
    for idx, text in enumerate(contract_source.split("\n"), 1):
        if idx >= from_line and idx <= to_line:
            if "function" in text:
                return regex.findall(r"function\s+(\w+)\s*\(", text)[0]
    return None


def find_function_boundaries(
    vulnerability_code: str,
    contract_ast: SourceUnit,
    contract_code: str,
    from_line: int,
    to_line: int,
) -> tuple[int, int]:
    function_name = find_function_name_in_source(vulnerability_code, from_line, to_line)
    total_length = int(
        find_function_in_contract(contract_ast, function_name).src.split(":")[1]
    )
    lines = contract_code.split("\n")
    for i, line in enumerate(lines, 1):
        if function_name in line and "function" in line:
            curr_length = 0
            for j in range(i - 1, len(lines)):
                curr_length += len(lines[j])
                if curr_length >= total_length:
                    return (i, j + 1)

    raise ValueError(f"Function {function_name} not found or length mismatch")


def get_vulnerability_bounds(
    vulnerability_report: VulnerabilityReport,
    contract_ast: SourceUnit,
    contract_source: str,
    vulnerability_source: str,
) -> Tuple[int, int]:

    return find_function_boundaries(
        vulnerability_source,
        contract_ast,
        contract_source,
        vulnerability_report.from_line,
        vulnerability_report.to_line,
    )


def rename_function_in_pseudo_contract(pseudocode: str) -> str:
    vuln_regex = regex.compile(r"function\s+vulnerability_(\w+)\s*\(")
    return regex.sub(
        vuln_regex, f"function {regex.findall(vuln_regex, pseudocode)[0]}(", pseudocode
    )


def create_contract(pseudocode: str, vulnerability_report: VulnerabilityReport) -> str:
    contract = f"contract PseudoContract {{\n\n{pseudocode}\n}}"
    contract = rename_function_in_pseudo_contract(contract)
    vulnerability_report.from_line += 2
    vulnerability_report.to_line += 2
    return contract


def create_task(
    contract_source: str,
    pseudo_vulnerability: str,
    vulnerability_report: VulnerabilityReport,
) -> ValidatorTask:
    ast = compile_contract_from_source(contract_source)
    try:
        ast_obj_contract = SourceUnit(**ast)
    except ValidationError as e:
        with open("contract.errors.txt", "w+") as f:
            f.write(str(e))
        raise e

    vulnerability_contract = create_contract(pseudo_vulnerability, vulnerability_report)
    ast_vulnerability = compile_contract_from_source(vulnerability_contract)

    try:
        ast_obj_vulnerability = SourceUnit(**ast_vulnerability)
    except ValidationError as e:
        with open("vulnerability.errors.txt", "w+") as f:
            f.write(str(e))
        raise e

    for variable in get_contract_variables(ast_obj_vulnerability):
        if not check_storage_in_contract(ast_obj_contract, variable.name):
            ast_obj_contract = append_node_to_contract(ast_obj_contract, variable)

    for function in get_contract_functions(ast_obj_vulnerability):
        if check_function_in_contract(ast_obj_contract, function.name):
            change_function_in_contract(ast_obj_contract, function)
        else:
            ast_obj_contract = append_node_to_contract(ast_obj_contract, function)

    contract_source = parse_ast_to_solidity(ast_obj_contract)

    suggested_version = solcx.install.select_pragma_version(
        contract_source, solcx.get_installable_solc_versions()
    )
    ast = solcx.compile_source(contract_source, solc_version=suggested_version)

    vulnerability_report.from_line, vulnerability_report.to_line = (
        get_vulnerability_bounds(
            vulnerability_report,
            ast_obj_contract,
            contract_source,
            vulnerability_contract,
        )
    )

    return ValidatorTask(
        contract_code=contract_source,
        from_line=vulnerability_report.from_line,
        to_line=vulnerability_report.to_line,
        vulnerability_class=vulnerability_report.vulnerability_class,
    )