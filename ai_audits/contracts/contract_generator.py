import json
from typing import Tuple, Union, List, Optional

from openai import BaseModel
from solc_ast_parser import parse_ast_to_solidity
from solc_ast_parser.models.ast_models import (
    SourceUnit,
    VariableDeclaration,
    FunctionDefinition,
)
from solc_ast_parser.ast_parser import build_function_header, parse_variable_declaration
from solc_ast_parser.models.base_ast_models import NodeType
from solc_ast_parser.models import ast_models
from solc_ast_parser.utils import create_ast_from_source, create_ast_with_standart_input
import solcx
from solc_ast_parser.enrichment import restore_function_definitions, restore_storages
from solc_ast_parser.comments import insert_comments_into_ast

from ai_audits.contracts.contract_utils import get_contract_nodes
from ai_audits.protocol import ValidatorTask, VulnerabilityReport, TaskType


def get_contract_nodes_from_source(source: str, node_type: NodeType) -> List[ast_models.ASTNode]:
    ast = create_ast_from_source(source)
    return get_contract_nodes(ast, node_type)


def change_function_in_contract(ast: SourceUnit, new_function: FunctionDefinition):
    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for idx, contract_node in enumerate(node.nodes):
                if contract_node.node_type == NodeType.FUNCTION_DEFINITION:
                    if contract_node.kind == new_function.kind and contract_node.name == new_function.name:
                        node.nodes[idx] = new_function
                        return ast
    raise ValueError("Function not found in contract")


def check_node_in_contract(ast: SourceUnit, node_type: NodeType, **kwargs):
    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for contract_node in node.nodes:
                if contract_node.node_type == node_type:
                    for key, value in kwargs.items():
                        if getattr(contract_node, key) == value:
                            return True
    return False


def append_node_to_contract(ast: SourceUnit, node: Union[FunctionDefinition, VariableDeclaration]):
    for ast_node in ast.nodes:
        if ast_node.node_type == NodeType.CONTRACT_DEFINITION:
            if node.node_type == NodeType.FUNCTION_DEFINITION:
                if node.kind == "constructor":
                    source_constructor = next(func for func in ast_node.nodes if func.kind == "constructor")
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


def find_function_in_contract(contract_ast: SourceUnit, function_name: str) -> Optional[FunctionDefinition]:
    for node in contract_ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for contract_node in node.nodes:
                if contract_node.node_type == NodeType.FUNCTION_DEFINITION:
                    if contract_node.name == function_name:
                        return contract_node
    return None


def find_function_boundaries(
    contract_ast: SourceUnit,
    contract_code: str,
    function_names: List[str],
) -> tuple[int, int]:
    for function_name in function_names:
        total_length = int(find_function_in_contract(contract_ast, function_name).src.split(":")[1])
        lines = contract_code.split("\n")
        for i, line in enumerate(lines, 1):
            if "function" in line and function_name in line:
                curr_length = 0
                for j in range(i - 1, len(lines)):
                    curr_length += len(lines[j])
                    if curr_length >= total_length:
                        return (i, j + 1)

                raise ValueError(
                    f"Something went wrong with length calculation: lines: {lines}, total_length: {total_length}, curr_length: {curr_length}"
                )

        raise ValueError(f"Function {function_name} not found or length mismatch.")


def create_contract(pseudocode: str) -> str:
    return f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.28;\ncontract PseudoContract {{\n\n{pseudocode}\n}}"


def insert_vulnerability_to_contract(
    contract_ast: SourceUnit,
    vulnerability_ast: SourceUnit,
) -> str:
    vuln_nodes = get_contract_nodes(vulnerability_ast)
    for node in vuln_nodes:
        if (
            node.node_type == NodeType.FUNCTION_DEFINITION
            and node.kind == "constructor"
            or node.node_type in (NodeType.COMMENT, NodeType.MULTILINE_COMMENT)
        ):
            continue
        elif node.node_type == NodeType.FUNCTION_DEFINITION and check_node_in_contract(
            contract_ast, NodeType.FUNCTION_DEFINITION, name=node.name
        ):
            change_function_in_contract(contract_ast, node)
        elif not check_node_in_contract(contract_ast, node.node_type, name=node.name):
            contract_ast = append_node_to_contract(contract_ast, node)

    return parse_ast_to_solidity(contract_ast)


class Vulnerability(BaseModel):
    vulnerabilityClass: str
    code: str


def prepare_vulnerability(vulnerability_source: str) -> Tuple[List[str], List[str]]:
    ast_obj_vulnerability = restore_storages(create_ast_with_standart_input(vulnerability_source))

    return [
        parse_variable_declaration(node)
        for node in get_contract_nodes(ast_obj_vulnerability, node_type=NodeType.VARIABLE_DECLARATION)
    ], [build_function_header(function) for function in restore_function_definitions(ast_obj_vulnerability)]


def create_task(
    contract_source: str,
    raw_vulnerability: Vulnerability,
) -> ValidatorTask:
    ast_obj_contract = create_ast_from_source(contract_source)

    vulnerability_contract = create_contract(raw_vulnerability.code)
    ast_obj_vulnerability = create_ast_with_standart_input(vulnerability_contract)

    ast_contract_with_vul = insert_comments_into_ast(vulnerability_contract, ast_obj_vulnerability)

    contract_source = insert_vulnerability_to_contract(ast_obj_contract, ast_obj_vulnerability)

    ast_contract_with_vul = create_ast_from_source(contract_source)

    from_line, to_line = find_function_boundaries(
        ast_contract_with_vul,
        contract_source,
        [node.name for node in get_contract_nodes(ast_obj_vulnerability, NodeType.FUNCTION_DEFINITION)],
    )

    vulnerability_report = VulnerabilityReport(
        from_line=from_line,
        to_line=to_line,
        vulnerability_class=raw_vulnerability.vulnerabilityClass,
    )

    return ValidatorTask(
        contract_code=contract_source,
        from_line=vulnerability_report.from_line,
        to_line=vulnerability_report.to_line,
        vulnerability_class=vulnerability_report.vulnerability_class,
        taskType=TaskType.HYBRID,
    )
