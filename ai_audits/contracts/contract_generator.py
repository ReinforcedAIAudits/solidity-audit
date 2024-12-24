from enum import Enum
import json
from typing import Union, Mapping, List, Optional
from dataclasses import dataclass
from fastapi.encoders import jsonable_encoder
import solcx

from ai_audits.contracts.ast_models import (
    Assignment,
    BinaryOperation,
    ElementaryTypeName,
    EventDefinition,
    FunctionCall,
    FunctionDefinition,
    Identifier,
    IndexAccess,
    MemberAccess,
    NodeType,
    ParameterList,
    PragmaDirective,
    SourceUnit,
    StructDefinition,
    TupleExpression,
    UnaryOperation,
    UserDefinedTypeName,
    Mapping,
    Literal,
    VariableDeclaration,
    VariableDeclarationStatement,
)

FILE_NAME = "contract.example.sol"
CONTRACT_NAME = "GalacticHub"


def compile_contract_from_file(filename: str, contract_name: str):
    with open(filename) as f:
        code = f.read()

    suggested_version = solcx.install.select_pragma_version(
        code, solcx.get_installable_solc_versions()
    )
    json_compiled = solcx.compile_source(code, solc_version=suggested_version)

    return json_compiled[f"<stdin>:{contract_name}"]["ast"]


def parse_literal(node: Literal, spaces_count: int = 0) -> str:
    subdenomination = f" {node.subdenomination}" if node.subdenomination else ""
    if node.kind == "string":
        return f"{' ' * spaces_count}{repr(node.value)}{subdenomination}"
    return f"{' ' * spaces_count}{node.value}{subdenomination}"


def parse_index_access(node: IndexAccess, spaces_count: int = 0) -> str:
    return f"{' ' * spaces_count}{parse_expression(node.base_expression)}[{parse_expression(node.index_expression)}]"


def parse_member_access(node: MemberAccess, spaces_count: int = 0) -> str:
    return f"{' ' * spaces_count}{parse_expression(node.expression)}.{node.member_name}"


def parse_parameter_list(node: ParameterList, spaces_count: int = 0) -> str:
    parsed = []
    for parameter in node.parameters:
        storage_location = (
            f" {parameter.storage_location}"
            if parameter.storage_location != "default"
            else ""
        )
        var_type = parse_type_name(parameter.type_name)
        name = f" {parameter.name}" if parameter.name else ""
        if parameter.node_type == NodeType.VARIABLE_DECLARATION:
            indexed = " indexed" if parameter.indexed else ""
        parsed.append(f"{var_type}{indexed}{storage_location}{name}")
    return ", ".join(parsed)


def parse_unary_operation(node: UnaryOperation, spaces_count: int = 0) -> str:
    if node.prefix:
        return f"{' ' * spaces_count}{node.operator}{node.sub_expression.name}"
    else:
        return f"{' ' * spaces_count}{node.sub_expression.name}{node.operator}"


def parse_binary_operation(node: BinaryOperation, spaces_count: int = 0):
    return f"{' ' * spaces_count}{parse_expression(node.left_expression)} {node.operator} {parse_expression(node.right_expression)}"


def parse_function_call(node: FunctionCall, spaces_count: int = 0) -> str:
    arguments = [parse_expression(arg) for arg in node.arguments]

    if node.kind == "typeConversion":
        return f"{' ' * spaces_count}{parse_type_name(node.expression.type_name)}({', '.join(arguments)})"

    return f"{' ' * spaces_count}{parse_expression(node.expression)}({', '.join(arguments)})"


def parse_assignment(node: Assignment, spaces_count: int = 0) -> str:
    return f"{' ' * spaces_count}{parse_expression(node.left_hand_side)} {node.operator} {parse_expression(node.right_hand_side)}"


def parse_variable_declaration(node: VariableDeclaration, spaces_count: int = 0) -> str:
    storage_location = (
        f" {node.storage_location}" if node.storage_location != "default" else ""
    )
    visibility = f" {node.visibility}" if node.visibility != "internal" else ""
    value = ""
    if node.value:
        value = f" = {parse_expression(node.value)}"
    return f"{' ' * spaces_count}{parse_type_name(node.type_name)}{visibility}{storage_location} {node.name}{value}"


def parse_tuple_expression(node: TupleExpression, spaces_count: int = 0) -> str:
    res_tuple = [parse_expression(component) for component in node.components]

    return f"{' ' * spaces_count}({', '.join(res_tuple)})"


def parse_variable_declaration_statement(node: VariableDeclarationStatement, spaces_count: int = 0) -> str:
    left = parse_variable_declaration(node.declarations[0])
    right = parse_index_access(node.initial_value)
    return f"{' ' * (spaces_count)}{left} = {right}"

def parse_expression(
    node: Union[
        Assignment,
        UnaryOperation,
        Identifier,
        Literal,
        MemberAccess,
        IndexAccess,
        BinaryOperation,
        FunctionCall,
        TupleExpression,
        VariableDeclarationStatement,
    ],
    spaces_count: int = 0,
) -> str:
    match node.node_type:
        case NodeType.IDENTIFIER:
            return f"{' ' * spaces_count}{node.name}"
        case NodeType.LITERAL:
            return parse_literal(node, spaces_count)
        case NodeType.MEMBER_ACCESS:
            return parse_member_access(node, spaces_count)
        case NodeType.VARIABLE_DECLARATION:
            return parse_variable_declaration(node, spaces_count)
        case NodeType.VARIABLE_DECLARATION_STATEMENT:
            return parse_variable_declaration_statement(node, spaces_count)
        case NodeType.ASSIGNMENT:
            return parse_assignment(node, spaces_count)
        case NodeType.UNARY_OPERATION:
            return parse_unary_operation(node, spaces_count)
        case NodeType.FUNCTION_CALL:
            return parse_function_call(node, spaces_count)
        case NodeType.TUPLE_EXPRESSION:
            return parse_tuple_expression(node, spaces_count)
        case NodeType.INDEX_ACCESS:
            return parse_index_access(node, spaces_count)
        case NodeType.BINARY_OPERATION:
            return parse_binary_operation(node, spaces_count)


def build_function_header(node: FunctionDefinition, spaces_count: int = 0) -> str:
    name = node.name
    visibility = node.visibility
    mutability = (
        f" {node.state_mutability}" if node.state_mutability != "nonpayable" else ""
    )
    return_params = parse_parameter_list(node.return_parameters)

    if return_params:
        return_params = f" returns ({return_params})"

    if node.kind == "constructor":
        return f"{' ' * spaces_count}constructor({parse_parameter_list(node.parameters)}) {{\n"
    else:
        return f"{' ' * spaces_count}function {name}({parse_parameter_list(node.parameters)}) {visibility}{mutability}{return_params} {{\n"


def parse_function_definition(node: FunctionDefinition, spaces_count: int = 0) -> str:
    result = ""

    result += build_function_header(node, spaces_count)

    spaces_count += 4

    for statement in node.body.statements:
        if statement.node_type == NodeType.EXPRESSION_STATEMENT:
            result += (
                f"{' ' * (spaces_count)}{parse_expression(statement.expression)};\n"
            )

        elif statement.node_type == NodeType.EMIT_STATEMENT:
            result += f"{' ' * (spaces_count)}emit {parse_function_call(statement.event_call)};\n"

        elif statement.node_type == NodeType.VARIABLE_DECLARATION_STATEMENT:
            result += f"{parse_variable_declaration_statement(statement, spaces_count)};\n"

        elif statement.node_type == NodeType.RETURN:
            if statement.expression:
                result += f"{' ' * (spaces_count)}return {parse_expression(statement.expression)};\n"
            else:
                result += f"{' ' * (spaces_count)}return;\n"

    spaces_count -= 4
    result += f"{' ' * spaces_count}}}\n\n"
    return result


def parse_type_name(
    node: Union[Mapping, ElementaryTypeName, UserDefinedTypeName]
) -> str:
    match node.node_type:
        case NodeType.MAPPING:
            key_type = node.key_type.name
            value_type = parse_type_name(node.value_type)
            return f"mapping({key_type} => {value_type})"
        case NodeType.USER_DEFINED_TYPE_NAME:
            return node.path_node.name
        case _:
            if node.name == "address" and node.state_mutability == "payable":
                return node.state_mutability
            return node.name


def parse_struct_definition(node: StructDefinition, spaces_count: int = 0) -> str:
    spaces = " " * spaces_count
    code = f"{' ' * spaces_count}struct {node.name} {{\n"
    spaces_count += 4
    for member in node.members:
        code += f"{' ' * spaces_count}{parse_type_name(member.type_name)} {member.name};\n"
    spaces_count -= 4

    code += f"{' ' * spaces_count}}}\n"
    return code


def parse_event_definition(node: EventDefinition, spaces_count: int = 0) -> str:
    return f"{' ' * spaces_count}event {node.name}({parse_parameter_list(node.parameters)});\n"

def parse_pragma_directive(node: PragmaDirective, spaces_count: int = 0) -> str:
    pragma_str = "".join(node.literals[1:])
    return f"{' ' * spaces_count}pragma {node.literals[0]} {pragma_str};\n\n"


def parse_contract_definition(node: SourceUnit, spaces_count: int = 0) -> str:
    code = f"contract {node.name} {{\n"
    spaces_count = 4
    for contract_node in node.nodes:
        if contract_node.node_type == NodeType.STRUCT_DEFINITION:
            code += parse_struct_definition(contract_node, spaces_count)
        elif contract_node.node_type == NodeType.EVENT_DEFINITION:
            code += parse_event_definition(contract_node, spaces_count)
        elif contract_node.node_type == NodeType.VARIABLE_DECLARATION:
            code += (
                f"{parse_variable_declaration(contract_node, spaces_count)};\n"
            )
        elif contract_node.node_type == NodeType.FUNCTION_DEFINITION:
            code += parse_function_definition(contract_node, spaces_count)
    code += "}"

    return code


def parse_ast_to_solidity(ast: SourceUnit) -> str:
    code = ""
    spaces_count = 0

    for node in ast.nodes:
        if node.node_type == NodeType.PRAGMA_DIRECTIVE:
            code += parse_pragma_directive(node, spaces_count)
        
        elif node.node_type == NodeType.CONTRACT_DEFINITION:
            code += parse_contract_definition(node, spaces_count)

    return code


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

def apppend_node_to_contract(ast: SourceUnit, node: Union[FunctionDefinition, VariableDeclaration]):
    for contract_node in ast.nodes:
        if contract_node.node_type == NodeType.CONTRACT_DEFINITION:
            contract_node.nodes.append(node)
    
    return ast

def main():
    solcx.install_solc()

    ast = compile_contract_from_file(FILE_NAME, CONTRACT_NAME)

    with open("contract_ast.json", "w+") as f:
        f.write(json.dumps(ast, indent=2))

    ast_obj_contract = SourceUnit(**ast)
    contract_source = parse_ast_to_solidity(ast_obj_contract)

    with open("restored.example.sol", "w+") as f:
        f.write(contract_source)

    ast_obj_reentrancy = SourceUnit(
        **compile_contract_from_file("reentrancy.example.sol", "Reentrancy")
    )

    with open("reentrancy_ast.json", "w+") as f:
        f.write(json.dumps(jsonable_encoder(ast_obj_reentrancy), indent=2))

    contract_source = parse_ast_to_solidity(ast_obj_reentrancy)


    variables_of_source = get_contract_variables(ast_obj_contract)
    functions_of_source = get_contract_functions(ast_obj_reentrancy)

    variables_of_reentrancy = get_contract_variables(ast_obj_reentrancy)
    functions_of_reentrancy = get_contract_functions(ast_obj_reentrancy)

    for variable in variables_of_reentrancy:
        if variable.name not in [var.name for var in variables_of_source]:
            ast_obj_contract = apppend_node_to_contract(ast_obj_contract, variable)

    for function in functions_of_reentrancy:
        if function.kind == "constructor":
            source_constructor = next(func for func in functions_of_source if func.kind == "constructor")
            if source_constructor:
                source_constructor.body.statements += function.body.statements
            else:
                ast_obj_contract = apppend_node_to_contract(ast_obj_contract, function)
            continue
        if function in functions_of_source:
            function.name = f"Test{function.name}" ## TODO - add a check for name uniqueness
        ast_obj_contract = apppend_node_to_contract(ast_obj_contract, function)

    contract_source = parse_ast_to_solidity(ast_obj_contract)

    suggested_version = solcx.install.select_pragma_version(
        contract_source, solcx.get_installable_solc_versions()
    )
    solcx.compile_source(contract_source, solc_version=suggested_version)

    with open("contract_with_vulnerability.sol", "w+") as f:
        f.write(contract_source)


if __name__ == "__main__":
    main()
