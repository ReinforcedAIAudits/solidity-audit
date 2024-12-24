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
    SourceUnit,
    StructDefinition,
    TupleExpression,
    UnaryOperation,
    UserDefinedTypeName,
    Mapping,
    Literal,
    VariableDeclaration,
)

FILE_NAME = "contract.example.sol"
CONTRACT_NAME = "GalacticHub"


def filter_dict(data, allowed_keys):
    if isinstance(data, dict):
        return {
            key: filter_dict(value, allowed_keys)
            for key, value in data.items()
            if key in allowed_keys
        }
    elif isinstance(data, list):
        return [filter_dict(item, allowed_keys) for item in data]
    else:
        return data


def compile_contract_from_file(filename: str, contract_name: str):
    with open(filename) as f:
        code = f.read()

    suggested_version = solcx.install.select_pragma_version(
        code, solcx.get_installable_solc_versions()
    )
    json_compiled = solcx.compile_source(code, solc_version=suggested_version)

    return json_compiled[f"<stdin>:{contract_name}"]["ast"]


def parse_default_member(
    node: Union[
        Identifier,
        Literal,
        UnaryOperation,
        BinaryOperation,
        MemberAccess,
        IndexAccess,
    ],
    spaces_count: int = 0,
):
    match node.node_type:
        case NodeType.IDENTIFIER:
            return f"{' ' * spaces_count}{node.name}"
        case NodeType.LITERAL:
            return f"{' ' * spaces_count}{node.value}"
        case NodeType.UNARY_OPERATION:
            return f"{' ' * spaces_count}{node.operator}{node.sub_expression.name}"
        case NodeType.BINARY_OPERATION:
            return f"{' ' * spaces_count}{node.left_expression.name} {node.operator} {node.right_expression.name}"
        case NodeType.MEMBER_ACCESS:
            return f"{' ' * spaces_count}{node.expression.name}.{node.member_name}"
        case NodeType.INDEX_ACCESS:
            return f"{' ' * spaces_count}{node.base_expression.name}[{node.index_expression.name}]"


def parse_index_access(node: IndexAccess) -> str:
    match node.base_expression.node_type:
        case NodeType.IDENTIFIER:
            base_expression = node.base_expression.name
        case NodeType.INDEX_ACCESS:
            base_expression = parse_index_access(node.base_expression)
        case NodeType.MEMBER_ACCESS:
            base_expression = parse_member_access(node.base_expression)
    return f"{base_expression}[{parse_member_access(node.index_expression) if node.index_expression.node_type == NodeType.MEMBER_ACCESS else node.index_expression.name}]"


def parse_member_access(node: MemberAccess) -> str:
    if node.expression.node_type == NodeType.IDENTIFIER:
        base_expression = node.expression.name
    elif node.expression.node_type == NodeType.INDEX_ACCESS:
        base_expression = parse_index_access(node.expression)
    elif node.expression.node_type == NodeType.FUNCTION_CALL:
        base_expression = parse_function_call(node.expression)

    return f"{base_expression}.{node.member_name}"


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
        return f"{' ' * spaces_count}{node.operator}{node.sub_expression.name};\n"
    else:
        return f"{' ' * spaces_count}{node.sub_expression.name}{node.operator};\n"


def parse_binary_operation(node: BinaryOperation, spaces_count: int = 0):
    left = ""
    right = ""

    match node.left_expression.node_type:
        case NodeType.BINARY_OPERATION:
            left = parse_binary_operation(node.left_expression)
        case NodeType.IDENTIFIER:
            left = node.left_expression.name
        case NodeType.LITERAL:
            left = node.left_expression.value
        case NodeType.MEMBER_ACCESS:
            left = parse_member_access(node.left_expression)
        case NodeType.INDEX_ACCESS:
            left = parse_index_access(node.left_expression)
        case NodeType.FUNCTION_CALL:
            left = parse_function_call(node.left_expression)
        case NodeType.TUPLE_EXPRESSION:
            left = parse_tuple_expression(node.left_expression)

    match node.right_expression.node_type:
        case NodeType.BINARY_OPERATION:
            right = parse_binary_operation(node.right_expression)
        case NodeType.IDENTIFIER:
            right = node.right_expression.name
        case NodeType.LITERAL:
            right = node.right_expression.value
        case NodeType.MEMBER_ACCESS:
            right = parse_member_access(node.right_expression)
        case NodeType.INDEX_ACCESS:
            right = parse_index_access(node.right_expression)
        case NodeType.FUNCTION_CALL:
            right = parse_function_call(node.right_expression)
        case NodeType.TUPLE_EXPRESSION:
            right = parse_tuple_expression(node.right_expression)

    return f"{' ' * spaces_count}{left} {node.operator} {right}"


def parse_function_call(node: FunctionCall, spaces_count: int = 0) -> str:
    arguments = []
    for arg in node.arguments:
        if arg.node_type == NodeType.IDENTIFIER:
            arguments.append(arg.name)

        elif arg.node_type == NodeType.LITERAL:
            if arg.kind == "string":
                arguments.append(repr(arg.value))
                continue
            arguments.append(arg.value)

        elif arg.node_type == NodeType.BINARY_OPERATION:
            arguments.append(parse_binary_operation(arg))

        elif arg.node_type == NodeType.INDEX_ACCESS:
            arguments.append(parse_index_access(arg))
        elif arg.node_type == NodeType.MEMBER_ACCESS:
            arguments.append(parse_member_access(arg))
        elif arg.node_type == NodeType.UNARY_OPERATION:
            arguments.append(parse_unary_operation(arg))

        match node.expression.node_type:
            case NodeType.IDENTIFIER:
                expression = node.expression.name
            case NodeType.ELEMENTARY_TYPE_NAME_EXPRESSION:
                expression = parse_type_name(node.expression.type_name)
            case NodeType.MEMBER_ACCESS:
                expression = parse_member_access(node.expression)
            case NodeType.INDEX_ACCESS:
                expression = parse_index_access(node.expression)

    if node.kind == "typeConversion":
        return f"{' ' * spaces_count}{parse_type_name(node.expression.type_name)}({', '.join(arguments)})"

    return f"{' ' * spaces_count}{expression}({', '.join(arguments)})"


def parse_assignment(node: Assignment, spaces_count: int = 0) -> str:
    left = ""
    if node.left_hand_side.node_type == NodeType.INDEX_ACCESS:
        left = parse_index_access(node.left_hand_side)
    elif node.left_hand_side.node_type == NodeType.MEMBER_ACCESS:
        left = parse_member_access(node.left_hand_side)
    else:
        left = node.left_hand_side.name

    match node.right_hand_side.node_type:
        case NodeType.INDEX_ACCESS:
            right = parse_index_access(node.right_hand_side)
        case NodeType.MEMBER_ACCESS:
            right = parse_member_access(node.right_hand_side)
        case NodeType.FUNCTION_CALL:
            right = parse_function_call(node.right_hand_side)
        case NodeType.BINARY_OPERATION:
            right = parse_binary_operation(node.right_hand_side)
        case NodeType.IDENTIFIER:
            right = node.right_hand_side.name
        case NodeType.LITERAL:
            right = node.right_hand_side.value
    op = node.operator
    return f"{' ' * spaces_count}{left} {op} {right};\n"


def parse_variable_declaration(node: VariableDeclaration, spaces_count: int = 0) -> str:
    storage_location = (
        f" {node.storage_location}" if node.storage_location != "default" else ""
    )
    visibility = f" {node.visibility}" if node.visibility != "internal" else ""
    if node.value:
        match node.value.node_type:
            case NodeType.IDENTIFIER:
                value = node.value.name
            case NodeType.LITERAL:
                value = (
                    repr(node.value.value)
                    if node.value.kind == "string"
                    else node.value.value
                )
            case NodeType.INDEX_ACCESS:
                value = parse_index_access(node.value)
            case NodeType.MEMBER_ACCESS:
                value = parse_member_access(node.value)
            case NodeType.FUNCTION_CALL:
                value = parse_function_call(node.value)
            case NodeType.BINARY_OPERATION:
                value = parse_binary_operation(node.value)
            case NodeType.UNARY_OPERATION:
                value = parse_unary_operation(node.value)
        return f"{' ' * spaces_count}{parse_type_name(node.type_name)}{visibility}{storage_location} {node.name} = {value}"
    return f"{' ' * spaces_count}{parse_type_name(node.type_name)}{visibility}{storage_location} {node.name}"


def parse_tuple_expression(node: TupleExpression, spaces_count: int = 0) -> str:
    res_tuple = []
    for component in node.components:
        match component.node_type:
            case NodeType.INDEX_ACCESS:
                res_tuple.append(parse_index_access(component))
            case NodeType.MEMBER_ACCESS:
                res_tuple.append(parse_member_access(component))
            case NodeType.IDENTIFIER:
                res_tuple.append(component.name)
            case NodeType.LITERAL:
                if component.kind == "string":
                    res_tuple.append(repr(component.value))
                    continue
                res_tuple.append(component.value)

            case NodeType.BINARY_OPERATION:
                res_tuple.append(parse_binary_operation(component))

    return f"({', '.join(res_tuple)})"


def parse_function_definition(node: FunctionDefinition, spaces_count: int = 0) -> str:
    result = ""
    name = node.name
    visibility = node.visibility

    mutability = (
        f" {node.state_mutability}" if node.state_mutability != "nonpayable" else ""
    )
    return_params = parse_parameter_list(node.return_parameters)

    if node.kind == "constructor":
        function_header = f"\n{' ' * spaces_count}constructor({parse_parameter_list(node.parameters)})"
    else:
        function_header = f"\n{' ' * spaces_count}function {name}({parse_parameter_list(node.parameters)})"

        if mutability:
            function_header += f" {visibility}{mutability}"
        else:
            function_header += f" {visibility}"

        if return_params:
            function_header += f" returns ({return_params})"

    result += function_header + " {\n"
    for statement in node.body.statements:
        if statement.node_type == NodeType.EXPRESSION_STATEMENT:
            expr = statement.expression

            if expr.node_type == NodeType.ASSIGNMENT:
                result += parse_assignment(expr, spaces_count + 4)

            elif expr.node_type == NodeType.UNARY_OPERATION:
                result += parse_unary_operation(expr, spaces_count + 4)

            elif expr.node_type == NodeType.FUNCTION_CALL:
                result += f"{parse_function_call(expr, spaces_count + 4)};\n"

        elif statement.node_type == NodeType.EMIT_STATEMENT:
            result += f"{' ' * (spaces_count + 4)}emit {parse_function_call(statement.event_call)};\n"

        elif statement.node_type == NodeType.VARIABLE_DECLARATION_STATEMENT:
            left = parse_variable_declaration(statement.declarations[0])
            right = parse_index_access(statement.initial_value)
            result += f"{' ' * (spaces_count + 4)}{left} = {right};\n"

        elif statement.node_type == NodeType.RETURN:

            if statement.expression.node_type == NodeType.LITERAL:
                return_value = getattr(statement.expression, "value", "")

            elif statement.expression.node_type == NodeType.INDEX_ACCESS:
                return_value = f"{statement.expression.base_expression.name}[{statement.expression.index_expression.expression.name}.{statement.expression.index_expression.member_name}]"
            elif statement.expression.node_type == NodeType.TUPLE_EXPRESSION:
                return_value = parse_tuple_expression(statement.expression)
            else:
                return_value = getattr(statement.expression, "name", "")
            result += f"{' ' * (spaces_count + 4)}return {return_value};\n"
    result += f"{' ' * spaces_count}}}\n"
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
            if node.state_mutability and node.state_mutability != "nonpayable":
                return node.state_mutability
            return node.name


def parse_struct_definition(node: StructDefinition, spaces_count: int = 0) -> str:
    spaces = " " * spaces_count
    code = f"{spaces}struct {node.name} {{\n"

    for member in node.members:
        code += f"{spaces}    {parse_type_name(member.type_name)} {member.name};\n"

    code += f"{spaces}}}\n"
    return code


def parse_event_definition(node: EventDefinition, spaces_count: int = 0) -> str:
    return f"{' ' * spaces_count}event {node.name}({parse_parameter_list(node.parameters)});\n"


def parse_ast_to_solidity(ast: SourceUnit) -> str:
    code = ""
    spaces_count = 0

    for node in ast.nodes:
        if node.node_type == NodeType.PRAGMA_DIRECTIVE:

            pragma_str = "".join(node.literals[1:])
            code += f"pragma {node.literals[0]} {pragma_str};\n\n"

        elif node.node_type == NodeType.CONTRACT_DEFINITION:
            code += f"contract {node.name} {{\n"
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


def add_offset(parameter: str, offset: int):
    parts = [int(x) for x in parameter.split(":")]
    parts[0] += offset
    return ":".join(map(str, parts))


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

    contract_source = parse_ast_to_solidity(ast_obj_reentrancy)

    node_index = -1
    offset = 1

    for contract_source in ast_obj_reentrancy.nodes:
        if contract_source.node_type != NodeType.PRAGMA_DIRECTIVE:

            for idx, node in enumerate(contract_source.nodes):
                if (
                    node.node_type == NodeType.FUNCTION_DEFINITION
                    and node.kind != "constructor"
                ):
                    print("Node found!")
                    node_index = idx
                    break

            offset += int(contract_source.nodes[node_index].src.split(":")[0])

    node = next(
        n for n in ast_obj_reentrancy.nodes[1].nodes if n.name == "balanceChange"
    )

    node.src = add_offset(node.src, offset)
    node.body.src = add_offset(node.body.src, offset)
    node.parameters.src = add_offset(node.parameters.src, offset)
    node.return_parameters.src = add_offset(node.return_parameters.src, offset)
    node.name_location = add_offset(node.name_location, offset)
    node.body.statements[0].expression.left_hand_side.src = add_offset(
        node.body.statements[0].expression.left_hand_side.src, offset
    )
    node.body.statements[0].expression.left_hand_side.base_expression.src = add_offset(
        node.body.statements[0].expression.left_hand_side.base_expression.src, offset
    )

    node.body.statements[0].expression.left_hand_side.index_expression.src = add_offset(
        node.body.statements[0].expression.left_hand_side.index_expression.src,
        offset,
    )

    node.body.statements[
        0
    ].expression.left_hand_side.index_expression.expression.src = add_offset(
        node.body.statements[
            0
        ].expression.left_hand_side.index_expression.expression.src,
        offset,
    )

    node.body.statements[0].expression.right_hand_side.src = add_offset(
        node.body.statements[0].expression.right_hand_side.src, offset
    )

    node.body.statements[0].expression.src = add_offset(
        node.body.statements[0].expression.src, offset
    )

    node.body.statements[0].src = add_offset(node.body.statements[0].src, offset)

    ast_obj_contract.nodes[1].nodes.append(node)

    contract_source = parse_ast_to_solidity(ast_obj_contract)

    suggested_version = solcx.install.select_pragma_version(
        contract_source, solcx.get_installable_solc_versions()
    )
    solcx.compile_source(contract_source, solc_version=suggested_version)

    with open("contract_with_vulnerability.sol", "w+") as f:
        f.write(contract_source)


if __name__ == "__main__":
    main()
