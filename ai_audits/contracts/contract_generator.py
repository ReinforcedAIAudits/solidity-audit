import json
from typing import Union
from fastapi.encoders import jsonable_encoder
import solcx

from ai_audits.contracts.ast_models import (
    BinaryOperation,
    ElementaryTypeName,
    EventDefinition,
    FunctionDefinition,
    IndexAccess,
    MemberAccess,
    NodeType,
    ParameterList,
    SourceUnit,
    StructDefinition,
    UnaryOperation,
    UserDefinedTypeName,
    Mapping,
    VariableDeclaration,
)

FILE_NAME = "contract.example.sol"
CONTRACT_NAME = "TaskManager"


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


def parse_index_access(node: IndexAccess) -> str:
    return f"{node.base_expression.name}[{parse_member_access(node.index_expression) if node.index_expression.node_type == NodeType.MEMBER_ACCESS else node.index_expression.name}]"


def parse_member_access(node: MemberAccess) -> str:
    if node.expression.node_type == NodeType.IDENTIFIER:
        base_expression = node.expression.name
    elif node.expression.node_type == NodeType.INDEX_ACCESS:
        base_expression = parse_index_access(node.expression)

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
        name = parameter.name
        parsed.append(f"{var_type}{storage_location} {name}")
    return {", ".join(parsed)}


def parse_unary_operation(node: UnaryOperation, spaces_count: int = 0) -> str:
    if node.prefix:
        return f"{' ' * spaces_count}{node.operator}{node.sub_expression.name}"
    else:
        return f"{' ' * spaces_count}{node.sub_expression.name}{node.operator}"


def parse_binary_operation(node: BinaryOperation, spaces_count: int = 0):
    if node.left_expression.node_type == NodeType.IDENTIFIER:
        pass


def parse_variable_declaration(node: VariableDeclaration, spaces_count: int = 0) -> str:
    return f"{' ' * spaces_count}{parse_type_name(node.type_name)} {node.visibility} {node.name}"


def parse_function_definition(node: FunctionDefinition, spaces_count: int = 0) -> str:
    result = ""
    name = node.name
    visibility = node.visibility

    mutability = (
        f" {node.state_mutability}" if node.state_mutability != "nonpayable" else ""
    )
    return_params = parse_parameter_list(node.return_parameters)

    function_header = f"\n{' ' * spaces_count}function {name}({parse_parameter_list(node.parameters)})"

    if mutability:
        function_header += f" {visibility} {mutability}"
    else:
        function_header += f" {visibility}"

    if return_params:
        function_header += f" returns ({return_params})"

    result += function_header + " {\n"
    for statement in node.body.statements:
        if statement.node_type == NodeType.EXPRESSION_STATEMENT:
            expr = statement.expression
            if expr.node_type == NodeType.ASSIGNMENT:
                left = ""
                if expr.left_hand_side.node_type == NodeType.INDEX_ACCESS:
                    left = parse_index_access(expr.left_hand_side)
                elif expr.left_hand_side.node_type == NodeType.MEMBER_ACCESS:
                    left = parse_member_access(expr.left_hand_side)
                else:
                    left = expr.left_hand_side.name
                if hasattr(expr.right_hand_side, "name"):
                    right = expr.right_hand_side.name
                else:
                    right = "msg.value"
                op = expr.operator
                result += f"{' ' * spaces_count + 2}{left} {op} {right};\n"
        elif statement.node_type == NodeType.RETURN:
            if statement.expression.node_type == NodeType.LITERAL:
                return_value = getattr(statement.expression, "value", "")
            elif statement.expression.node_type == NodeType.INDEX_ACCESS:
                return_value = f"{statement.expression.base_expression.name}[{statement.expression.index_expression.expression.name}.{statement.expression.index_expression.member_name}]"
            else:
                return_value = getattr(statement.expression, "name", "")
            result += f"{' ' * spaces_count + 2}return {return_value};\n"
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
            return node.name


def parse_struct_definition(node: StructDefinition, spaces_count: int = 0) -> str:
    spaces = " " * spaces_count
    code = f"{spaces}struct {node.name} {{\n"

    for member in node.members:
        code += f"{spaces}    {parse_type_name(member.type_name)} {member.name};\n"

    code += f"{spaces}}}\n"
    return code


def parse_event_definition(node: EventDefinition, spaces_count: int = 0) -> str:
    return f"{' ' * spaces_count}event {node.name}({', '.join([parse_variable_declaration(parameter) for parameter in node.parameters.parameters])});\n"


def parse_ast_to_solidity(ast: SourceUnit) -> str:
    code = ""
    spaces_count = 0

    for node in ast.nodes:
        if node.node_type == NodeType.PRAGMA_DIRECTIVE:
            pragma_str = " ".join(node.literals)
            code += f"pragma {pragma_str};\n\n"

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
                elif (
                    contract_node.node_type == NodeType.FUNCTION_DEFINITION
                    and contract_node.kind == "constructor"
                ):
                    params = []
                    for param in contract_node.parameters.parameters:
                        param_type = (
                            param["typeName"]["name"] if "typeName" in param else ""
                        )
                        param_name = param["name"]
                        params.append(f"{param_type} {param_name}")

                    code += f"\n    constructor({', '.join(params)}) {{\n"

                    for statement in contract_node.body.statements:
                        if statement.node_type == NodeType.EXPRESSION_STATEMENT:
                            expr = statement.expression
                            if expr.node_type == NodeType.ASSIGNMENT:
                                left = expr.left_hand_side.name
                                right = ""
                                if (
                                    expr.right_hand_side.node_type
                                    == NodeType.MEMBER_ACCESS
                                ):
                                    right = f"msg.sender"
                                code += f"        {left} = {right};\n"

                    code += "    }\n"

                elif (
                    contract_node.node_type == NodeType.FUNCTION_DEFINITION
                    and contract_node.kind == "function"
                ):
                    name = contract_node.name
                    visibility = contract_node.visibility
                    mutability = contract_node.state_mutability

                    params = []
                    for param in contract_node.parameters.parameters:
                        param_type = (
                            param.type_name.name if hasattr(param, "type_name") else ""
                        )
                        param_name = param.name if hasattr(param, "name") else ""
                        if param_type or param_name:
                            params.append(f"{param_type} {param_name}".strip())

                    return_params = []
                    if hasattr(contract_node, "return_parameters"):
                        for param in contract_node.return_parameters.parameters:
                            return_type = (
                                param.type_name.name
                                if hasattr(param, "type_name")
                                else ""
                            )
                            if return_type:
                                return_params.append(return_type)

                    function_header = f"\n    function {name}({', '.join(params)})"
                    if mutability:
                        function_header += f" {visibility} {mutability}"
                    else:
                        function_header += f" {visibility}"
                    if return_params:
                        function_header += f" returns ({', '.join(return_params)})"

                    code += function_header + " {\n"

                    for statement in contract_node.body.statements:
                        if statement.node_type == NodeType.EXPRESSION_STATEMENT:
                            expr = statement.expression
                            if expr.node_type == NodeType.ASSIGNMENT:
                                left = ""
                                if (
                                    expr.left_hand_side.node_type
                                    == NodeType.INDEX_ACCESS
                                ):
                                    print(expr.left_hand_side)
                                    left = parse_index_access(expr.left_hand_side)
                                elif (
                                    expr.left_hand_side.node_type
                                    == NodeType.MEMBER_ACCESS
                                ):
                                    left = parse_member_access(expr.left_hand_side)
                                else:
                                    left = expr.left_hand_side.name

                                if hasattr(expr.right_hand_side, "name"):
                                    right = expr.right_hand_side.name
                                else:
                                    right = "msg.value"

                                op = expr.operator
                                code += f"        {left} {op} {right};\n"

                        elif statement.node_type == NodeType.RETURN:
                            if statement.expression.node_type == NodeType.LITERAL:
                                return_value = getattr(
                                    statement.expression, "value", ""
                                )
                            elif (
                                statement.expression.node_type == NodeType.INDEX_ACCESS
                            ):
                                return_value = f"{statement.expression.base_expression.name}[{statement.expression.index_expression.expression.name}.{statement.expression.index_expression.member_name}]"
                            else:
                                return_value = getattr(statement.expression, "name", "")
                            code += f"        return {return_value};\n"

                    code += "    }\n"

            code += "}"

    return code


def add_offset(parameter: str, offset: int):
    parts = [int(x) for x in parameter.split(":")]
    parts[0] += offset
    return ":".join(map(str, parts))


def main():
    solcx.install_solc()

    ast = compile_contract_from_file(FILE_NAME, CONTRACT_NAME)

    filtered = filter_dict(
        ast["nodes"][1]["nodes"], ["id", "nodeType", "body", "expression", "statements"]
    )
    with open("contract_ast_node_types.json", "w+") as f:
        f.write(json.dumps(filtered, indent=2))

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
