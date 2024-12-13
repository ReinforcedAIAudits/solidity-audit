import json
from fastapi.encoders import jsonable_encoder
import solcx

from ai_audits.contracts.ast_models import NodeType, SourceUnit, VariableDeclaration

FILE_NAME = "contract.example.sol"
CONTRACT_NAME = "SimpleWallet"


def compile_contract_from_file(filename: str, contract_name: str):
    with open(filename) as f:
        code = f.read()

    suggested_version = solcx.install.select_pragma_version(
        code, solcx.get_installable_solc_versions()
    )
    json_compiled = solcx.compile_source(code, solc_version=suggested_version)

    return json_compiled[f"<stdin>:{contract_name}"]["ast"]


def parse_ast_to_solidity(ast: SourceUnit):
    code = ""

    for node in ast.nodes:
        if node.node_type == NodeType.PRAGMA_DIRECTIVE:
            pragma_str = " ".join(node.literals)
            code += f"pragma {pragma_str};\n\n"

        elif node.node_type == NodeType.CONTRACT_DEFINITION:
            code += f"contract {node.name} {{\n\n"

            for contract_node in node.nodes:
                if contract_node.node_type == NodeType.VARIABLE_DECLARATION:
                    visibility = contract_node.visibility
                    var_type = ""

                    if contract_node.type_name.node_type == NodeType.MAPPING:
                        key_type = contract_node.type_name.key_type.name
                        value_type = contract_node.type_name.value_type.name
                        var_type = f"mapping({key_type} => {value_type})"
                    else:
                        var_type = contract_node.type_name.name

                    name = contract_node.name
                    code += f"    {var_type} {visibility} {name};\n"

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
                                    type(expr.left_hand_side) == dict
                                    and expr.left_hand_side["nodeType"]
                                    == NodeType.INDEX_ACCESS
                                    or getattr(expr.left_hand_side, "node_type", None)
                                    == NodeType.INDEX_ACCESS
                                ):
                                    map_name = expr.left_hand_side.base_expression.name
                                    index = "msg.sender"
                                    left = f"{map_name}[{index}]"
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

node = next(n for n in ast_obj_reentrancy.nodes[1].nodes if n.name == "balanceChange")


def add_offset(parameter: str, offset: int):
    parts = [int(x) for x in parameter.split(":")]
    parts[0] += offset
    return ":".join(map(str, parts))


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

node.body.statements[0].expression.left_hand_side.index_expression.expression.src = (
    add_offset(
        node.body.statements[
            0
        ].expression.left_hand_side.index_expression.expression.src,
        offset,
    )
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
