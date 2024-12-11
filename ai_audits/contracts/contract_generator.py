import json
from fastapi.encoders import jsonable_encoder
import solcx

from model_servers.contracts.ast_models import SourceUnit, VariableDeclaration


solcx.install_solc("0.8.28", True)
solcx.compile_solc("0.8.28")

with open("./contract.example.sol") as f:
    code = f.read()
suggested_version = solcx.install.select_pragma_version(
    code, solcx.get_installable_solc_versions()
)

output_json = solcx.compile_files(
    "./contract.example.sol", solc_version=suggested_version
)

output_json_copy = output_json.copy()


with open("input.json", "w+") as f:
    f.write(json.dumps(output_json_copy, indent=2))


def parse_ast_to_solidity(ast: SourceUnit):
    code = ""

    for node in ast.nodes:
        if node.node_type == "ContractDefinition":
            code += f"contract {node.name} {{\n\n"

            for contract_node in node.nodes:
                if contract_node.node_type == "VariableDeclaration":
                    visibility = contract_node.visibility
                    var_type = ""

                    if contract_node.type_name.node_type == "Mapping":
                        key_type = contract_node.type_name.key_type.name
                        value_type = contract_node.type_name.value_type.name
                        var_type = f"mapping({key_type} => {value_type})"
                    else:
                        var_type = contract_node.type_name.name

                    name = contract_node.name
                    code += f"    {var_type} {visibility} {name};\n"

                elif (
                    contract_node.node_type == "FunctionDefinition"
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
                        if statement.node_type == "ExpressionStatement":
                            expr = statement.expression
                            if expr.node_type == "Assignment":
                                left = expr.left_hand_side.name
                                right = ""
                                if expr.right_hand_side.node_type == "MemberAccess":
                                    right = f"msg.sender"
                                code += f"        {left} = {right};\n"

                    code += "    }\n"

                elif (
                    contract_node.node_type == "FunctionDefinition"
                    and contract_node.kind == "function"
                ):
                    name = contract_node.name
                    visibility = contract_node.visibility
                    mutability = contract_node.state_mutability

                    if mutability:
                        code += (
                            f"\n    function {name}() {visibility} {mutability} {{\n"
                        )
                    else:
                        code += f"\n    function {name}() {visibility} {{\n"

                    for statement in contract_node.body.statements:
                        if statement.node_type == "ExpressionStatement":
                            expr = statement.expression
                            if expr.node_type == "Assignment":
                                left = ""
                                if (
                                    type(expr.left_hand_side) == dict
                                    and expr.left_hand_side["nodeType"] == "IndexAccess"
                                    or expr.left_hand_side.node_type == "IndexAccess"
                                ):
                                    map_name = expr.left_hand_side["baseExpression"][
                                        "name"
                                    ]
                                    index = "msg.sender"
                                    left = f"{map_name}[{index}]"
                                else:
                                    left = expr.left_hand_side.name

                                right = "msg.value"
                                op = expr.operator

                                code += f"        {left} {op} {right};\n"

                    code += "    }\n"

            code += "}"

    return code


ast_contract = SourceUnit(
    **output_json_copy["contract.example.sol:TreasureVault"]["ast"]
)
contract = parse_ast_to_solidity(ast_contract)
print(contract)

with open("contract_ast_obj.json", "w+") as f:
    f.write(json.dumps(jsonable_encoder(ast_contract)))

ast = output_json["contract.example.sol:TreasureVault"]["ast"]

with open("contract_ast.json", "w+") as f:
    f.write(json.dumps(ast, indent=2))


with open("./reentrancy.example.sol") as f:
    code = f.read()
suggested_version = solcx.install.select_pragma_version(
    code, solcx.get_installable_solc_versions()
)
output_json = solcx.compile_files(
    "./reentrancy.example.sol", solc_version=suggested_version
)


ast_obj = SourceUnit(**output_json["reentrancy.example.sol:Reentrancy"]["ast"])
node_index = -1
print(json.dumps(jsonable_encoder(ast_obj)))

contract = parse_ast_to_solidity(ast_obj)
print(contract)

parts = []
offset = 1

for contract in ast_contract.nodes:
    for idx, node in enumerate(contract.nodes):
        # print(json.dumps(jsonable_encoder(node)))
        if (
            type(node) != VariableDeclaration
            and node.node_type == "FunctionDefinition"
            and node.kind != "constructor"
        ):
            print("Hello, World!")
            node_index = idx
            break
    offset += int(contract.nodes[node_index].src.split(":")[0])

    # contract.nodes.append()
node = next(n for n in ast_obj.nodes[0].nodes if n.name == "balanceChange")


def add_offset(parameter: str, offset: int):
    parts = [int(x) for x in parameter.split(":")]
    parts[0] += offset
    return ":".join(map(str, parts))


node.src = add_offset(node.src, offset)
node.body.src = add_offset(node.body.src, offset)
node.parameters.src = add_offset(node.parameters.src, offset)
node.return_parameters.src = add_offset(node.return_parameters.src, offset)
node.name_location = add_offset(node.name_location, offset)
node.body.statements[0].expression.left_hand_side["src"] = add_offset(
    node.body.statements[0].expression.left_hand_side["src"], offset
)
node.body.statements[0].expression.left_hand_side["baseExpression"]["src"] = add_offset(
    node.body.statements[0].expression.left_hand_side["baseExpression"]["src"], offset
)

node.body.statements[0].expression.left_hand_side["indexExpression"]["src"] = (
    add_offset(
        node.body.statements[0].expression.left_hand_side["indexExpression"]["src"],
        offset,
    )
)

node.body.statements[0].expression.left_hand_side["indexExpression"]["expression"][
    "src"
] = add_offset(
    node.body.statements[0].expression.left_hand_side["indexExpression"]["expression"][
        "src"
    ],
    offset,
)

node.body.statements[0].expression.right_hand_side["src"] = add_offset(
    node.body.statements[0].expression.right_hand_side["src"], offset
)

node.body.statements[0].expression.src = add_offset(
    node.body.statements[0].expression.src, offset
)

node.body.statements[0].src = add_offset(node.body.statements[0].src, offset)

ast_contract.nodes[0].nodes.append(node)

output_json_copy["contract.example.sol:TreasureVault"]["ast"] = jsonable_encoder(
    ast_contract
)


contract = parse_ast_to_solidity(ast_contract)
print(contract)


with open("output_contract.json", "w+") as f:
    f.write(json.dumps(output_json_copy, indent=2))

solcx.compile_source(contract, solc_version=suggested_version)
