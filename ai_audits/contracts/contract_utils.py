from typing import Callable, Any, List
from solc_ast_parser.models.base_ast_models import NodeType
from solc_ast_parser.models.ast_models import SourceUnit, TypeName, VariableDeclaration
from solc_ast_parser.models import ast_models


def get_contract_nodes(ast: SourceUnit, node_type: NodeType = None) -> List[ast_models.ASTNode]:
    nodes = []
    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            if not node_type:
                return node.nodes
            for contract_node in node.nodes:
                if contract_node.node_type == node_type:
                    if contract_node.node_type == NodeType.FUNCTION_DEFINITION and contract_node.kind == "constructor":
                        continue
                    nodes.append(contract_node)
    return nodes


def traverse_ast(node: ast_models.ASTNode, visitor: Callable[[Any], None]):
    if node is None:
        return

    visitor(node)

    fields = node.model_fields

    for field_name, field in fields.items():
        value = getattr(node, field_name)

        if isinstance(value, list):
            for item in value:
                if hasattr(item, "__fields__"):
                    traverse_ast(item, visitor, node)

        elif hasattr(value, "__fields__"):
            traverse_ast(value, visitor, node)


def append_storage_declaration_to_contract(ast: SourceUnit, storage_declaration: VariableDeclaration) -> SourceUnit:
    for ast_node in ast.nodes:
        if ast_node.node_type == NodeType.CONTRACT_DEFINITION:
            ast_node.nodes.append(storage_declaration)
            return ast
    raise ValueError("Contract not found in AST")


def create_storage_declaration(
    storage_name: str,
    storage_type: TypeName,
    visibility: str = "internal",
    constant: bool = False,
    mutability: str = "nonpayable",
    state_variable: bool = False,
    storage_location: str = "",
) -> VariableDeclaration:
    return VariableDeclaration(
        name=storage_name,
        typeName=storage_type,
        constant=constant,
        mutability=mutability,
        state_variable=state_variable,
        storage_location=storage_location,
        visibility=visibility,
        node_type=NodeType.VARIABLE_DECLARATION,
    )


def restore_storages(ast: SourceUnit):
    storages = [s.name for s in get_contract_nodes(ast, NodeType.VARIABLE_DECLARATION)]
    # identifiers_to_restore = 
    


def restore_assignments(node: ast_models.ASTNode, storages: List[str]):
    uint_solidity_operators = ["+=", "-=", "*=", "/=", "%="]
    if node.node_type == NodeType.ASSIGNMENT and node.operator in uint_solidity_operators:
        uint_identifiers = []
        traverse_ast(
            node,
            lambda n: (
                uint_identifiers.append(n) if n.node_type == NodeType.IDENTIFIER and n.name not in storages else None
            ),
        )
    return uint_identifiers
