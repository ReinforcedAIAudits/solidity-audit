import random
from typing import Callable, Any, List, Tuple, Union
from solc_ast_parser.models.base_ast_models import NodeType
from solc_ast_parser.models.ast_models import (
    SourceUnit,
    TypeName,
    VariableDeclaration,
    Identifier,
    ElementaryTypeName,
    StructDefinition,
    FunctionCall,
    ParameterList
)
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
                if hasattr(item, "__fields__") and hasattr(item, "node_type"):
                    traverse_ast(item, visitor)

        elif hasattr(value, "__fields__") and hasattr(value, "node_type"):
            traverse_ast(value, visitor)


def find_node_with_properties(ast: ast_models.ASTNode, **kwargs) -> List[ast_models.ASTNode]:
    def check_node(node):
        for key, value in kwargs.items():
            if not hasattr(node, key) or getattr(node, key) != value:
                return False
        return True

    nodes = []
    traverse_ast(ast, lambda n: nodes.append(n) if check_node(n) else None)
    return nodes


def append_declaration_to_contract(
    ast: SourceUnit, declaration: Union[VariableDeclaration, StructDefinition]
) -> SourceUnit:
    for ast_node in ast.nodes:
        if ast_node.node_type == NodeType.CONTRACT_DEFINITION:
            if declaration.node_type == NodeType.STRUCT_DEFINITION:
                ast_node.nodes.insert(0, declaration)
            else:
                last_struct_definition = next(
                    (
                        idx
                        for idx, contract_node in enumerate(reversed(ast_node.nodes))
                        if contract_node.node_type == NodeType.STRUCT_DEFINITION
                    ),
                    None,
                )
                if last_struct_definition:
                    ast_node.nodes.insert(last_struct_definition, declaration)
                else:
                    ast_node.nodes.insert(0, declaration)            
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
        stateVariable=state_variable,
        storageLocation=storage_location,
        visibility=visibility,
        nameLocation="",
        nodeType=NodeType.VARIABLE_DECLARATION,
        id=random.randint(0, 100000),
        src="",
    )


def create_elementary_type(type_name: str) -> ElementaryTypeName:
    return ElementaryTypeName(
        name=type_name,
        nodeType=NodeType.ELEMENTARY_TYPE_NAME,
        id=random.randint(0, 100000),
        src="",
    )

def create_struct_declaration(
    struct_name: str,
    struct_members: List[VariableDeclaration],
    visibility: str = "internal",
) -> StructDefinition:
    return StructDefinition(
        name=struct_name,
        nameLocation=" ",
        members=struct_members,
        visibility=visibility,
        nodeType=NodeType.STRUCT_DEFINITION,
        id=random.randint(0, 100000),
        src="",
    )


def restore_storages(ast: SourceUnit) -> SourceUnit:
    storages = [s.name for s in get_contract_nodes(ast, NodeType.VARIABLE_DECLARATION)]
    identifiers_to_restore: List[Identifier] = []
    traverse_ast(ast, lambda n: identifiers_to_restore.extend(restore_assignments(ast, n, storages)))

    for identifier in identifiers_to_restore:
        storage_declaration = create_storage_declaration(
            storage_name=identifier.name, storage_type=create_elementary_type("uint256")
        )
        ast = append_declaration_to_contract(ast, storage_declaration)

    return ast


def restore_assignments(ast: SourceUnit, node: ast_models.ASTNode, storages: List[str]):
    uint_solidity_operators = ["+=", "-=", "*=", "/=", "%="]
    uint_identifiers = []
    if node.node_type == NodeType.ASSIGNMENT and node.operator in uint_solidity_operators:
        traverse_ast(
            node,
            lambda n: (
                uint_identifiers.append(n)
                if n.node_type == NodeType.IDENTIFIER
                and n.name not in storages
                and n.name
                not in [
                    node.name
                    for node in find_node_with_properties(ast, node_type=NodeType.VARIABLE_DECLARATION, name=n.name)
                ]
                else None
            ),
        )
    return uint_identifiers


def extract_index_access(node: ast_models.ASTNode) -> Tuple[str]:
    if node.node_type == NodeType.INDEX_ACCESS:
        identifier_name = []
        traverse_ast(
            node.base_expression,
            lambda n: identifier_name.append(n.name) if n.node_type == NodeType.IDENTIFIER else None,
        )
        return identifier_name[0], [node.index_expression]
    return None

def extract_member_access(node: ast_models.ASTNode) -> Tuple[str, List[str]]:
    if node.node_type == NodeType.MEMBER_ACCESS:
        if node.expression.node_type == NodeType.INDEX_ACCESS:
            return None
        
        struct_name = []

        traverse_ast(
            node.expression,
            lambda n: struct_name.append(n.name) if n.node_type == NodeType.IDENTIFIER else None,
        )
        return struct_name[0], [node.member_name]
    return None



# def restore_structs(ast: SourceUnit) -> SourceUnit:
#     structs = [s.name for s in get_contract_nodes(ast, NodeType.STRUCT_DEFINITION)]
#     struct_to_restore = []
#     traverse_ast(
#         ast,
#         lambda n: struct_to_restore.append(extract_member_access(n))
#     )
#     print(list(filter(None, struct_to_restore)))
    


def restore_struct_members(ast: SourceUnit) -> List[StructDefinition]:
    struct_accesses = {}
    
    def collect_struct_accesses(node):
        result = extract_member_access(node)
        if result:
            struct_name, member_names = result
            if struct_name not in struct_accesses:
                struct_accesses[struct_name] = set()
            struct_accesses[struct_name].update(member_names)
    
    traverse_ast(ast, collect_struct_accesses)
    
    updated_structs = []
    existing_structs = {
        s.name: s for s in get_contract_nodes(ast, NodeType.STRUCT_DEFINITION)
    }
    
    for struct_name, members in struct_accesses.items():
        if struct_name not in existing_structs:
            struct_members = [
                create_storage_declaration(
                    storage_name=member,
                    storage_type=create_elementary_type("uint256")
                )
                for member in members
            ]
            
            updated_structs.append(
                create_struct_declaration(
                    struct_name=struct_name.capitalize(),
                    struct_members=struct_members
                )
            )
        else:
            existing_members = {m.name for m in existing_structs[struct_name].members}
            missing_members = members - existing_members
            
            if missing_members:
                new_struct = existing_structs[struct_name].copy()
                new_struct.members.extend([
                    create_storage_declaration(
                        storage_name=member,
                        storage_type=create_elementary_type("uint256")
                    )
                    for member in missing_members
                ])
                updated_structs.append(new_struct)
    
    return updated_structs

def extract_type_name(node: ast_models.TypeName) -> str:
    match node.node_type:
        case NodeType.ELEMENTARY_TYPE_NAME:
            return node.name
        case NodeType.MAPPING:
            return f"mapping({extract_type_name(node.key_type)} => {extract_type_name(node.value_type)})"
        case NodeType.ARRAY_TYPE_NAME:
            return f"{extract_type_name(node.base_type)}[]"
        case NodeType.FUNCTION_TYPE_NAME:
            return f"function({', '.join([extract_type_name(param) for param in node.parameter_types])}){extract_type_name(node.return_parameter_types)}"
        case NodeType.USER_DEFINED_TYPE_NAME:
            return node.name
    return None

def extract_expression_type(ast: ast_models.ASTNode, node: ast_models.Expression) -> str:
    type_name = []

    match node.node_type:
        case NodeType.IDENTIFIER:
            traverse_ast(
                ast,
                lambda n: type_name.append(extract_type_name(n.type_name)) if n.node_type == NodeType.VARIABLE_DECLARATION and n.name == node.name else None
            )
        case NodeType.FUNCTION_CALL:
            traverse_ast(
                ast,
                lambda n: type_name.extend([extract_type_name(param.type_name) for param in n.return_parameters]) if n.node_type == NodeType.FUNCTION_DEFINITION and n.name == node.name else None
            )
        case NodeType.INDEX_ACCESS:
            traverse_ast(
                ast,
                lambda n: type_name.append(extract_type_name(n.base_expression)) if n.node_type == NodeType.VARIABLE_DECLARATION and n.name == node.base_expression.name else None
            )
        case NodeType.MEMBER_ACCESS:
            traverse_ast(
                ast,
                lambda n: type_name.append(extract_type_name(n.expression)) if n.node_type == NodeType.VARIABLE_DECLARATION and n.name == node.expression.name else None
            )
        case NodeType.BINARY_OPERATION:
            type_name.append(extract_expression_type(ast, node.left_expression))
        case NodeType.UNARY_OPERATION:
            type_name.append(extract_expression_type(ast, node.sub_expression))
        case NodeType.LITERAL:
            type_name.append(node.type)
        case NodeType.TUPLE_EXPRESSION:
            type_name.extend([extract_expression_type(ast, expression) for expression in node.components])
        case _:
            raise ValueError(f"Unsupported node type: {node.node_type}")
    return type_name if type_name else None
        

def extract_expression_name(node: ast_models.Expression) -> str:
    match node.node_type:
        case NodeType.IDENTIFIER:
            return node.name
        case NodeType.FUNCTION_CALL:
            return extract_expression_name(node.expression)
        case NodeType.INDEX_ACCESS:
            return extract_expression_name(node.base_expression)
        case NodeType.MEMBER_ACCESS:
            return extract_expression_name(node.expression)
        case NodeType.BINARY_OPERATION:
            return extract_expression_name(node.left_expression)
        case NodeType.UNARY_OPERATION:
            return extract_expression_name(node.sub_expression)
        case NodeType.TUPLE_EXPRESSION:
            return [extract_expression_name(expression) for expression in node.components]
        case _:
            raise ValueError(f"Unsupported node type: {node.node_type}")

def restore_function_definitions(ast: SourceUnit) -> List[ast_models.ASTNode]:
    def restore_function_arguments(node: FunctionCall):
        args = []
        for argument in node.arguments:
            type_name = extract_expression_type(ast, argument)
            if type_name:
                args.append(
                    create_storage_declaration(
                        storage_name=argument.name,
                        storage_type=create_elementary_type(type_name)
                    )
                )
        return args

                
                
    function_calls = find_node_with_properties(ast, node_type=NodeType.FUNCTION_CALL)
    function_definitions = find_node_with_properties(ast, node_type=NodeType.FUNCTION_DEFINITION)
    for function_call in function_calls:
        function_names = [f.name for f in function_definitions]
        function_name = extract_expression_name(function_call.expression)
        if function_name not in function_names:
            function_arguments = restore_function_arguments(function_call)
            function_definitions.append(
                ast_models.FunctionDefinition(
                    name=function_name,
                    nameLocation="",
                    parameters=ParameterList(
                        parameters=function_arguments,
                        nodeType=NodeType.PARAMETER_LIST,
                        id=random.randint(0, 100000),
                        src="",
                    ),
                    returnParameters=ParameterList(
                        parameters=[],
                        nodeType=NodeType.PARAMETER_LIST,   
                        id=random.randint(0, 100000),
                        src="",
                    ),
                    implemented=True,
                    visibility="internal",
                    stateMutability="nonpayable",
                    nodeType=NodeType.FUNCTION_DEFINITION,
                    id=random.randint(0, 100000),
                    src="",
                    kind="function",
                )
            )
    return function_definitions

def restore_ast(ast: SourceUnit) -> SourceUnit:
    ast = restore_storages(ast)
    
    # array_declarations = restore_arrays(ast)
    # for decl in array_declarations:
    #     ast = append_declaration_to_contract(ast, decl)
        
    
    struct_declarations = restore_struct_members(ast)
    for decl in struct_declarations:
        ast = append_declaration_to_contract(ast, decl)
        

    function_declarations = restore_function_definitions(ast)
    for decl in function_declarations:
        for node in ast.nodes:
            if node.node_type == NodeType.CONTRACT_DEFINITION:
                node.nodes.append(decl)
                
    return ast