import enum
from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field


class NodeType(enum.Enum):
    SOURCE_UNIT = "SourceUnit"
    BLOCK = "Block"
    PRAGMA_DIRECTIVE = "PragmaDirective"
    CONTRACT_DEFINITION = "ContractDefinition"
    FUNCTION_DEFINITION = "FunctionDefinition"
    VARIABLE_DECLARATION = "VariableDeclaration"
    VARIABLE_DECLARATION_STATEMENT = "VariableDeclarationStatement"
    FUNCTION_CALL = "FunctionCall"
    PARAMETER_LIST = "ParameterList"
    EVENT_DEFINITION = "EventDefinition"
    EMIT_STATEMENT = "EmitStatement"
    ASSIGNMENT = "Assignment"
    BINARY_OPERATION = "BinaryOperation"
    UNARY_OPERATION = "UnaryOperation"
    LITERAL = "Literal"
    IDENTIFIER = "Identifier"
    IDENTIFIER_PATH = "IdentifierPath"
    MEMBER_ACCESS = "MemberAccess"
    INDEX_ACCESS = "IndexAccess"
    TUPLE_EXPRESSION = "TupleExpression"
    EXPRESSION_STATEMENT = "ExpressionStatement"
    RETURN = "Return"
    ELEMENTARY_TYPE_NAME = "ElementaryTypeName"
    USER_DEFINED_TYPE_NAME = "UserDefinedTypeName"
    STRUCT_DEFINITION = "StructDefinition"
    MAPPING = "Mapping"


class NodeBase(BaseModel):
    id: int
    src: str
    node_type: NodeType = Field(alias="nodeType")


class TypeDescriptions(BaseModel):
    type_identifier: Optional[str] = Field(alias="typeIdentifier")
    type_string: Optional[str] = Field(alias="typeString")


class ElementaryTypeName(NodeBase):
    name: str
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")
    state_mutability: Optional[str] = Field(default=None, alias="stateMutability")


class PathNode(NodeBase):
    name: str
    name_locations: List[str] = Field(alias="nameLocations")
    node_type: str = Field(alias="nodeType")
    referenced_declaration: int = Field(alias="referencedDeclaration")


class UserDefinedTypeName(NodeBase):
    path_node: PathNode = Field(alias="pathNode")
    referenced_declaration: int = Field(alias="referencedDeclaration")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class Mapping(NodeBase):
    key_name: str = Field(alias="keyName")
    key_name_location: str = Field(alias="keyNameLocation")
    key_type: ElementaryTypeName = Field(alias="keyType")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")
    value_name: str = Field(alias="valueName")
    value_name_location: str = Field(alias="valueNameLocation")
    value_type: Union[UserDefinedTypeName, ElementaryTypeName] = Field(
        alias="valueType"
    )


class VariableDeclaration(NodeBase):
    constant: bool
    function_selector: Optional[str] = Field(default=None, alias="functionSelector")
    mutability: str
    name: str
    name_location: Optional[str] = Field(alias="nameLocation")
    scope: int
    state_variable: bool = Field(alias="stateVariable")
    storage_location: str = Field(alias="storageLocation")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")
    type_name: Union[Mapping, ElementaryTypeName, UserDefinedTypeName] = Field(alias="typeName")
    visibility: str


class ParameterList(NodeBase):
    parameters: List[VariableDeclaration]


class Identifier(NodeBase):
    name: str
    overloaded_declarations: List[int] = Field(alias="overloadedDeclarations")
    referenced_declaration: int = Field(alias="referencedDeclaration")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class Literal(NodeBase):
    hex_value: str = Field(alias="hexValue")
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    kind: str
    value: str
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class UnaryOperation(NodeBase):
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    operator: str
    prefix: bool
    sub_expression: Identifier = Field(alias="subExpression")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class BinaryOperation(NodeBase):
    common_type: TypeDescriptions = Field(alias="commonType")
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    left_expression: Union[Identifier, Literal, "BinaryOperation"] = Field(
        alias="leftExpression"
    )
    operator: str
    right_expression: Union[Identifier, Literal, "BinaryOperation"] = Field(
        alias="rightExpression"
    )
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class Return(NodeBase):
    function_return_parameters: int = Field(alias="functionReturnParameters")
    expression: Union[Identifier, Literal]


class MemberAccess(NodeBase):
    expression: Union[Identifier, "IndexAccess"]
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    member_location: str = Field(alias="memberLocation")
    member_name: str = Field(alias="memberName")
    sub_expression: Optional[Identifier] = Field(default=None, alias="subExpression")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class IndexAccess(NodeBase):
    base_expression: Identifier = Field(alias="baseExpression")
    index_expression: Union[MemberAccess, Identifier] = Field(alias="indexExpression")
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class FunctionCall(NodeBase):
    arguments: List[Union[Identifier, Literal, BinaryOperation]]
    expression: Identifier
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    kind: str
    name_locations: List[str] = Field(alias="nameLocations")
    names: List[str]
    try_call: bool = Field(alias="tryCall")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class EmitStatement(NodeBase):
    event_call: FunctionCall = Field(alias="eventCall")


class Assignment(NodeBase):
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    left_hand_side: Optional[Union[Identifier, MemberAccess, IndexAccess]] = Field(
        default=None, alias="leftHandSide"
    )
    operator: str
    prefix: Optional[bool] = Field(default=None)
    right_hand_side: Optional[
        Union[MemberAccess, Identifier, Literal, FunctionCall]
    ] = Field(default=None, alias="rightHandSide")
    sub_expression: Optional[Identifier] = Field(default=None, alias="subExpression")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class TupleExpression(NodeBase):
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    is_inline_array: bool = Field(alias="isInlineArray")
    components: List[Union[MemberAccess, IndexAccess]]
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class VariableDeclarationStatement(NodeBase):
    assignments: List[int]
    declarations: List[VariableDeclaration]
    initial_value: IndexAccess = Field(alias="initialValue")


class ExpressionStatement(NodeBase):
    expression: Union[
        Assignment,
        UnaryOperation,
        IndexAccess,
        BinaryOperation,
        FunctionCall,
        TupleExpression,
        VariableDeclarationStatement,
    ]


class Block(NodeBase):
    statements: List[Union[ExpressionStatement, Return, EmitStatement, FunctionCall, VariableDeclarationStatement]]


class FunctionDefinition(NodeBase):
    body: Block
    function_selector: Optional[str] = Field(default=None, alias="functionSelector")
    implemented: bool = True
    kind: str
    modifiers: List = Field(default_factory=list)
    name_location: str = Field(alias="nameLocation")
    parameters: ParameterList
    return_parameters: ParameterList = Field(alias="returnParameters")
    scope: int
    name: str
    state_mutability: str = Field(alias="stateMutability")
    virtual: bool = False
    visibility: str


class StructDefinition(NodeBase):
    canonical_name: str = Field(alias="canonicalName")
    members: List[VariableDeclaration | FunctionDefinition]
    name_location: str = Field(alias="nameLocation")
    scope: int
    name: str
    visibility: str


class PragmaDirective(NodeBase):
    literals: List[str]


class EventDefinition(NodeBase):
    anonymous: bool
    event_selector: str = Field(alias="eventSelector")
    name_location: str = Field(alias="nameLocation")
    parameters: ParameterList
    name: str


class ContractDefinition(NodeBase):
    abstract: bool
    base_contracts: List = Field(alias="baseContracts")
    canonical_name: str = Field(alias="canonicalName")
    contract_dependencies: List = Field(alias="contractDependencies")
    contract_kind: str = Field(alias="contractKind")
    fully_implemented: bool = Field(alias="fullyImplemented")
    linearized_base_contracts: List[int] = Field(alias="linearizedBaseContracts")
    name_location: str = Field(alias="nameLocation")
    nodes: List[
        Union[
            VariableDeclaration, StructDefinition, FunctionDefinition, EventDefinition
        ]
    ]
    scope: int
    name: str
    used_errors: List = Field(alias="usedErrors")
    used_events: List = Field(alias="usedEvents")


class SourceUnit(NodeBase):
    license: Optional[str] = Field(default=None)
    absolute_path: str = Field(alias="absolutePath")
    exported_symbols: Dict[str, List[int]] = Field(alias="exportedSymbols")
    nodes: List[Union[ContractDefinition, PragmaDirective]]
