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
    ELEMENTARY_TYPE_NAME_EXPRESSION = "ElementaryTypeNameExpression"


DefaultMember = Union[
    "Identifier",
    "Literal",
    "UnaryOperation",
    "BinaryOperation",
    "MemberAccess",
    "IndexAccess",
]


class TypeDescriptions(BaseModel):
    type_identifier: Optional[str] = Field(default=None, alias="typeIdentifier")
    type_string: Optional[str] = Field(default=None, alias="typeString")


class NodeBase(BaseModel):
    id: int
    src: str
    node_type: NodeType = Field(alias="nodeType")


class TypeBase(NodeBase):
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")


class ExpressionBase(TypeBase):
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")


class ElementaryTypeName(TypeBase):
    name: str
    state_mutability: Optional[str] = Field(default=None, alias="stateMutability")


class PathNode(NodeBase):
    name: str
    name_locations: List[str] = Field(alias="nameLocations")
    node_type: str = Field(alias="nodeType")
    referenced_declaration: int = Field(alias="referencedDeclaration")


class UserDefinedTypeName(TypeBase):
    path_node: PathNode = Field(alias="pathNode")
    referenced_declaration: int = Field(alias="referencedDeclaration")


class Mapping(TypeBase):
    key_name: str = Field(alias="keyName")
    key_name_location: str = Field(alias="keyNameLocation")
    key_type: ElementaryTypeName = Field(alias="keyType")
    value_name: str = Field(alias="valueName")
    value_name_location: str = Field(alias="valueNameLocation")
    value_type: Union[UserDefinedTypeName, ElementaryTypeName, "Mapping"] = Field(
        alias="valueType"
    )


class VariableDeclaration(TypeBase):
    constant: bool
    function_selector: Optional[str] = Field(default=None, alias="functionSelector")
    mutability: str
    indexed: Optional[bool] = Field(default=None)
    name: str
    name_location: Optional[str] = Field(alias="nameLocation")
    value: Optional[DefaultMember] = Field(default=None)
    scope: int
    state_variable: bool = Field(alias="stateVariable")
    storage_location: str = Field(alias="storageLocation")
    type_name: Union[Mapping, ElementaryTypeName, UserDefinedTypeName] = Field(
        alias="typeName"
    )
    visibility: str


class ParameterList(NodeBase):
    parameters: List[VariableDeclaration]


class Identifier(TypeBase):
    name: str
    overloaded_declarations: List[int] = Field(alias="overloadedDeclarations")
    referenced_declaration: int = Field(alias="referencedDeclaration")


class Literal(ExpressionBase):
    hex_value: str = Field(alias="hexValue")
    subdenomination: Optional[str] = Field(default=None)
    kind: str
    value: str


class UnaryOperation(ExpressionBase):
    operator: str
    prefix: bool
    sub_expression: Identifier = Field(alias="subExpression")


class BinaryOperation(ExpressionBase):
    common_type: TypeDescriptions = Field(alias="commonType")
    left_expression: Union[
        DefaultMember,
        "TupleExpression",
        "FunctionCall",
    ] = Field(alias="leftExpression")
    operator: str
    right_expression: Union[
        DefaultMember,
        "TupleExpression",
        "FunctionCall",
    ] = Field(alias="rightExpression")


class Return(NodeBase):
    function_return_parameters: int = Field(alias="functionReturnParameters")
    expression: Union[Identifier, Literal]


class MemberAccess(ExpressionBase):
    expression: Union[DefaultMember, "FunctionCall"]
    member_location: str = Field(alias="memberLocation")
    member_name: str = Field(alias="memberName")
    sub_expression: Optional[Identifier] = Field(default=None, alias="subExpression")


class IndexAccess(ExpressionBase):
    base_expression: Union[Identifier, "IndexAccess", MemberAccess] = Field(
        alias="baseExpression"
    )
    index_expression: Union[MemberAccess, Identifier, Literal, "IndexAccess"] = Field(
        alias="indexExpression"
    )


class FunctionCall(ExpressionBase):
    arguments: List[DefaultMember]
    expression: Union[Identifier, MemberAccess, IndexAccess, "ElementaryTypeNameExpression"]
    kind: str
    name_locations: List[str] = Field(alias="nameLocations")
    names: List[str]
    try_call: bool = Field(alias="tryCall")


class EmitStatement(NodeBase):
    event_call: FunctionCall = Field(alias="eventCall")


class Assignment(ExpressionBase):
    left_hand_side: Optional[Union[Identifier, MemberAccess, IndexAccess]] = Field(
        default=None, alias="leftHandSide"
    )
    operator: str
    right_hand_side: Union[DefaultMember, FunctionCall, "TupleExpression"] = Field(
        default=None, alias="rightHandSide"
    )


class ElementaryTypeNameExpression(ExpressionBase):
    type_name: ElementaryTypeName = Field(alias="typeName")
    argument_types: List[TypeDescriptions] = Field(alias="argumentTypes")


class TupleExpression(ExpressionBase):
    is_inline_array: bool = Field(alias="isInlineArray")
    components: List[DefaultMember]


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
    statements: List[
        Union[
            ExpressionStatement,
            Return,
            EmitStatement,
            FunctionCall,
            VariableDeclarationStatement,
        ]
    ]


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
