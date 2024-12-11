from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field

class TypeDescriptions(BaseModel):
    type_identifier: str = Field(alias="typeIdentifier")
    type_string: str = Field(alias="typeString")

class ElementaryTypeName(BaseModel):
    id: int
    name: str
    node_type: str = Field(alias="nodeType")
    src: str
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")
    state_mutability: Optional[str] = Field(default=None, alias="stateMutability")

class Mapping(BaseModel):
    id: int
    key_name: str = Field(alias="keyName")
    key_name_location: str = Field(alias="keyNameLocation")
    key_type: ElementaryTypeName = Field(alias="keyType")
    node_type: str = Field(alias="nodeType")
    src: str
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")
    value_name: str = Field(alias="valueName")
    value_name_location: str = Field(alias="valueNameLocation")
    value_type: ElementaryTypeName = Field(alias="valueType")

class VariableDeclaration(BaseModel):
    constant: bool
    function_selector: Optional[str] = Field(alias="functionSelector")
    id: int
    mutability: str
    name: str
    name_location: str = Field(alias="nameLocation")
    node_type: str = Field(alias="nodeType")
    scope: int
    src: str
    state_variable: bool = Field(alias="stateVariable")
    storage_location: str = Field(alias="storageLocation")
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")
    type_name: Union[Mapping, ElementaryTypeName] = Field(alias="typeName")
    visibility: str

class ParameterList(BaseModel):
    id: int
    node_type: str = Field(alias="nodeType")
    parameters: List[dict]
    src: str

class Identifier(BaseModel):
    id: int
    name: str
    node_type: str = Field(alias="nodeType")
    overloaded_declarations: List[int] = Field(alias="overloadedDeclarations")
    referenced_declaration: int = Field(alias="referencedDeclaration")
    src: str
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")

class MemberAccess(BaseModel):
    expression: Identifier
    id: int
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    member_location: str = Field(alias="memberLocation")
    member_name: str = Field(alias="memberName")
    node_type: str = Field(alias="nodeType")
    src: str
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")

class Assignment(BaseModel):
    id: int
    is_constant: bool = Field(alias="isConstant")
    is_lvalue: bool = Field(alias="isLValue")
    is_pure: bool = Field(alias="isPure")
    lvalue_requested: bool = Field(alias="lValueRequested")
    left_hand_side: Union[Identifier, Dict] = Field(alias="leftHandSide")
    node_type: str = Field(alias="nodeType")
    operator: str
    right_hand_side: Union[MemberAccess, Dict] = Field(alias="rightHandSide")
    src: str
    type_descriptions: TypeDescriptions = Field(alias="typeDescriptions")

class ExpressionStatement(BaseModel):
    expression: Assignment
    id: int
    node_type: str = Field(alias="nodeType")
    src: str

class Block(BaseModel):
    id: int
    node_type: str = Field(alias="nodeType")
    src: str
    statements: List[ExpressionStatement]

class FunctionDefinition(BaseModel):
    body: Block
    function_selector: Optional[str] = Field(default=None, alias="functionSelector")
    id: int
    implemented: bool
    kind: str
    modifiers: List
    name: str
    name_location: str = Field(alias="nameLocation")
    node_type: str = Field(alias="nodeType")
    parameters: ParameterList
    return_parameters: ParameterList = Field(alias="returnParameters")
    scope: int
    src: str
    state_mutability: str = Field(alias="stateMutability")
    virtual: bool
    visibility: str

class ContractDefinition(BaseModel):
    abstract: bool
    base_contracts: List = Field(alias="baseContracts")
    canonical_name: str = Field(alias="canonicalName")
    contract_dependencies: List = Field(alias="contractDependencies")
    contract_kind: str = Field(alias="contractKind")
    fully_implemented: bool = Field(alias="fullyImplemented")
    id: int
    linearized_base_contracts: List[int] = Field(alias="linearizedBaseContracts")
    name: str
    name_location: str = Field(alias="nameLocation")
    node_type: str = Field(alias="nodeType")
    nodes: List[Union[VariableDeclaration, FunctionDefinition]]
    scope: int
    src: str
    used_errors: List = Field(alias="usedErrors")
    used_events: List = Field(alias="usedEvents")

class SourceUnit(BaseModel):
    absolute_path: str = Field(alias="absolutePath")
    exported_symbols: Dict[str, List[int]] = Field(alias="exportedSymbols")
    id: int
    node_type: str = Field(alias="nodeType")
    nodes: List[ContractDefinition]
    src: str