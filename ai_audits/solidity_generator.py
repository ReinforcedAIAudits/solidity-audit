import string
from hypothesis import strategies, given, settings


__all__ = ["SolidityGenerator"]


class SolidityGenerator:
    solidity_types = strategies.sampled_from([
        "uint", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
        "int", "int8", "int16", "int32", "int64", "int128", "int256",
        "bytes", "bytes32", "bool", "address"
    ])

    identifiers = strategies.text(alphabet=f'{string.ascii_letters}_', min_size=1, max_size=10)

    eth_address = strategies.text(alphabet="0123456789abcdef", min_size=40, max_size=40).map(lambda x: "0x" + x)

    values = (
            strategies.integers(min_value=0, max_value=10000).map(str) |
            strategies.sampled_from(["true", "false", "msg.sender"]) |
            eth_address
    )

    bin_ops = strategies.sampled_from(["+", "-", "*", "/", "%", "&&", "||", "==", "!="])

    expressions = strategies.recursive(
        base=values | identifiers,
        extend=(lambda bin_ops: lambda children: strategies.tuples(
            children, bin_ops, children
        ).map(lambda t: f"({t[0]} {t[1]} {t[2]})"))(bin_ops),
        max_leaves=3
    )

    variable_declarations = strategies.tuples(solidity_types, identifiers, expressions).map(
        lambda t: f"{t[0]} {t[1]} = {t[2]};"
    )

    if_statements = strategies.tuples(expressions, variable_declarations, variable_declarations).map(
        lambda t: f"if ({t[0]}) {{\n    {t[1]}\n}} else {{\n    {t[2]}\n}}"
    )

    functions = strategies.tuples(identifiers, variable_declarations | if_statements).map(
        lambda t: f"function {t[0]}() public {{\n    {t[1]}\n}}"
    )

    contracts = strategies.tuples(identifiers, strategies.lists(variable_declarations | functions, min_size=3, max_size=6)).map(
        lambda t: f"contract {t[0]} {{\n    " + "\n    ".join(t[1]) + "\n}}"
    )

    @classmethod
    def generate_contract(cls):
        contracts = []
        (given(cls.contracts)(settings(max_examples=2)(lambda ex: contracts.append(ex))))()
        return contracts[-1]
