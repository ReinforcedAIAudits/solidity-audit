from substrateinterface import SubstrateInterface, Keypair


interface = SubstrateInterface("ws://localhost:9946")

ROOT_ID = 0
NET_UID = 1
SUBNET_TEMPO = 10
EMISSION_TEMPO = 30
interface.init_runtime()

keypair_alice = Keypair.create_from_uri("//Alice")
keypair_bob = Keypair.create_from_uri("//Bob")

metadata = interface.get_runtime_metadata()["result"][1]["V14"]
pallets = metadata['pallets']
# metadata = interface.get_metadata()
# print(metadata)
print(pallets)

def create_extrinsic(
    pallet: str, method: str, params: dict, keypair: Keypair = keypair_alice
):
    return interface.create_signed_extrinsic(
        call=interface.compose_call(
            call_module=pallet,
            call_function=method,
            call_params=params,
        ),
        keypair=keypair,
    )


def create_sudo_extrinsic(
    pallet: str, method: str, params: dict, keypair: Keypair = keypair_alice
):
    return interface.create_signed_extrinsic(
        call=interface.compose_call(
            call_module="Sudo",
            call_function="sudo",
            call_params={
                "call": interface.compose_call(
                    call_module=pallet,
                    call_function=method,
                    call_params=params,
                ).value
            },
        )
    )

# interface.submit_extrinsic(
#     create_extrinsic(
#         "Balances",
#         "forceTransfer",
#         {"netuid": NET_UID, "dests": [0, 1], "weights": [0, 0], "versionKey": 0},
#         keypair_bob,
#     )
# )

interface.submit_extrinsic(
    create_sudo_extrinsic(
        "AdminUtils",
        "SudoSetWeightsSetRateLimit",
        {"netuid": NET_UID, "weightsSetRateLimit": 0},
    )
)
# interface.submit_extrinsic(
#     create_sudo_extrinsic(
#         "AdminUtils",
#         "SudoSetWeightsSetRateLimit",
#         {"netuid": ROOT_ID, "weightsSetRateLimit": 0},
#     )
# )

# interface.submit_extrinsic(
#     create_extrinsic(
#         "AdminUtils",
#         "SudoSetTargetStakesPerInterval",
#         {"targetStakesPerInterval": 1000},
#     )
# )
# interface.submit_extrinsic(
#     create_extrinsic(
#         "AdminUtils",
#         "SudoSetTargetRegistrationsPerInterval",
#         {"netuid": NET_UID, "targetRegistrationsPerInterval": 1000},
#     )
# )
# interface.submit_extrinsic(
#     create_extrinsic("AdminUtils", "sudoSetTxRateLimit", {"sudoSetTxRateLimit": 0})
# )
# interface.submit_extrinsic(
#     create_extrinsic(
#         "AdminUtils",
#         "SudoSetTempo",
#         {"netuid": NET_UID, "tempo": SUBNET_TEMPO},
#     )
# )

# interface.submit_extrinsic(
#     create_extrinsic(
#         "AdminUtils",
#         "SudoSetTempo",
#         {"netuid": ROOT_ID, "tempo": SUBNET_TEMPO},
#     )
# )

# interface.submit_extrinsic(
#     create_extrinsic(
#         "AdminUtils",
#         "SudoSetHotkeyEmissionTempo",
#         {"emissionTempo": EMISSION_TEMPO},
#     )
# )

interface.submit_extrinsic(
    create_extrinsic(
        "SubtensorModule",
        "SetWeights",
        {"netuid": NET_UID, "dests": [0, 1], "weights": [0, 0], "versionKey": 0},
        keypair_bob,
    )
)
interface.submit_extrinsic(
    create_extrinsic(
        "SubtensorModule",
        "RootRegister",
        {"hotkey": keypair_alice.ss58_address},
    )
)
interface.submit_extrinsic(
    create_extrinsic(
        "SubtensorModule",
        "SetRootWeights",
        {
            "netuid": ROOT_ID,
            "hotkey": keypair_alice.ss58_address,
            "dests": [0, 1],
            "weights": [65535, 65535],
            "versionKey": 0,
        },
    )
)
