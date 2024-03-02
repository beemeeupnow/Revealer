from nucypher.policy.conditions.lingo import ConditionLingo, ConditionType, Lingo
from nucypher.policy.conditions.types import ContractConditionDict, ReturnValueTestDict

contract_condition = ContractConditionDict(
    name="isKeySet",
    conditionType=ConditionType.CONTRACT.value,
    chain=80001,
    method="isKeySet",
    returnValueTest=ReturnValueTestDict(comparator="==", value=True),
    contractAddress="0x96ebdf35199219BDd16E3c3E1aD8C89C9185b734",  # set this to the contract that has initialWindow
    standardContractType="",
    functionAbi={
        "inputs": [],
        "name": "isKeySet",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    }
)

is_material_released_condition: Lingo = {
        "version": ConditionLingo.VERSION,
        "condition": contract_condition,
    }
