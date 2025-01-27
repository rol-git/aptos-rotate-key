import asyncio
from typing import List, Union
from loguru import logger
from aptos_sdk.account import Account, RotationProofChallenge
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import RestClient
from aptos_sdk.authenticator import Authenticator
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from aptos_sdk.ed25519 import PrivateKey

logger.add("logs/{time:YYYY-MM-DD}.log", rotation="500 MB")

NODE_URL = "https://fullnode.mainnet.aptoslabs.com/v1"
MAX_WORKERS = 10


async def read_private_keys(file_path: str) -> List[str]:
    with open(file_path, "r") as file:
        return [line.strip() for line in file.readlines()]


async def write_private_keys(file_path: str, keys: Union[List[str], List[None]]):
    with open(file_path, "w") as file:
        for key in keys:
            file.write(f"{key if key else 'error'}\n")


def generate_new_private_keys(count: int) -> List[str]:
    return [Account.generate().private_key.hex() for _ in range(count)]


async def rotate_auth_key(
        rest_client: RestClient,
        from_account: Account,
        new_private_key: PrivateKey,
) -> str:
    to_account = Account.load_key(new_private_key.hex())
    from_scheme = Authenticator.from_key(from_account.public_key())
    to_scheme = Authenticator.from_key(to_account.public_key())

    rotation_proof_challenge = RotationProofChallenge(
        sequence_number=await rest_client.account_sequence_number(from_account.address()),
        originator=from_account.address(),
        current_auth_key=AccountAddress.from_str_relaxed(from_account.auth_key()),
        new_public_key=to_account.public_key(),
    )

    serializer = Serializer()
    rotation_proof_challenge.serialize(serializer)
    rotation_proof_challenge_bcs = serializer.output()

    from_signature = from_account.sign(rotation_proof_challenge_bcs)
    to_signature = to_account.sign(rotation_proof_challenge_bcs)

    payload = EntryFunction.natural(
        module="0x1::account",
        function="rotate_authentication_key",
        ty_args=[],
        args=[
            TransactionArgument(from_scheme, Serializer.u8),
            TransactionArgument(from_account.public_key(), Serializer.struct),
            TransactionArgument(to_scheme, Serializer.u8),
            TransactionArgument(to_account.public_key(), Serializer.struct),
            TransactionArgument(from_signature, Serializer.struct),
            TransactionArgument(to_signature, Serializer.struct),
        ],
    )

    signed_transaction = await rest_client.create_bcs_signed_transaction(from_account, TransactionPayload(payload))
    tx_hash = await rest_client.submit_bcs_transaction(signed_transaction)
    await rest_client.wait_for_transaction(tx_hash)

    return tx_hash


async def rotate_key(old_private_key: str, new_private_key: str, semaphore: asyncio.Semaphore) -> Union[str, None]:
    async with semaphore:
        rest_client = RestClient(NODE_URL)
        from_account = Account.load_key(old_private_key)
        new_private_key_obj = PrivateKey.from_hex(new_private_key, strict=False)

        try:
            tx_hash = await rotate_auth_key(rest_client, from_account, new_private_key_obj)

            logger.info(
                f"Key rotation successful. Address: {from_account.address()}, "
                f"Old Private Key: {old_private_key}, New Private Key: {new_private_key}, "
                f"Transaction Hash: {tx_hash}"
            )

            return new_private_key

        except Exception as e:
            logger.error(f"Key rotation failed for address {from_account.address()}: {e}")
            return None

        finally:
            await rest_client.close()


async def main():
    old_keys = await read_private_keys("old_private_keys.txt")
    new_keys = generate_new_private_keys(len(old_keys))

    semaphore = asyncio.Semaphore(MAX_WORKERS)

    tasks = [
        rotate_key(old_key, new_key, semaphore)
        for old_key, new_key in zip(old_keys, new_keys)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    result_keys = [result if isinstance(result, str) else "error" for result in results]

    await write_private_keys("result_private_keys.txt", result_keys)


if __name__ == "__main__":
    asyncio.run(main())
