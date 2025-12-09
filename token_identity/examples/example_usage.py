from __future__ import annotations

import json

from token_identity.models import TokenIdentity
from token_identity.prism_did import PrismDIDManager


def example_usage():
    token_identity = TokenIdentity(
        policy_id="7b39a0d5e11c670",
        collection_name="ExampleToken",
        asset_name="Token1",
        social_accounts={
            "twitter": ["https://twitter.com/exampletoken"],
            "discord": ["https://discord.gg/exampletoken"],
        },
        website=["https://example.com"],
        rwa_details={
            "assetType": "RealEstate",
            "jurisdiction": "United States",
            "registrationNumber": "ABC123",
        },
    )

    manager = PrismDIDManager(token_identity)
    did_doc = manager.create_did_document()
    did = did_doc["id"]
    metadata = manager.create_token_metadata(did)

    did_valid = manager.verify_did_document(did_doc)
    metadata_valid = manager.verify_metadata(metadata, did)

    return {
        "did_document": did_doc,
        "metadata": metadata,
        "verification": {"did_valid": did_valid, "metadata_valid": metadata_valid},
    }


if __name__ == "__main__":
    result = example_usage()
    print("\nDID Document:")
    print(json.dumps(result["did_document"], indent=2))
    print("\nMetadata:")
    print(json.dumps(result["metadata"], indent=2))
    print("\nVerification Results:")
    print(json.dumps(result["verification"], indent=2))

