from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class TokenIdentity:
    """Represents identity information for a token collection or individual token.

    - policy_id: Optional Cardano policy id (company DID does not require it)
    - collection_name: Collection name used as metadata key
    - asset_name: Optional individual token asset name
    - social_accounts: Mapping like {"twitter": [..], "discord": [..]}
    - website: List of website URLs/domains
    - rwa_details: Optional dict with keys like assetType, jurisdiction, registrationNumber
    - extra_payload: Optional dict merged into DID payload prior to signing
    """

    policy_id: Optional[str]
    collection_name: str
    asset_name: Optional[str]
    social_accounts: Dict[str, List[str]]
    website: List[str]
    rwa_details: Optional[Dict[str, Any]] = None
    extra_payload: Optional[Dict[str, Any]] = None
