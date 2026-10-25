"""
Identity resolution module for Ghost Data Still Exists.
Resolves current and historical user identities across user_identities.csv and user_audit_log.csv.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
import csv


@dataclass
class UserProfile:
    user_id: str
    current_name: str
    current_email: str
    current_phone: str
    current_email_hash: str
    updated_at: str
    all_emails: Set[str] = field(default_factory=set)
    all_phones: Set[str] = field(default_factory=set)
    all_names: Set[str] = field(default_factory=set)
    all_hashes: Set[str] = field(default_factory=set)
    audit_history: List[Dict[str, str]] = field(default_factory=list)

    def matches_any_identifier(self, identifier: str) -> bool:
        if not identifier:
            return False
        clean = identifier.strip().lower()
        if clean in self.all_emails:
            return True
        if identifier.strip() in self.all_phones:
            return True
        if clean in self.all_hashes:
            return True
        if identifier.strip().lower() in [n.lower() for n in self.all_names]:
            return True
        if identifier.strip() == self.user_id:
            return True
        return False


class IdentityResolver:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = Path(dataset_dir)
        self.users_by_id: Dict[str, UserProfile] = {}
        self.email_to_user_id: Dict[str, str] = {}
        self.phone_to_user_id: Dict[str, str] = {}
        self.hash_to_user_id: Dict[str, str] = {}
        self._load_identities()
        self._load_audit_log()

    def _load_identities(self):
        identities_file = self.dataset_dir / "user_identities.csv"
        if not identities_file.exists():
            raise FileNotFoundError(f"Missing {identities_file}")

        with open(identities_file, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"]
                name = row["name"]
                email = row["email"].strip().lower()
                phone = row["phone"].strip()
                email_hash = row["email_hash"].strip().lower()
                updated_at = row["updated_at"]

                profile = UserProfile(
                    user_id=uid,
                    current_name=name,
                    current_email=email,
                    current_phone=phone,
                    current_email_hash=email_hash,
                    updated_at=updated_at,
                    all_emails={email},
                    all_phones={phone} if phone else set(),
                    all_names={name} if name else set(),
                    all_hashes={email_hash} if email_hash else set(),
                )
                self.users_by_id[uid] = profile
                self.email_to_user_id[email] = uid
                if phone:
                    self.phone_to_user_id[phone] = uid
                if email_hash:
                    self.hash_to_user_id[email_hash] = uid

    def _load_audit_log(self):
        audit_file = self.dataset_dir / "user_audit_log.csv"
        if not audit_file.exists():
            return

        with open(audit_file, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"]
                field_name = row["field_name"]
                old_val = row["old_value"].strip()
                new_val = row["new_value"].strip()

                if uid not in self.users_by_id:
                    continue

                profile = self.users_by_id[uid]
                profile.audit_history.append(row)

                if field_name == "email":
                    if old_val:
                        old_lower = old_val.lower()
                        profile.all_emails.add(old_lower)
                        self.email_to_user_id[old_lower] = uid
                    if new_val:
                        new_lower = new_val.lower()
                        profile.all_emails.add(new_lower)
                        self.email_to_user_id[new_lower] = uid

                elif field_name == "phone":
                    if old_val:
                        profile.all_phones.add(old_val)
                        self.phone_to_user_id[old_val] = uid
                    if new_val:
                        profile.all_phones.add(new_val)
                        self.phone_to_user_id[new_val] = uid

                elif field_name == "email_hash":
                    if old_val:
                        old_h = old_val.lower()
                        profile.all_hashes.add(old_h)
                        self.hash_to_user_id[old_h] = uid
                    if new_val:
                        new_h = new_val.lower()
                        profile.all_hashes.add(new_h)
                        self.hash_to_user_id[new_h] = uid

                elif field_name == "name":
                    if old_val:
                        profile.all_names.add(old_val)
                    if new_val:
                        profile.all_names.add(new_val)

    def resolve_by_email(self, email: str) -> Optional[UserProfile]:
        if not email:
            return None
        clean_email = email.strip().lower()
        uid = self.email_to_user_id.get(clean_email)
        if uid and uid in self.users_by_id:
            return self.users_by_id[uid]
        return None

    def resolve_by_user_id(self, user_id: str) -> Optional[UserProfile]:
        return self.users_by_id.get(user_id)

    def resolve_by_identifier(self, identifier: str) -> Optional[UserProfile]:
        if not identifier:
            return None
        clean = identifier.strip()
        # Try user_id
        if clean in self.users_by_id:
            return self.users_by_id[clean]
        # Try email
        clean_email = clean.lower()
        if clean_email in self.email_to_user_id:
            return self.users_by_id[self.email_to_user_id[clean_email]]
        # Try phone
        if clean in self.phone_to_user_id:
            return self.users_by_id[self.phone_to_user_id[clean]]
        # Try hash
        if clean_email in self.hash_to_user_id:
            return self.users_by_id[self.hash_to_user_id[clean_email]]
        return None
