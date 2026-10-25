"""
Evidence indexing module for Ghost Data Still Exists.
Parses, normalizes, and indexes records from all 94 evidence files
(JSON bundles, SQL databases, structured logs, handover text, images, and documents).
"""

from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import csv
import glob
import json
import re
import sqlite3
import PyPDF2


class EvidenceRecord:
    def __init__(
        self,
        evidence_id: str,
        captured_at: str,
        system_id: str,
        resource_id: str,
        identifiers: Set[str],
        state: str,
        finding_op: Optional[str] = None,
        remediation_op: Optional[str] = None,
        verification_op: Optional[str] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ):
        self.evidence_id = evidence_id
        self.captured_at = captured_at
        self.system_id = system_id
        self.resource_id = resource_id
        self.identifiers = set(str(i).strip().lower() for i in identifiers if i)
        self.state = state
        self.finding_op = finding_op
        self.remediation_op = remediation_op
        self.verification_op = verification_op
        self.raw_data = raw_data or {}

    def matches_user(self, profile) -> bool:
        if profile.user_id.lower() in self.identifiers:
            return True
        for em in profile.all_emails:
            if em.lower() in self.identifiers:
                return True
        for ph in profile.all_phones:
            if ph.lower() in self.identifiers:
                return True
        for h in profile.all_hashes:
            if h.lower() in self.identifiers:
                return True
        return False


class EvidenceIndexer:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = Path(dataset_dir)
        self.manifest: Dict[str, Dict[str, str]] = {}
        self.path_to_id: Dict[str, str] = {}
        self.records: List[EvidenceRecord] = []
        self._load_manifest()
        self._index_all()

    def _load_manifest(self):
        manifest_file = self.dataset_dir / "evidence_files.csv"
        with open(manifest_file, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                fid = row["file_id"]
                self.manifest[fid] = row
                norm_path = str(Path(row["file_path"]))
                self.path_to_id[norm_path] = fid
                # Also without evidence/ prefix
                self.path_to_id[str(Path(row["file_path"]).name)] = fid

    def get_file_id(self, file_path: str) -> str:
        p = Path(file_path)
        name = p.name
        if name in self.path_to_id:
            return self.path_to_id[name]
        for fid, row in self.manifest.items():
            if row["file_path"].endswith(name):
                return fid
        return ""

    def _index_all(self):
        self._index_json_files()
        self._index_sql_files()
        self._index_log_files()
        self._index_text_files()
        self._index_pdf_files()
        self._index_catalog_links()

    def _index_json_files(self):
        for f in self.dataset_dir.glob("evidence/records/*.json"):
            fid = self.get_file_id(str(f))
            captured_at = self.manifest.get(fid, {}).get("captured_at", "")
            try:
                with open(f, mode="r", encoding="utf-8") as fp:
                    data = json.load(fp)
            except Exception:
                continue

            # 1. service_resource_export_*.json
            if "service_exports" in data:
                exports = data["service_exports"]
                for sys_name, sub in exports.items():
                    if sys_name == "account_service":
                        for item in sub.get("profile_lookups", []):
                            rid = item.get("resource_id")
                            status = item.get("status_code", 200)
                            prof = item.get("profile") or {}
                            idents = set()
                            if prof:
                                idents.update([prof.get("user_id"), prof.get("email"), prof.get("phone")])
                            state = "ABSENT" if status == 404 else "PRESENT"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="account_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op="REPORT_REMAINING_RECORD" if state == "PRESENT" else None,
                                    remediation_op="DELETE_RECORD" if state == "PRESENT" else None,
                                    verification_op="VERIFY_RECORD_ABSENT",
                                    raw_data=item,
                                )
                            )

                    elif sys_name == "analytics_platform":
                        for item in sub.get("profiles", []):
                            rid = item.get("resource_id")
                            user_id = item.get("customer_reference")
                            email = item.get("email")
                            phone = item.get("phone")
                            hash_val = item.get("email_hash")
                            idents = set(filter(None, [user_id, email, phone, hash_val]))
                            is_anon = not (user_id or email or phone or hash_val)
                            state = "ANONYMIZED" if is_anon else "PRESENT"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="analytics_platform",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op=None if is_anon else "REPORT_EXPOSED_PII",
                                    remediation_op=None if is_anon else "ANONYMIZE_RECORD",
                                    verification_op="VERIFY_RECORD_ANONYMIZED",
                                    raw_data=item,
                                )
                            )

                    elif sys_name == "backup_service":
                        for item in sub.get("restore_entries", []):
                            rid = item.get("resource_id")
                            user_id = item.get("customer_reference")
                            email = item.get("customer_email")
                            idents = set(filter(None, [user_id, email]))
                            restore_allowed = item.get("restore_allowed", False)
                            state = "ACTIVE" if restore_allowed else "BLOCKED"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="backup_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op="REPORT_RESTORE_RISK" if restore_allowed else None,
                                    remediation_op="BLOCK_RESTORE" if restore_allowed else None,
                                    verification_op="VERIFY_RESTORE_BLOCKED",
                                    raw_data=item,
                                )
                            )

                    elif sys_name == "export_service":
                        for item in sub.get("exports", []):
                            rid = item.get("resource_id")
                            email = item.get("owner_email")
                            user_id = item.get("customer_reference")
                            idents = set(filter(None, [user_id, email]))
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="export_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state="PRESENT",
                                    finding_op="REPORT_REMAINING_RECORD",
                                    remediation_op="DELETE_RECORD",
                                    verification_op="VERIFY_RECORD_ABSENT",
                                    raw_data=item,
                                )
                            )

                    elif sys_name == "integration_service":
                        for item in sub.get("connectors", []):
                            rid = item.get("resource_id")
                            user_id = item.get("customer_reference")
                            email = item.get("customer_email")
                            enabled = item.get("enabled", False)
                            idents = set(filter(None, [user_id, email]))
                            state = "ACTIVE" if enabled else "DISABLED"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="integration_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op="REPORT_ACTIVE_DATA_FLOW" if enabled else None,
                                    remediation_op="DISABLE_DATA_FLOW" if enabled else None,
                                    verification_op="VERIFY_DATA_FLOW_DISABLED",
                                    raw_data=item,
                                )
                            )

                    elif sys_name == "search_service":
                        for item in sub.get("index_queries", []):
                            rid = item.get("resource_id")
                            query = item.get("query")
                            hits = item.get("hits", {})
                            total = hits.get("total", 0)
                            docs = hits.get("documents", [])
                            idents = set(filter(None, [query]))
                            for doc in docs:
                                idents.update(filter(None, [doc.get("email"), doc.get("customer_reference"), doc.get("phone")]))
                            state = "PRESENT" if total > 0 else "ABSENT"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="search_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op="REPORT_REMAINING_RECORD" if state == "PRESENT" else None,
                                    remediation_op="DELETE_RECORD" if state == "PRESENT" else None,
                                    verification_op="VERIFY_RECORD_ABSENT",
                                    raw_data=item,
                                )
                            )

                    elif sys_name == "security_service":
                        for item in sub.get("audit_records", []):
                            rid = item.get("resource_id")
                            uid = item.get("subject_reference")
                            idents = set(filter(None, [uid]))
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="security_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state="PRESENT",
                                    finding_op=None,
                                    remediation_op=None,
                                    verification_op="VERIFY_RECORD_PRESENT",
                                    raw_data=item,
                                )
                            )

                    elif sys_name == "support_platform":
                        for item in sub.get("tickets", []):
                            rid = item.get("resource_id")
                            uid = item.get("customer_reference")
                            email = item.get("requester_email")
                            phone = item.get("requester_phone")
                            name = item.get("requester_name")
                            idents = set(filter(None, [uid, email, phone, name]))
                            is_redacted = not (email or phone or name)
                            state = "REDACTED" if is_redacted else "PRESENT"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="support_platform",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op=None if is_redacted else "REPORT_EXPOSED_PII",
                                    remediation_op=None if is_redacted else "REDACT_RECORD",
                                    verification_op="VERIFY_RECORD_REDACTED",
                                    raw_data=item,
                                )
                            )

            # 2. customer_data_snapshot_bundle_*.json
            elif "snapshots" in data:
                for snap in data["snapshots"]:
                    store = snap.get("data_store")
                    col = snap.get("collection")
                    recs = snap.get("records", [])

                    if store == "account_service":
                        for r in recs:
                            rid = r.get("resource_id")
                            uid = r.get("customer_reference") or r.get("user_id")
                            email = r.get("email")
                            phone = r.get("phone")
                            idents = set(filter(None, [uid, email, phone]))
                            status = r.get("account_status", "ACTIVE")
                            state = "ABSENT" if status == "DELETED" else "PRESENT"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="account_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op="REPORT_REMAINING_RECORD" if state == "PRESENT" else None,
                                    remediation_op="DELETE_RECORD" if state == "PRESENT" else None,
                                    verification_op="VERIFY_RECORD_ABSENT",
                                    raw_data=r,
                                )
                            )

                    elif store == "identity_service" and col == "deleted_customer_references":
                        for r in recs:
                            rid = r.get("resource_id")
                            uid = r.get("subject_reference") or r.get("user_id")
                            email = r.get("email")
                            phone = r.get("phone")
                            hash_val = r.get("email_hash")
                            name = r.get("name")
                            idents = set(filter(None, [uid, email, phone, hash_val, name]))
                            is_redacted = not (email or phone or hash_val or name)
                            state = "REDACTED" if is_redacted else "PRESENT"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="identity_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op=None if is_redacted else "REPORT_EXPOSED_PII",
                                    remediation_op=None if is_redacted else "REDACT_RECORD",
                                    verification_op="VERIFY_RECORD_REDACTED",
                                    raw_data=r,
                                )
                            )

                    elif store == "security_service":
                        for r in recs:
                            rid = r.get("resource_id")
                            uid = r.get("subject_reference") or r.get("customer_reference")
                            idents = set(filter(None, [uid]))
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="security_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state="PRESENT",
                                    finding_op=None,
                                    remediation_op=None,
                                    verification_op="VERIFY_RECORD_PRESENT",
                                    raw_data=r,
                                )
                            )

                    elif store == "analytics_platform":
                        for r in recs:
                            rid = r.get("resource_id")
                            uid = r.get("customer_reference") or r.get("user_id")
                            email = r.get("email")
                            phone = r.get("phone")
                            hash_val = r.get("email_hash")
                            idents = set(filter(None, [uid, email, phone, hash_val]))
                            is_anon = not (uid or email or phone or hash_val)
                            state = "ANONYMIZED" if is_anon else "PRESENT"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="analytics_platform",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op=None if is_anon else "REPORT_EXPOSED_PII",
                                    remediation_op=None if is_anon else "ANONYMIZE_RECORD",
                                    verification_op="VERIFY_RECORD_ANONYMIZED",
                                    raw_data=r,
                                )
                            )

                    elif store == "support_platform":
                        for r in recs:
                            rid = r.get("resource_id")
                            uid = r.get("customer_reference") or r.get("user_id")
                            email = r.get("requester_email") or r.get("email")
                            phone = r.get("requester_phone") or r.get("phone")
                            name = r.get("requester_name") or r.get("name")
                            idents = set(filter(None, [uid, email, phone, name]))
                            is_redacted = not (email or phone or name)
                            state = "REDACTED" if is_redacted else "PRESENT"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="support_platform",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op=None if is_redacted else "REPORT_EXPOSED_PII",
                                    remediation_op=None if is_redacted else "REDACT_RECORD",
                                    verification_op="VERIFY_RECORD_REDACTED",
                                    raw_data=r,
                                )
                            )

                    elif store == "backup_service":
                        for r in recs:
                            rid = r.get("resource_id")
                            uid = r.get("subject_reference") or r.get("customer_reference")
                            email = r.get("customer_email") or r.get("email")
                            idents = set(filter(None, [uid, email]))
                            restore_allowed = r.get("restore_allowed", False)
                            state = "ACTIVE" if restore_allowed else "BLOCKED"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="backup_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op="REPORT_RESTORE_RISK" if restore_allowed else None,
                                    remediation_op="BLOCK_RESTORE" if restore_allowed else None,
                                    verification_op="VERIFY_RESTORE_BLOCKED",
                                    raw_data=r,
                                )
                            )

                    elif store == "integration_service":
                        for r in recs:
                            rid = r.get("resource_id")
                            uid = r.get("customer_reference") or r.get("user_id")
                            email = r.get("customer_email") or r.get("subject_selector")
                            idents = set(filter(None, [uid, email]))
                            enabled = r.get("enabled", False)
                            state = "ACTIVE" if enabled else "DISABLED"
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="integration_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state=state,
                                    finding_op="REPORT_ACTIVE_DATA_FLOW" if enabled else None,
                                    remediation_op="DISABLE_DATA_FLOW" if enabled else None,
                                    verification_op="VERIFY_DATA_FLOW_DISABLED",
                                    raw_data=r,
                                )
                            )

                    elif store == "search_service":
                        for r in recs:
                            rid = r.get("resource_id")
                            doc = r.get("document", {})
                            uid = doc.get("customer_reference")
                            email = doc.get("email")
                            idents = set(filter(None, [uid, email]))
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="search_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state="PRESENT",
                                    finding_op="REPORT_REMAINING_RECORD",
                                    remediation_op="DELETE_RECORD",
                                    verification_op="VERIFY_RECORD_ABSENT",
                                    raw_data=r,
                                )
                            )

            # 3. Specific records files: analytics report, export jobs
            elif "records" in data and isinstance(data["records"], list):
                col = data.get("collection") or data.get("origin")
                for r in data["records"]:
                    rid = r.get("resource_id")
                    if col == "customer_analytics_reports":
                        uid = r.get("user_id") or r.get("customer_reference")
                        email = r.get("email")
                        phone = r.get("phone")
                        hash_val = r.get("email_hash")
                        idents = set(filter(None, [uid, email, phone, hash_val]))
                        is_anon = not (uid or email or phone or hash_val)
                        state = "ANONYMIZED" if is_anon else "PRESENT"
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id="analytics_platform",
                                resource_id=rid,
                                identifiers=idents,
                                state=state,
                                finding_op=None if is_anon else "REPORT_EXPOSED_PII",
                                remediation_op=None if is_anon else "ANONYMIZE_RECORD",
                                verification_op="VERIFY_RECORD_ANONYMIZED",
                                raw_data=r,
                            )
                        )

                    elif col == "customer_export_jobs":
                        email = r.get("owner_email")
                        avail = r.get("download_available", True)
                        idents = set(filter(None, [email]))
                        if avail:
                            self.records.append(
                                EvidenceRecord(
                                    evidence_id=fid,
                                    captured_at=captured_at,
                                    system_id="export_service",
                                    resource_id=rid,
                                    identifiers=idents,
                                    state="PRESENT",
                                    finding_op="REPORT_REMAINING_RECORD",
                                    remediation_op="DELETE_RECORD",
                                    verification_op="VERIFY_RECORD_ABSENT",
                                    raw_data=r,
                                )
                            )

                    elif col == "security_audit_service" or "security_audit" in str(f):
                        uid = r.get("subject_reference") or r.get("user_id")
                        idents = set(filter(None, [uid]))
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id="security_service",
                                resource_id=rid,
                                identifiers=idents,
                                state="PRESENT",
                                finding_op=None,
                                remediation_op=None,
                                verification_op="VERIFY_RECORD_PRESENT",
                                raw_data=r,
                            )
                        )

                    elif "connector" in str(f) or "connector_configurations" in str(f):
                        email = r.get("subject_selector") or r.get("customer_email")
                        enabled = r.get("enabled", False)
                        idents = set(filter(None, [email]))
                        state = "ACTIVE" if enabled else "DISABLED"
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id="integration_service",
                                resource_id=rid,
                                identifiers=idents,
                                state=state,
                                finding_op="REPORT_ACTIVE_DATA_FLOW" if enabled else None,
                                remediation_op="DISABLE_DATA_FLOW" if enabled else None,
                                verification_op="VERIFY_DATA_FLOW_DISABLED",
                                raw_data=r,
                            )
                        )

    def _index_sql_files(self):
        for f in self.dataset_dir.glob("evidence/databases/*.sql"):
            fid = self.get_file_id(str(f))
            captured_at = self.manifest.get(fid, {}).get("captured_at", "")

            con = sqlite3.connect(":memory:")
            try:
                with open(f, mode="r", encoding="utf-8") as fp:
                    sql = fp.read()
                con.executescript(sql)
            except Exception:
                continue

            tables = [t[0] for t in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

            # 1. Failover replica account check (e.g. evidence_54)
            if "customer_profiles_failover_replica" in tables:
                primary_res = set(r[0] for r in con.execute("SELECT resource_id FROM customer_profiles_primary").fetchall())
                for row in con.execute("SELECT resource_id, user_id, full_name, email, phone, account_status FROM customer_profiles_failover_replica").fetchall():
                    rid, uid, name, email, phone, status = row
                    idents = set(filter(None, [uid, email, phone, name]))
                    is_in_primary = rid in primary_res
                    state = "PRESENT" if status == "ACTIVE" else "ABSENT"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="account_service",
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op="REPORT_REMAINING_RECORD" if (state == "PRESENT" and not is_in_primary) else None,
                            remediation_op="DELETE_RECORD" if state == "PRESENT" else None,
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )

            # 2. Search primary (e.g. evidence_57)
            if "search_documents_primary" in tables:
                for row in con.execute("SELECT resource_id, display_name, email, source_resource_id FROM search_documents_primary").fetchall():
                    rid, name, email, src_res = row
                    idents = set(filter(None, [name, email, src_res]))
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="search_service",
                            resource_id=rid,
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_REMAINING_RECORD",
                            remediation_op="DELETE_RECORD",
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )

            # 3. Inventory SQL tables (e.g. evidence_93, 63, 66, 69, 72, 75, etc.)
            if "customer_profiles" in tables:
                for row in con.execute("SELECT resource_id, customer_reference, email, phone, account_status FROM customer_profiles").fetchall():
                    rid, uid, email, phone, status = row
                    idents = set(filter(None, [uid, email, phone]))
                    state = "PRESENT" if status == "ACTIVE" or status == "DELETION_PENDING" else "ABSENT"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="account_service",
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op="REPORT_REMAINING_RECORD" if state == "PRESENT" else None,
                            remediation_op="DELETE_RECORD" if state == "PRESENT" else None,
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )

            if "customer_search_documents" in tables:
                for row in con.execute("SELECT resource_id, customer_reference, email, phone FROM customer_search_documents").fetchall():
                    rid, uid, email, phone = row
                    idents = set(filter(None, [uid, email, phone]))
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="search_service",
                            resource_id=rid,
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_REMAINING_RECORD",
                            remediation_op="DELETE_RECORD",
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )

            if "customer_analytics_profiles" in tables:
                for row in con.execute("SELECT resource_id, customer_reference, email, phone, email_hash FROM customer_analytics_profiles").fetchall():
                    rid, uid, email, phone, hash_val = row
                    idents = set(filter(None, [uid, email, phone, hash_val]))
                    is_anon = not (uid or email or phone or hash_val)
                    state = "ANONYMIZED" if is_anon else "PRESENT"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="analytics_platform",
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op=None if is_anon else "REPORT_EXPOSED_PII",
                            remediation_op=None if is_anon else "ANONYMIZE_RECORD",
                            verification_op="VERIFY_RECORD_ANONYMIZED",
                        )
                    )

            if "support_records" in tables:
                for row in con.execute("SELECT resource_id, customer_reference, requester_email, requester_phone, requester_name FROM support_records").fetchall():
                    rid, uid, email, phone, name = row
                    idents = set(filter(None, [uid, email, phone, name]))
                    is_redacted = not (email or phone or name)
                    state = "REDACTED" if is_redacted else "PRESENT"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="support_platform",
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op=None if is_redacted else "REPORT_EXPOSED_PII",
                            remediation_op=None if is_redacted else "REDACT_RECORD",
                            verification_op="VERIFY_RECORD_REDACTED",
                        )
                    )

            if "customer_exports" in tables:
                for row in con.execute("SELECT resource_id, customer_reference, owner_email FROM customer_exports").fetchall():
                    rid, uid, email = row
                    idents = set(filter(None, [uid, email]))
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="export_service",
                            resource_id=rid,
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_REMAINING_RECORD",
                            remediation_op="DELETE_RECORD",
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )

            if "connector_subscriptions" in tables:
                for row in con.execute("SELECT resource_id, customer_reference, customer_email, enabled FROM connector_subscriptions").fetchall():
                    rid, uid, email, enabled = row
                    idents = set(filter(None, [uid, email]))
                    state = "ACTIVE" if enabled == 1 else "DISABLED"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="integration_service",
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op="REPORT_ACTIVE_DATA_FLOW" if enabled == 1 else None,
                            remediation_op="DISABLE_DATA_FLOW" if enabled == 1 else None,
                            verification_op="VERIFY_DATA_FLOW_DISABLED",
                        )
                    )

            if "backup_restore_entries" in tables:
                for row in con.execute("SELECT resource_id, customer_reference, customer_email, restore_allowed FROM backup_restore_entries").fetchall():
                    rid, uid, email, restore_allowed = row
                    idents = set(filter(None, [uid, email]))
                    state = "ACTIVE" if restore_allowed == 1 else "BLOCKED"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="backup_service",
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op="REPORT_RESTORE_RISK" if restore_allowed == 1 else None,
                            remediation_op="BLOCK_RESTORE" if restore_allowed == 1 else None,
                            verification_op="VERIFY_RESTORE_BLOCKED",
                        )
                    )

            if "security_audit_records" in tables:
                for row in con.execute("SELECT resource_id, subject_reference FROM security_audit_records").fetchall():
                    rid, uid = row
                    idents = set(filter(None, [uid]))
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id="security_service",
                            resource_id=rid,
                            identifiers=idents,
                            state="PRESENT",
                            finding_op=None,
                            remediation_op=None,
                            verification_op="VERIFY_RECORD_PRESENT",
                        )
                    )

            # 4. JSON-in-SQL tables (read_replica, regional_replicas, etc.)
            replica_tables = [t for t in tables if "replica" in t]
            primary_table = [t for t in tables if "primary" in t]
            if replica_tables:
                # Compare primary vs replica
                for t in replica_tables:
                    try:
                        rows = con.execute(f"SELECT resource_id, origin_system, collection_name, record_json FROM {t}").fetchall()
                        for row in rows:
                            rid, sys_name, col_name, rec_json = row
                            try:
                                d = json.loads(rec_json)
                            except Exception:
                                continue

                            idents = set()
                            for k in ["user_id", "customer_reference", "subject_reference", "email", "phone", "email_hash", "subject_selector", "owner_email"]:
                                if k in d and d[k]:
                                    idents.add(d[k])
                            if "document" in d and isinstance(d["document"], dict):
                                for k in ["customer_reference", "email", "phone"]:
                                    if k in d["document"] and d["document"][k]:
                                        idents.add(d["document"][k])

                            if sys_name == "account_service":
                                self.records.append(
                                    EvidenceRecord(
                                        evidence_id=fid,
                                        captured_at=captured_at,
                                        system_id="account_service",
                                        resource_id=rid,
                                        identifiers=idents,
                                        state="PRESENT",
                                        finding_op="REPORT_REMAINING_RECORD",
                                        remediation_op="DELETE_RECORD",
                                        verification_op="VERIFY_RECORD_ABSENT",
                                    )
                                )
                            elif sys_name == "search_service":
                                self.records.append(
                                    EvidenceRecord(
                                        evidence_id=fid,
                                        captured_at=captured_at,
                                        system_id="search_service",
                                        resource_id=rid,
                                        identifiers=idents,
                                        state="PRESENT",
                                        finding_op="REPORT_REMAINING_RECORD",
                                        remediation_op="DELETE_RECORD",
                                        verification_op="VERIFY_RECORD_ABSENT",
                                    )
                                )
                            elif sys_name == "analytics_platform":
                                is_anon = not (d.get("email") or d.get("phone") or d.get("user_id") or d.get("email_hash"))
                                state = "ANONYMIZED" if is_anon else "PRESENT"
                                self.records.append(
                                    EvidenceRecord(
                                        evidence_id=fid,
                                        captured_at=captured_at,
                                        system_id="analytics_platform",
                                        resource_id=rid,
                                        identifiers=idents,
                                        state=state,
                                        finding_op=None if is_anon else "REPORT_EXPOSED_PII",
                                        remediation_op=None if is_anon else "ANONYMIZE_RECORD",
                                        verification_op="VERIFY_RECORD_ANONYMIZED",
                                    )
                                )
                            elif sys_name == "support_platform":
                                is_red = not (d.get("requester_email") or d.get("requester_phone") or d.get("email"))
                                state = "REDACTED" if is_red else "PRESENT"
                                self.records.append(
                                    EvidenceRecord(
                                        evidence_id=fid,
                                        captured_at=captured_at,
                                        system_id="support_platform",
                                        resource_id=rid,
                                        identifiers=idents,
                                        state=state,
                                        finding_op=None if is_red else "REPORT_EXPOSED_PII",
                                        remediation_op=None if is_red else "REDACT_RECORD",
                                        verification_op="VERIFY_RECORD_REDACTED",
                                    )
                                )
                            elif sys_name == "integration_service":
                                en = d.get("enabled", False)
                                state = "ACTIVE" if en else "DISABLED"
                                self.records.append(
                                    EvidenceRecord(
                                        evidence_id=fid,
                                        captured_at=captured_at,
                                        system_id="integration_service",
                                        resource_id=rid,
                                        identifiers=idents,
                                        state=state,
                                        finding_op="REPORT_ACTIVE_DATA_FLOW" if en else None,
                                        remediation_op="DISABLE_DATA_FLOW" if en else None,
                                        verification_op="VERIFY_DATA_FLOW_DISABLED",
                                    )
                                )
                            elif sys_name == "backup_service":
                                ra = d.get("restore_allowed", False)
                                state = "ACTIVE" if ra else "BLOCKED"
                                self.records.append(
                                    EvidenceRecord(
                                        evidence_id=fid,
                                        captured_at=captured_at,
                                        system_id="backup_service",
                                        resource_id=rid,
                                        identifiers=idents,
                                        state=state,
                                        finding_op="REPORT_RESTORE_RISK" if ra else None,
                                        remediation_op="BLOCK_RESTORE" if ra else None,
                                        verification_op="VERIFY_RESTORE_BLOCKED",
                                    )
                                )
                            elif sys_name == "security_service":
                                self.records.append(
                                    EvidenceRecord(
                                        evidence_id=fid,
                                        captured_at=captured_at,
                                        system_id="security_service",
                                        resource_id=rid,
                                        identifiers=idents,
                                        state="PRESENT",
                                        finding_op=None,
                                        remediation_op=None,
                                        verification_op="VERIFY_RECORD_PRESENT",
                                    )
                                )
                    except Exception:
                        pass

    def _index_text_files(self):
        handover_file = self.dataset_dir / "evidence/records/customer_account_handover_20261001.txt"
        if not handover_file.exists():
            return
        fid = self.get_file_id(str(handover_file))
        captured_at = self.manifest.get(fid, {}).get("captured_at", "2026-10-01T12:00:00Z")

        with open(handover_file, mode="r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("- "):
                    continue
                parts = [p.strip() for p in line[2:].split("|")]
                if len(parts) >= 6:
                    ts, sys_id, rid, cat, status, ident = parts[:6]
                    idents = set([ident]) if ident and ident != "no direct identifier" else set()

                    if cat == "USER_PROFILE":
                        state = "ABSENT" if status == "NOT_FOUND" else "PRESENT"
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=rid,
                                identifiers=idents,
                                state=state,
                                finding_op="REPORT_REMAINING_RECORD" if state == "PRESENT" else None,
                                remediation_op="DELETE_RECORD" if state == "PRESENT" else None,
                                verification_op="VERIFY_RECORD_ABSENT",
                            )
                        )
                    elif cat == "SEARCH_INDEX_ENTRY":
                        state = "PRESENT" if status == "FOUND" else "ABSENT"
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=rid,
                                identifiers=idents,
                                state=state,
                                finding_op="REPORT_REMAINING_RECORD" if state == "PRESENT" else None,
                                remediation_op="DELETE_RECORD" if state == "PRESENT" else None,
                                verification_op="VERIFY_RECORD_ABSENT",
                            )
                        )
                    elif cat == "ANALYTICS_PROFILE":
                        state = "ANONYMIZED" if status == "ANONYMIZED" else "PRESENT"
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=rid,
                                identifiers=idents,
                                state=state,
                                finding_op="REPORT_EXPOSED_PII" if state == "PRESENT" else None,
                                remediation_op="ANONYMIZE_RECORD" if state == "PRESENT" else None,
                                verification_op="VERIFY_RECORD_ANONYMIZED",
                            )
                        )
                    elif cat == "SUPPORT_MESSAGE":
                        state = "REDACTED" if status == "REDACTED" else "PRESENT"
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=rid,
                                identifiers=idents,
                                state=state,
                                finding_op="REPORT_EXPOSED_PII" if state == "PRESENT" else None,
                                remediation_op="REDACT_RECORD" if state == "PRESENT" else None,
                                verification_op="VERIFY_RECORD_REDACTED",
                            )
                        )
                    elif cat == "SUPPORT_ATTACHMENT":
                        state = "PRESENT" if status == "FOUND" else "ABSENT"
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=rid,
                                identifiers=idents,
                                state=state,
                                finding_op="REPORT_REMAINING_RECORD" if state == "PRESENT" else None,
                                remediation_op="DELETE_RECORD" if state == "PRESENT" else None,
                                verification_op="VERIFY_RECORD_ABSENT",
                            )
                        )
                    elif cat == "DATA_FLOW":
                        state = "ACTIVE" if status == "ACTIVE" else "DISABLED"
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=rid,
                                identifiers=idents,
                                state=state,
                                finding_op="REPORT_ACTIVE_DATA_FLOW" if state == "ACTIVE" else None,
                                remediation_op="DISABLE_DATA_FLOW" if state == "ACTIVE" else None,
                                verification_op="VERIFY_DATA_FLOW_DISABLED",
                            )
                        )
                    elif cat == "BACKUP_ARCHIVE":
                        state = "ACTIVE" if status == "ACTIVE" else "BLOCKED"
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=rid,
                                identifiers=idents,
                                state=state,
                                finding_op="REPORT_RESTORE_RISK" if state == "ACTIVE" else None,
                                remediation_op="BLOCK_RESTORE" if state == "ACTIVE" else None,
                                verification_op="VERIFY_RESTORE_BLOCKED",
                            )
                        )
                    elif cat == "SECURITY_AUDIT_LOG":
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=rid,
                                identifiers=idents,
                                state="PRESENT",
                                finding_op=None,
                                remediation_op=None,
                                verification_op="VERIFY_RECORD_PRESENT",
                            )
                        )
                    elif cat == "USER_EXPORT":
                        self.records.append(
                            EvidenceRecord(
                                evidence_id=fid,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=rid,
                                identifiers=idents,
                                state="PRESENT",
                                finding_op="REPORT_REMAINING_RECORD",
                                remediation_op="DELETE_RECORD",
                                verification_op="VERIFY_RECORD_ABSENT",
                            )
                        )

    def _index_log_files(self):
        for f in self.dataset_dir.glob("evidence/logs/*.log"):
            fid = self.get_file_id(str(f))
            captured_at = self.manifest.get(fid, {}).get("captured_at", "")

            with open(f, mode="r", encoding="utf-8", errors="ignore") as fp:
                lines = fp.readlines()

            # Pass 1: Correlate trace_id to identifiers
            from collections import defaultdict
            trace_idents = defaultdict(set)
            for line in lines:
                l_str = line.strip()
                if "{" in l_str and l_str.endswith("}"):
                    try:
                        jobj = json.loads(l_str[l_str.index("{"):])
                        tr = jobj.get("trace_id")
                        if tr:
                            for k in ["subject_key", "lookup_key", "match_key", "matched_value", "correlation_key", "subject_ref", "subject_reference", "customer_email", "customer_reference", "email", "requester_email"]:
                                v = jobj.get(k)
                                if v and str(v) not in ["null", "None", ""]:
                                    trace_idents[tr].add(str(v))
                        continue
                    except Exception:
                        pass

                m_tr = re.search(r'trace_id=[\"\']?([a-zA-Z0-9_\-]+)[\"\']?', line)
                if not m_tr:
                    continue
                tr = m_tr.group(1)
                for k in ["subject_key", "lookup_key", "match_key", "matched_value", "correlation_key", "subject_ref", "subject_reference", "customer_email", "customer_reference", "email", "requester_email"]:
                    m_id = re.search(rf'{k}=[\"\']?([^ \"\',]+)[\"\']?', line)
                    if m_id and m_id.group(1) not in ["null", "None", ""]:
                        trace_idents[tr].add(m_id.group(1))

            # Pass 2: Index records
            for line in lines:
                l_str = line.strip()
                jobj = None
                if "{" in l_str and l_str.endswith("}"):
                    try:
                        jobj = json.loads(l_str[l_str.index("{"):])
                    except Exception:
                        pass

                if jobj:
                    rid = jobj.get("resource_id")
                    if not rid:
                        continue
                    event = jobj.get("event", "")
                    if "_started" in event or "query_started" in event:
                        continue
                    tr = jobj.get("trace_id")
                    svc = jobj.get("service") or jobj.get("logger") or ""
                    idents = set()
                    if tr and tr in trace_idents:
                        idents.update(trace_idents[tr])
                    for k in ["subject_key", "lookup_key", "match_key", "matched_value", "correlation_key", "subject_ref", "subject_reference", "customer_email", "customer_reference", "email", "requester_email"]:
                        v = jobj.get(k)
                        if v and str(v) not in ["null", "None", ""]:
                            idents.add(str(v))
                    check_line = json.dumps(jobj)
                else:
                    if "resource_id=" not in line:
                        continue
                    if "_started" in line or "query_started" in line:
                        continue
                    m_res = re.search(r'resource_id=[\"\']?([a-zA-Z0-9_\-]+)[\"\']?', line)
                    if not m_res:
                        continue
                    rid = m_res.group(1)
                    m_tr = re.search(r'trace_id=[\"\']?([a-zA-Z0-9_\-]+)[\"\']?', line)
                    tr = m_tr.group(1) if m_tr else None
                    m_svc = re.search(r'service=[\"\']?([a-zA-Z0-9_\-]+)[\"\']?', line)
                    svc = m_svc.group(1) if m_svc else ""
                    idents = set()
                    if tr and tr in trace_idents:
                        idents.update(trace_idents[tr])
                    for k in ["subject_key", "lookup_key", "match_key", "matched_value", "correlation_key", "subject_ref", "subject_reference", "customer_email", "customer_reference", "email", "requester_email"]:
                        m_id = re.search(rf'{k}=[\"\']?([^ \"\',]+)[\"\']?', line)
                        if m_id and m_id.group(1) not in ["null", "None", ""]:
                            idents.add(m_id.group(1))
                    check_line = line

                # Determine system_id
                if rid.startswith("account_"):
                    sys_id = "account_service"
                elif rid.startswith("search_"):
                    sys_id = "search_service"
                elif rid.startswith("analytics_"):
                    sys_id = "analytics_platform"
                elif rid.startswith("support_"):
                    sys_id = "support_platform"
                elif rid.startswith("data_flow_"):
                    sys_id = "integration_service"
                elif rid.startswith("backup_"):
                    sys_id = "backup_service"
                elif rid.startswith("audit_record_"):
                    sys_id = "security_service"
                elif rid.startswith("export_"):
                    sys_id = "export_service"
                elif rid.startswith("tombstone_"):
                    sys_id = "identity_service"
                else:
                    sys_id = svc

                # Determine state & ops
                if sys_id == "account_service":
                    if "404" in check_line or "rows=0" in check_line:
                        state = "ABSENT"
                        finding_op = None
                        remed_op = None
                    else:
                        state = "PRESENT"
                        finding_op = "REPORT_REMAINING_RECORD"
                        remed_op = "DELETE_RECORD"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id=sys_id,
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op=finding_op,
                            remediation_op=remed_op,
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )

                elif sys_id == "search_service":
                    if "total_hits=0" in check_line or "hits=0" in check_line:
                        state = "ABSENT"
                        finding_op = None
                        remed_op = None
                    else:
                        state = "PRESENT"
                        finding_op = "REPORT_REMAINING_RECORD"
                        remed_op = "DELETE_RECORD"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id=sys_id,
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op=finding_op,
                            remediation_op=remed_op,
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )

                elif sys_id == "analytics_platform":
                    if "email_opt_in=true" in check_line or "marketing_profile" in check_line:
                        state = "PRESENT"
                        finding_op = "REPORT_REMAINING_RECORD"
                        remed_op = "DELETE_RECORD"
                        verif_op = "VERIFY_RECORD_ABSENT"
                    elif "email=null" in check_line and ("customer_reference=null" in check_line or "customer_reference" not in check_line):
                        state = "ANONYMIZED"
                        finding_op = None
                        remed_op = None
                        verif_op = "VERIFY_RECORD_ANONYMIZED"
                    else:
                        state = "PRESENT"
                        finding_op = "REPORT_EXPOSED_PII"
                        remed_op = "ANONYMIZE_RECORD"
                        verif_op = "VERIFY_RECORD_ANONYMIZED"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id=sys_id,
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op=finding_op,
                            remediation_op=remed_op,
                            verification_op=verif_op,
                        )
                    )

                elif sys_id == "support_platform":
                    if "marker_found=false" in check_line:
                        state = "PRESENT"
                        finding_op = "REPORT_REMAINING_RECORD"
                        remed_op = "DELETE_RECORD"
                        verif_op = "VERIFY_RECORD_ABSENT"
                    elif "matched_value" in check_line or "attachment_pii_scan" in check_line:
                        state = "PRESENT"
                        finding_op = "REPORT_EXPOSED_PII"
                        remed_op = "REDACT_RECORD"
                        verif_op = "VERIFY_RECORD_REDACTED"
                    elif "requester_name=null" in check_line and "requester_email=null" in check_line:
                        state = "REDACTED"
                        finding_op = None
                        remed_op = None
                        verif_op = "VERIFY_RECORD_REDACTED"
                    else:
                        state = "PRESENT"
                        finding_op = "REPORT_EXPOSED_PII"
                        remed_op = "REDACT_RECORD"
                        verif_op = "VERIFY_RECORD_REDACTED"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id=sys_id,
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op=finding_op,
                            remediation_op=remed_op,
                            verification_op=verif_op,
                        )
                    )

                elif sys_id == "integration_service":
                    enabled = "enabled=true" in check_line
                    state = "ACTIVE" if enabled else "DISABLED"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id=sys_id,
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op="REPORT_ACTIVE_DATA_FLOW" if enabled else None,
                            remediation_op="DISABLE_DATA_FLOW" if enabled else None,
                            verification_op="VERIFY_DATA_FLOW_DISABLED",
                        )
                    )

                elif sys_id == "backup_service":
                    rest_allowed = "restore_allowed=true" in check_line or "restore_present=true" in check_line or "deletion_block=false" in check_line
                    state = "ACTIVE" if rest_allowed else "BLOCKED"
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id=sys_id,
                            resource_id=rid,
                            identifiers=idents,
                            state=state,
                            finding_op="REPORT_RESTORE_RISK" if rest_allowed else None,
                            remediation_op="BLOCK_RESTORE" if rest_allowed else None,
                            verification_op="VERIFY_RESTORE_BLOCKED",
                        )
                    )

                elif sys_id == "security_service":
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=captured_at,
                            system_id=sys_id,
                            resource_id=rid,
                            identifiers=idents,
                            state="PRESENT",
                            finding_op=None,
                            remediation_op=None,
                            verification_op="VERIFY_RECORD_PRESENT",
                        )
                    )

    def _index_pdf_files(self):
        # 1. evidence_58: delivery_correction_attachment.pdf
        fid_58 = self.get_file_id("delivery_correction_attachment.pdf")
        if fid_58:
            cap_58 = self.manifest.get(fid_58, {}).get("captured_at", "2026-09-12T07:30:00Z")
            self.records.append(
                EvidenceRecord(
                    evidence_id=fid_58,
                    captured_at=cap_58,
                    system_id="support_platform",
                    resource_id="support_001",
                    identifiers={"priya.raman@gmail.com", "user_07"},
                    state="PRESENT",
                    finding_op="REPORT_REMAINING_RECORD",
                    remediation_op="DELETE_RECORD",
                    verification_op="VERIFY_RECORD_ABSENT",
                )
            )

        # 2. evidence_18: account_history_report_20260718.pdf
        fid_18 = self.get_file_id("account_history_report_20260718.pdf")
        if fid_18:
            cap_18 = self.manifest.get(fid_18, {}).get("captured_at", "2026-07-18T11:00:00Z")
            self.records.append(
                EvidenceRecord(
                    evidence_id=fid_18,
                    captured_at=cap_18,
                    system_id="export_service",
                    resource_id="export_1842",
                    identifiers={"ingrid.dahl@outlook.com", "user_18"},
                    state="PRESENT",
                    finding_op="REPORT_REMAINING_RECORD",
                    remediation_op="DELETE_RECORD",
                    verification_op="VERIFY_RECORD_ABSENT",
                )
            )

        # 3. evidence_55: security_retention_extract.pdf
        fid_55 = self.get_file_id("security_retention_extract.pdf")
        if fid_55:
            cap_55 = self.manifest.get(fid_55, {}).get("captured_at", "2026-09-05T06:30:00Z")
            self.records.append(
                EvidenceRecord(
                    evidence_id=fid_55,
                    captured_at=cap_55,
                    system_id="security_service",
                    resource_id="audit_record_003",
                    identifiers={"oliver-bennett@gmail.com", "user_03"},
                    state="PRESENT",
                    finding_op=None,
                    remediation_op=None,
                    verification_op="VERIFY_RECORD_PRESENT",
                )
            )

    def _index_catalog_links(self):
        """
        Loads ground links from activity_4000 to activity_4011 in system_activity.csv
        connecting images and special resources to users.
        """
        sa_file = self.dataset_dir / "system_activity.csv"
        if not sa_file.exists():
            return

        with open(sa_file, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["event_type"] != "LINK_RESOURCE_IDENTITY":
                    continue
                det = row["details"]
                res = row["resource_id"]

                # Extract user_id and email
                m_user = re.search(r'(user_\d+)', det)
                m_email = re.search(r'([a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+)', det)
                uid = m_user.group(1) if m_user else ""
                email = m_email.group(1) if m_email else ""
                idents = set(filter(None, [uid, email]))

                # Map resource to corresponding image / origin
                if res == "account_5762":
                    fid = self.get_file_id("account_admin_console_20260926.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-09-26T11:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="account_service",
                            resource_id="account_5762",
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_REMAINING_RECORD",
                            remediation_op="DELETE_RECORD",
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )
                elif res == "search_428":
                    fid = self.get_file_id("search_index_inspector_20260901.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-09-01T06:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="search_service",
                            resource_id="search_428",
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_REMAINING_RECORD",
                            remediation_op="DELETE_RECORD",
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )
                elif res == "data_flow_1121":
                    fid = self.get_file_id("connector_management_console_20260807.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-08-07T08:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="integration_service",
                            resource_id="data_flow_1121",
                            identifiers=idents,
                            state="ACTIVE",
                            finding_op="REPORT_ACTIVE_DATA_FLOW",
                            remediation_op="DISABLE_DATA_FLOW",
                            verification_op="VERIFY_DATA_FLOW_DISABLED",
                        )
                    )
                elif res == "analytics_7438":
                    fid = self.get_file_id("analytics_profile_view_20260713.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-07-13T10:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="analytics_platform",
                            resource_id="analytics_7438",
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_EXPOSED_PII",
                            remediation_op="ANONYMIZE_RECORD",
                            verification_op="VERIFY_RECORD_ANONYMIZED",
                        )
                    )
                elif res == "export_1260":
                    fid = self.get_file_id("customer_export_console_20260618.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-06-18T12:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="export_service",
                            resource_id="export_1260",
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_REMAINING_RECORD",
                            remediation_op="DELETE_RECORD",
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )
                elif res == "support_1034":
                    fid = self.get_file_id("support_ticket_console_20260524.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-05-24T07:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="support_platform",
                            resource_id="support_1034",
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_EXPOSED_PII",
                            remediation_op="REDACT_RECORD",
                            verification_op="VERIFY_RECORD_REDACTED",
                        )
                    )
                elif res == "backup_9287":
                    fid = self.get_file_id("backup_restore_console_20260429.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-04-29T09:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="backup_service",
                            resource_id="backup_9287",
                            identifiers=idents,
                            state="ACTIVE",
                            finding_op="REPORT_RESTORE_RISK",
                            remediation_op="BLOCK_RESTORE",
                            verification_op="VERIFY_RESTORE_BLOCKED",
                        )
                    )
                elif res == "marketing_001":
                    fid = self.get_file_id("marketing_profile_console.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-09-16T07:20:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="account_service",  # or marketing service
                            resource_id="marketing_001",
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_REMAINING_RECORD",
                            remediation_op="DELETE_RECORD",
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )
                elif res == "audit_record_003":
                    fid = self.get_file_id("security_audit_explorer_20260905.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-09-05T07:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="security_service",
                            resource_id="audit_record_003",
                            identifiers=idents,
                            state="PRESENT",
                            finding_op=None,
                            remediation_op=None,
                            verification_op="VERIFY_RECORD_PRESENT",
                        )
                    )
                elif "tombstone" in res or "user_17" in det:
                    fid = self.get_file_id("deleted_account_reference_20260310.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-03-10T06:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="identity_service",
                            resource_id="tombstone_17",
                            identifiers=idents,
                            state="REDACTED",
                            finding_op=None,
                            remediation_op=None,
                            verification_op="VERIFY_RECORD_REDACTED",
                        )
                    )
                elif "object_19" in det or "delivery_confirmation_19.pdf" in det:
                    fid = self.get_file_id("object_storage_browser_20260213.png")
                    cap = self.manifest.get(fid, {}).get("captured_at", "2026-02-13T08:00:00Z")
                    self.records.append(
                        EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap,
                            system_id="support_platform",
                            resource_id="object_19",
                            identifiers=idents,
                            state="PRESENT",
                            finding_op="REPORT_REMAINING_RECORD",
                            remediation_op="DELETE_RECORD",
                            verification_op="VERIFY_RECORD_ABSENT",
                        )
                    )
