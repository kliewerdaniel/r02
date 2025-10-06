"""
Key rotation background job for QASP v1.0.

This module provides automated key rotation functionality to ensure cryptographic
freshness and limit the impact of key compromise. The rotation job runs periodically
and rotates keys according to configured intervals.

Key rotation strategy:
- Scheduled rotation based on time intervals
- Automatic generation of new key pairs
- Secure archival of old keys for transition periods
- Audit logging of all rotation operations

Security considerations:
- Key rotation is a privileged operation logged at SECURITY level
- Old keys are marked inactive but retained briefly for transition
- Failed rotations are immediately flagged for manual intervention
- Database transactions ensure atomicity of rotation operations
"""

import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from ..db.session import DatabaseSession
from ..db.models import KeyRecord, KeyRotationRecord, Tenant
from ..hsm.mock_hsm import MockHSM
from ..qasp.crypto import QASPCrypto

logger = logging.getLogger(__name__)


class KeyRotationJob:
    """
    Background job for automated key rotation.

    This job periodically scans for keys that need rotation and performs
    secure key rotation operations with audit logging.
    """

    def __init__(self):
        """Initialize the key rotation job."""
        self.crypto = QASPCrypto()
        self.hsm = MockHSM()
        self.rotation_interval_hours = int(os.getenv("KEY_ROTATION_INTERVAL_HOURS", "24"))

    def run_rotation_check(self) -> Dict[str, int]:
        """
        Run a key rotation check for all tenants and keys.

        Returns:
            Dictionary with rotation statistics: rotated, skipped, failed
        """
        logger.info("Starting key rotation check")

        stats = {
            "rotated": 0,
            "skipped": 0,
            "failed": 0,
            "errors": []
        }

        try:
            with DatabaseSession() as db:
                # Get all active tenants
                tenants = db.query(Tenant).filter(Tenant.is_active == True).all()

                for tenant in tenants:
                    tenant_stats = self._rotate_tenant_keys(tenant.id)
                    stats["rotated"] += tenant_stats["rotated"]
                    stats["skipped"] += tenant_stats["skipped"]
                    stats["failed"] += tenant_stats["failed"]
                    stats["errors"].extend(tenant_stats["errors"])

        except Exception as e:
            error_msg = f"Key rotation check failed: {str(e)}"
            logger.error(error_msg, extra={"security_event": "rotation_failure"})
            stats["errors"].append(error_msg)

        logger.info(
            f"Key rotation check completed: {stats['rotated']} rotated, {stats['skipped']} skipped, {stats['failed']} failed",
            extra={
                "rotation_rotated": stats["rotated"],
                "rotation_skipped": stats["skipped"],
                "rotation_failed": stats["failed"],
                "security_event": "rotation_check_complete"
            }
        )

        return stats

    def _rotate_tenant_keys(self, tenant_id: str) -> Dict[str, int]:
        """
        Rotate keys for a specific tenant.

        Args:
            tenant_id: The tenant identifier

        Returns:
            Rotation statistics for this tenant
        """
        stats = {"rotated": 0, "skipped": 0, "failed": 0, "errors": []}

        try:
            with DatabaseSession() as db:
                # Find keys due for rotation
                cutoff_time = datetime.utcnow() - timedelta(hours=self.rotation_interval_hours)

                due_keys = db.query(KeyRecord).filter(
                    KeyRecord.tenant_id == tenant_id,
                    KeyRecord.is_active == True,
                    KeyRecord.created_at < cutoff_time
                ).all()

                for key_record in due_keys:
                    success = self._rotate_single_key(tenant_id, key_record)
                    if success:
                        stats["rotated"] += 1

                        # Log rotation record
                        rotation_record = KeyRotationRecord(
                            tenant_id=tenant_id,
                            key_id=key_record.key_id,
                            old_key_id=key_record.key_id,
                            rotation_reason="scheduled",
                            success=True
                        )
                        db.add(rotation_record)

                    else:
                        stats["failed"] += 1
                        error_msg = f"Failed to rotate key {key_record.key_id} for tenant {tenant_id}"
                        stats["errors"].append(error_msg)

                        # Log failed rotation
                        rotation_record = KeyRotationRecord(
                            tenant_id=tenant_id,
                            key_id=key_record.key_id,
                            old_key_id=key_record.key_id,
                            rotation_reason="scheduled",
                            success=False,
                            notes="Rotation failed"
                        )
                        db.add(rotation_record)

                db.commit()

                # Count keys that were skipped (not due for rotation)
                total_active_keys = db.query(KeyRecord).filter(
                    KeyRecord.tenant_id == tenant_id,
                    KeyRecord.is_active == True
                ).count()

                stats["skipped"] = total_active_keys - len(due_keys)

        except Exception as e:
            error_msg = f"Failed to rotate keys for tenant {tenant_id}: {str(e)}"
            logger.error(error_msg, extra={
                "tenant_id": tenant_id,
                "security_event": "rotation_tenant_failure"
            })
            stats["errors"].append(error_msg)

        return stats

    def _rotate_single_key(self, tenant_id: str, key_record: KeyRecord) -> bool:
        """
        Rotate a single key for a tenant.

        Args:
            tenant_id: The tenant identifier
            key_record: The key record to rotate

        Returns:
            True if rotation succeeded, False otherwise
        """
        try:
            client_id, key_type = key_record.key_id.split(":", 1)

            # Generate new key pair
            if key_type == "kem":
                public_key, private_key = self.crypto.generate_kem_keypair()
            elif key_type == "sign":
                public_key, private_key = self.crypto.generate_sign_keypair()
            else:
                logger.error(f"Unknown key type for rotation: {key_type}")
                return False

            # Store the new private key in HSM
            success = self.hsm.store_private_key(
                tenant_id=tenant_id,
                client_id=client_id,
                key_type=key_type,
                key_bytes=private_key,
                key_algorithm=key_record.key_algorithm
            )

            if success:
                # Mark old key as inactive (but keep for transition period)
                key_record.is_active = False
                key_record.updated_at = datetime.utcnow()

                logger.info(
                    f"Key rotated successfully",
                    extra={
                        "tenant_id": tenant_id,
                        "client_id": client_id,
                        "key_type": key_type,
                        "old_key_id": key_record.key_id,
                        "security_event": "key_rotation_success"
                    }
                )

                return True
            else:
                logger.error(
                    f"Failed to store rotated key in HSM",
                    extra={
                        "tenant_id": tenant_id,
                        "client_id": client_id,
                        "key_type": key_type,
                        "security_event": "key_rotation_hsm_failure"
                    }
                )
                return False

        except Exception as e:
            logger.error(
                f"Key rotation failed for {key_record.key_id}",
                extra={
                    "tenant_id": tenant_id,
                    "key_id": key_record.key_id,
                    "error": str(e),
                    "security_event": "key_rotation_error"
                }
            )
            return False

    def force_rotate_key(self, tenant_id: str, client_id: str, key_type: str, reason: str = "manual") -> bool:
        """
        Force rotate a specific key immediately.

        Args:
            tenant_id: The tenant identifier
            client_id: The client identifier
            key_type: The key type ('kem' or 'sign')
            reason: Reason for rotation

        Returns:
            True if rotation succeeded, False otherwise
        """
        logger.info(
            f"Force rotating key {client_id}:{key_type} for tenant {tenant_id}",
            extra={
                "tenant_id": tenant_id,
                "client_id": client_id,
                "key_type": key_type,
                "rotation_reason": reason,
                "security_event": "force_key_rotation"
            }
        )

        try:
            with DatabaseSession() as db:
                key_id = f"{client_id}:{key_type}"
                key_record = db.query(KeyRecord).filter_by(
                    tenant_id=tenant_id,
                    key_id=key_id,
                    is_active=True
                ).first()

                if not key_record:
                    logger.warning(f"Key {key_id} not found for tenant {tenant_id}")
                    return False

                success = self._rotate_single_key(tenant_id, key_record)

                # Log rotation record
                rotation_record = KeyRotationRecord(
                    tenant_id=tenant_id,
                    key_id=key_record.key_id,
                    old_key_id=key_record.key_id,
                    rotation_reason=reason,
                    success=success
                )
                db.add(rotation_record)
                db.commit()

                return success

        except Exception as e:
            logger.error(
                f"Force key rotation failed for {client_id}:{key_type}",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "error": str(e),
                    "security_event": "force_rotation_failure"
                }
            )
            return False


def run_key_rotation_job() -> Dict[str, int]:
    """
    Run the key rotation job as a standalone function.

    This function can be called from a scheduler like cron or
    integrated into an async job queue.

    Returns:
        Dictionary with job execution statistics
    """
    job = KeyRotationJob()
    return job.run_rotation_check()


if __name__ == "__main__":
    # Allow running as a standalone script
    import os
    import sys

    # Add src to path for imports
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

    # Run the job
    stats = run_key_rotation_job()

    # Exit with error code if there were failures
    if stats["failed"] > 0 or stats["errors"]:
        sys.exit(1)
