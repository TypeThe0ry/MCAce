package com.ellan.mcace.cloud.anchor;

import com.ellan.mcace.core.persistence.AuditAnchorPublication;
import com.ellan.mcace.core.persistence.StoredAuditAnchor;

public interface AuditAnchorPublisher {
    AuditAnchorPublication publish(StoredAuditAnchor anchor) throws AuditAnchorPublicationException;
}
