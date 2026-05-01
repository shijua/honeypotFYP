# Admin Console Incident Runbook

Use this runbook when `intranet-admin-02` rejects SSO or change-ticket validation.

1. Confirm the current CAB window in OPS-ADMIN.
2. Check whether the April migration token is still present in the customer portal backup area.
3. Verify `PORTAL_READER_USERNAME=portal.reader` before opening the internal service directory.
4. If Redis inventory is stale, query `service:customer-portal:upstream` on `redis-cache.internal.local`.
5. If remote access is required, download the current contractor profile from the VPN appliance.
