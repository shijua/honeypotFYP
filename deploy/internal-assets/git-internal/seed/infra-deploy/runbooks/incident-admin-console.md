# Admin Console Incident Runbook

Use this runbook when `intranet-admin-02` rejects SSO or change-ticket validation.

1. Confirm the current CAB window in OPS-ADMIN.
2. Check whether the April migration token is still present in the customer portal backup area.
3. Verify `PORTAL_READER_USERNAME=portal.reader` before opening the internal service directory.
4. If Redis inventory is stale, query `service:customer-portal:upstream` on `redis-cache.internal.local:16379`.
5. Check the admin console at `http://intranet-admin-02.internal:18081/`.
6. If remote access is required, download the current contractor profile from `https://vpn-ra-01.internal:18443/`.
7. Use `admin-jumpbox-01.internal:10222` only for an approved interactive support session.
