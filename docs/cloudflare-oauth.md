# Cloudflare OAuth setup

HostKnot uses a private Cloudflare Authorization Code OAuth client with server-side client authentication, PKCE S256, state validation, refresh-token rotation, and an exact callback URI.

1. Open the HostKnot Cloudflare page. Keep it open: it displays the exact callback URI for this VPS.
2. Select **Create OAuth client in Cloudflare** to open the account's OAuth Clients page, then create a private client.
3. Add that callback URI exactly, including `https`, the IP literal, port `9443`, and `/oauth/cloudflare/callback`.
4. Grant Zone Read, DNS Write, and offline access.
5. Save the client, then enter its ID and secret in HostKnot.
6. Select **Authorize with Cloudflare** and approve access.

Private clients are intended for members of the Cloudflare account that owns the client. Reconfiguration clears existing access and refresh tokens. HostKnot refuses disconnect while bindings still depend on Cloudflare; remove those bindings first so their DNS receipts can be safely reverted.

For an optional live smoke test, use a disposable zone and keep client credentials in a local secret store or CI secret. Never commit them to this repository.
