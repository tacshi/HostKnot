# Hostknot operations

## Before installation

Point the configured public IP at this VPS, permit inbound TCP 80/443/9443, and make sure no other process owns those ports. Run `hostknot doctor --config /etc/hostknot/config.toml` after installation. Its checks cover configuration, master-key permissions, SQLite integrity, listener availability, and outbound Cloudflare/ACME connectivity.

## Backup

The database and master key are one recovery unit. Losing the key makes provider tokens, ACME account credentials, and certificate private keys unrecoverable. Copying only the database is not a valid backup.

For a simple consistent backup:

```sh
systemctl stop hostknot
install -d -m 0700 /root/hostknot-backup
cp -a /etc/hostknot/config.toml /var/lib/hostknot/master.key \
  /var/lib/hostknot/hostknot.sqlite3 /root/hostknot-backup/
systemctl start hostknot
```

Store that directory in an encrypted backup system. If online backup is required, use SQLite’s `.backup` command rather than copying a live WAL database.

## Restore

Install the same or a newer Hostknot binary, stop the service, restore `config.toml`, `master.key`, and `hostknot.sqlite3` to their original paths, enforce mode `0600` on the key and `0700` on the state directory, then start the service. Run `hostknot doctor` and inspect the event history. Hostknot reloads certificates and resumes pending certificate, DNS, and drain states.

## Upgrade and migrations

1. Back up the state unit described above.
2. Verify the new binary checksum.
3. Run `hostknot service install --public-ip <current-IP> --binary ./hostknot`.
4. Restart the service and run `hostknot doctor`.

Schema migrations are transactional and forward-only. Do not start an older Hostknot binary against a database already opened by a newer major/minor release unless its release notes explicitly permit downgrade.

## Failure behavior

- **Port 80/public IP unreachable:** IP or domain issuance remains certificate-pending and the log reports the HTTP-01 failure. Fix firewall/NAT/address routing; reconciliation retries with bounded backoff.
- **Cloudflare rate limit or transient 5xx:** requests honor `Retry-After` and use bounded retries. Persisted pending work resumes later.
- **Conflicting records:** Hostknot requires explicit replacement confirmation and stores the prior records in its encrypted state.
- **DNS drift during edit/unbind:** the binding becomes drifted and Hostknot leaves externally changed records untouched.
- **Upstream unavailable:** clients receive a minimal 502 and the binding becomes degraded. A successful request returns it to active/healthy.
- **Lost admin password:** run `hostknot admin reset`; existing routes remain online.

## Security notes

Only bind upstreams on IPv4/IPv6 loopback. The proxy never accepts arbitrary target addresses and does not access the Docker socket. Keep port 9443 firewall-restricted where practical. Do not expose `/var/lib/hostknot/master.key`, the SQLite database, OAuth client secret, or setup/reset URLs.
