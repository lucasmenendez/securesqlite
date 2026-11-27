# Security policy

## Status

`securesqlite` is experimental and has not been independently audited. Do not
describe it as audited or production-secure. Review the design and the
implementation for your threat model before relying on it.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository (Security tab →
Report a vulnerability). Do not open a public issue for a suspected
vulnerability. Include the affected version, a minimal reproduction, and the
impact you believe is possible. Do not include real keys, plaintext, or
production database contents.

If private reporting is unavailable, open a public issue asking for a private
contact channel without disclosing details.

## Supported versions

Only the latest tagged release is supported. Security fixes are released from
`main`; older tags may not receive patches.

## Threat model

| Threat | v1 guarantee |
|---|---|
| Offline read of a database, WAL, or backup without the key | Confidentiality of correctly encrypted values, subject to size, frequency, and other metadata leakage. |
| Modification of ciphertext, tag, or context | Decryption fails when the expected context is used. |
| Moving ciphertext between records, fields, scopes, or databases | Authentication fails when the context is reconstructed from trusted data. |
| Wrong key or damaged metadata | `Open` fails. This is not a whole-database integrity check. |
| Row substitution or deletion, schema modification, ACL or balance changes | No global detection. |
| Replay of an old value or restoration of an older backup | Not detected. |
| Full replacement with another valid database under the same key | Not detected without an external expected identity; use a different key per database. |
| Compromised Go process, host administrator, key, or arbitrary SQL execution | Not protected. |
| Observation of blind indexes | Reveals equality and frequency within a domain; does not hide query patterns. |

## Operational requirements

- Use one random 32-byte master key per database. Never share keys between
  applications or environments.
- Keep the key separate from the database and its backups.
- Use a private local directory; do not use network filesystems with WAL.
- Do not open SQLite files supplied by third parties. Metadata authentication
  happens after SQLite has started interpreting the file.
- Keep SQLite and the pinned driver updated. `trusted_schema=OFF` reduces the
  schema surface but is not isolation.
- Protect backups with the same care as the database and key. An encrypted
  value remains encrypted in a backup, but schema and non-sensitive metadata do
  not.
- Do not use blind indexes for low-cardinality data whose equality leakage is
  unacceptable.
- Passwords must be hashed with a password KDF. Do not use `Encrypt` or `Index`
  for password storage.
- Large documents need their own encrypted storage.
- There is no guarantee of secure memory erasure in Go.

## Application responsibilities

The package encrypts values; it does not authorize requests. Read `Scope`,
record IDs, and tenant identifiers from trusted authentication context. Verify
relationships and invariants in the domain layer. A decrypted value is not proof
that the row, the user, or the authorization decision is authentic.

Do not expose decryption errors as detailed oracles in HTTP responses. Map
internal failures to generic responses and log without keys, plaintext,
ciphertext, or sensitive SQL parameters.

## Domain integrity

Selective encryption does not authenticate schema, ACLs, roles, balances,
public keys, row existence, or SQL query results. For audit logs, ledgers,
signatures, or balances, use domain-level integrity controls and externally
anchored state in addition to this package.
