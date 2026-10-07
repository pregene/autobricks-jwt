# Supported Databases

Autobricks JWT provides direct database connections for:

- PostgreSQL
- MariaDB
- MySQL
- SQLite
- SQLCipher

## Connection Ownership

Direct database connections are owned and managed by Autobricks JWT. They operate independently of Autobricks Cache.

- JWT database access does not pass through the Autobricks Cache interface.
- JWT database support does not depend on database adapters provided by Autobricks Cache.
- Direct database configuration and Autobricks Cache configuration are separate.
- Each direct connection uses the driver and connection settings for its configured database.

## Database Functions

Direct database connections provide database access for JWT service data, token source data, service registration data, and session records.

SQLCipher provides encrypted SQLite storage. The SQLCipher database key used for JWT key storage is managed through an HSM as defined by the JWT key-management boundary.
