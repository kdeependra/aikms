#!/bin/bash
# Creates multiple PostgreSQL databases on a single instance
set -e

for db in aikms_kms aikms_auth aikms_audit aikms_policy; do
  echo "Creating database: $db"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE $db OWNER $POSTGRES_USER;
EOSQL
done
