package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import javax.sql.DataSource;

public final class PostgresSchemaMigrator {
    private static final long MIGRATION_LOCK_ID = 0x4d434163654442L;
    private static final String DELIMITER = "(?m)^-- MCAce statement\\s*$";
    private static final List<Migration> MIGRATIONS = List.of(
            new Migration(1, "security audit", "/db/migration/V001__security_audit.sql"),
            new Migration(2, "cloud control plane", "/db/migration/V002__cloud_control_plane.sql"),
            new Migration(3, "review and appeal workflow",
                    "/db/migration/V003__review_and_appeal_workflow.sql"),
            new Migration(4, "risk policy rollout and metrics",
                    "/db/migration/V004__risk_policy_rollout_and_metrics.sql"),
            new Migration(5, "distributed authentication challenges",
                    "/db/migration/V005__distributed_authentication_challenges.sql"),
            new Migration(6, "external audit anchors",
                    "/db/migration/V006__external_audit_anchors.sql"),
            new Migration(7, "web portal sessions and notifications",
                    "/db/migration/V007__web_portal_sessions_and_notifications.sql"));

    private PostgresSchemaMigrator() {
    }

    public static void migrate(DataSource dataSource) throws SecurityPersistenceException {
        Objects.requireNonNull(dataSource, "dataSource");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement lock = connection.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
                    lock.setLong(1, MIGRATION_LOCK_ID);
                    lock.execute();
                }
                try (Statement statement = connection.createStatement()) {
                    statement.execute("""
                            CREATE TABLE IF NOT EXISTS mcace_schema_migrations (
                                version BIGINT PRIMARY KEY,
                                description TEXT NOT NULL,
                                sha256_hex TEXT NOT NULL CHECK (length(sha256_hex) = 64),
                                applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
                            )
                            """);
                }
                for (Migration migration : MIGRATIONS) {
                    apply(connection, migration);
                }
                connection.commit();
            } catch (SQLException | IOException exception) {
                rollback(connection, exception);
                throw new SecurityPersistenceException("PostgreSQL schema migration failed", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to PostgreSQL for migration", exception);
        }
    }

    private static void apply(Connection connection, Migration migration) throws SQLException, IOException {
        String sql = readResource(migration.resource());
        String checksum = sha256Hex(sql.getBytes(StandardCharsets.UTF_8));
        try (PreparedStatement query = connection.prepareStatement(
                "SELECT sha256_hex FROM mcace_schema_migrations WHERE version = ?")) {
            query.setLong(1, migration.version());
            try (ResultSet result = query.executeQuery()) {
                if (result.next()) {
                    if (!checksum.equals(result.getString(1))) {
                        throw new SQLException("migration checksum mismatch for version " + migration.version());
                    }
                    return;
                }
            }
        }
        for (String statementSql : sql.split(DELIMITER)) {
            if (!statementSql.isBlank()) {
                try (Statement statement = connection.createStatement()) {
                    statement.execute(statementSql.trim());
                }
            }
        }
        try (PreparedStatement insert = connection.prepareStatement(
                "INSERT INTO mcace_schema_migrations(version, description, sha256_hex) VALUES (?, ?, ?)")) {
            insert.setLong(1, migration.version());
            insert.setString(2, migration.description());
            insert.setString(3, checksum);
            insert.executeUpdate();
        }
    }

    private static String readResource(String path) throws IOException {
        try (InputStream input = PostgresSchemaMigrator.class.getResourceAsStream(path)) {
            if (input == null) throw new IOException("missing migration resource " + path);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String sha256Hex(byte[] content) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException exception) {
            throw new IOException("SHA-256 is unavailable", exception);
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private record Migration(long version, String description, String resource) { }
}
