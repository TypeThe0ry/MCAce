package com.ellan.mcace.cloud.auth;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;

public final class PostgresAuthenticationChallengeStore implements AuthenticationChallengeStore {
    private final DataSource dataSource;

    public PostgresAuthenticationChallengeStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public void create(
            StoredAuthenticationChallenge challenge,
            Instant now,
            int maximumOutstanding,
            int maximumPerServer) throws AuthenticationException {
        Objects.requireNonNull(challenge, "challenge");
        Objects.requireNonNull(now, "now");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                lockIssuanceGuard(connection);
                deleteExpired(connection, now);
                if (count(connection, null) >= maximumOutstanding
                        || count(connection, challenge.serverId()) >= maximumPerServer) {
                    throw new AuthenticationException("too many outstanding authentication challenges");
                }
                insert(connection, challenge, now);
                connection.commit();
            } catch (SQLException | AuthenticationException exception) {
                rollback(connection, exception);
                if (exception instanceof AuthenticationException authenticationException) {
                    throw authenticationException;
                }
                throw new AuthenticationException("authentication challenge storage failed", exception);
            }
        } catch (SQLException exception) {
            throw new AuthenticationException("authentication challenge storage failed", exception);
        }
    }

    @Override
    public Optional<StoredAuthenticationChallenge> consume(UUID challengeId) throws AuthenticationException {
        Objects.requireNonNull(challengeId, "challengeId");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     DELETE FROM mcace_auth_challenges WHERE challenge_id = ?
                     RETURNING challenge_id, server_id, public_key, scopes, signing_payload, expires_at
                     """)) {
            statement.setObject(1, challengeId);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? Optional.of(read(result)) : Optional.empty();
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new AuthenticationException("authentication challenge storage failed", exception);
        }
    }

    private static void lockIssuanceGuard(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT singleton FROM mcace_auth_challenge_guard
                WHERE singleton = TRUE FOR UPDATE
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next()) {
                throw new SQLException("authentication challenge guard is missing");
            }
        }
    }

    private static void deleteExpired(Connection connection, Instant now) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM mcace_auth_challenges WHERE expires_at <= ?")) {
            statement.setTimestamp(1, Timestamp.from(now));
            statement.executeUpdate();
        }
    }

    private static long count(Connection connection, String serverId) throws SQLException {
        String sql = serverId == null
                ? "SELECT count(*) FROM mcace_auth_challenges"
                : "SELECT count(*) FROM mcace_auth_challenges WHERE server_id = ?";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            if (serverId != null) {
                statement.setString(1, serverId);
            }
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("authentication challenge count is unavailable");
                }
                return result.getLong(1);
            }
        }
    }

    private static void insert(
            Connection connection, StoredAuthenticationChallenge challenge, Instant now) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO mcace_auth_challenges(
                    challenge_id, server_id, public_key, scopes, signing_payload, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, challenge.challengeId());
            statement.setString(2, challenge.serverId());
            statement.setBytes(3, challenge.publicKeyEncoded());
            String[] scopes = challenge.scopes().stream().map(Enum::name).sorted().toArray(String[]::new);
            statement.setArray(4, connection.createArrayOf("text", scopes));
            statement.setBytes(5, challenge.signingPayload());
            statement.setTimestamp(6, Timestamp.from(now));
            statement.setTimestamp(7, Timestamp.from(challenge.expiresAt()));
            statement.executeUpdate();
        }
    }

    private static StoredAuthenticationChallenge read(ResultSet result) throws SQLException {
        EnumSet<ApiScope> scopes = EnumSet.noneOf(ApiScope.class);
        Array array = result.getArray(4);
        try {
            Object raw = array.getArray();
            if (!(raw instanceof String[] values)) {
                throw new SQLException("invalid authentication challenge scopes");
            }
            for (String value : values) {
                scopes.add(ApiScope.valueOf(value));
            }
        } finally {
            array.free();
        }
        return new StoredAuthenticationChallenge(
                result.getObject(1, UUID.class), result.getString(2), result.getBytes(3), scopes,
                result.getBytes(5), result.getTimestamp(6).toInstant());
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }
}
