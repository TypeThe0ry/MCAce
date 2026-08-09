package com.ellan.mcace.storage.postgres;

import java.util.Objects;
import javax.sql.DataSource;
import org.postgresql.ds.PGSimpleDataSource;

public final class PostgresDataSources {
    private PostgresDataSources() {
    }

    public static DataSource create(String jdbcUrl, String username, String password) {
        Objects.requireNonNull(jdbcUrl, "jdbcUrl");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
        if (!jdbcUrl.startsWith("jdbc:postgresql:") || username.isBlank()) {
            throw new IllegalArgumentException("a PostgreSQL JDBC URL and username are required");
        }
        PGSimpleDataSource dataSource = new PGSimpleDataSource();
        dataSource.setURL(jdbcUrl);
        dataSource.setUser(username);
        dataSource.setPassword(password);
        dataSource.setApplicationName("MCAce");
        dataSource.setConnectTimeout(10);
        dataSource.setSocketTimeout(15);
        return dataSource;
    }
}
