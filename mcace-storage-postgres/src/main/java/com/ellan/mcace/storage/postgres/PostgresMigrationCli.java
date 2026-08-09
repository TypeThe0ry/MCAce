package com.ellan.mcace.storage.postgres;

public final class PostgresMigrationCli {
    private PostgresMigrationCli() {
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 0) {
            throw new IllegalArgumentException("migration CLI accepts configuration through environment variables only");
        }
        String jdbcUrl = requireEnvironment("MCACE_DB_URL");
        String username = requireEnvironment("MCACE_DB_USER");
        String password = requireEnvironment("MCACE_DB_PASSWORD");
        PostgresSchemaMigrator.migrate(PostgresDataSources.create(jdbcUrl, username, password));
        System.out.println("MCAce PostgreSQL migrations completed successfully");
    }

    private static String requireEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("required environment variable is missing: " + name);
        }
        return value;
    }
}
