dependencies {
    api(project(":mcace-core"))
    implementation("org.postgresql:postgresql:42.7.10")

    testImplementation(platform("org.testcontainers:testcontainers-bom:2.0.5"))
    testImplementation("org.testcontainers:testcontainers-junit-jupiter")
    testImplementation("org.testcontainers:testcontainers-postgresql")
}
