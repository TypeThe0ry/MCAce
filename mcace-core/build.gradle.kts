dependencies {
    api(project(":mcace-sdk"))
    implementation(project(":mcace-protocol"))
    implementation("com.google.protobuf:protobuf-java-util:4.32.1")
    testImplementation(project(":mcace-client-common"))
}
