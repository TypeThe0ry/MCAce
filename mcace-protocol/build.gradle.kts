plugins {
    id("com.google.protobuf") version "0.10.0"
}

dependencies {
    api("com.google.protobuf:protobuf-java:4.32.1")
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:4.32.1"
    }
}
