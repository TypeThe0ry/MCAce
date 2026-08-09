package com.ellan.mcace.launcher;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

@FunctionalInterface
public interface ContentFetcher {
    InputStream open(URI uri) throws IOException, InterruptedException;
}
