package org.revengi.abhi.yarax;

public class Scanner implements AutoCloseable {
    private long nativePtr;

    public Scanner(Rules rules) {
        if (rules == null) throw new IllegalArgumentException("Rules cannot be null");
        nativePtr = create(rules.getNativePtr());
        if (nativePtr == 0) throw new RuntimeException("Failed to create scanner");
    }

    public String setTimeout(int seconds) {
        if (nativePtr == 0) throw new IllegalStateException("Scanner is closed");
        if (seconds < 0) throw new IllegalArgumentException("Timeout must be non-negative");
        return setTimeout(nativePtr, seconds);
    }

    public String setMaxMatchesPerPattern(int maxMatches) {
        if (nativePtr == 0) throw new IllegalStateException("Scanner is closed");
        if (maxMatches < 0) throw new IllegalArgumentException("Max matches must be non-negative");
        return setMaxMatchesPerPattern(nativePtr, maxMatches);
    }

    public String setGlobal(String name, String value) {
        if (nativePtr == 0) throw new IllegalStateException("Scanner is closed");
        if (name == null || value == null) throw new IllegalArgumentException("Global name/value cannot be null");
        return setGlobal(nativePtr, name, value);
    }

    public String useMmap(boolean enabled) {
        if (nativePtr == 0) throw new IllegalStateException("Scanner is closed");
        return useMmap(nativePtr, enabled);
    }

    public String scanBytes(byte[] data) {
        if (nativePtr == 0) throw new IllegalStateException("Scanner is closed");
        if (data == null) throw new IllegalArgumentException("Data cannot be null");
        return scanBytes(nativePtr, data);
    }

    public String scanFile(String path) {
        if (nativePtr == 0) throw new IllegalStateException("Scanner is closed");
        if (path == null) throw new IllegalArgumentException("Path cannot be null");
        return scanFile(nativePtr, path);
    }

    @Override
    public void close() {
        if (nativePtr != 0) {
            destroy(nativePtr);
            nativePtr = 0;
        }
    }

    public boolean isOpen() { return nativePtr != 0; }
    long getNativePtr() { return nativePtr; }

    private static native long create(long rulesPtr);
    private static native String setTimeout(long ptr, int seconds);
    private static native String setMaxMatchesPerPattern(long ptr, int maxMatches);
    private static native String setGlobal(long ptr, String name, String value);
    private static native String useMmap(long ptr, boolean enabled);
    private static native String scanBytes(long ptr, byte[] data);
    private static native String scanFile(long ptr, String path);
    private static native void destroy(long ptr);

    static { System.loadLibrary("yarax_android"); }
}
