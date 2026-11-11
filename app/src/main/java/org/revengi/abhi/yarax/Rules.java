package org.revengi.abhi.yarax;

public class Rules {
    private long nativePtr;

    Rules(long nativePtr) { this.nativePtr = nativePtr; }

    public byte[] serialize() {
        if (nativePtr == 0) throw new IllegalStateException("Rules are closed");
        byte[] result = serialize(nativePtr);
        if (result == null) throw new RuntimeException("Failed to serialize rules");
        return result;
    }

    public static Rules deserialize(byte[] bytes) {
        if (bytes == null) throw new IllegalArgumentException("Bytes cannot be null");
        long rulesPtr = deserializeFromBytes(bytes);
        if (rulesPtr == 0) throw new RuntimeException("Failed to deserialize rules");
        return new Rules(rulesPtr);
    }

    public void close() {
        if (nativePtr != 0) {
            destroy(nativePtr);
            nativePtr = 0;
        }
    }

    public boolean isOpen() { return nativePtr != 0; }
    long getNativePtr() { return nativePtr; }

    private static native byte[] serialize(long ptr);
    private static native long deserializeFromBytes(byte[] bytes);
    private static native void destroy(long ptr);

    static { System.loadLibrary("yarax_android"); }
}
