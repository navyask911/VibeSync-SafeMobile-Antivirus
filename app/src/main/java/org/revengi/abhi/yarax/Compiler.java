package org.revengi.abhi.yarax;

public class Compiler {
    private long nativePtr;

    public Compiler() {
        nativePtr = create();
        if (nativePtr == 0) throw new RuntimeException("Failed to create compiler");
    }

    public String addSource(String source) {
        if (nativePtr == 0) throw new IllegalStateException("Compiler is closed");
        if (source == null) throw new IllegalArgumentException("Source cannot be null");
        return addSource(nativePtr, source);
    }

    /**
     * Creates a namespace for subsequently added rules.
     * The native JNI export in the pinned yarax_android revision is
     * Java_org_revengi_abhi_yarax_Compiler_createNamespace.
     */
    public void newNamespace(String namespace) {
        if (nativePtr == 0) throw new IllegalStateException("Compiler is closed");
        if (namespace == null) throw new IllegalArgumentException("Namespace cannot be null");
        if (createNamespace(nativePtr, namespace) == 0) {
            throw new RuntimeException("Failed to create YARA-X namespace");
        }
    }

    public String defineGlobal(String name, String value) {
        if (nativePtr == 0) throw new IllegalStateException("Compiler is closed");
        if (name == null || value == null) throw new IllegalArgumentException("Global name/value cannot be null");
        return defineGlobal(nativePtr, name, value);
    }

    public Rules build() {
        if (nativePtr == 0) throw new IllegalStateException("Compiler is closed");
        long rulesPtr = build(nativePtr);
        nativePtr = 0;
        if (rulesPtr == 0) throw new RuntimeException("Failed to build rules");
        return new Rules(rulesPtr);
    }

    public void close() {
        if (nativePtr != 0) {
            destroy(nativePtr);
            nativePtr = 0;
        }
    }

    public boolean isOpen() { return nativePtr != 0; }

    private static native long create();
    private static native String addSource(long ptr, String source);
    // This JNI method name matches the exported Rust symbol at the pinned revision.
    private static native long createNamespace(long ptr, String namespace);
    private static native String defineGlobal(long ptr, String name, String value);
    private static native long build(long ptr);
    private static native void destroy(long ptr);

    static { System.loadLibrary("yarax_android"); }
}
