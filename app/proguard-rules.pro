# Release R8 minification and resource shrinking are enabled in app/build.gradle.kts.
# Room adapters are generated and link entities directly; do not pin the names of
# every local database/model class. Tink ships its own consumer shrinker metadata.
# Keep only JNI entry points exported by the pinned YARA-X Rust wrapper.
-keepclasseswithmembernames,includedescriptorclasses class org.revengi.abhi.yarax.** {
    native <methods>;
}
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
# R8 renames classes and members; it does not encrypt string literals or raw assets.
# Keep YARA definitions and the 215-feature schema auditable and byte-for-byte pinned.
