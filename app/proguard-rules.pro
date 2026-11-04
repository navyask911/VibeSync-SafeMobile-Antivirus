-keep class com.vibesync.antivirus.data.local.** { *; }
-keep class com.google.crypto.tink.** { *; }
-keepattributes *Annotation*
# Preserve exact JNI class/method names exported by the pinned Rust wrapper.
-keep class org.revengi.abhi.yarax.** { *; }
