# Vosk exposes a JNI surface through JNA and this release smoke test loads its
# API by name. Keep the JNA runtime lookup and Vosk native registration names.
-keep class com.sun.jna.* { *; }
-keep class * extends com.sun.jna.* { *; }
-keepclassmembers class * extends com.sun.jna.* { public *; }
-dontwarn java.awt.**
-keep class org.vosk.LibVosk { *; }
-keep enum org.vosk.LogLevel { *; }

# The local Sherpa AAR has an empty consumer rules file; its JNI bridge reads
# configuration DTO types and members by name. Keep only that wrapper namespace.
-keep class com.k2fsa.sherpa.onnx.** { *; }

# AGP's optimized Android default rules preserve native method names. RN and
# Gson ship consumer rules; the application's BC PQC APIs are statically used.

# AndroidX Test's instrumentation tracing facade is shared from the target APK.
# Keep its public runtime ABI because test APK packaging omits the duplicate.
-keep class androidx.tracing.Trace { *; }

# Release AndroidTest bytecode shares the target's stdlib. Preserve only the
# Kotlin runtime ABI reached from that test APK, traced with AGP's bundled R8.
-keep @interface kotlin.Deprecated {
  public java.lang.String message();
  public kotlin.ReplaceWith replaceWith();
}
-keep @interface kotlin.ExtensionFunctionType {
}
-keep interface kotlin.Lazy {
  public java.lang.Object getValue();
}
-keep class kotlin.LazyKt {
}
-keep @interface kotlin.Metadata {
  public java.lang.String[] d1();
  public java.lang.String[] d2();
  public int k();
  public int[] mv();
  public int xi();
}
-keep class kotlin.Result$Companion {
}
-keep class kotlin.Result {
  public static java.lang.Object constructor-impl(java.lang.Object);
  public static java.lang.Throwable exceptionOrNull-impl(java.lang.Object);
  kotlin.Result$Companion Companion;
}
-keep class kotlin.ResultKt {
  public static java.lang.Object createFailure(java.lang.Throwable);
  public static void throwOnFailure(java.lang.Object);
}
-keep class kotlin.Triple {
  public <init>(java.lang.Object, java.lang.Object, java.lang.Object);
  public java.lang.Object component1();
  public java.lang.Object component2();
  public java.lang.Object component3();
}
-keep class kotlin.TuplesKt {
}
-keep class kotlin.collections.MapsKt {
}
-keep class kotlin.collections.MapsKt__MapsJVMKt {
  public static int mapCapacity(int);
}
-keep class kotlin.collections.MapsKt__MapsKt {
  public static java.lang.Object getValue(java.util.Map, java.lang.Object);
}
-keep class kotlin.coroutines.ContinuationKt {
}
-keep class kotlin.coroutines.intrinsics.IntrinsicsKt {
}
-keep class kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt {
  public static java.lang.Object getCOROUTINE_SUSPENDED();
}
-keep class kotlin.coroutines.jvm.internal.ContinuationImpl {
  protected java.lang.Object invokeSuspend(java.lang.Object);
}
-keep class kotlin.coroutines.jvm.internal.DebugProbesKt {
}
-keep interface kotlin.coroutines.jvm.internal.SuspendFunction {
}
-keep class kotlin.io.ByteStreamsKt {
  public static byte[] readBytes(java.io.InputStream);
}
-keep class kotlin.io.CloseableKt {
  public static void closeFinally(java.io.Closeable, java.lang.Throwable);
}
-keep class kotlin.io.FilesKt {
}
-keep class kotlin.io.FilesKt__FileReadWriteKt {
  public static byte[] readBytes(java.io.File);
  public static java.lang.String readText$default(java.io.File, java.nio.charset.Charset, int, java.lang.Object);
  public static java.lang.String readText(java.io.File, java.nio.charset.Charset);
  public static void writeBytes(java.io.File, byte[]);
  public static void writeText$default(java.io.File, java.lang.String, java.nio.charset.Charset, int, java.lang.Object);
  public static void writeText(java.io.File, java.lang.String, java.nio.charset.Charset);
}
-keep class kotlin.io.FilesKt__UtilsKt {
  public static java.io.File copyTo$default(java.io.File, java.io.File, boolean, int, int, java.lang.Object);
  public static boolean deleteRecursively(java.io.File);
}
-keep class kotlin.io.TextStreamsKt {
  public static java.lang.String readText(java.io.Reader);
}
-keep class kotlin.jdk7.AutoCloseableKt {
  public static void closeFinally(java.lang.AutoCloseable, java.lang.Throwable);
}
-keep @interface kotlin.jvm.JvmStatic {
}
-keep interface kotlin.jvm.functions.Function1 {
  public java.lang.Object invoke(java.lang.Object);
}
-keep interface kotlin.jvm.functions.Function2 {
}
-keep class kotlin.jvm.internal.DefaultConstructorMarker {
}
-keep class kotlin.jvm.internal.Ref$BooleanRef {
  public <init>();
  boolean element;
}
-keep class kotlin.jvm.internal.StringCompanionObject {
  kotlin.jvm.internal.StringCompanionObject INSTANCE;
}
-keep class kotlin.ranges.RangesKt {
}
-keep class kotlin.ranges.RangesKt___RangesKt {
  public static int coerceAtLeast(int, int);
  public static long coerceIn(long, long, long);
}
-keep class kotlin.text.Regex {
  public <init>(java.lang.String);
  public boolean matches(java.lang.CharSequence);
  public java.lang.String replace(java.lang.CharSequence, java.lang.String);
}
-keep class kotlin.time.Duration$Companion {
}
-keep class kotlin.time.Duration {
  kotlin.time.Duration$Companion Companion;
}
-keep class kotlin.time.DurationKt {
  public static long toDuration(int, kotlin.time.DurationUnit);
}
-keep enum kotlin.time.DurationUnit {
  kotlin.time.DurationUnit SECONDS;
}

# Kotlin's multifile facade inherits these static methods from its part classes;
# TraceReferences sees the facade shell but does not retain inherited members.
-keep class kotlin.LazyKt__LazyKt {
  public <init>();
}
-keep class kotlin.LazyKt__LazyJVMKt {
  public <init>();
  public static kotlin.Lazy lazy(kotlin.jvm.functions.Function0);
  public static kotlin.Lazy lazy(kotlin.LazyThreadSafetyMode, kotlin.jvm.functions.Function0);
}

# Keep the exact app, Gson, and Kotlin members used by the selected release
# instrumentation sources, derived from their original pre-R8 class files.
-keep class ai.cicada.client.ModelCatalog$Asset {
  long bytes;
  java.lang.String name;
  java.lang.String sha256;
}
-keep class ai.cicada.client.ModelCatalog$ModelSpec {
  java.util.List assets;
  java.lang.String engine;
}
-keep class ai.cicada.client.ModelCatalog {
  static ai.cicada.client.ModelCatalog$ModelSpec get(java.lang.String);
}
-keep class ai.cicada.client.hub.ClientHubSession$Companion {
  public java.io.File profileDirectory$app_release(android.content.Context, java.lang.String);
}
-keep class ai.cicada.client.hub.ClientHubSession {
  public <init>(android.content.Context, java.lang.String);
  public com.google.gson.JsonObject createDeviceIdentity();
  public void deleteProfileState$app_release();
  public com.google.gson.JsonObject getStatus();
  public static com.google.gson.JsonObject rpc$default(ai.cicada.client.hub.ClientHubSession, java.lang.String, com.google.gson.JsonObject, java.lang.String, int, java.lang.Object);
  public com.google.gson.JsonObject rpc(java.lang.String, com.google.gson.JsonObject, java.lang.String);
  ai.cicada.client.hub.ClientHubSession$Companion Companion;
}
-keep class ai.cicada.client.hub.ClientWireCrypto$Identity$Companion {
  public ai.cicada.client.hub.ClientWireCrypto$Identity fromPrivateJson(java.lang.String);
  public ai.cicada.client.hub.ClientWireCrypto$Identity generate();
}
-keep class ai.cicada.client.hub.ClientWireCrypto$Identity {
  public byte[] decapsulate$app_release(byte[]);
  public byte[] sign(byte[]);
  ai.cicada.client.hub.ClientWireCrypto$Identity$Companion Companion;
  ai.cicada.client.hub.ClientWireCrypto$PublicIdentity publicIdentity;
}
-keep class ai.cicada.client.hub.ClientWireCrypto$OpenedResponse {
  com.google.gson.JsonObject body;
}
-keep class ai.cicada.client.hub.ClientWireCrypto$PublicIdentity$Companion {
  public ai.cicada.client.hub.ClientWireCrypto$PublicIdentity parse(com.google.gson.JsonObject);
}
-keep class ai.cicada.client.hub.ClientWireCrypto$PublicIdentity {
  public boolean sameAs(ai.cicada.client.hub.ClientWireCrypto$PublicIdentity);
  public java.lang.String toJson();
  ai.cicada.client.hub.ClientWireCrypto$PublicIdentity$Companion Companion;
  java.lang.String id;
  byte[] signingPublic;
}
-keep class ai.cicada.client.hub.ClientWireCrypto$Route$Companion {
  public ai.cicada.client.hub.ClientWireCrypto$Route parse(com.google.gson.JsonObject);
}
-keep class ai.cicada.client.hub.ClientWireCrypto$Route {
  public <init>();
  public java.lang.String toJson();
  ai.cicada.client.hub.ClientWireCrypto$Route$Companion Companion;
  java.lang.String deviceId;
  java.lang.String direction;
  java.lang.String hubId;
  java.lang.String operation;
  java.lang.String operationId;
  java.lang.String ownerId;
  java.lang.String receiverKeyId;
  long receiverKeyVersion;
  java.lang.String senderKeyId;
  long senderKeyVersion;
  long sequence;
  long sessionEpoch;
}
-keep class ai.cicada.client.hub.ClientWireCrypto {
  public static ai.cicada.client.hub.ClientWireCrypto$OpenedResponse openResponse(ai.cicada.client.hub.ClientWireCrypto$Identity, ai.cicada.client.hub.ClientWireCrypto$PublicIdentity, ai.cicada.client.hub.ClientWireCrypto$Route, java.lang.String);
  public java.lang.String sealRawEnvelope$app_release(ai.cicada.client.hub.ClientWireCrypto$Identity, ai.cicada.client.hub.ClientWireCrypto$PublicIdentity, long, byte[], byte[]);
  public static java.lang.String sealRequest(ai.cicada.client.hub.ClientWireCrypto$Identity, ai.cicada.client.hub.ClientWireCrypto$PublicIdentity, ai.cicada.client.hub.ClientWireCrypto$Route, java.lang.String);
  public static boolean verify(ai.cicada.client.hub.ClientWireCrypto$PublicIdentity, byte[], byte[]);
  ai.cicada.client.hub.ClientWireCrypto INSTANCE;
}
-keep class ai.cicada.client.hub.HubSessionException {
  public java.lang.String getErrorCode();
}
-keep class com.google.gson.JsonArray {
  public <init>();
  public void add(java.lang.String);
  public java.util.Iterator iterator();
  public int size();
}
-keep class com.google.gson.JsonElement {
  public boolean getAsBoolean();
  public int getAsInt();
  public com.google.gson.JsonObject getAsJsonObject();
  public long getAsLong();
  public java.lang.String getAsString();
  public java.lang.String toString();
}
-keep class com.google.gson.JsonObject {
  public <init>();
  public void add(java.lang.String, com.google.gson.JsonElement);
  public void addProperty(java.lang.String, java.lang.Boolean);
  public void addProperty(java.lang.String, java.lang.Number);
  public void addProperty(java.lang.String, java.lang.String);
  public com.google.gson.JsonObject deepCopy();
  public com.google.gson.JsonElement get(java.lang.String);
  public com.google.gson.JsonArray getAsJsonArray(java.lang.String);
  public com.google.gson.JsonObject getAsJsonObject(java.lang.String);
  public boolean has(java.lang.String);
  public int hashCode();
  public int size();
}
-keep class com.google.gson.JsonParser {
  public static com.google.gson.JsonElement parseString(java.lang.String);
}
-keep class com.google.gson.stream.JsonWriter {
  public <init>(java.io.Writer);
  public com.google.gson.stream.JsonWriter beginObject();
  public void close();
  public com.google.gson.stream.JsonWriter endObject();
  public com.google.gson.stream.JsonWriter name(java.lang.String);
  public com.google.gson.stream.JsonWriter nullValue();
  public void setSerializeNulls(boolean);
  public com.google.gson.stream.JsonWriter value(long);
  public com.google.gson.stream.JsonWriter value(java.lang.Number);
  public com.google.gson.stream.JsonWriter value(java.lang.String);
}
-keep @interface kotlin.Metadata {
  public java.lang.String[] d1();
  public java.lang.String[] d2();
  public int k();
  public int[] mv();
  public int xi();
}
-keep class kotlin.Pair {
  public java.lang.Object component1();
  public java.lang.Object component2();
}
-keep class kotlin.TuplesKt {
  public static kotlin.Pair to(java.lang.Object, java.lang.Object);
}
-keep class kotlin.Unit {
  kotlin.Unit INSTANCE;
}
-keep class kotlin.collections.ArraysKt {
}
-keep class kotlin.collections.ArraysKt___ArraysJvmKt {
  public static byte[] copyOfRange(byte[], int, int);
}
-keep class kotlin.collections.ArraysKt___ArraysKt {
  public static int getLastIndex(byte[]);
  public static java.lang.String joinToString$default(byte[], java.lang.CharSequence, java.lang.CharSequence, java.lang.CharSequence, int, java.lang.CharSequence, kotlin.jvm.functions.Function1, int, java.lang.Object);
  public static byte last(byte[]);
}
-keep class kotlin.collections.CollectionsKt {
}
-keep class kotlin.collections.CollectionsKt__CollectionsKt {
  public static java.util.List listOf(java.lang.Object[]);
}
-keep class kotlin.collections.CollectionsKt__IterablesKt {
  public static int collectionSizeOrDefault(java.lang.Iterable, int);
}
-keep class kotlin.collections.CollectionsKt___CollectionsKt {
  public static java.util.List plus(java.util.Collection, java.lang.Iterable);
  public static java.util.Set toSet(java.lang.Iterable);
}
-keep class kotlin.io.ByteStreamsKt {
  public static byte[] readBytes(java.io.InputStream);
}
-keep class kotlin.io.CloseableKt {
  public static void closeFinally(java.io.Closeable, java.lang.Throwable);
}
-keep class kotlin.io.FilesKt {
}
-keep class kotlin.io.FilesKt__FileReadWriteKt {
  public static byte[] readBytes(java.io.File);
  public static java.lang.String readText$default(java.io.File, java.nio.charset.Charset, int, java.lang.Object);
  public static void writeText$default(java.io.File, java.lang.String, java.nio.charset.Charset, int, java.lang.Object);
}
-keep class kotlin.io.FilesKt__UtilsKt {
  public static boolean deleteRecursively(java.io.File);
}
-keep class kotlin.io.TextStreamsKt {
  public static java.lang.String readText(java.io.Reader);
}
-keep class kotlin.jdk7.AutoCloseableKt {
  public static void closeFinally(java.lang.AutoCloseable, java.lang.Throwable);
}
-keep interface kotlin.jvm.functions.Function0 {
  public java.lang.Object invoke();
}
-keep interface kotlin.jvm.functions.Function1 {
  public java.lang.Object invoke(java.lang.Object);
}
-keep class kotlin.jvm.internal.DefaultConstructorMarker {
}
-keep class kotlin.jvm.internal.Intrinsics {
  public static boolean areEqual(java.lang.Object, java.lang.Object);
  public static void checkNotNull(java.lang.Object);
  public static void checkNotNull(java.lang.Object, java.lang.String);
  public static void checkNotNullExpressionValue(java.lang.Object, java.lang.String);
  public static void checkNotNullParameter(java.lang.Object, java.lang.String);
}
-keep @interface kotlin.jvm.internal.SourceDebugExtension {
  public java.lang.String[] value();
}
-keep class kotlin.text.Charsets {
  java.nio.charset.Charset US_ASCII;
  java.nio.charset.Charset UTF_8;
}
-keep class kotlin.text.StringsKt {
}
-keep class kotlin.text.StringsKt__StringsJVMKt {
  public static boolean startsWith$default(java.lang.String, java.lang.String, boolean, int, java.lang.Object);
}
-keep class kotlin.text.StringsKt__StringsKt {
  public static boolean contains$default(java.lang.CharSequence, java.lang.CharSequence, boolean, int, java.lang.Object);
  public static boolean isBlank(java.lang.CharSequence);
  public static java.lang.CharSequence trim(java.lang.CharSequence);
}
-keeppackagenames ai.cicada.client

# Preserve package-private Kotlin multifile superclass access while allowing
# R8 to obfuscate individual classes within these finite traced packages.
-keeppackagenames kotlin
-keeppackagenames kotlin.collections
-keeppackagenames kotlin.coroutines
-keeppackagenames kotlin.coroutines.intrinsics
-keeppackagenames kotlin.coroutines.jvm.internal
-keeppackagenames kotlin.io
-keeppackagenames kotlin.jdk7
-keeppackagenames kotlin.jvm
-keeppackagenames kotlin.jvm.functions
-keeppackagenames kotlin.jvm.internal
-keeppackagenames kotlin.ranges
-keeppackagenames kotlin.text
-keeppackagenames kotlin.time
