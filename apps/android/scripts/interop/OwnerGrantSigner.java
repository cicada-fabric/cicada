package interop;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonWriter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;

/** Development-only independent owner key and grant signer; never packaged in the APK. */
public final class OwnerGrantSigner {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] GRANT_DOMAIN = bytes("cicada/client/owner-device-grant/v1\0");
    private static final byte[] FINGERPRINT_DOMAIN = bytes("cicada/client/device-public-key/v1\0");

    private OwnerGrantSigner() {}

    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static String b64(byte[] value) { return Base64.getEncoder().encodeToString(value); }
    private static byte[] from64(String value) { return Base64.getDecoder().decode(value); }
    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte b : value) result.append(String.format("%02x", b & 255));
        return result.toString();
    }
    private static byte[] sha(byte[] value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }
    private static byte[] join(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
    private static String keyId(byte[] kem, byte[] signing) throws Exception {
        return "pq1-" + hex(Arrays.copyOf(sha(join(kem, signing)), 16));
    }
    private static String publicJson(String id, byte[] kem, byte[] signing) throws Exception {
        StringWriter result = new StringWriter();
        JsonWriter writer = new JsonWriter(result);
        writer.beginObject().name("id").value(id).name("kem_public").value(b64(kem))
                .name("signing_public").value(b64(signing)).endObject();
        writer.close();
        return result.toString();
    }
    private static void writeNew(Path path, String value) throws Exception {
        try (FileChannel output = FileChannel.open(path,
                EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ByteBuffer data = ByteBuffer.wrap(bytes(value));
            while (data.hasRemaining()) output.write(data);
        }
    }
    private static void generate(Path secretPath, Path publicPath) throws Exception {
        if (Files.exists(secretPath) || Files.exists(publicPath)) {
            throw new IllegalArgumentException("Key files already exist");
        }
        MLKEMKeyPairGenerator kemGenerator = new MLKEMKeyPairGenerator();
        kemGenerator.init(new MLKEMKeyGenerationParameters(RANDOM, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kemPair = kemGenerator.generateKeyPair();
        MLDSAKeyPairGenerator signingGenerator = new MLDSAKeyPairGenerator();
        signingGenerator.init(new MLDSAKeyGenerationParameters(RANDOM, MLDSAParameters.ml_dsa_65));
        AsymmetricCipherKeyPair signingPair = signingGenerator.generateKeyPair();
        MLKEMPrivateKeyParameters kemPrivate = (MLKEMPrivateKeyParameters) kemPair.getPrivate();
        MLDSAPrivateKeyParameters signingPrivate = (MLDSAPrivateKeyParameters) signingPair.getPrivate();
        byte[] kemPublic = kemPrivate.getPublicKey();
        byte[] signingPublic = signingPrivate.getPublicKey();
        String id = keyId(kemPublic, signingPublic);
        JsonObject secret = new JsonObject();
        secret.addProperty("version", 1);
        secret.addProperty("kem_private", b64(kemPrivate.getEncoded()));
        secret.addProperty("signing_private", b64(signingPrivate.getEncoded()));
        secret.addProperty("public_identity", publicJson(id, kemPublic, signingPublic));
        writeNew(secretPath, secret.toString());
        writeNew(publicPath, publicJson(id, kemPublic, signingPublic) + "\n");
        System.out.println(id);
    }
    private static void grant(Path secretPath, String ownerId, String deviceId,
                              String hubId, Path devicePublicPath, Path outputPath) throws Exception {
        if (Files.exists(outputPath)) throw new IllegalArgumentException("Grant file already exists");
        JsonObject owner = JsonParser.parseString(Files.readString(secretPath)).getAsJsonObject();
        MLDSAPrivateKeyParameters privateKey = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65,
                from64(owner.get("signing_private").getAsString()));
        JsonObject ownerPublic = JsonParser.parseString(owner.get("public_identity").getAsString())
                .getAsJsonObject();
        JsonObject device = JsonParser.parseString(Files.readString(devicePublicPath)).getAsJsonObject();
        byte[] deviceKem = from64(device.get("kem_public").getAsString());
        byte[] deviceSigning = from64(device.get("signing_public").getAsString());
        String deviceKeyId = keyId(deviceKem, deviceSigning);
        if (!deviceKeyId.equals(device.get("id").getAsString())) {
            throw new IllegalArgumentException("Device public identity ID mismatch");
        }
        String canonicalPublic = publicJson(deviceKeyId, deviceKem, deviceSigning);
        String fingerprint = hex(sha(join(FINGERPRINT_DOMAIN, bytes(canonicalPublic))));
        byte[] nonce = new byte[32];
        RANDOM.nextBytes(nonce);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        StringWriter claimsBuffer = new StringWriter();
        JsonWriter claims = new JsonWriter(claimsBuffer);
        claims.beginObject().name("version").value(1)
                .name("owner_id").value(ownerId)
                .name("owner_key_id").value(ownerPublic.get("id").getAsString())
                .name("device_id").value(deviceId)
                .name("device_key_id").value(deviceKeyId)
                .name("device_key_fingerprint").value(fingerprint)
                .name("hub_id").value(hubId)
                .name("purpose").value("CLIENT_CONTROL")
                .name("issued_at").value(now.minus(1, ChronoUnit.MINUTES).toString())
                .name("expires_at").value(now.plus(1, ChronoUnit.HOURS).toString())
                .name("nonce").value(hex(nonce)).endObject();
        claims.close();
        String unsigned = claimsBuffer.toString();
        MLDSASigner signer = new MLDSASigner();
        signer.init(true, privateKey);
        byte[] signedBytes = join(GRANT_DOMAIN, bytes(unsigned));
        signer.update(signedBytes, 0, signedBytes.length);
        byte[] signature = signer.generateSignature();
        String grant = unsigned.substring(0, unsigned.length() - 1) +
                ",\"signature\":\"" + b64(signature) + "\"}";
        writeNew(outputPath, grant);
        System.out.println("owner_key_id=" + ownerPublic.get("id").getAsString());
        System.out.println("grant_file=" + outputPath);
    }
    public static void main(String[] args) throws Exception {
        if (args.length == 3 && args[0].equals("generate")) {
            generate(Path.of(args[1]), Path.of(args[2]));
        } else if (args.length == 7 && args[0].equals("grant")) {
            grant(Path.of(args[1]), args[2], args[3], args[4], Path.of(args[5]), Path.of(args[6]));
        } else {
            throw new IllegalArgumentException("generate SECRET PUBLIC | grant SECRET OWNER DEVICE HUB DEVICE_PUBLIC GRANT_FILE");
        }
    }
}
