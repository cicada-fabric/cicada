package interop;

import ai.cicada.client.hub.ClientWireCrypto;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;

/** Test-only command exercising the actual Android Kotlin wire codec against the Docker Hub. */
public final class HostPacketProbe {
    private HostPacketProbe() {}

    private static String read(String path) throws Exception { return Files.readString(Path.of(path)); }

    private static void writeNew(String path, String data) throws Exception {
        Path file = Path.of(path);
        try (FileChannel output = FileChannel.open(file,
                EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ByteBuffer dataBuffer = ByteBuffer.wrap(data.getBytes(StandardCharsets.UTF_8));
            while (dataBuffer.hasRemaining()) output.write(dataBuffer);
        }
    }

    private static ClientWireCrypto.Identity device(String privateFile) throws Exception {
        return ClientWireCrypto.Identity.fromPrivateJson(read(privateFile));
    }

    private static ClientWireCrypto.HubPin hub(String identityFile) throws Exception {
        return ClientWireCrypto.HubPin.parse(read(identityFile));
    }

    private static void generate(String[] args) throws Exception {
        try (ClientWireCrypto.Identity identity = ClientWireCrypto.Identity.generate()) {
            writeNew(args[1], identity.privateJson());
            writeNew(args[2], identity.publicIdentity.toJson());
            System.out.println("generated public identity " + identity.publicIdentity.id);
        }
    }

    private static void seal(String[] args) throws Exception {
        // seal PRIVATE HUB_IDENTITY OWNER DEVICE SEQUENCE OPERATION_ID OPERATION BODY_FILE PACKET_FILE
        ClientWireCrypto.Identity device = device(args[1]);
        ClientWireCrypto.HubPin hub = hub(args[2]);
        ClientWireCrypto.Route route = new ClientWireCrypto.Route();
        route.direction = "REQUEST";
        route.hubId = hub.hubId;
        route.ownerId = args[3];
        route.deviceId = args[4];
        route.sessionEpoch = 1;
        route.sequence = Long.parseLong(args[5]);
        route.operationId = args[6];
        route.operation = args[7];
        route.senderKeyId = device.publicIdentity.id;
        route.senderKeyVersion = 1;
        route.receiverKeyId = hub.control.id;
        route.receiverKeyVersion = hub.keyVersion;
        String packet = ClientWireCrypto.sealRequest(device, hub.control, route, read(args[8]));
        writeNew(args[9], packet);
        System.out.println("sealed sequence=" + route.sequence + " operation=" + route.operation);
    }

    private static void open(String[] args) throws Exception {
        // open PRIVATE HUB_IDENTITY REQUEST_PACKET RESPONSE_PACKET RESULT_FILE
        ClientWireCrypto.Identity device = device(args[1]);
        ClientWireCrypto.HubPin hub = hub(args[2]);
        JsonObject packet = JsonParser.parseString(read(args[3])).getAsJsonObject();
        ClientWireCrypto.Route request = ClientWireCrypto.Route.parse(packet.getAsJsonObject("route"));
        ClientWireCrypto.OpenedResponse result = ClientWireCrypto.openResponse(
                device, hub.control, request, read(args[4]));
        writeNew(args[5], result.body.toString());
        System.out.println("verified response operation=" + result.route.operation +
                " ok=" + result.body.get("ok").getAsBoolean());
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && args[0].equals("generate")) generate(args);
        else if (args.length == 10 && args[0].equals("seal")) seal(args);
        else if (args.length == 6 && args[0].equals("open")) open(args);
        else throw new IllegalArgumentException("generate PRIVATE PUBLIC | seal PRIVATE HUB_IDENTITY OWNER DEVICE SEQUENCE OP_ID OP BODY PACKET | open PRIVATE HUB_IDENTITY REQUEST RESPONSE RESULT");
    }
}
