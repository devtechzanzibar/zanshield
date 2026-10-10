package tz.co.devtech.zanshield;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * Builds and opens ZanShield tickets: signs and encrypts outbound tickets addressed to
 * ZanShield's engine, and decrypts + verifies the signed acknowledgement tickets it sends back.
 *
 * <p>Wire format (all base64url of the concatenation): {@code [4-byte big-endian length of the
 * RSA-wrapped AES key][RSA-wrapped AES key][12-byte GCM IV][AES-GCM ciphertext, tag appended]}.
 * See DOCS/03-Integration-Guide.html §3.2 for the full protocol spec.
 *
 * <p>The ticket only says who the user is. ZanShield decides everything else: whether they set
 * up a first method or verify an existing one, which methods their system allows, and lets them
 * add another method after verifying.
 *
 * <p>Usage:
 * <pre>{@code
 * ZanShieldClient client = new ZanShieldClient(
 *     "YOUR_SYSTEM_CODE", "YOUR_INSTITUTION_CODE",
 *     PemKeyReader.readPrivateKey(yourPrivateKeyPem),
 *     PemKeyReader.readPublicKey(zanShieldEnginePublicKeyPem));
 *
 * // After your own password check:
 * String ticket = client.createTicket(userId, email, fullName, mobile);
 * response.sendRedirect(ZanShieldClient.portalUrl(portalBaseUrl, ticket, false));
 *
 * // ... later, at your redirectUri, with the ack ticket from the query string:
 * TicketPayload ack = client.acceptAcknowledgement(ackTicket); // throws if it must not sign in
 * startSessionFor(ack.getUserId());
 * }</pre>
 */
public class ZanShieldClient {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String RSA_WRAP_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    // The transformation name above is misleading: without an explicit OAEPParameterSpec,
    // JCE's default MGF1 digest is SHA-1 regardless of the "SHA-256" in the name — only the
    // main OAEP hash follows it. This spec makes both genuinely SHA-256, matching the
    // integration spec and every non-Java SDK.
    private static final OAEPParameterSpec OAEP_SHA256_SPEC = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_CIPHER = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;
    private static final int AES_KEY_BITS = 256;

    private final String systemCode;
    private final String institutionCode;
    private final PrivateKey myPrivateKey;
    private final PublicKey enginePublicKey;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();
    private TxnIdStore txnIdStore = new InMemoryTxnIdStore();
    private Duration maxAcknowledgementAge = Duration.ofMinutes(3);
    private Clock clock = Clock.systemUTC();

    public ZanShieldClient(String systemCode, String institutionCode, PrivateKey myPrivateKey, PublicKey enginePublicKey) {
        this.systemCode = systemCode;
        this.institutionCode = institutionCode;
        this.myPrivateKey = myPrivateKey;
        this.enginePublicKey = enginePublicKey;
    }

    /**
     * Where {@link #acceptAcknowledgement(String)} remembers used {@code txnID}s. Replace the
     * in-memory default when you run more than one server.
     */
    public ZanShieldClient withTxnIdStore(TxnIdStore txnIdStore) {
        this.txnIdStore = txnIdStore;
        return this;
    }

    /** How old an acknowledgement may be when it reaches your redirectUri. Default 3 minutes. */
    public ZanShieldClient withMaxAcknowledgementAge(Duration maxAge) {
        this.maxAcknowledgementAge = maxAge;
        return this;
    }

    ZanShieldClient withClock(Clock clock) {
        this.clock = clock;
        return this;
    }

    /** Builds a signed, sealed ticket asking ZanShield to verify {@code userId}/{@code email}. */
    public String createTicket(String userId, String email) {
        return createTicket(userId, email, null, null);
    }

    /** Same, plus {@code fullName} so the portal can greet the user by name. */
    public String createTicket(String userId, String email, String fullName) {
        return createTicket(userId, email, fullName, null);
    }

    /**
     * Same, plus {@code mobile} (any common format, e.g. "0772 123 456") — without it the user
     * can't choose SMS codes. Pass {@code null} for anything you don't have.
     */
    public String createTicket(String userId, String email, String fullName, String mobile) {
        TicketPayload payload = TicketPayload.builder()
                .systemCode(systemCode)
                .institutionCode(institutionCode)
                .userId(userId)
                .email(email)
                .fullName(fullName)
                .mobile(mobile)
                .dateTime(OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC).toString())
                .build();
        return createTicket(payload);
    }

    /**
     * The portal address to redirect the browser to. With {@code addMethod} (e.g. from an "Add
     * an MFA method" button in your app), the user goes straight to adding a method after verifying.
     */
    public static String portalUrl(String portalBaseUrl, String ticket, boolean addMethod) {
        String base = portalBaseUrl.replaceAll("/+$", "");
        String encodedTicket = URLEncoder.encode(ticket, StandardCharsets.UTF_8);
        return base + "/ticket?ticket=" + encodedTicket + (addMethod ? "&add=1" : "");
    }

    /**
     * Everything your redirectUri must check before starting a session, in one call: decrypts and
     * verifies the acknowledgement ({@link #openAcknowledgement}), then requires a successful
     * verification, a fresh {@code dateTime}, and a {@code txnID} never accepted before.
     *
     * @throws AcknowledgementRejectedException if it's genuine but must not sign the user in
     * @throws ZanShieldException if it isn't a valid ZanShield acknowledgement at all
     */
    public TicketPayload acceptAcknowledgement(String ticket) {
        TicketPayload ack = openAcknowledgement(ticket);
        if (ack.getResponseCode() == null
                || ack.getResponseCode() != ResponseCodes.SUCCESS
                || !Boolean.TRUE.equals(ack.getIsAuthenticated())) {
            throw new AcknowledgementRejectedException(AcknowledgementRejectedException.Reason.NOT_AUTHENTICATED,
                    ack.getMessage() != null ? ack.getMessage() : "ZanShield verification was not completed", ack);
        }

        Instant issuedAt;
        try {
            issuedAt = OffsetDateTime.parse(ack.getDateTime()).toInstant();
        } catch (Exception e) {
            throw new AcknowledgementRejectedException(
                    AcknowledgementRejectedException.Reason.EXPIRED, "Acknowledgement has no valid dateTime", ack);
        }
        Instant now = clock.instant();
        if (issuedAt.isBefore(now.minus(maxAcknowledgementAge))) {
            throw new AcknowledgementRejectedException(
                    AcknowledgementRejectedException.Reason.EXPIRED, "Acknowledgement has expired", ack);
        }

        if (ack.getTxnID() == null || !txnIdStore.markUsed(ack.getTxnID(), issuedAt.plus(maxAcknowledgementAge))) {
            throw new AcknowledgementRejectedException(
                    AcknowledgementRejectedException.Reason.REPLAYED, "Acknowledgement was already used", ack);
        }
        return ack;
    }

    /** Lower-level form for when you need to set fields the convenience overloads don't expose. */
    public String createTicket(TicketPayload payload) {
        try {
            byte[] payloadBytes = objectMapper.writeValueAsBytes(payload);
            byte[] signature = sign(payloadBytes, myPrivateKey);

            Envelope envelope = new Envelope(
                    Base64.getEncoder().encodeToString(payloadBytes),
                    Base64.getEncoder().encodeToString(signature));
            byte[] envelopeBytes = objectMapper.writeValueAsBytes(envelope);

            byte[] sealed = seal(envelopeBytes, enginePublicKey);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sealed);
        } catch (Exception e) {
            throw new ZanShieldException("Failed to build ZanShield ticket", e);
        }
    }

    /**
     * Decrypts {@code ticket} with your key, then verifies it was signed by ZanShield's engine key.
     * This only proves the ticket is genuine — prefer {@link #acceptAcknowledgement(String)}, which
     * also checks it's a fresh, successful, first-time-used verification.
     */
    public TicketPayload openAcknowledgement(String ticket) {
        try {
            byte[] sealed = Base64.getUrlDecoder().decode(ticket);
            byte[] envelopeBytes = unseal(sealed, myPrivateKey);
            Envelope envelope = objectMapper.readValue(envelopeBytes, Envelope.class);

            byte[] payloadBytes = Base64.getDecoder().decode(envelope.payload());
            byte[] signature = Base64.getDecoder().decode(envelope.signature());

            if (!verify(payloadBytes, signature, enginePublicKey)) {
                throw new ZanShieldException("Ticket signature verification failed");
            }
            return objectMapper.readValue(payloadBytes, TicketPayload.class);
        } catch (ZanShieldException e) {
            throw e;
        } catch (Exception e) {
            throw new ZanShieldException("Failed to open acknowledgement ticket", e);
        }
    }

    private byte[] sign(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    private byte[] seal(byte[] plaintext, PublicKey recipientPublicKey) throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(AES_KEY_BITS, secureRandom);
        SecretKey aesKey = keyGen.generateKey();

        byte[] iv = new byte[GCM_IV_BYTES];
        secureRandom.nextBytes(iv);

        Cipher aesCipher = Cipher.getInstance(AES_CIPHER);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = aesCipher.doFinal(plaintext);

        Cipher rsaCipher = Cipher.getInstance(RSA_WRAP_ALGORITHM);
        rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey, OAEP_SHA256_SPEC);
        byte[] wrappedKey = rsaCipher.doFinal(aesKey.getEncoded());

        byte[] lengthPrefix = ByteBuffer.allocate(4).putInt(wrappedKey.length).array();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(lengthPrefix, 0, lengthPrefix.length);
        out.write(wrappedKey, 0, wrappedKey.length);
        out.write(iv, 0, iv.length);
        out.write(ciphertext, 0, ciphertext.length);
        return out.toByteArray();
    }

    private byte[] unseal(byte[] sealed, PrivateKey myPrivateKey) throws GeneralSecurityException {
        ByteBuffer buffer = ByteBuffer.wrap(sealed);
        int wrappedKeyLength = buffer.getInt();
        byte[] wrappedKey = new byte[wrappedKeyLength];
        buffer.get(wrappedKey);
        byte[] iv = new byte[GCM_IV_BYTES];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        Cipher rsaCipher = Cipher.getInstance(RSA_WRAP_ALGORITHM);
        rsaCipher.init(Cipher.DECRYPT_MODE, myPrivateKey, OAEP_SHA256_SPEC);
        byte[] aesKeyBytes = rsaCipher.doFinal(wrappedKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, AES_ALGORITHM);

        Cipher aesCipher = Cipher.getInstance(AES_CIPHER);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return aesCipher.doFinal(ciphertext);
    }

    private record Envelope(String payload, String signature) {}
}
