package tz.co.devtech.zanshield;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Simulates both sides of the protocol with throwaway key pairs — a "client" (this SDK) and a
 * stand-in "engine" — to prove the wire format round-trips correctly without needing real
 * ZanShield keys.
 */
class ZanShieldClientTest {

    private static KeyPair clientKeys;
    private static KeyPair engineKeys;

    @BeforeAll
    static void keys() throws Exception {
        clientKeys = generateKeyPair();
        engineKeys = generateKeyPair();
    }

    @Test
    void ticketCarriesWhoTheUserIsAndNoRequestType() {
        String ticket = client().createTicket("user-123", "user@example.com", "Amina Juma", "0772 108 420");

        TicketPayload opened = engineView().openAcknowledgement(ticket);
        assertEquals("TESTSYS", opened.getSystemCode());
        assertEquals("TESTINST", opened.getInstitutionCode());
        assertEquals("user-123", opened.getUserId());
        assertEquals("user@example.com", opened.getEmail());
        assertEquals("Amina Juma", opened.getFullName());
        assertEquals("0772 108 420", opened.getMobile());
        assertTrue(opened.getDateTime().endsWith("Z"), opened.getDateTime());
    }

    @Test
    void optionalFieldsAreLeftOut() {
        TicketPayload opened = engineView().openAcknowledgement(client().createTicket("user-123", "user@example.com"));
        assertNull(opened.getFullName());
        assertNull(opened.getMobile());
    }

    @Test
    void buildsThePortalUrl() {
        assertEquals("https://portal.example/ticket?ticket=a%2Bb", ZanShieldClient.portalUrl("https://portal.example/", "a+b", false));
        assertEquals("https://portal.example/ticket?ticket=abc&add=1", ZanShieldClient.portalUrl("https://portal.example", "abc", true));
    }

    @Test
    void acceptsAFreshSuccessfulAcknowledgementOnce() {
        ZanShieldClient client = client();
        String ack = engineAck(9000, true, "txn-1", OffsetDateTime.now(ZoneOffset.UTC));

        TicketPayload accepted = client.acceptAcknowledgement(ack);
        assertEquals("user-123", accepted.getUserId());
        assertEquals("TOTP", accepted.getAuthenticationMethod());

        AcknowledgementRejectedException replay =
                assertThrows(AcknowledgementRejectedException.class, () -> client.acceptAcknowledgement(ack));
        assertEquals(AcknowledgementRejectedException.Reason.REPLAYED, replay.getReason());
    }

    @Test
    void rejectsAnUnsuccessfulAcknowledgement() {
        ZanShieldClient client = client();
        String ack = engineAck(9032, false, "txn-2", OffsetDateTime.now(ZoneOffset.UTC));

        AcknowledgementRejectedException e =
                assertThrows(AcknowledgementRejectedException.class, () -> client.acceptAcknowledgement(ack));
        assertEquals(AcknowledgementRejectedException.Reason.NOT_AUTHENTICATED, e.getReason());
        assertEquals(9032, e.getAcknowledgement().getResponseCode());
    }

    @Test
    void rejectsAnOldAcknowledgement() {
        Instant now = Instant.parse("2026-10-08T12:00:00Z");
        ZanShieldClient client = client().withClock(Clock.fixed(now, ZoneOffset.UTC));
        String ack = engineAck(9000, true, "txn-3", OffsetDateTime.parse("2026-10-08T11:56:00Z"));

        AcknowledgementRejectedException e =
                assertThrows(AcknowledgementRejectedException.class, () -> client.acceptAcknowledgement(ack));
        assertEquals(AcknowledgementRejectedException.Reason.EXPIRED, e.getReason());

        // ... unless the client chose a longer window.
        client.withMaxAcknowledgementAge(Duration.ofMinutes(5));
        assertEquals("txn-3", client.acceptAcknowledgement(ack).getTxnID());
    }

    @Test
    void usesTheConfiguredTxnIdStore() {
        TxnIdStore alwaysUsed = (txnId, keepUntil) -> false;
        ZanShieldClient client = client().withTxnIdStore(alwaysUsed);
        String ack = engineAck(9000, true, "txn-4", OffsetDateTime.now(ZoneOffset.UTC));

        assertThrows(AcknowledgementRejectedException.class, () -> client.acceptAcknowledgement(ack));
    }

    @Test
    void rejectsATicketSignedByTheWrongKey() throws Exception {
        KeyPair impostorKeys = generateKeyPair();
        ZanShieldClient impostor = new ZanShieldClient("TESTSYS", "TESTINST", impostorKeys.getPrivate(), engineKeys.getPublic());
        String forged = impostor.createTicket("user-123", "user@example.com");
        ZanShieldClient engine = engineView();

        assertThrows(ZanShieldException.class, () -> engine.openAcknowledgement(forged));
    }

    @Test
    void rejectsATamperedTicket() {
        String ticket = client().createTicket("user-123", "user@example.com");
        char[] chars = ticket.toCharArray();
        chars[chars.length / 2] = chars[chars.length / 2] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);
        ZanShieldClient engine = engineView();

        assertThrows(ZanShieldException.class, () -> engine.openAcknowledgement(tampered));
    }

    private static ZanShieldClient client() {
        return new ZanShieldClient("TESTSYS", "TESTINST", clientKeys.getPrivate(), engineKeys.getPublic());
    }

    /** The engine's side: decrypts with its key, trusts the client's public key — and signs acks. */
    private static ZanShieldClient engineView() {
        return new ZanShieldClient("TESTSYS", "TESTINST", engineKeys.getPrivate(), clientKeys.getPublic());
    }

    private static String engineAck(int responseCode, boolean authenticated, String txnId, OffsetDateTime issuedAt) {
        TicketPayload ack = TicketPayload.builder()
                .systemCode("TESTSYS")
                .institutionCode("TESTINST")
                .userId("user-123")
                .email("user@example.com")
                .dateTime(issuedAt.toString())
                .build();
        ack.setResponseCode(responseCode);
        ack.setIsAuthenticated(authenticated);
        ack.setAuthenticationMethod("TOTP");
        ack.setTxnID(txnId);
        ack.setMessage(responseCode == 9000 ? "Success" : "Maximum attempt reached");
        return engineView().createTicket(ack);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
