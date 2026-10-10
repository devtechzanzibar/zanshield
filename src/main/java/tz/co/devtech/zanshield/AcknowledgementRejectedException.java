package tz.co.devtech.zanshield;

/**
 * Thrown by {@link ZanShieldClient#acceptAcknowledgement(String)} when a genuine acknowledgement
 * must still not start a session. {@link #getAcknowledgement()} has its contents (for logging, or
 * to show ZanShield's {@code message}).
 */
public class AcknowledgementRejectedException extends ZanShieldException {

    public enum Reason {
        /** The user did not verify — {@code responseCode} isn't 9000 or {@code isAuthenticated} isn't true. */
        NOT_AUTHENTICATED,
        /** Older than the allowed age (3 minutes by default), or its {@code dateTime} is missing/unreadable. */
        EXPIRED,
        /** This {@code txnID} was already accepted once. */
        REPLAYED
    }

    private final Reason reason;
    private final transient TicketPayload acknowledgement;

    public AcknowledgementRejectedException(Reason reason, String message, TicketPayload acknowledgement) {
        super(message);
        this.reason = reason;
        this.acknowledgement = acknowledgement;
    }

    public Reason getReason() {
        return reason;
    }

    public TicketPayload getAcknowledgement() {
        return acknowledgement;
    }
}
