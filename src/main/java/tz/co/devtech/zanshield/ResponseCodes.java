package tz.co.devtech.zanshield;

/** The {@code responseCode} values ZanShield puts on acknowledgements — Integration Guide §7. */
public final class ResponseCodes {

    private ResponseCodes() {}

    /** The only code that means the user verified successfully. */
    public static final int SUCCESS = 9000;
    public static final int INVALID_TICKET = 9031;
    public static final int MAX_ATTEMPTS_REACHED = 9032;
    public static final int TICKET_EXPIRED = 9038;
    public static final int UNKNOWN_CLIENT_SYSTEM = 9040;
    public static final int METHOD_ALREADY_REGISTERED = 9041;
    public static final int METHOD_NOT_REGISTERED = 9042;
    public static final int INVALID_CODE = 9043;
    public static final int WEBAUTHN_ERROR = 9044;
    public static final int METHOD_NOT_ALLOWED = 9045;
    public static final int MOBILE_NOT_AVAILABLE = 9046;
    public static final int SMS_DELIVERY_FAILED = 9047;
}
