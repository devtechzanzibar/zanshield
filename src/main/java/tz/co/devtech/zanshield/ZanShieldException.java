package tz.co.devtech.zanshield;

/** Thrown for any failure while building or opening a ZanShield ticket. */
public class ZanShieldException extends RuntimeException {

    public ZanShieldException(String message) {
        super(message);
    }

    public ZanShieldException(String message, Throwable cause) {
        super(message, cause);
    }
}
