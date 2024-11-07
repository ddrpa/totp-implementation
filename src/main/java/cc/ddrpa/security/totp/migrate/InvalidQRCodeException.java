package cc.ddrpa.security.totp.migrate;

public class InvalidQRCodeException extends Exception {

    public InvalidQRCodeException(String message) {
        super(message);
    }

    public InvalidQRCodeException(String message, Throwable cause) {
        super(message, cause);
    }
}