package cc.ddrpa.security.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cc.ddrpa.security.totp.migrate.GoogleAuthenticatorMigrationDecoder;
import cc.ddrpa.security.totp.migrate.InvalidQRCodeException;
import java.io.UnsupportedEncodingException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class GoogleAuthenticatorMigrationDecoderTests {

    private static final Logger logger = LoggerFactory.getLogger(GoogleAuthenticatorMigrationDecoderTests.class);

    private final String DECODED_QR_CODE = "otpauth-migration://offline?data=CjYKCjc0YTA3ZTliNTASE0VUSElDQS3EsEhTQU4gQUxUVU4aDWV0aGljYXNpZ29ydGEgASgBMAIQARgBIAA";

    @Test
    void migrateTest() throws InvalidQRCodeException, UnsupportedEncodingException {
        OTPAuth auth = GoogleAuthenticatorMigrationDecoder.migrate(DECODED_QR_CODE);
        assertEquals("G42GCMBXMU4WENJQ", auth.secret());
        String newQRCode = Authenticator.generateQRCode(auth);
        logger.info("New QR Code: {}", newQRCode);
    }
}