package cc.ddrpa.security.totp;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ShowcaseTests {

    private static final Logger logger = LoggerFactory.getLogger(ShowcaseTests.class);

    @Test
    void generateNewQRCodeURITest() {
        String secret = Authenticator.generateSecret();
        String uri = Authenticator.generateQRCode(secret, "ddrpa.cc", "yufan@live.com");
        logger.info("URI: {}", uri);
    }

    @Test
    void verifyTest() throws NoSuchAlgorithmException, InvalidKeyException {
        String secret = "ID4UT73Q55ZB3JXP";
        assertTrue(
            Authenticator.verifyCode(secret, 228037, Authenticator.DEFAULT_TIME_STEP_IN_SECONDS,
                1));
    }
}