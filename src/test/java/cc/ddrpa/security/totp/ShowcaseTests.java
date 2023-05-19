package cc.ddrpa.security.totp;

import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ShowcaseTests {
    @Test
    void generateNewQRCodeURITest() {
        String secret = Authenticator.generateSecret();
        String uri = Authenticator.generateQRCode(secret, "ddrpa.cc", "yufan@live.com");
        System.out.println(uri);
    }

    @Test
    void verifyTest() throws NoSuchAlgorithmException, InvalidKeyException {
        String secret = "ID4UT73Q55ZB3JXP";
        assertTrue(Authenticator.verifyCode(secret, 228037, Authenticator.DEFAULT_TIME_STEP_IN_SECONDS, 1));
    }
}