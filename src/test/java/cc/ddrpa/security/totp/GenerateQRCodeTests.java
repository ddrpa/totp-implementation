package cc.ddrpa.security.totp;

import cc.ddrpa.security.totp.migrate.GoogleAuthenticatorMigrationDecoder;
import cc.ddrpa.security.totp.migrate.InvalidQRCodeException;
import com.google.zxing.WriterException;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;

public class GenerateQRCodeTests {

    private final String DECODED_QR_CODE = "otpauth-migration://offline?data=CjYKCjc0YTA3ZTliNTASE0VUSElDQS3EsEhTQU4gQUxUVU4aDWV0aGljYXNpZ29ydGEgASgBMAIQARgBIAA";

    @Test
    void saveTest() throws InvalidQRCodeException, IOException, WriterException {
        OTPAuth auth = GoogleAuthenticatorMigrationDecoder.migrate(DECODED_QR_CODE);
        String barcodeText = Authenticator.generateQRCode(auth);
        BufferedImage image = QRCodeGenerator.generateQRCodeImage(barcodeText);
        ImageIO.write(image, "png", new File("qrcode.png"));
    }
}