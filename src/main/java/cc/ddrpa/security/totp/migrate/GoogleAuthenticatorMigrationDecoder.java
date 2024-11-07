package cc.ddrpa.security.totp.migrate;

import cc.ddrpa.security.totp.OTPAuth;
import cc.ddrpa.security.totp.migrate.google.proto.Payload;
import cc.ddrpa.security.totp.migrate.google.proto.Payload.OtpParameters;
import com.google.common.io.BaseEncoding;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Base64;

/**
 * 解析从 Google Authenticator 导出的 TOTP 二维码，协议应当为 otpauth-migration，参考： <a
 * href="https://stackoverflow.com/questions/70983346/how-can-%C4%B1-get-secret-key-google-auth-qrcode">How
 * can ı get secret key google auth QRCode? - Stack Overflow</a>
 */
public class GoogleAuthenticatorMigrationDecoder {

    private GoogleAuthenticatorMigrationDecoder() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static OTPAuth migrate(String decodedQRCode)
        throws InvalidQRCodeException, UnsupportedEncodingException {
        String dataString = extractDataParameter(decodedQRCode);
        Payload payload;
        try {
            payload = Payload.parseFrom(Base64.getDecoder().decode(dataString));
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidQRCodeException("Unrecognized protocol buffer data", e);
        }
        if (payload.getOtpParametersCount() == 0) {
            throw new InvalidQRCodeException("No OTP parameters found");
        }
        OtpParameters otpParameters = payload.getOtpParameters(0);
        String secretAsString = BaseEncoding.base32()
            .encode(otpParameters.getSecret().toByteArray());
        String organization = otpParameters.getIssuer();
        String account = otpParameters.getName();
        return new OTPAuth(secretAsString, organization, account);
    }

    /**
     * 返回 otpauth-migration://offline?data=... 中的 data 参数
     *
     * @param decodedQRCode 解码后的字符串
     * @return
     * @throws InvalidQRCodeException
     * @throws UnsupportedEncodingException
     */
    private static String extractDataParameter(String decodedQRCode)
        throws InvalidQRCodeException, UnsupportedEncodingException {
        if (!decodedQRCode.startsWith("otpauth-migration://offline?data=")) {
            throw new InvalidQRCodeException(
                "Unrecognized QR code format, should similar to otpauth-migration://offline?data=...");
        }
        String dataParameter = decodedQRCode.replace("otpauth-migration://offline?data=", "");
        return URLDecoder.decode(dataParameter, "UTF-8");
    }
}