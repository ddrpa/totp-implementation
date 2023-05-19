package cc.ddrpa.security.totp;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Longs;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Authenticator {
    // 默认时间步长为 30 秒
    // 在 30 秒区间内的计算的验证码是相同的
    public static final Long DEFAULT_TIME_STEP_IN_SECONDS = 30L;
    // 生成 6 位 OTP
    private static final Long VERIFICATION_CODE_MODULUS = 1000L * 1000L;

    private static final SecureRandom random = new SecureRandom();

    /**
     * 生成 16 个字符长度的 Base32 编码密钥，可用于生成二维码或手动录入两步验证器
     *
     * @return
     */
    public static String generateSecret() {
        byte[] buffer = new byte[10];
        random.nextBytes(buffer);
        return BaseEncoding.base32().encode(buffer);
    }

    /**
     * 计算给定 Secret 的 OTP
     *
     * @param secret Base32 编码的密钥
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static int calculateCode(String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = BaseEncoding.base32().decode(secret);
        return rawCalculate(key, Longs.toByteArray(getTime(DEFAULT_TIME_STEP_IN_SECONDS)));
    }

    /**
     * 计算给定 Secret 的 OTP
     *
     * @param secret   Base32 编码的密钥
     * @param timeStep 自定义时间步长，单位为秒
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static int calculateCode(String secret, long timeStep) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = BaseEncoding.base32().decode(secret);
        return rawCalculate(key, Longs.toByteArray(getTime(timeStep)));
    }

    /**
     * 验证给定的 OTP 是否正确
     *
     * @param secret Base32 编码的密钥
     * @param code   待验证的 OTP
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static boolean verifyCode(String secret, int code) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = BaseEncoding.base32().decode(secret);
        return rawCalculate(key, Longs.toByteArray(getTime(DEFAULT_TIME_STEP_IN_SECONDS))) == code;
    }

    /**
     * 验证给定的 OTP 是否正确
     *
     * @param secret     Base32 编码的密钥
     * @param code       待验证的 OTP
     * @param timeStep   自定义时间步长，单位为秒
     * @param windowSize 考虑到用户可能会出现时间不同步的情况，可以设置一个前后偏移窗口，比如设置为 3，那么会计算当前时间段前后 3 个时间段的验证码
     *                   0 表示只计算当前时间段的验证码
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static boolean verifyCode(String secret, int code, long timeStep, long windowSize) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = BaseEncoding.base32().decode(secret);
        long time = getTime(timeStep);
        if (rawCalculate(key, Longs.toByteArray(time)) == code) {
            return true;
        } else if (windowSize == 0) {
            return false;
        }
        for (long i = 1; i <= windowSize; i++) {
            if (rawCalculate(key, Longs.toByteArray(time - i)) == code) {
                return true;
            }
            if (rawCalculate(key, Longs.toByteArray(time + i)) == code) {
                return true;
            }
        }
        return false;
    }

    /**
     * 拼接一个可供 Google Authenticator 识别的二维码字符串
     *
     * @param secret       密钥
     * @param organization 组织名称，会显示在 Authenticator 中
     * @param account      账户名称，会显示在 Authenticator 中
     * @return
     */
    public static String generateQRCode(String secret, String organization, String account) {
        return String.format("otpauth://totp/%s:%s?secret=%s", organization, account, secret);
    }

    /**
     * @param key
     * @param payload
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static int rawCalculate(byte[] key, byte[] payload) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA1");
        hmac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] hash = hmac.doFinal(payload);
        return truncate(hash);
    }

    /**
     * https://github.com/google/google-authenticator-libpam/blob/master/src/google-authenticator.c
     *
     * @param hash
     * @return
     */
    private static int truncate(byte[] hash) {
        int offset = hash[20 - 1] & 0xF;
        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            // We are dealing with signed bytes:
            // we just keep the first byte.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= VERIFICATION_CODE_MODULUS;
        return (int) truncatedHash;
    }

    private static long getTime(long timeStep) {
        return (System.currentTimeMillis() / 1000L) / timeStep;
    }

    private Authenticator() {
        throw new IllegalStateException("Utility class");
    }
}