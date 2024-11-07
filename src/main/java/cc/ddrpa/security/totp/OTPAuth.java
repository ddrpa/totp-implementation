package cc.ddrpa.security.totp;

public class OTPAuth {

    private String secret;
    private String organization;
    private String account;

    public OTPAuth(String secret, String organization, String account) {
        this.secret = secret;
        this.organization = organization;
        this.account = account;
    }

    public String secret() {
        return secret;
    }

    public String organization() {
        return organization;
    }

    public String account() {
        return account;
    }
}