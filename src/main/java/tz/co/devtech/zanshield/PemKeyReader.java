package tz.co.devtech.zanshield;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Parses PEM-encoded RSA keys: PKCS#8 private keys and X.509 public keys. */
public final class PemKeyReader {

    private PemKeyReader() {}

    public static PrivateKey readPrivateKey(String pem) {
        try {
            byte[] der = Base64.getMimeDecoder().decode(strip(pem));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid RSA private key PEM", e);
        }
    }

    public static PublicKey readPublicKey(String pem) {
        try {
            byte[] der = Base64.getMimeDecoder().decode(strip(pem));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(new X509EncodedKeySpec(der));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid RSA public key PEM", e);
        }
    }

    private static String strip(String pem) {
        return pem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s", "");
    }
}
