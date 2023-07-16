import java.io.*;
import java.security.*;
import java.security.spec.*;

public class KeyGen {
    private static final String PUBLIC_KEY_FILE = "pk.bin";
    private static final String PRIVATE_KEY_FILE = "sk.bin";

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        // 保存公钥
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        FileOutputStream pubfos = new FileOutputStream(PUBLIC_KEY_FILE);
        pubfos.write(publicKeyBytes);
        pubfos.close();

        // 保存私钥
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        FileOutputStream prifos = new FileOutputStream(PRIVATE_KEY_FILE);
        prifos.write(privateKeyBytes);
        prifos.close();

        System.out.println("Keys generated successfully.");
    }
}