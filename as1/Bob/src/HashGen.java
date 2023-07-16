import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.security.spec.X509EncodedKeySpec;

public class HashGen {
    private static final String PUBLIC_KEY_FILE = "../Alice/pk.bin";
    private static final String HASH_FILE = "hash.txt";

    public static void main(String[] args) throws Exception {
        // 从公钥文件中读取公钥
        FileInputStream fis = new FileInputStream(PUBLIC_KEY_FILE);
        byte[] publicKeyBytes = new byte[fis.available()];
        fis.read(publicKeyBytes);
        fis.close();
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        // 计算公钥的哈希值
        byte[] hash = MessageDigest.getInstance("SHA-1").digest(publicKey.getEncoded());

        // 将哈希值转换为 Base64 编码字符串
        String hashString = Base64.getEncoder().encodeToString(hash);

        // 保存哈希值到文件
        FileOutputStream fos = new FileOutputStream(HASH_FILE);
        fos.write(hashString.getBytes(StandardCharsets.UTF_8));
        fos.close();

        System.out.println("Hash generated successfully.");
    }
}