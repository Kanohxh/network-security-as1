import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.math.BigInteger;
import javax.crypto.Cipher;

public class Client {
    private static final String KEY_FILE = "../Alice/pk.bin";
    private static final String HASH_FILE = "hash.txt";

    public static void main(String[] args) throws Exception {
        // 从公钥文件中读取 Alice 的公钥
        FileInputStream keyfis = new FileInputStream(KEY_FILE);
        byte[] encodedKey = keyfis.readAllBytes();
        keyfis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // 从文件中读取 Alice 的公钥哈希值
        BufferedReader hashReader = new BufferedReader(new FileReader(HASH_FILE));
        byte[] storedHash = Base64.getDecoder().decode(hashReader.readLine());
        hashReader.close();

        // 比较哈希值
        byte[] actualHash = MessageDigest.getInstance("SHA-1").digest(publicKey.getEncoded());
        if (!MessageDigest.isEqual(storedHash, actualHash)) {
            System.err.println("Public key has been tampered with.");
            return;
        }

        // 请求用户名和密码
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        System.out.print("Enter username: ");
        String username = in.readLine();
        System.out.print("Enter password: ");
        String password = in.readLine();

        // 连接服务器套接字并创建输入输出流
        Socket serverSocket = new Socket("localhost", 12345);
        ObjectOutputStream out = new ObjectOutputStream(serverSocket.getOutputStream());
        out.flush();
        ObjectInputStream inFromServer = new ObjectInputStream(serverSocket.getInputStream());

        // 发送用户名给服务器
        out.writeObject(username);
        out.flush();

        // 接收加密后的 NA，并使用 RSA 公钥解密
        byte[] encryptedNa = (byte[]) inFromServer.readObject();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedNa = cipher.doFinal(encryptedNa);
        BigInteger na = new BigInteger(1, decryptedNa);

        // 计算 OTP，并用 RSA 公钥加密后发送给服务器
        byte[] hashedPassword = MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
        BigInteger otp = na.xor(new BigInteger(1, hashedPassword));
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedOtp = cipher.doFinal(otp.toByteArray());
        out.writeObject(encryptedOtp);
        out.flush();

        // 接收服务器的认证结果
        String message = (String) inFromServer.readObject();
        System.out.println(message);

        // 关闭输入输出流和套接字
        inFromServer.close();
        out.close();
        serverSocket.close();
    }
}