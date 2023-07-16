import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import java.math.BigInteger;

public class Host {
    private static final String KEY_FILE = "sk.bin";
    private static final String PASSWORD_FILE = "password.txt";

    public static void main(String[] args) throws Exception {
        // 从私钥文件中读取 Alice 的私钥
        FileInputStream keyfis = new FileInputStream(KEY_FILE);
        byte[] encodedKey = keyfis.readAllBytes();
        keyfis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // 读取密码文件
        BufferedReader passwordReader = new BufferedReader(new FileReader(PASSWORD_FILE));
        String[] passwordInfo = passwordReader.readLine().split(",");
        String username = passwordInfo[0];
        byte[] hashedPassword = hexStringToByteArray(passwordInfo[1]);
        passwordReader.close();

        // 创建服务器套接字并等待客户端连接
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Host started. Waiting for connection...");
        Socket clientSocket = serverSocket.accept();
        System.out.println("Client connected.");

        // 创建输入输出流
        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
        out.flush();
        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

        // 接收客户端发送的用户名
        String clientUsername = (String) in.readObject();
        if (!clientUsername.equals(username)) {
            System.err.println("Invalid username.");
            return;
        }

        // 生成随机数 NA
        SecureRandom random = new SecureRandom();
        byte[] naBytes = new byte[32];
        random.nextBytes(naBytes);
        BigInteger na = new BigInteger(1, naBytes);

        // 使用 RSA 私钥加密 NA，并发送给客户端
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedNa = cipher.doFinal(na.toByteArray());
        out.writeObject(encryptedNa);
        out.flush();

        // 接收客户端发送的加密后的 OTP，并进行解密和验证
        byte[] encryptedOtp = (byte[]) in.readObject();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedOtp = cipher.doFinal(encryptedOtp);
        BigInteger otp = new BigInteger(1, decryptedOtp);
        if (!otp.equals(na.xor(new BigInteger(1, hashedPassword)))) {
            System.err.println("Invalid password.");
            return;
        }

        // 发送认证通过的消息
        out.writeObject("Authentication succeeded.");
        out.flush();

        // 关闭输入输出流和套接字
        in.close();
        out.close();
        clientSocket.close();
        serverSocket.close();

        System.out.println("Authentication succeeded.");
    }

    /**
     * 将十六进制字符串转换为字节数组
     */
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}