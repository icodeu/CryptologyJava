import java.io.File;
import java.io.FileInputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MessageDigestUtil {

	public static String encryptMD5(byte[] data) throws Exception {
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		md5.update(data);
		byte[] resultBytes = md5.digest();

		String resultString = BytesToString.fromBytesToString(resultBytes);
		return resultString;
	}

	public static String encryptSHA(byte[] data) throws Exception {
		MessageDigest sha = MessageDigest.getInstance("SHA");
		sha.update(data);
		byte[] resultBytes = sha.digest();

		String resultString = BytesToString.fromBytesToString(resultBytes);
		return resultString;
	}
	
	public static byte[] initHMACKey() throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
		keyGen.init(64);  //接受任何大小的密钥 但密文都是128位
		SecretKey secretKey = keyGen.generateKey();
		return secretKey.getEncoded();
	}

	public static String encryptHMAC(byte[] data, byte[] key) throws Exception {
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD5");
		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(secretKey);
		byte[] resultBytes = mac.doFinal(data);
		String resultString = BytesToString.fromBytesToString(resultBytes);
		return resultString;
	}
	
	public static String getMD5OfFile(String path) throws Exception{
		FileInputStream fis = new FileInputStream(new File(path));
		DigestInputStream dis = new DigestInputStream(fis, MessageDigest.getInstance("MD5"));
		byte[] buffer = new byte[1024];
		int read = dis.read(buffer, 0, 1024);
		while (read != -1){
			read = dis.read(buffer, 0, 1024);
		}
		dis.close();
		MessageDigest md = dis.getMessageDigest();
		byte[] resultBytes = md.digest();
		String resultString = BytesToString.fromBytesToString(resultBytes);
		return resultString;
	}

}
