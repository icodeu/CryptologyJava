import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {
	
	public static byte[] initKey() throws Exception{
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(128);  //加入password可使密钥唯一
		SecretKey secretKey = keygen.generateKey();
		return secretKey.getEncoded();
	}

	public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
		SecretKey secretKey = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] cipherByte = cipher.doFinal(data);
		return cipherByte;
	}

	public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
		SecretKey secretKey = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] plainByte = cipher.doFinal(data);
		return plainByte;
	}

}
