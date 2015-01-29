import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class TripleDESUtil {

	public static byte[] initKey() throws Exception {
		KeyGenerator keygen = KeyGenerator.getInstance("DESede");
		keygen.init(168);
		SecretKey secretKey = keygen.generateKey();
		return secretKey.getEncoded();
	}

	public static byte[] encrypt3DES(byte[] data, byte[] key) throws Exception {
		SecretKey secretKey = new SecretKeySpec(key, "DESede");
		Cipher cipher = Cipher.getInstance("DESede");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] cipherByte = cipher.doFinal(data);
		return cipherByte;
	}

	public static byte[] decrypt3DES(byte[] data, byte[] key) throws Exception {
		SecretKey secretKey = new SecretKeySpec(key, "DESede");
		Cipher cipher = Cipher.getInstance("DESede");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] plainByte = cipher.doFinal(data);
		return plainByte;
	}

}
