import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

public class RSAUtil {

	public static final String PUBLIC_KEY = "RSAPublicKey";
	public static final String PRIVATE_KEY = "RSAPrivateKey";

	public static byte[] encryptRSA(byte[] srcBytes, RSAPublicKey publicKey)
			throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] resultBytes = cipher.doFinal(srcBytes);
		return resultBytes;
	}

	public static byte[] decryptRSA(byte[] srcBytes, RSAPrivateKey privateKey)
			throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] resultBytes = cipher.doFinal(srcBytes);
		return resultBytes;
	}

	public static Map<String, Object> initKey() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PRIVATE_KEY, privateKey);
		keyMap.put(PUBLIC_KEY, publicKey);
		return keyMap;
	}

	public static RSAPublicKey getPublicKey(Map<String, Object> keyMap)
			throws Exception {
		RSAPublicKey publicKey = (RSAPublicKey) keyMap.get(PUBLIC_KEY);
		return publicKey;
	}

	public static RSAPrivateKey getPrivateKey(Map<String, Object> keyMap)
			throws Exception {
		RSAPrivateKey privateKey = (RSAPrivateKey) keyMap.get(PRIVATE_KEY);
		return privateKey;
	}
}
