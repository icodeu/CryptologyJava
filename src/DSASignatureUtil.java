import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


public class DSASignatureUtil {
	public static final String ALGORITHM = "DSA";
	public static final String SIGNATURE_ALGORITHM = "SHA1withDSA";
	public static final String PUBLIC_KEY = "DSAPublicKey";
	public static final String PRIVATE_KEY = "DSAPrivateKey";
	public static final int KEY_SIZE = 1024;
	
	public static byte[] sign(byte[] data, byte[] privateKey) throws Exception {
		//还原私钥  将私钥从字节数组转换为PrivateKey
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		//实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		//取得私钥对象
		PrivateKey priKey = keyFactory.generatePrivate(keySpec);
		//实例化Signature
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		//初始化Signature
		signature.initSign(priKey);
		//更新
		signature.update(data);
		//生成签名
		return signature.sign();
	}
	
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign) throws Exception {
		//还原公钥 将公钥从字节数组转换为PublicKey
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
		//实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		//取得公钥对象
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		//实例化Signature
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		//初始化Signature
		signature.initVerify(pubKey);
		//更新
		signature.update(data);
		//验证签名
		return signature.verify(sign);
	}
	
	public static Map<String, Object> initKey() throws Exception {
		//初始化密钥对生成器
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
		//实例化密钥对生成器
		keyPairGenerator.initialize(KEY_SIZE);  //可加入new SecureRandom
		//实例化密钥对
		KeyPair keyPair = keyPairGenerator.generateKeyPair();  //也可以 .genKeyPair()
		DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();
		DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
		//封装密钥
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
	
	public static byte[] getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
	
	public static byte[] getPrivateKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}
	
}
