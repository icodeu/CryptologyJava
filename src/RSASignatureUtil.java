import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


public class RSASignatureUtil {
	
	public static final String KEY_ALGORITHM = "RSA";
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
	public static final String PUBLIC_KEY = "RSAPublicKey";
	public static final String PRIVATE_KEY = "RSAPrivateKey";
	public static final int KEY_SIZE = 512;
	
	public static byte[] sign(byte[] data, byte[] privateKey) throws Exception{
		//还原私钥  将私钥从字节数组转换为PrivateKey
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		//实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
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
	
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign) throws Exception{
		//还原公钥 将公钥从字节数组转换为PublicKey
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
		//实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		//生成公钥
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		//实例化Signature
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		//初始化Signature
		signature.initVerify(pubKey);
		//更新
		signature.update(data);
		//验证
		return signature.verify(sign);
	}
	
	public static byte[] getPrivateKey(Map<String, Object> keyMap) throws Exception{
		Key privateKey = (Key) keyMap.get(PRIVATE_KEY);  //注意Key包的导入
		return privateKey.getEncoded();
	}
	
	public static byte[] getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key publicKey = (Key) keyMap.get(PUBLIC_KEY);
		return publicKey.getEncoded();
	}
	
	public static Map<String, Object> initKey() throws Exception {
		//实例化密钥对生成器
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		//初始化密钥对生成器
		keyPairGenerator.initialize(KEY_SIZE);
		//生成密钥对
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		//封装密钥
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
}
