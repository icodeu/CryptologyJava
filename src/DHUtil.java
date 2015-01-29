import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DHUtil {

	// 密钥交换算法
	public static final String KEY_ALGORITHM = "DH";
	// 本地密钥算法 DES 3DES AES
	public static final String SECRET_ALGORITHM = "AES";
	// 密钥长度 默认是1024 64的倍数 512-1024
	public static final int KEY_SIZE = 512;
	public static final String PUBLIC_KEY = "DHPublicKey";
	public static final String PRIVATE_KEY = "DHPrivateKey";

	// 初始化并返回甲方密钥对
	public static Map<String, Object> initKey() throws Exception {
		// 实例化密钥对生成器
		KeyPairGenerator keyPairGenerator = KeyPairGenerator
				.getInstance(KEY_ALGORITHM);
		// 初始化密钥对生成器
		keyPairGenerator.initialize(KEY_SIZE);
		// 生成密钥对
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// 得到甲方公钥
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		// 得到甲方私钥
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		// 将公钥和私钥封装在Map中， 方便之后使用
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	// 初始化并返回乙方密钥对
	public static Map<String, Object> initKey(byte[] key) throws Exception {
		// 将甲方公钥从字节数组转换为PublicKey
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		// 实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		// 产生甲方公钥pubKey
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		// 开始由甲方公钥构建乙方密钥
		DHParameterSpec dhParameterSpec = ((DHPublicKey) pubKey).getParams();
		//实例化密钥对生成器
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
		//初始化密钥对生成器
		keyPairGenerator.initialize(dhParameterSpec);
		//产生密钥对
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		//得到乙方公钥
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		//得到乙方私钥
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		// 将公钥和私钥封装在Map中， 方便之后使用
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
	
	//从Map中取得公钥
	public static byte[] getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
	
	//从Map中取得私钥
	public static byte[] getPrivateKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}
	
	public static byte[] getSecretKey(byte[] publicKey, byte[] privateKey) throws Exception {
		//实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		//将公钥从字节数组转换为PublicKey
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		//将私钥从字节数组转换为PrivateKey
		PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(privateKey);
		PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);
		//准备根据以上公钥和私钥生成本地密钥SecretKey
		//先实例化KeyAgreement
		KeyAgreement keyAgreement = KeyAgreement.getInstance(keyFactory.getAlgorithm());
		//用自己的私钥初始化keyAgreement
		keyAgreement.init(priKey);
		//结合对方的公钥进行运算
		keyAgreement.doPhase(pubKey, true);
		//开始生成本地密钥SecretKey
		SecretKey secretKey = keyAgreement.generateSecret(SECRET_ALGORITHM);
		return secretKey.getEncoded();
	}

}
