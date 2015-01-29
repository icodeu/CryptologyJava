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
		//��ԭ˽Կ  ��˽Կ���ֽ�����ת��ΪPrivateKey
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		//ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		//ȡ��˽Կ����
		PrivateKey priKey = keyFactory.generatePrivate(keySpec);
		//ʵ����Signature
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		//��ʼ��Signature
		signature.initSign(priKey);
		//����
		signature.update(data);
		//����ǩ��
		return signature.sign();
	}
	
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign) throws Exception{
		//��ԭ��Կ ����Կ���ֽ�����ת��ΪPublicKey
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
		//ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		//���ɹ�Կ
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		//ʵ����Signature
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		//��ʼ��Signature
		signature.initVerify(pubKey);
		//����
		signature.update(data);
		//��֤
		return signature.verify(sign);
	}
	
	public static byte[] getPrivateKey(Map<String, Object> keyMap) throws Exception{
		Key privateKey = (Key) keyMap.get(PRIVATE_KEY);  //ע��Key���ĵ���
		return privateKey.getEncoded();
	}
	
	public static byte[] getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key publicKey = (Key) keyMap.get(PUBLIC_KEY);
		return publicKey.getEncoded();
	}
	
	public static Map<String, Object> initKey() throws Exception {
		//ʵ������Կ��������
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		//��ʼ����Կ��������
		keyPairGenerator.initialize(KEY_SIZE);
		//������Կ��
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		//��װ��Կ
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
}
