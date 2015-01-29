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
		//��ԭ˽Կ  ��˽Կ���ֽ�����ת��ΪPrivateKey
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		//ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
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
	
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign) throws Exception {
		//��ԭ��Կ ����Կ���ֽ�����ת��ΪPublicKey
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
		//ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		//ȡ�ù�Կ����
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		//ʵ����Signature
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		//��ʼ��Signature
		signature.initVerify(pubKey);
		//����
		signature.update(data);
		//��֤ǩ��
		return signature.verify(sign);
	}
	
	public static Map<String, Object> initKey() throws Exception {
		//��ʼ����Կ��������
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
		//ʵ������Կ��������
		keyPairGenerator.initialize(KEY_SIZE);  //�ɼ���new SecureRandom
		//ʵ������Կ��
		KeyPair keyPair = keyPairGenerator.generateKeyPair();  //Ҳ���� .genKeyPair()
		DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();
		DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
		//��װ��Կ
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
