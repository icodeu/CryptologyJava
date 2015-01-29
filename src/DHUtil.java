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

	// ��Կ�����㷨
	public static final String KEY_ALGORITHM = "DH";
	// ������Կ�㷨 DES 3DES AES
	public static final String SECRET_ALGORITHM = "AES";
	// ��Կ���� Ĭ����1024 64�ı��� 512-1024
	public static final int KEY_SIZE = 512;
	public static final String PUBLIC_KEY = "DHPublicKey";
	public static final String PRIVATE_KEY = "DHPrivateKey";

	// ��ʼ�������ؼ׷���Կ��
	public static Map<String, Object> initKey() throws Exception {
		// ʵ������Կ��������
		KeyPairGenerator keyPairGenerator = KeyPairGenerator
				.getInstance(KEY_ALGORITHM);
		// ��ʼ����Կ��������
		keyPairGenerator.initialize(KEY_SIZE);
		// ������Կ��
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// �õ��׷���Կ
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		// �õ��׷�˽Կ
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		// ����Կ��˽Կ��װ��Map�У� ����֮��ʹ��
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	// ��ʼ���������ҷ���Կ��
	public static Map<String, Object> initKey(byte[] key) throws Exception {
		// ���׷���Կ���ֽ�����ת��ΪPublicKey
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		// ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		// �����׷���ԿpubKey
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		// ��ʼ�ɼ׷���Կ�����ҷ���Կ
		DHParameterSpec dhParameterSpec = ((DHPublicKey) pubKey).getParams();
		//ʵ������Կ��������
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
		//��ʼ����Կ��������
		keyPairGenerator.initialize(dhParameterSpec);
		//������Կ��
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		//�õ��ҷ���Կ
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		//�õ��ҷ�˽Կ
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		// ����Կ��˽Կ��װ��Map�У� ����֮��ʹ��
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
	
	//��Map��ȡ�ù�Կ
	public static byte[] getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
	
	//��Map��ȡ��˽Կ
	public static byte[] getPrivateKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}
	
	public static byte[] getSecretKey(byte[] publicKey, byte[] privateKey) throws Exception {
		//ʵ������Կ����
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		//����Կ���ֽ�����ת��ΪPublicKey
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		//��˽Կ���ֽ�����ת��ΪPrivateKey
		PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(privateKey);
		PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);
		//׼���������Ϲ�Կ��˽Կ���ɱ�����ԿSecretKey
		//��ʵ����KeyAgreement
		KeyAgreement keyAgreement = KeyAgreement.getInstance(keyFactory.getAlgorithm());
		//���Լ���˽Կ��ʼ��keyAgreement
		keyAgreement.init(priKey);
		//��϶Է��Ĺ�Կ��������
		keyAgreement.doPhase(pubKey, true);
		//��ʼ���ɱ�����ԿSecretKey
		SecretKey secretKey = keyAgreement.generateSecret(SECRET_ALGORITHM);
		return secretKey.getEncoded();
	}

}
