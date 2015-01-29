import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class Main {
	// �����ܵ�����
	public static final String DATA = "jikexueyuan";
	// �ļ���Ե�ַ����������MD5
	public static final String PATH = "mysql-installer-web-community-5.6.22.0.msi";

	public static void main(String[] args) throws Exception {
		
		/* ����Base64 */
		String base64Result = Base64Util.encryptBase64(DATA.getBytes());
		System.out.println(DATA + "  >>>Base64 ����>>> " + base64Result);
		String base64String = Base64Util.decryptBase64(base64Result);
		System.out.println(DATA + "  >>>Base64 ����>>> " + base64String);
		showDivider();
		

		/* ����MD5 */
		String md5Result = MessageDigestUtil.encryptMD5(DATA.getBytes());
		System.out.println(DATA + "  >>>MD5>>>  " + md5Result);
		showDivider();
		

		/* �����ļ�MD5 */
		String fileMD5Result = MessageDigestUtil.getMD5OfFile(PATH);
		System.out.println("�ļ�MD5: " + fileMD5Result);
		showDivider();
		

		/* ����SHA */
		String shaResult = MessageDigestUtil.encryptSHA(DATA.getBytes());
		System.out.println(DATA + "  >>>SHA>>>  " + shaResult);
		showDivider();
		

		/* ����HMAC */
		byte[] hmacKey = MessageDigestUtil.initHMACKey();
		System.out.println("HMAC ��Կ(): " + BytesToString.fromBytesToString(hmacKey));
		String hmacResult = MessageDigestUtil.encryptHMAC(DATA.getBytes(), hmacKey);
		System.out.println(DATA + "  >>>HMAC>>>  " + hmacResult);
		showDivider();
		

		/* ����DES */
		byte[] desKey = DESUtil.initKey();
		System.out.println("DES ��Կ(56+8): " + BytesToString.fromBytesToString(desKey));
		byte[] desResult = DESUtil.encrypt(DATA.getBytes(), desKey);
		System.out.println(DATA + "  >>>DES ����>>> " + BytesToString.fromBytesToString(desResult));
		byte[] plain = DESUtil.decrypt(desResult, desKey);
		System.out.println(DATA + "  >>>DES ����>>> " + new String(plain));
		showDivider();
		

		/* ����3DES */
		byte[] tripledesKey = TripleDESUtil.initKey();
		System.out.println("3DES ��Կ(168+24): " + BytesToString.fromBytesToString(tripledesKey));
		byte[] tripledesResult = TripleDESUtil.encrypt3DES(DATA.getBytes(), tripledesKey);
		System.out.println(DATA + "  >>>3DES ����>>> " + BytesToString.fromBytesToString(tripledesResult));
		byte[] tripledesPlain = TripleDESUtil.decrypt3DES(tripledesResult, tripledesKey);
		System.out.println(DATA + "  >>>3DES ����>>> "
				+ new String(tripledesPlain));
		showDivider();
		

		/* ����AES */
		byte[] aesKey = AESUtil.initKey();
		System.out.println("AES ��Կ(128λ): " + BytesToString.fromBytesToString(aesKey));
		byte[] aesResult = AESUtil.encrypt(DATA.getBytes(), aesKey);
		System.out.println(DATA + "  >>>AES ����>>> " + BytesToString.fromBytesToString(aesResult));
		byte[] aesPlain = AESUtil.decrypt(aesResult, aesKey);
		System.out.println(DATA + "  >>>AES ����>>> " + new String(aesPlain));
		showDivider();
		

		/* ����RSA */
		Map<String, Object> keyMap = RSAUtil.initKey();
		RSAPublicKey publicKey = RSAUtil.getPublicKey(keyMap);
		RSAPrivateKey privateKey = RSAUtil.getPrivateKey(keyMap);
		System.out.println("PublicKey: " + publicKey);
		System.out.println("PrivateKey: " + privateKey);

		byte[] rsaResult = RSAUtil.encryptRSA(DATA.getBytes(), publicKey);
		System.out.println(DATA + "  >>>RSA ����>>> " + BytesToString.fromBytesToString(rsaResult));
		byte[] rsaPlain = RSAUtil.decryptRSA(rsaResult, privateKey);
		System.out.println(DATA + "  >>>RSA ����>>> " + new String(rsaPlain));
		showDivider();
		

		/* ����RSA Signature */
		byte[] privateKeyRSA;
		byte[] publicKeyRSA;

		Map<String, Object> keyMapRSA = RSASignatureUtil.initKey();
		publicKeyRSA = RSASignatureUtil.getPublicKey(keyMapRSA);
		privateKeyRSA = RSASignatureUtil.getPrivateKey(keyMapRSA);
		System.out.println("RSASignature ��Կ: " + BytesToString.fromBytesToString(publicKeyRSA));
		System.out.println("RSASignature ˽Կ: " + BytesToString.fromBytesToString(privateKeyRSA));

		byte[] sign = RSASignatureUtil.sign(DATA.getBytes(), privateKeyRSA);
		System.out.println("RSAǩ��Ϊ: " + BytesToString.fromBytesToString(sign));
		boolean verifyBool = RSASignatureUtil.verify(DATA.getBytes(),
				publicKeyRSA, sign);
		// boolean verifyBool = RSASignature.verify((DATA +
		// "123").getBytes(), publicKeyRSA, sign); //ȡ������ע�� ע������һ�� ��ǩ����֤ʧ��
		System.out.println("RSA��֤���: " + verifyBool);
		showDivider();

		/* ����DSA Signature */
		byte[] privateKeyDSA;
		byte[] publicKeyDSA;
		Map<String, Object> keyMapDSA = DSASignatureUtil.initKey();
		publicKeyDSA = DSASignatureUtil.getPublicKey(keyMapDSA);
		privateKeyDSA = DSASignatureUtil.getPrivateKey(keyMapDSA);
		System.out.println("DSASignature ��Կ: " + BytesToString.fromBytesToString(publicKeyDSA));
		System.out.println("DSASignature ˽Կ: " + BytesToString.fromBytesToString(privateKeyDSA));

		sign = DSASignatureUtil.sign(DATA.getBytes(), privateKeyDSA);
		System.out.println("DSAǩ��Ϊ: " + BytesToString.fromBytesToString(sign));
		verifyBool = DSASignatureUtil
				.verify(DATA.getBytes(), publicKeyDSA, sign);
		// verifyBool = DSASignature.verify((DATA + "123").getBytes(),
		// publicKeyDSA, sign); //ȡ������ע�� ע������һ�� ��ǩ����֤ʧ��
		System.out.println("DSA��֤���: " + verifyBool);
		showDivider();
		
		
		/*����DH��Կ����*/
		//�׷���Կ
		byte[] publicKey1;
		//�׷�˽Կ
		byte[] privateKey1;
		//�׷�������Կ
		byte[] secretKey1;
		//�ҷ���Կ
		byte[] publicKey2;
		//�ҷ�˽Կ
		byte[] privateKey2;
		//�ҷ�������Կ
		byte[] secretKey2;
		
		//��ʼ����Կ �����ɼ׷���Կ��
		Map<String, Object> keyMap1 = DHUtil.initKey();
		publicKey1 = DHUtil.getPublicKey(keyMap1);
		privateKey1 = DHUtil.getPrivateKey(keyMap1);
		System.out.println("DH�׷���Կ: " + BytesToString.fromBytesToString(publicKey1));
		System.out.println("DH�׷�˽Կ: " + BytesToString.fromBytesToString(privateKey1));
		//�ҷ����ݼ׷���Կ�����ҷ���Կ��
		Map<String, Object> keyMap2 = DHUtil.initKey(publicKey1);
		publicKey2 = DHUtil.getPublicKey(keyMap2);
		privateKey2 = DHUtil.getPrivateKey(keyMap2);
		System.out.println("DH�ҷ���Կ: " + BytesToString.fromBytesToString(publicKey2));
		System.out.println("DH�ҷ�˽Կ: " + BytesToString.fromBytesToString(privateKey2));
		//���ڼ׷��� ������˽Կ���ҷ��������Ĺ�Կ�� �����䱾����ԿsecretKey1
		secretKey1 = DHUtil.getSecretKey(publicKey2, privateKey1);
		System.out.println("�׷�������Կ: " + BytesToString.fromBytesToString(secretKey1));
		//�����ҷ��� ������˽Կ�ͼ׷��������Ĺ�Կ�� �����䱾����ԿsecretKey2
		secretKey2 = DHUtil.getSecretKey(publicKey1, privateKey2);
		System.out.println("�ҷ�������Կ: " + BytesToString.fromBytesToString(secretKey2));
	}
	
	
	private static void showDivider(){
		System.out.println("--------------------------------------------\n");
	}
}
