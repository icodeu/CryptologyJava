import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class Main {
	// 待加密的明文
	public static final String DATA = "jikexueyuan";
	// 文件相对地址，用来计算MD5
	public static final String PATH = "mysql-installer-web-community-5.6.22.0.msi";

	public static void main(String[] args) throws Exception {
		
		/* 测试Base64 */
		String base64Result = Base64Util.encryptBase64(DATA.getBytes());
		System.out.println(DATA + "  >>>Base64 加密>>> " + base64Result);
		String base64String = Base64Util.decryptBase64(base64Result);
		System.out.println(DATA + "  >>>Base64 解密>>> " + base64String);
		showDivider();
		

		/* 测试MD5 */
		String md5Result = MessageDigestUtil.encryptMD5(DATA.getBytes());
		System.out.println(DATA + "  >>>MD5>>>  " + md5Result);
		showDivider();
		

		/* 计算文件MD5 */
		String fileMD5Result = MessageDigestUtil.getMD5OfFile(PATH);
		System.out.println("文件MD5: " + fileMD5Result);
		showDivider();
		

		/* 测试SHA */
		String shaResult = MessageDigestUtil.encryptSHA(DATA.getBytes());
		System.out.println(DATA + "  >>>SHA>>>  " + shaResult);
		showDivider();
		

		/* 测试HMAC */
		byte[] hmacKey = MessageDigestUtil.initHMACKey();
		System.out.println("HMAC 密钥(): " + BytesToString.fromBytesToString(hmacKey));
		String hmacResult = MessageDigestUtil.encryptHMAC(DATA.getBytes(), hmacKey);
		System.out.println(DATA + "  >>>HMAC>>>  " + hmacResult);
		showDivider();
		

		/* 测试DES */
		byte[] desKey = DESUtil.initKey();
		System.out.println("DES 密钥(56+8): " + BytesToString.fromBytesToString(desKey));
		byte[] desResult = DESUtil.encrypt(DATA.getBytes(), desKey);
		System.out.println(DATA + "  >>>DES 加密>>> " + BytesToString.fromBytesToString(desResult));
		byte[] plain = DESUtil.decrypt(desResult, desKey);
		System.out.println(DATA + "  >>>DES 解密>>> " + new String(plain));
		showDivider();
		

		/* 测试3DES */
		byte[] tripledesKey = TripleDESUtil.initKey();
		System.out.println("3DES 密钥(168+24): " + BytesToString.fromBytesToString(tripledesKey));
		byte[] tripledesResult = TripleDESUtil.encrypt3DES(DATA.getBytes(), tripledesKey);
		System.out.println(DATA + "  >>>3DES 加密>>> " + BytesToString.fromBytesToString(tripledesResult));
		byte[] tripledesPlain = TripleDESUtil.decrypt3DES(tripledesResult, tripledesKey);
		System.out.println(DATA + "  >>>3DES 解密>>> "
				+ new String(tripledesPlain));
		showDivider();
		

		/* 测试AES */
		byte[] aesKey = AESUtil.initKey();
		System.out.println("AES 密钥(128位): " + BytesToString.fromBytesToString(aesKey));
		byte[] aesResult = AESUtil.encrypt(DATA.getBytes(), aesKey);
		System.out.println(DATA + "  >>>AES 加密>>> " + BytesToString.fromBytesToString(aesResult));
		byte[] aesPlain = AESUtil.decrypt(aesResult, aesKey);
		System.out.println(DATA + "  >>>AES 解密>>> " + new String(aesPlain));
		showDivider();
		

		/* 测试RSA */
		Map<String, Object> keyMap = RSAUtil.initKey();
		RSAPublicKey publicKey = RSAUtil.getPublicKey(keyMap);
		RSAPrivateKey privateKey = RSAUtil.getPrivateKey(keyMap);
		System.out.println("PublicKey: " + publicKey);
		System.out.println("PrivateKey: " + privateKey);

		byte[] rsaResult = RSAUtil.encryptRSA(DATA.getBytes(), publicKey);
		System.out.println(DATA + "  >>>RSA 加密>>> " + BytesToString.fromBytesToString(rsaResult));
		byte[] rsaPlain = RSAUtil.decryptRSA(rsaResult, privateKey);
		System.out.println(DATA + "  >>>RSA 解密>>> " + new String(rsaPlain));
		showDivider();
		

		/* 测试RSA Signature */
		byte[] privateKeyRSA;
		byte[] publicKeyRSA;

		Map<String, Object> keyMapRSA = RSASignatureUtil.initKey();
		publicKeyRSA = RSASignatureUtil.getPublicKey(keyMapRSA);
		privateKeyRSA = RSASignatureUtil.getPrivateKey(keyMapRSA);
		System.out.println("RSASignature 公钥: " + BytesToString.fromBytesToString(publicKeyRSA));
		System.out.println("RSASignature 私钥: " + BytesToString.fromBytesToString(privateKeyRSA));

		byte[] sign = RSASignatureUtil.sign(DATA.getBytes(), privateKeyRSA);
		System.out.println("RSA签名为: " + BytesToString.fromBytesToString(sign));
		boolean verifyBool = RSASignatureUtil.verify(DATA.getBytes(),
				publicKeyRSA, sign);
		// boolean verifyBool = RSASignature.verify((DATA +
		// "123").getBytes(), publicKeyRSA, sign); //取消此行注释 注释上面一行 则签名验证失败
		System.out.println("RSA验证结果: " + verifyBool);
		showDivider();

		/* 测试DSA Signature */
		byte[] privateKeyDSA;
		byte[] publicKeyDSA;
		Map<String, Object> keyMapDSA = DSASignatureUtil.initKey();
		publicKeyDSA = DSASignatureUtil.getPublicKey(keyMapDSA);
		privateKeyDSA = DSASignatureUtil.getPrivateKey(keyMapDSA);
		System.out.println("DSASignature 公钥: " + BytesToString.fromBytesToString(publicKeyDSA));
		System.out.println("DSASignature 私钥: " + BytesToString.fromBytesToString(privateKeyDSA));

		sign = DSASignatureUtil.sign(DATA.getBytes(), privateKeyDSA);
		System.out.println("DSA签名为: " + BytesToString.fromBytesToString(sign));
		verifyBool = DSASignatureUtil
				.verify(DATA.getBytes(), publicKeyDSA, sign);
		// verifyBool = DSASignature.verify((DATA + "123").getBytes(),
		// publicKeyDSA, sign); //取消此行注释 注释上面一行 则签名验证失败
		System.out.println("DSA验证结果: " + verifyBool);
		showDivider();
		
		
		/*测试DH密钥交换*/
		//甲方公钥
		byte[] publicKey1;
		//甲方私钥
		byte[] privateKey1;
		//甲方本地密钥
		byte[] secretKey1;
		//乙方公钥
		byte[] publicKey2;
		//乙方私钥
		byte[] privateKey2;
		//乙方本地密钥
		byte[] secretKey2;
		
		//初始化密钥 并生成甲方密钥对
		Map<String, Object> keyMap1 = DHUtil.initKey();
		publicKey1 = DHUtil.getPublicKey(keyMap1);
		privateKey1 = DHUtil.getPrivateKey(keyMap1);
		System.out.println("DH甲方公钥: " + BytesToString.fromBytesToString(publicKey1));
		System.out.println("DH甲方私钥: " + BytesToString.fromBytesToString(privateKey1));
		//乙方根据甲方公钥产生乙方密钥对
		Map<String, Object> keyMap2 = DHUtil.initKey(publicKey1);
		publicKey2 = DHUtil.getPublicKey(keyMap2);
		privateKey2 = DHUtil.getPrivateKey(keyMap2);
		System.out.println("DH乙方公钥: " + BytesToString.fromBytesToString(publicKey2));
		System.out.println("DH乙方私钥: " + BytesToString.fromBytesToString(privateKey2));
		//对于甲方， 根据其私钥和乙方发过来的公钥， 生成其本地密钥secretKey1
		secretKey1 = DHUtil.getSecretKey(publicKey2, privateKey1);
		System.out.println("甲方本地密钥: " + BytesToString.fromBytesToString(secretKey1));
		//对于乙方， 根据其私钥和甲方发过来的公钥， 生成其本地密钥secretKey2
		secretKey2 = DHUtil.getSecretKey(publicKey1, privateKey2);
		System.out.println("乙方本地密钥: " + BytesToString.fromBytesToString(secretKey2));
	}
	
	
	private static void showDivider(){
		System.out.println("--------------------------------------------\n");
	}
}
