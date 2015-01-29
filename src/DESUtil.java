import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class DESUtil {
	
    public static byte[] initKey() throws Exception{
    	//KeyGenerator 提供对称密钥生成器的功能，支持各种算法  
    	KeyGenerator keygen = KeyGenerator.getInstance("DES");
    	//初始化密钥生成器，密钥加上8位校验共64位
    	keygen.init(56);
    	//生成密钥并返回
    	SecretKey secretKey = keygen.generateKey();
    	return secretKey.getEncoded();
    }
      
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
    	//恢复密钥 --将key从字节数组转换为SecretKey,负责保存对称密钥  
    	SecretKey secretKey = new SecretKeySpec(key, "DES");
    	//Cipher负责完成加密或解密工作  
    	Cipher cipher = Cipher.getInstance("DES");
        // 根据密钥，对Cipher对象进行初始化，ENCRYPT_MODE表示加密模式  
    	cipher.init(Cipher.ENCRYPT_MODE, secretKey);  
        // 加密，结果保存进cipherByte  
        byte[] cipherByte = cipher.doFinal(data);  
        return cipherByte;  
    }  
   
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception { 
    	//恢复密钥 --将key从字节数组转换为SecretKey,负责保存对称密钥 
    	SecretKey secretKey = new SecretKeySpec(key, "DES");
    	//Cipher负责完成加密或解密工作  
    	Cipher cipher = Cipher.getInstance("DES");
        // 根据密钥，对Cipher对象进行初始化，DECRYPT_MODE表示解密模式  
    	cipher.init(Cipher.DECRYPT_MODE, secretKey);  
    	// 加密，结果保存进plainByte  
        byte[] plainByte = cipher.doFinal(data);  
        return plainByte;  
    }  
	
}
