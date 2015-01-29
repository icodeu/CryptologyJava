import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class DESUtil {
	
    public static byte[] initKey() throws Exception{
    	//KeyGenerator �ṩ�Գ���Կ�������Ĺ��ܣ�֧�ָ����㷨  
    	KeyGenerator keygen = KeyGenerator.getInstance("DES");
    	//��ʼ����Կ����������Կ����8λУ�鹲64λ
    	keygen.init(56);
    	//������Կ������
    	SecretKey secretKey = keygen.generateKey();
    	return secretKey.getEncoded();
    }
      
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
    	//�ָ���Կ --��key���ֽ�����ת��ΪSecretKey,���𱣴�Գ���Կ  
    	SecretKey secretKey = new SecretKeySpec(key, "DES");
    	//Cipher������ɼ��ܻ���ܹ���  
    	Cipher cipher = Cipher.getInstance("DES");
        // ������Կ����Cipher������г�ʼ����ENCRYPT_MODE��ʾ����ģʽ  
    	cipher.init(Cipher.ENCRYPT_MODE, secretKey);  
        // ���ܣ���������cipherByte  
        byte[] cipherByte = cipher.doFinal(data);  
        return cipherByte;  
    }  
   
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception { 
    	//�ָ���Կ --��key���ֽ�����ת��ΪSecretKey,���𱣴�Գ���Կ 
    	SecretKey secretKey = new SecretKeySpec(key, "DES");
    	//Cipher������ɼ��ܻ���ܹ���  
    	Cipher cipher = Cipher.getInstance("DES");
        // ������Կ����Cipher������г�ʼ����DECRYPT_MODE��ʾ����ģʽ  
    	cipher.init(Cipher.DECRYPT_MODE, secretKey);  
    	// ���ܣ���������plainByte  
        byte[] plainByte = cipher.doFinal(data);  
        return plainByte;  
    }  
	
}
