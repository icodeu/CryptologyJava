import Decoder.BASE64Decoder;
import Decoder.BASE64Encoder;

public class Base64Util {

	public static String encryptBase64(byte[] data) {
		String resultString = new BASE64Encoder().encode(data);
		return resultString;
	}

	public static String decryptBase64(String data) throws Exception {
		byte[] resultBytes = new BASE64Decoder().decodeBuffer(data);
		return new String(resultBytes);
	}

}
