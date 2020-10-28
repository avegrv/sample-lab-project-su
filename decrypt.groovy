import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

if (args.size() < 2 ) {
  println "Usage: decrypt.groovy <base64 key> <base64 text>"
  return 1
}

final String cypherInstance = "AES/CBC/PKCS5Padding";
final String initializationVector = "8119745113154120";
    
String key = args[0]
String text = args[1]

byte[] decode = text.decodeBase64()
SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
Cipher instance = Cipher.getInstance(cypherInstance);
instance.init(2, secretKeySpec, new IvParameterSpec(initializationVector.getBytes()));
println new String(instance.doFinal(decode), StandardCharsets.UTF_8);