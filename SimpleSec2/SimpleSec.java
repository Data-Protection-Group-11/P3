import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Scanner;

public class SimpleSec {

	//String to hold the name of the private key file.
	public static final String PRIVATE_KEY_FILE = "./data/private.key";

	// String to hold name of the public key file.
	public static final String PUBLIC_KEY_FILE = "./data/public.key";

	public static void generate(){
		// Generate a pair of RSA keys
		System.out.println("caso g");
		//"Introduce passphrase:"
		Scanner myObj = new Scanner(System.in);  // Create a Scanner object
		System.out.println("Enter password for encrypting private key");

		String passphrase = myObj.nextLine();	// Read user input
		byte[] byteKey = passphrase.getBytes();  

		//Create public and private key using RSALibrary
		RSALibrary rsa = new RSALibrary();
		Key pv = null;
		KeyPair kp = null;

		try{
			kp = rsa.generateKeys();
			pv = kp.getPrivate();
			
		} catch (Exception e){
			e.getStackTrace();
		}

		SymmetricCipher s = new SymmetricCipher();
		try {
			byte[] ePrivKey = s.encryptCBC(pv.getEncoded(), byteKey);
			
			 // Store the public key in the file PUBLIC_KEY_FILE	  
			OutputStream out = new FileOutputStream(PUBLIC_KEY_FILE);
			out.write(kp.getPublic().getEncoded());
			out.close();

			//Store the private key in the file PRIVATE_KEY_FILE
			out = new FileOutputStream(PRIVATE_KEY_FILE);
			out.write(ePrivKey);
			out.close();

		} catch (Exception e){

		}


		// Encrypt the private key using AES/CBC using the passphrase as key
		
		// Store the encrypted private key in the file "private.key"
	}
	
	public static void encrypt(String sourceFile, String destinationFile){
		
		// Encrypt sourceFile using AES/CBC and a random AES key (session key)
		SymmetricCipher e = new SymmetricCipher();


		//generate a random aes key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128); // for example
		SecretKey sessionKey = keyGen.generateKey();
		byte[] encryptedFile = e.encryptCBC(sourceFile, sessionKey);

		// Session key is encrypted using RSA and the public key
		InputStream in = new FileInputStream(PUBLIC_KEY_FILE);
		PublicKey pubKey = (PublicKey) in.read();
		in.close();

		// Encrypt session key using RSALIBRARY.encrypt
		RSALibrary rsa = new RSALibrary();
		byte[] encSessionKey = rsa.encrypt(sessionKey, pubKey);

		// Concatenate encrypted session key with encrypted sourceFile
		byte[] result = new byte[encSessionKey.length + encryptedFile.length];
		System.arraycopy(encSessionKey, 0, result, 0, encSessionKey.length);
		System.arraycopy(encryptedFile, 0, result, encSessionKey.length, encryptedFile.length);
		
		// As the private key is needed, the user will insert the previous
		// passphrase in order to decrypt the "private.key" file
		Scanner myObj = new Scanner(System.in);  // Create a Scanner object
		System.out.println("Enter passphrase for signing the document");
		String passphrase = myObj.nextLine();	// Read user input
		byte[] byteKey = passphrase.getBytes();
		
		//get private key from file
		InputStream in2 = new FileInputStream(PRIVATE_KEY_FILE);
		PrivateKey privKey = (PrivateKey) in2.read();
		in2.close();
		byte[] decPrivKey = s.decryptCBC(privKey, byteKey);

		//from byte[] decprivkey to private key
		PrivateKey privK = (PrivateKey) decPrivKey;


		// The resulting concatenation is encrypted with the private key
		byte[] sign = rsa.sign(result, privateKey);
		
		//concatenate result with signature
		byte[] finalEnc = new byte[result.length + sign.length];
		System.arraycopy(result, 0, finalEnc, 0, result.length);
		System.arraycopy(sign, 0, finalEnc, result.length, sign.length);

		//save in destinationFile
		FileOutputStream out = new FileOutputStream(destinationFile);
		out.write(finalEnc);
		out.close();


		// The encrypted concatenation is again concatenated with the previously
		// encrypted session key

		
	}


	public static void main(String[] args) {
		switch ("g") {
			case "g": 
				generate();
			case "e":
				String sourceFile = "./data/data.txt";
				String destinationFile = "./data/dst.enc";

				//String sourceFile = args[1];
				//String destinationFile = args[2];
				encrypt(sourceFile, destinationFile);
				
			case "d":
				// Separate firm and payload

				// Verify firm

				// Separate ciphertext and encrypted session key

				// As private key is needed, introduce passphrase to decrypt the private.key file, and store the private key

				// Decrypt session key using RSA and private key

				// Use the session key to decrypt the ciphertext using AES/CBC

				// Result is stored int he file args[2]
			default:
				
				System.out.println("Error!");
			}

	}
}
