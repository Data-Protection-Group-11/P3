import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SimpleSec {

	//String to hold the name of the private key file.
	public static final String PRIVATE_KEY_FILE = "./data/private.key";

	// String to hold name of the public key file.
	public static final String PUBLIC_KEY_FILE = "./data/public.key";

	public static void generate(){
		//"Introduce passphrase:"
		Scanner myObj = new Scanner(System.in);  // Create a Scanner object
		System.out.println("Enter passfrase for encrypting private key");
		System.out.println("This passfrase must be 16 characters long");

		String passphrase = myObj.nextLine();	// Read user input
		byte[] byteKey = passphrase.getBytes();  
		if(byteKey.length != 16){
			System.out.println("Error, enter a 16 character passphrase");
			System.exit(0);
		}

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
			// Encrypt the private key using AES/CBC using the passphrase as key
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
			e.printStackTrace();
		}
	}
	
	public static PublicKey loadPublicKey(String inputFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		// read public key DER file
		File pubKeyFile = new File(inputFile);
        DataInputStream dis = new DataInputStream(new 
        FileInputStream(pubKeyFile));
        byte[] pubKeyBytes = new byte[(int)pubKeyFile.length()];
        dis.readFully(pubKeyBytes);
        dis.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
		PublicKey pk = keyFactory.generatePublic(pubKeySpec);
		return pk;
	}


	public static PrivateKey loadPrivateKey(String inputFile, byte[] byteKey) throws Exception, IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		// read private key from file
		File pubKeyFile = new File(inputFile);
        DataInputStream dis = new DataInputStream(new 
        FileInputStream(pubKeyFile));
        byte[] privKeyBytes = new byte[(int)pubKeyFile.length()];
        dis.readFully(privKeyBytes);
        dis.close();
		
		SymmetricCipher s = new SymmetricCipher();
		byte[] dPrivKey = s.decryptCBC(privKeyBytes, byteKey);

 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
			dPrivKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}


	public static void encrypt(String sourceFile, String destinationFile) throws Exception{
		//generate a random AES key (session key)
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128); // for example
		Key sessionKey = keyGen.generateKey();
		
		SymmetricCipher e = new SymmetricCipher();
	
		//get data to encrypt
		Path path = Paths.get(sourceFile);
        String input = new String();
        try {
            input = Files.readString(path);
        } catch (IOException ex) {
            ex.printStackTrace();
        }

		// Encrypt sourceFile using AES/CBC and a session key
		byte[] encryptedFile = e.encryptCBC(input.getBytes(), sessionKey.getEncoded());

		// Session key is encrypted using RSA and the public key
		PublicKey pubKey = loadPublicKey(PUBLIC_KEY_FILE);

		// Encrypt session key using RSALIBRARY.encrypt
		RSALibrary rsa = new RSALibrary();
		byte[] encSessionKey = rsa.encrypt(sessionKey.getEncoded(), pubKey);

		// Concatenate encrypted session key with encrypted sourceFile
		byte[] result = new byte[encSessionKey.length + encryptedFile.length];
		System.arraycopy(encryptedFile, 0, result, 0, encryptedFile.length);
		System.arraycopy(encSessionKey, 0, result, encryptedFile.length, encSessionKey.length);


		// As the private key is needed, the user will insert the previous
		// passphrase in order to decrypt the "private.key" file
		Scanner myObj = new Scanner(System.in);  // Create a Scanner object
		System.out.println("Enter passphrase for signing the document with the Private key");
		String passphrase = myObj.nextLine();	// Read user input
		byte[] byteKey = passphrase.getBytes();

		//get the private key from its file and the passphrase provided:
		PrivateKey privK = loadPrivateKey(PRIVATE_KEY_FILE, byteKey);

		// The resulting concatenation is encrypted with the private key
		byte[] sign = rsa.sign(result, privK);
		
		//concatenate result with signature
		byte[] finalEnc = new byte[result.length + sign.length];
		System.arraycopy(result, 0, finalEnc, 0, result.length);
		System.arraycopy(sign, 0, finalEnc, result.length, sign.length);

		//save in destinationFile
		FileOutputStream out = new FileOutputStream(destinationFile);
		out.write(finalEnc);
		out.close();

		
	}

	public static void decrypt(String sourceFile, String destinationFile) throws Exception{
		// Separate firm and payload from the sourceFile
		File f = new File(sourceFile);
		DataInputStream dis = new DataInputStream(new 
		FileInputStream(f));
		int size = (int)f.length();
		byte[] data = new byte[size];
		dis.read(data);
		dis.close();

		//get 128 bytes signature and the rest are for the data package
		byte[] signature = new byte[128];
		byte[] other = new byte[size - 128];
		System.arraycopy(data, 0, other, 0, size - 128);
		System.arraycopy(data, size - 128, signature, 0, 128);


		//get public key from file to decrypt the signature
		PublicKey pubKey = loadPublicKey(PUBLIC_KEY_FILE);

		//decrypt signature
		RSALibrary rsa = new RSALibrary();
		
		
		// Verify firm
		boolean valid = rsa.verify(other, signature, pubKey);
		if(valid) System.out.println("Signature is valid");
		else {
			System.out.println("Signature is not valid");
			System.out.println("Exiting program");
			return;
		}

		// As private key is needed, introduce passphrase to decrypt the private.key file, and store the private key
		Scanner myObj = new Scanner(System.in);  // Create a Scanner object
		System.out.println("Enter passphrase for decrypting the private key");

		String passphrase = myObj.nextLine();	// Read user input
		byte[] byteKey = passphrase.getBytes();  


		//other contains the session key and the plaintext ciphered with the session key
		byte[] sessionKeyEnc = new byte[128];
		byte[] encryptedText = new byte[other.length - 128];
		System.arraycopy(other, 0, encryptedText, 0, other.length - 128);
		System.arraycopy(other, other.length - 128, sessionKeyEnc, 0, 128);

		//get pk from file with passphrase inserted
		PrivateKey privK = loadPrivateKey(PRIVATE_KEY_FILE, byteKey);

		// Decrypt session key using RSA and private key
		byte[] sessionKeyDec = rsa.decrypt(sessionKeyEnc, privK);

		// Use the session key to decrypt the ciphertext using AES/CBC
		SymmetricCipher s = new SymmetricCipher();
		byte[] decryptedText = s.decryptCBC(encryptedText, sessionKeyDec);

		// Result is stored int he file args[2]
		FileOutputStream out = new FileOutputStream(destinationFile);
		out.write(decryptedText);
		out.close();

	}

	public static void main(String[] args) throws Exception{
		switch (args[0]) {
			case "g": 
				generate();
				System.out.println("Keys created");
				break;
			case "e":
				String sourceFile = "./data/data.txt";
				String destinationFile = "./data/dst.enc";
				encrypt(sourceFile, destinationFile);
				break;
			case "d":
				String sourceFile2 = "./data/dst.enc";
				String destinationFile2 = "./data/dst.dec";
				decrypt(sourceFile2, destinationFile2);
				break;
			default:
				System.out.println("Error!");
				break;
			}

	}
}
