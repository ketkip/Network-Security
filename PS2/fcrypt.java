import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class fcrypt {
	/**
	 * String to hold name of the encryption algorithms.
	 */
	public static final String ASSYMETRICALGORITHM = "RSA";
	public static final String SYMETRICALGORITHM = "AES";
	/**
	 * String to hold the name of the Receiver's private key file.
	 */
	public static final String RECEIVER_PRIVATE_KEY_FILE = "ReceiverPrivate.key";
	/**
	 * String to hold name of the Receivers's public key file.
	 */
	public static final String RECEIVER_PUBLIC_KEY_FILE = "ReceiverPublic.key";
	/**
	 * String to hold name of the Sender's public key file.
	 */
	public static final String SENDER_PUBLIC_KEY_FILE = "SenderPublic.key";
	/**
	 * String to hold name of the Sender's private key file.
	 */
	public static final String SENDER_PRIVATE_KEY_FILE = "SenderPrivate.key";

	/**
	 * Generates Symmetric key of 128 bits
	 * 
	 * @return Key object which is a Symmetric key
	 * */
	public static Key generateSymmetricKey() throws NoSuchAlgorithmException {
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128);
		Key s = (Key) kg.generateKey();
		return s;
	}

	/**
	 * Encrypts plain text using symmetric key
	 * 
	 * @return byte array which is cipher text
	 * */
	public static ArrayList<byte[]> aesEncrypt(String plainText, Key key) {
		byte[] cipherText = null;
		ArrayList<byte[]> nbb = new ArrayList<byte[]>();
		try {
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			byte[] iv = "1234567812345678".getBytes();
			c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			cipherText = c.doFinal(plainText.getBytes());
			nbb.add(cipherText);
			nbb.add(iv);

		} catch (Exception e) {
			e.getMessage();
		}
		return nbb;
	}

	/**
	 * Generates sender's pair of private and public keys and writes them in a
	 * file
	 * */
	public static void generateSendersKey() {
		SecureRandom random = new SecureRandom();
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator
					.getInstance(ASSYMETRICALGORITHM);
			keyGen.initialize(1024, random);
			final KeyPair key = keyGen.generateKeyPair();
			File privateKeyFile = new File(SENDER_PRIVATE_KEY_FILE);
			File publicKeyFile = new File(SENDER_PUBLIC_KEY_FILE);

			// Create files to store public and private key
			if (privateKeyFile.getParentFile() != null) {
				privateKeyFile.getParentFile().mkdirs();
			}
			privateKeyFile.createNewFile();

			if (publicKeyFile.getParentFile() != null) {
				publicKeyFile.getParentFile().mkdirs();
			}
			publicKeyFile.createNewFile();

			// Saving the Public key in a file
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(
					new FileOutputStream(publicKeyFile));
			publicKeyOS.writeObject(key.getPublic());
			publicKeyOS.close();

			// Saving the Private key in a file
			ObjectOutputStream privateKeyOS = new ObjectOutputStream(
					new FileOutputStream(privateKeyFile));
			privateKeyOS.writeObject(key.getPrivate());
			privateKeyOS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * Checks if the pair of public and private key has been generated.
	 * 
	 * @return flag indicating if the pair of keys were generated.
	 */
	public static boolean areKeysPresent() {

		File privateKey = new File(SENDER_PRIVATE_KEY_FILE);
		File publicKey = new File(SENDER_PUBLIC_KEY_FILE);

		if (privateKey.exists() && publicKey.exists()) {
			return true;
		}
		return false;
	}

	/**
	 * Encrypt the plain text using public key.
	 * 
	 * @param text
	 *            : original plain text
	 * @param key
	 *            :The public key
	 * @return Encrypted text
	 * @throws java.lang.Exception
	 */
	public static byte[] encrypt(byte[] text, PublicKey key) {
		byte[] cipherText = null;
		try {
			// get an RSA cipher object
			final Cipher cipher = Cipher.getInstance(ASSYMETRICALGORITHM);
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	/**
	 * Signs plain text
	 * 
	 * @param text
	 *            :plain text
	 * @param key
	 *            :The Private key
	 * @return Signature in the form of bytes
	 * @throws java.lang.Exception
	 */
	private static byte[] signPlaintext(String plainText, PrivateKey pr) {
		byte[] signatureBytes = null;
		try {
			Signature sig = Signature.getInstance("MD5WithRSA");
			sig.initSign(pr);
			sig.update(plainText.getBytes());
			signatureBytes = sig.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return signatureBytes;
	}
	/**
	 * Generate receiver's  pair of private and public keys and
	 * writes them in a file
	 **/
	public static void generateReceiversKey() {
		SecureRandom random = new SecureRandom();
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator
					.getInstance(ASSYMETRICALGORITHM);

			keyGen.initialize(2048, random);
			final KeyPair key = keyGen.generateKeyPair();

			File privateKeyFile = new File(RECEIVER_PRIVATE_KEY_FILE);
			File publicKeyFile = new File(RECEIVER_PUBLIC_KEY_FILE);

			// Create files to store public and private key
			if (privateKeyFile.getParentFile() != null) {
				privateKeyFile.getParentFile().mkdirs();
			}
			privateKeyFile.createNewFile();

			if (publicKeyFile.getParentFile() != null) {
				publicKeyFile.getParentFile().mkdirs();
			}
			publicKeyFile.createNewFile();

			// Saving the Public key in a file
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(
					new FileOutputStream(publicKeyFile));
			publicKeyOS.writeObject(key.getPublic());
			publicKeyOS.close();

			// Saving the Private key in a file
			ObjectOutputStream privateKeyOS = new ObjectOutputStream(
					new FileOutputStream(privateKeyFile));
			privateKeyOS.writeObject(key.getPrivate());
			privateKeyOS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * Checks if the pair of public and private key has been generated.
	 * 
	 * @return flag indicating if the pair of keys were generated.
	 */
	public static boolean areKeysPresent1() {

		File privateKey = new File(RECEIVER_PRIVATE_KEY_FILE);
		File publicKey = new File(RECEIVER_PUBLIC_KEY_FILE);

		if (privateKey.exists() && publicKey.exists()) {
			return true;
		}
		return false;
	}

	/**
	 * Decrypt Symmetric key using private key.
	 * 
	 * @param text
	 *            :encrypted symmeric key
	 * @param key
	 *            :The private key
	 * @return Symmetric key in bytes form * @throws java.lang.Exception
	 */
	public static byte[] decrypt(byte[] symmetricKey, PrivateKey key) {
		byte[] s = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ASSYMETRICALGORITHM);

			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			s = cipher.doFinal(symmetricKey);

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return s;
	}

	/**
	 * Decrypts text using Symmetric key.
	 * 
	 * @param text
	 *            :encrypted text
	 * @param key
	 *            :The Symmetric key
	 * @return plain text in the form of bytes
	 * @throws java.lang.Exception
	 */
	public static String aesDecrypt(byte[] text, Key key, byte[] iv) {
		byte[] decryptedText = null;
		try {
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			decryptedText = c.doFinal(text);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(decryptedText);
	}

	/**
	 * Verifies the signature
	 * 
	 * @param text
	 *            :plain text
	 * @param byte array :signed byte array
	 * @param key
	 *            :The Symmetric key
	 * @return plain text in the form of bytes
	 * @throws java.lang.Exception
	 */
	private static boolean verifySign(String plain, byte[] signedArray,
			PublicKey pb) throws SignatureException {
		Signature sig = null;
		try {
			sig = Signature.getInstance("MD5WithRSA");
			sig.initVerify(pb);
			sig.update(plain.getBytes());
		} catch (Exception e) {
			e.printStackTrace();

		}
		return sig.verify(signedArray);
	}


	public static void main(String[] args) throws IOException {
		ObjectInputStream inputStream = null;
		ObjectOutputStream outputStream = null;
		FileOutputStream fo = null;
		FileInputStream fis = null;
		try {

			if (args[0].equals("-e")) {
				// Check if the pair of sender's keys are present else generate
				// those.
				if (!areKeysPresent()) {
					generateSendersKey();
				}
				// Check if the pair of receiver's keys are present else
				// generate those.
				if (!areKeysPresent1()) {
					generateReceiversKey();
				}

				// read command line argument
				String destinationPublicKeyFile = args[1];
				String SenderPrivateKeyFile = args[2];
				String plainTextFile = args[3];
				String cipherTextFile = args[4];

				File old = new File(SENDER_PRIVATE_KEY_FILE);
				File new1 = new File(SenderPrivateKeyFile);
				old.renameTo(new1);

				File old2 = new File(RECEIVER_PUBLIC_KEY_FILE);
				File new2 = new File(destinationPublicKeyFile);
				old2.renameTo(new2);

				// creates plain text file
				File f = new File(plainTextFile);
				f.createNewFile();
				fo = new FileOutputStream(f);
				String s = "Hello";
				fo.write(s.getBytes(), 0, s.getBytes().length);

				// read plain text
				fis = new FileInputStream(f);
				int content;

				char arr[] = new char[500];
				int i = 0;
				while ((content = fis.read()) != -1) {

					arr[i] = (char) content;
					i++;
				}

				String originalText = String.valueOf(arr);

				// Sign plain text with private key of the sender
				inputStream = new ObjectInputStream(new FileInputStream(
						SenderPrivateKeyFile));
				final PrivateKey pr = (PrivateKey) inputStream.readObject();
				byte[] signed = signPlaintext(originalText, pr);

				// generate symmetric key
				Key symmetric = generateSymmetricKey();

				// encrypt plain text using symmetric key
				final ArrayList<byte[]> cipherText = aesEncrypt(originalText,
						symmetric);

				// encrypt symmetric key using receivers public key
				inputStream = new ObjectInputStream(new FileInputStream(
						destinationPublicKeyFile));
				final PublicKey publicKey = (PublicKey) inputStream
						.readObject();
				final byte[] encryptedKey = encrypt(symmetric.getEncoded(),
						publicKey);

				// write signature and cipher to a file
				List<byte[]> list = new ArrayList<byte[]>();
				list.add(cipherText.get(0));// cipher
				list.add(cipherText.get(1));
				list.add(encryptedKey);
				list.add(signed);
				outputStream = new ObjectOutputStream(new FileOutputStream(
						cipherTextFile));
				outputStream.writeObject(list);
				System.out.println("Encrypted");
				outputStream.close();
				fis.close();

			}

			else if (args[0].equals("-d")) {
				// reads command line argument
				String destinationPrivateKey = args[1];
				String senderPublicKey = args[2];
				String cipherText = args[3];
				String outputText = args[4];

				File old = new File(SENDER_PUBLIC_KEY_FILE);
				File new1 = new File(senderPublicKey);
				old.renameTo(new1);

				File old2 = new File(RECEIVER_PRIVATE_KEY_FILE);
				File new2 = new File(destinationPrivateKey);
				old2.renameTo(new2);
				// Read public key of the sender to verify signature
				inputStream = new ObjectInputStream(new FileInputStream(
						senderPublicKey));
				final PublicKey publicKey2 = (PublicKey) inputStream
						.readObject();

				// read bytes
				inputStream = new ObjectInputStream(new FileInputStream(
						cipherText));
				List<byte[]> byteList = (List<byte[]>) inputStream.readObject();

				// Decrypt the encrypted key using the private key of the
				// receiver
				inputStream = new ObjectInputStream(new FileInputStream(
						destinationPrivateKey));
				final PrivateKey privateKey = (PrivateKey) inputStream
						.readObject();

				// decrypt symmetric key
				byte[] text2 = decrypt(byteList.get(2), privateKey);
				Key key2 = new SecretKeySpec(text2, 0, text2.length, "AES");

				// decrypt cipher text using symmetric key
				String plain2 = aesDecrypt(byteList.get(0), key2,
						byteList.get(1));

				// verify signed message
				verifySign(plain2, byteList.get(3), publicKey2);

				// writes decrypted plain text into the output file
				File f = new File(outputText);
				f.createNewFile();
				fo = new FileOutputStream(outputText);
				fo.write(plain2.getBytes(), 0, plain2.getBytes().length);
				System.out.println("decrypted and verified");

				fo.close();
				inputStream.close();
			}
		}

		catch (Exception e) {
			e.printStackTrace();
		}

	}
}