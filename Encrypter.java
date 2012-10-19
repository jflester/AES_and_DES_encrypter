package cmsc414.p1;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;

/* Encrypter uses Base64Coder class to do conversions in encrypt and decrypt.
   
   Encrypter supports AES and DES cipher algorithms.
   Is currently in ECB mode with NoPadding as padding.
   Does CBC manually in encrypt and decrypt methods.
   
   Strings must be in multiples of 64-bits or 128-bits
   for DES and AES, respectively.
*/

public class Encrypter {
	private String encryptionType;
	private byte[] ivAES = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	private byte[] ivDES = {0, 0, 0, 0, 0, 0, 0, 0};
	private IvParameterSpec ipsAES = new IvParameterSpec(ivAES);
	private IvParameterSpec ipsDES = new IvParameterSpec(ivDES);
	private SecretKey key;

	//Basic Constructor.
	public Encrypter(String encryptionType) {
		this.encryptionType = encryptionType;
		this.key = this.generateSecretKey();
	}

	//Generates a secret key.
	public SecretKey generateSecretKey() {
		KeyGenerator keyGen = null;
		SecretKey key = null;
		try {
			keyGen = KeyGenerator.getInstance(encryptionType);
			key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No such algorithm.");
		}
		return key;
	}

	//Xors two byte arrays (byte[]) and returns a single byte[].
	//Does not modify either of the arrays passed in.
	private byte[] xorba(byte[] one, byte[] two){
		byte[] res = new byte[one.length];
		for (int i = 0; i < one.length; i++){
			res[i] = one[i];
			res[i] ^= two[i];
		}
		return res;
	}

	//Encrypts a String plaintext with the given secretKey using AES/DES.
	public String encrypt(String plainText, SecretKey secretKey) {
		byte[] encryptThis = null;
		byte[] ciphertext = null;
		String res = "";
		Cipher cipher = null;
		int pos = 0;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			encryptThis = plainText.getBytes("UTF-8");
			cipher = Cipher.getInstance(encryptionType.toString()+"/ECB/NoPadding");
			if ((encryptThis.length)%8 == 0 && encryptionType.equals("DES")) {
				cipher.init(Cipher.ENCRYPT_MODE, secretKey);
				byte[] curr = new byte[8];
				byte[] prev = new byte[8];
				while (pos < encryptThis.length){
					for (int i = 0; i < 8; i++){
						curr[i] = encryptThis[pos+i];
						if (pos == 0){
							prev[i] = ivDES[i];
						}
					}
					prev = xorba(prev, curr);
					prev = cipher.doFinal(prev);
					baos.write(prev);
					pos += 8;
				}
				res = new String(Base64Coder.encode(baos.toByteArray()));
			} else if ((encryptThis.length)%16 == 0 && encryptionType.equals("AES")) {
				cipher.init(Cipher.ENCRYPT_MODE,  secretKey);
				byte[] curr = new byte[16];
				byte[] prev = new byte[16];
				while (pos < encryptThis.length){
					for (int i = 0; i < 16; i++){
						curr[i] = encryptThis[pos+i];
						if (pos == 0){
							prev[i] = ivAES[i];
						}
					}
					prev = xorba(prev, curr);
					prev = cipher.doFinal(prev);
					baos.write(prev);
					pos += 16;
				}
				res = new String(Base64Coder.encode(baos.toByteArray()));
			} else {
				return null;
			}
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No such algorithm.");
		} catch (NoSuchPaddingException e) {
			System.out.println("No such padding.");
		} catch (InvalidKeyException e) {
			System.out.println("Invalid key.");
		} catch (IllegalBlockSizeException e) {
			System.out.println("Illegal block size.");
		} catch (BadPaddingException e) {
			System.out.println("Bad padding.");
		} catch (UnsupportedEncodingException e) {
			System.out.println("Unsupported Encoding.");
		} catch (IOException e) {
			System.out.println("IO Exception.");
		}
		return res;
	}

	//Decrypts the given cipherText using the given secretKey and AES/DES.
	public String decrypt(String cipherText, SecretKey secretKey) {
		String plaintext = "";
		Cipher cipher = null;
		char[] decrypt = null;
		byte[] decryptThis = null;
		Stack<byte[]> s = new Stack<byte[]>();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			decrypt = cipherText.toCharArray();
			decryptThis = Base64Coder.decode(decrypt);
			int pos = decryptThis.length;
			cipher = Cipher.getInstance(encryptionType.toString()+"/ECB/NoPadding");
			if ((decryptThis.length)%8 == 0 && encryptionType.equals("DES")){
				cipher.init(Cipher.DECRYPT_MODE, secretKey);
				byte[] curr = new byte[8];
				byte[] prev = new byte[8];
				byte[] block = new byte[8];
				for (int i = 0; i < 8; i++){
					prev[i] = decryptThis[pos-8+i];
				}
				pos -= 8;
				while (pos > 0) {
					for (int i = 0; i < 8; i++){
						curr[i] = decryptThis[pos-8+i];
					}
					prev = cipher.doFinal(prev);
					block = xorba(prev, curr);
					s.push(block);
					System.arraycopy(curr, 0, prev, 0, curr.length);
					pos -= 8;
				}
				s.push(xorba(cipher.doFinal(prev), ivDES));
				while (!s.isEmpty()) {
					baos.write(s.pop());
				}
				plaintext = baos.toString("UTF-8");
			} else if ((decryptThis.length)%16 == 0 && encryptionType.equals("AES")) {
				cipher.init(Cipher.DECRYPT_MODE, secretKey);
				byte[] curr = new byte[16];
				byte[] prev = new byte[16];
				byte[] block = new byte[16];
				for (int i = 0; i < 16; i++){
					prev[i] = decryptThis[pos-16+i];
				}
				pos -= 16;
				while (pos > 0) {
					for (int i = 0; i < 16; i++){
						curr[i] = decryptThis[pos-16+i];
					}
					prev = cipher.doFinal(prev);
					block = xorba(prev, curr);
					s.push(block);
					System.arraycopy(curr, 0, prev, 0, curr.length);
					pos -= 16;
				}
				s.push(xorba(cipher.doFinal(prev), ivAES));
				while (!s.isEmpty()) {
					baos.write(s.pop());
				}
				plaintext = baos.toString("UTF-8");
			} else {
				return null;
			}
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No such algorithm.");
		} catch (NoSuchPaddingException e) {
			System.out.println("No such padding.");
		} catch (InvalidKeyException e) {
			System.out.println("Invalid key.");
		} catch (IllegalBlockSizeException e) {
			System.out.println("Illegal block size.");
		} catch (BadPaddingException e) {
			System.out.println("Bad padding.");
		} catch (UnsupportedEncodingException e) {
			System.out.println("Unsupported encoding.");
		} catch (IOException e) {
			System.out.println("IO Exception.");
		}
		return plaintext;
	}

}