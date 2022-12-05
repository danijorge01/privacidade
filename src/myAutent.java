import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;


public class myAutent {

	private Map<String, Socket> clients = new HashMap<String, Socket>();

	public static void main(String[] args) throws IOException, Exception, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("servidor: main");
		myAutent server = new myAutent();
		server.startServer();
	}
	
	/*
	public void fileHashVerification(String pass) throws Exception{
		PBEKeySpec keySpec = new PBEKeySpec(pass.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		SecretKey key = kf.generateSecret(keySpec);

		//Hash file from client
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(key);
		BufferedInputStream fileBIS = new BufferedInputStream(new FileInputStream("passwords.txt"));
		byte[] array = new byte[1024];
		int x = 0;
		while((x = fileBIS.read(array, 0, 1024)) > 0) {
			mac.update(array, 0, x);
		}
		byte[] arrayFinal = mac.doFinal();
		fileBIS.close();

		BufferedInputStream fileHashBIS = new BufferedInputStream(new FileInputStream("passwords_hash.txt"));
		Long len = new File("passwords_hash.txt").length();
		int temp = len.intValue();
		byte[] array1 = new byte[arrayFinal.length];
		x = 0;
		while(temp > 0) {
			x = fileHashBIS.read(array1, 0, temp > arrayFinal.length ? arrayFinal.length : temp);
			temp -= x;
		}
		fileHashBIS.close();
		
		String new_mac = new String(arrayFinal);
		String old_mac = new String(array1);
		if(old_mac.equals(new_mac)) {
			System.out.println("MAC of password file is correct");
		} else{
			throw new Exception("MAC of password file is invalid");
		}
	}
	
	public void createFileHash(String pass) throws Exception {
		PBEKeySpec keySpec = new PBEKeySpec(pass.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		SecretKey key = kf.generateSecret(keySpec);

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(key);

		BufferedOutputStream oos = new BufferedOutputStream(new FileOutputStream("passwords_hash.txt"));
		BufferedInputStream fileBIS = new BufferedInputStream(new FileInputStream("passwords.txt"));
		byte[] array = new byte[1024];
		int x = 0;
		while((x = fileBIS.read(array, 0, 1024)) > 0) {
			mac.update(array, 0, x);
		}
		oos.write(mac.doFinal());
		oos.close();
		fileBIS.close();
	}	
	*/
	
	public void startServer () throws Exception{
		ServerSocket sSoc = null;
		try {
			System.setProperty("javax.net.ssl.keyStore", "keystore.server");
			System.setProperty("javax.net.ssl.keyStorePassword", "ninis1234");
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
			sSoc = ssf.createServerSocket(23456);

		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		while(true) {
			try {
				Socket inSoc = sSoc.accept();
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	//Threads used for comunication with clients
	class ServerThread extends Thread {
		private Socket socket = null;
		ServerThread(Socket inSoc) {
			socket = inSoc;
			System.out.println("server thread for each client");
		}
		
		/*
		public void sendsDecryptedFile(String fileName, int temp, String id, String pwd, ObjectOutputStream outStream) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException { 
				//READ WRAPPED KEY
				FileInputStream fileKey = new FileInputStream("./user_directories/data/" + id + "/" + fileName + ".key");
				byte[] keyEncoded = new byte [fileKey.available()];
				fileKey.read(keyEncoded);	
	   			fileKey.close();

				//GET PRIVATE KEY
				FileInputStream kfile = new FileInputStream("keystore.server"); //keystore
				KeyStore kstore = KeyStore.getInstance("JKS");
				kstore.load(kfile, "ninis1234".toCharArray()); //password
				Key myPrivateKey = kstore.getKey(String.valueOf(id), "ninis1234".toCharArray()); 

				//GET RANDOM AES KEY CREATED IN CIPHER
				Cipher cRSA = Cipher.getInstance("RSA");
				cRSA.init(Cipher.UNWRAP_MODE, myPrivateKey); 
				Key keyAES = cRSA.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);

				//DECRYPT CIPHER
				Cipher cAES = Cipher.getInstance("AES");
	   			cAES.init(Cipher.DECRYPT_MODE, keyAES);

				//DECRYPT FILE WITH AES KEY
				FileInputStream fileFIS = new FileInputStream("./user_directories/data/" + id + "/" + fileName + ".cif");
				CipherOutputStream fileCOS = new CipherOutputStream(outStream, cAES);
				byte[] array = new byte[1024];
				outStream.writeObject(temp); //sends file size
				int x = 0;
				while((x = fileFIS.read(array, 0, 1024)) > 0) {
					fileCOS.write(array, 0, x);
					fileCOS.flush();
				}
				System.out.println("File: " + fileName +  " sent to client of id: " + id);
				fileFIS.close();
				fileCOS.close();
			}*/
			
		public void run(){
			
			try {
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());

				// Sends the available clients to chat to the client
				String clientName = (String) inStream.readObject();
				clients.put(clientName, socket);
				outStream.writeObject(clients);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}

	}
			/** Closes the given socket, ignoring (but printing) any exception. */
			// private void closeSocket(Socket socket) {
			// 	try {
			// 		socket.close();
			// 	} catch (IOException ex) {
			// 		ex.printStackTrace(System.err);
			// 	}
			// }
	
			// /** Removes all closed sockets from the given list. */
			// private void removeClosed(List<Socket> listeners) {
			// 	listeners.removeIf(socket -> socket.isClosed());
			// }

}
