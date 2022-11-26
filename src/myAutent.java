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
import java.util.List;
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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;


public class myAutent {

	public static void main(String[] args) throws IOException, Exception, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("servidor: main");
		myAutent server = new myAutent();
		server.startServer();
	}
	
	public void PasswordHash(String id, String name, String pass, FileWriter myWriter ) throws Exception {
		//create salt
		byte[] salt = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		
		//hash pass
		MessageDigest md = MessageDigest.getInstance("SHA-512");//SHA256?
		md.update(salt);
		byte[] hash = md.digest(pass.getBytes(StandardCharsets.UTF_8));
		
		//encode
		String encodedHash = Base64.getEncoder().encodeToString(hash);
		String encodedSalt = Base64.getEncoder().encodeToString(salt);
		
		//write to file
		myWriter.write(id + ";" + name +";" + encodedHash + ";" + encodedSalt + "\n");
		myWriter.close();
	}

	public Boolean passwordHashVerification(String id, String pass) throws Exception {
		Boolean idFound = false;
		String hashedPassString;
		byte[] hashedPass = new byte[16];
		byte[] salt = new byte[16];
		
		//finds hashed password of given id
		File file_pass = new File("passwords.txt");
		Scanner myReader = new Scanner(file_pass);
		while (myReader.hasNextLine() && !idFound) {
			String data = myReader.nextLine();
			String[] userData =  data.split(";");

			if(userData[0].equals(id)){
				hashedPassString = new String(Base64.getDecoder().decode(userData[2]));	
				hashedPass = hashedPassString.getBytes();
				salt = Base64.getDecoder().decode(userData[3]);
				idFound = true;
			}
		}
		
		//hash pass
		MessageDigest md = MessageDigest.getInstance("SHA-512");//SHA256
		md.update(salt);
		byte[] hash = md.digest(pass.getBytes(StandardCharsets.UTF_8));
		
		if(new String(hashedPass).equals(new String(hash))) {
			return true;
		}else {
			return false;
		}		
	}
	
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

		File file_pass = new File("passwords.txt");
		Scanner obj = new Scanner(System.in);  // Create a Scanner object
		System.out.println("Enter the admin password: ");
		String pass = obj.nextLine();  // Read user input
		obj.close();

		if(!(file_pass.isFile())){
			file_pass.createNewFile();
			FileWriter myWriter = new FileWriter(file_pass);
			PasswordHash("1", "Admin", pass, myWriter);

			// Generate secret key
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

		} else {
			File file_pass_hashed = new File("passwords_hash.txt");
			
			if(!(file_pass_hashed.isFile())) { //creates hash				
				System.out.println("Hashed file wasn't calculated for password file. Calculating MAC");
				createFileHash(pass);
			} else { //verifies if hash is correct
				fileHashVerification(pass);
			}
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

		private boolean userExists(String id) throws FileNotFoundException {
			File file_pass = new File("passwords.txt");
			Scanner myReader = new Scanner(file_pass);
			
			while (myReader.hasNextLine()) {
				String data = myReader.nextLine();
				String[] userData =  data.split(";");
				if(userData[0].equals(id)){
					myReader.close();
					return true;
				}
			}
			myReader.close();
			return false;
		}
		
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
			}
			
		public void run(){
			try {
				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
				String option = (String) inStream.readObject();

				if(option.equals("c")) {
					//admin
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();

					//new user
					String idUser = (String) inStream.readObject();
					String name = (String) inStream.readObject();
					String password = (String) inStream.readObject();

					File file_pass_hashed = new File("passwords_hash.txt");
					if(file_pass_hashed.isFile()) {
						fileHashVerification(pwd);
					}else {
						System.out.println("Can't find hashed file for password file. Calculating MAC");
						createFileHash(pwd);
					}

					if(passwordHashVerification(String.valueOf(id), pwd)) {
						File file_pass = new File("passwords.txt");
						FileWriter myWriter = new FileWriter(file_pass, true);
						
						if(!userExists(idUser)) { 
							PasswordHash(idUser, name, password, myWriter );
							new File("./user_directories/data/" + idUser).mkdirs();
							System.out.println("User named " + name + " and id " + idUser + " was successfully created");
							outStream.writeObject((Boolean) true);

							System.out.println("Passwords file was changed. Calculating new MAC");
							createFileHash(pwd);
							
						}else {
							System.out.println("User named " + name + " and id " + idUser + " already exists");
							outStream.writeObject((Boolean) false);
						}
					}else {
						System.out.println("Admin given password is incorrect");
					}
					Cifra.main(String.valueOf(idUser), pwd);
		
				} else if(option.equals("l")) {
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();
					if(!passwordHashVerification(String.valueOf(id), pwd)) {
						throw new Exception("invalid user");
					}

					List<String> file_list = new ArrayList<String>();
					File path = new File("./user_directories/data/" + id);
					File[] contents = path.listFiles();
					outStream.writeObject(contents.length);

					if(contents.length != 0){
						for(int i=0; i < contents.length; i++){
							BasicFileAttributes attr = Files.readAttributes(contents[i].toPath(), BasicFileAttributes.class);
							file_list.add(contents[i].getName());
							file_list.add(attr.creationTime().toString());
						}
						outStream.writeObject(file_list);
					}
					System.out.println("List sent to client: " + id);

				} else if(option.equals("e")) { //recieve and save files
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();
					if(!passwordHashVerification(String.valueOf(id), pwd)) {
						throw new Exception("invalid user");
					}
									
					int numberOfFiles = (int) inStream.readObject(); //number of files
					for(int i = 1; i <= numberOfFiles; i++){
						String fileName = (String) inStream.readObject(); //file name
						Boolean fileClientExists = (Boolean) inStream.readObject(); //file exists in client
						
						if(fileClientExists){
							Long fileSize = (Long) inStream.readObject(); //file size
							File fileServerExists = new File("./user_directories/data/" + id + "/" + fileName);
							if(!fileServerExists.isFile()) {	
								outStream.writeObject((Boolean)false); //file does'nt exist in server
								
								//GET PRIVATE KEY FOR SIGNATURE
								FileInputStream kfile = new FileInputStream("keystore.server"); //keystore
								KeyStore kstore = KeyStore.getInstance("JKS");
								kstore.load(kfile, "ninis1234".toCharArray()); //password
								System.out.println(pwd);
								Key myPrivateKey = kstore.getKey(String.valueOf(id), "ninis1234".toCharArray());
								PrivateKey pk = (PrivateKey) myPrivateKey;

								if(myPrivateKey instanceof PrivateKey) {
									//SIGNATURE WITH PK
									Signature sig = Signature.getInstance("SHA256withRSA");
									sig.initSign(pk);
								
									//GET RADOM AES KEY
									KeyGenerator kg = KeyGenerator.getInstance("AES"); //generate random key for AES
									kg.init(128);
									SecretKey key = kg.generateKey();

									//CIPHER FILE WITH AES KEY
									Cipher cAES = Cipher.getInstance("AES");
									cAES.init(Cipher.ENCRYPT_MODE, key);
									FileOutputStream newServerFileFOS = new FileOutputStream("./user_directories/data/" + id + "/" + fileName + "_signed." + id +".cif");
									CipherOutputStream newServerFileCOS = new CipherOutputStream(newServerFileFOS, cAES);
									byte[] array = new byte[1024];
									int temp = fileSize.intValue();
									int x = 0;
									while(temp > 0) {
										x = inStream.read(array, 0, temp > 1024 ? 1024 : temp);
										sig.update(array, 0, x);
										newServerFileCOS.write(array, 0, x); //writes file data
										temp -= x;
									}
									newServerFileCOS.write(sig.sign()); //writes signature
									newServerFileCOS.close();
									kfile.close();

									//GET USER PUBLIC KEY FOR WRAP
									Certificate cert = kstore.getCertificate(String.valueOf(id));  //user alias
									PublicKey myPublicKey = cert.getPublicKey();

									//CIPHER WRAP WITH RSA PUBLIC KEY
									Cipher cRSA = Cipher.getInstance("RSA");
									cRSA.init(Cipher.WRAP_MODE, myPublicKey);
									
									//WRAP AES KEY WITH USER PUBLIC KEY
									byte[] keyEncoded = key.getEncoded();
									SecretKeySpec keySpec = new SecretKeySpec(keyEncoded, "AES");				
									byte[] wrappedKey = cRSA.wrap(keySpec);

									//SAVE WRAPPED KEY IN FILE .key 
									FileOutputStream kos = new FileOutputStream("./user_directories/data/" + id + "/" + fileName + "_signed." + id +".key");
									kos.write(wrappedKey);
									kos.close();

									//SEND FILE TO CLIENT
									sendsDecryptedFile(fileName + "_signed." + String.valueOf(id), fileSize.intValue() + 256, String.valueOf(id), pwd, outStream);
								}else{
									System.out.println("Wrong private key");
								}
							}else {
								outStream.writeObject((Boolean)true); //file already exists in server: can't overwrite
								System.out.println("The file: " + fileName + " already exists in server: can't overwrite");
							}
						}else {
							System.out.println("The file: " + fileName + " doesn't exist in client");
						}
					}
					
				} else if(option.equals("d")) { //SEND FILES
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();
					if(!passwordHashVerification(String.valueOf(id), pwd)) {
						throw new Exception("invalid user");
					}
					
					int numberOfFiles = (int) inStream.readObject(); //number of files
					for(int i = 1; i <= numberOfFiles; i++){
						String fileName = (String) inStream.readObject(); //file name
						Boolean fileExistsInClient = (Boolean) inStream.readObject(); //file exists in client
						if(!fileExistsInClient) {
							File fileClient = new File("./user_directories/data/" + id + "/" + fileName + "_signed." + String.valueOf(id) + ".cif");
							
							if(fileClient.isFile()) { //file exists in server
								outStream.writeObject((Boolean)true); //file exists in server
								Long tempLong = fileClient.length();
								sendsDecryptedFile(fileName + "_signed." + String.valueOf(id), tempLong.intValue(), String.valueOf(id), pwd, outStream);
							}else {
								outStream.writeObject((Boolean)false); //file doesn't in server
								System.out.println("The file: " + fileName +  " doesn't exist in server");
							}
						}else{
							System.out.println("The file: " + fileName +  " already exists in client: can't overwrite");
						}	
					}
					
				} else if (option.equals("s")){
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();
					if(!passwordHashVerification(String.valueOf(id), pwd)) {
						throw new Exception("invalid user");
					}
					
					FileInputStream kfile = new FileInputStream("keystore.server"); //keystore
					KeyStore kstore = KeyStore.getInstance("JKS");
					kstore.load(kfile, "ninis1234".toCharArray()); //password
	
					Key myPrivateKey = kstore.getKey(String.valueOf(id), "ninis1234".toCharArray());
					PrivateKey pk = (PrivateKey) myPrivateKey;
	
					Signature sig = Signature.getInstance("SHA256withRSA");
					sig.initSign(pk);
					
					int numberOfFiles = (int) inStream.readObject();
					for(int i = 1; i <= numberOfFiles; i++){
						Boolean fileExists = (Boolean) inStream.readObject();

						if(fileExists){
							int x = 0;
							int temp = (int) inStream.readObject(); //read size
							byte[] array = new byte[temp];
							while(temp > 0) {
								x = inStream.read(array, 0, temp > 16 ? 16 : temp);
								sig.update(array, 0, x);
								temp -= x;
							}	
							byte[] signHash = sig.sign();
							outStream.writeObject(signHash);
							outStream.flush();
														
						}else{
							String fileName = (String) inStream.readObject();
							System.out.println("The file: " + fileName + " doesn't exist in client");
						}
					}

				} else if (option.equals("v")){
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();
					if(!passwordHashVerification(String.valueOf(id), pwd)) {
						throw new Exception("invalid user");
					}
					int numberOfFiles = (int) inStream.readObject();
					for(int i = 1; i <= numberOfFiles; i++){
						Boolean fileExists = (Boolean) inStream.readObject();
						
						//RECIEVES HASHED FILE
						if(fileExists){
							
							//creates signature from client hash and verifies with client signature
							FileInputStream kfile = new FileInputStream("keystore.server"); //keystore
							KeyStore kstore = KeyStore.getInstance("JKS");
							kstore.load(kfile, "ninis1234".toCharArray()); //password

							Certificate cert = kstore.getCertificate(String.valueOf(id));
							PublicKey publickey = cert.getPublicKey();
							Signature s = Signature.getInstance("SHA256withRSA");
							s.initVerify(publickey);
							
							byte[] hashMac = (byte[]) inStream.readObject(); //file size 
							s.update(hashMac);
		
							byte[] signatureFromClient = (byte[]) inStream.readObject();
				
							if (s.verify(signatureFromClient)) {
								outStream.writeObject("Message is valid");
							}else {
								outStream.writeObject("Message was corrupted");
							}
						}
					}

				} else if (option.equals("notenough")) {
					System.out.println("Not enough arguments");

				} else {
					socket.close();
					throw new Exception("option doesn't exist");
				}
				outStream.close();
				inStream.close();
				socket.close();

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
