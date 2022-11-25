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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
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
	public Boolean PasswordHashVerification(String id, String pass) throws Exception {
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
	
	
	/*
	public void PasswordSaltCipherEncrypt(String id, String name, String pass, FileWriter myWriter) throws Exception{
		byte[] salt = { (byte) 0xc9, (byte) 0x36, (byte) 0x78, (byte) 0x99, (byte) 0x52,
			(byte) 0x3e, (byte) 0xea, (byte) 0xf2 };
		
		//byte[] iv = new byte[16];
	    //new SecureRandom().nextBytes(iv);
	    //IvParameterSpec ivspec = new IvParameterSpec(iv);
	    
		byte[] IV = new byte[] { 0x01, 0x02, 0x03, 0x04,
			    0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
			    0x05, 0x06, 0x07, 0x08  };

		// Indicar o salt e número de iterações
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20, new IvParameterSpec(IV));
		
		// Gerar a chave secreta baseando-se na password
		PBEKeySpec keySpec = new PBEKeySpec(pass.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		SecretKey key = kf.generateSecret(keySpec);
		
		Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
		c.init(Cipher.ENCRYPT_MODE, key, paramSpec);
		byte[] passInBytes = new byte[16];
		passInBytes = pass.getBytes("UTF-8");
		
		byte[] pass_cif = c.doFinal(passInBytes);
		
		myWriter.write(id + ";" + name +";" + Base64.getEncoder().encodeToString(pass_cif));
		myWriter.close();
	}
	*/
	/*
	public byte[] PasswordSaltCipherDecrypt(String pass, String id) throws Exception{
		byte[] salt = { (byte) 0xc9, (byte) 0x36, (byte) 0x78, (byte) 0x99, (byte) 0x52,
			(byte) 0x3e, (byte) 0xea, (byte) 0xf2 };
		
		File file_pass = new File("passwords.txt");
		Scanner myReader = new Scanner(file_pass);
		byte[] encryptedPass = new byte[16];
		Boolean idFound = false;
		
		while (myReader.hasNextLine() && !idFound) {
			String data = myReader.nextLine();
			String[] userData =  data.split(";");

			if(userData[0].equals(id)){
				encryptedPass = userData[2].getBytes();	
				idFound = true;
			}
		}
		myReader.close();
		
		//byte[] iv = new byte[16];
	    //new SecureRandom().nextBytes(iv);
	    //IvParameterSpec ivspec = new IvParameterSpec(iv);
	    
		byte[] IV = new byte[] { 0x01, 0x02, 0x03, 0x04,
			    0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
			    0x05, 0x06, 0x07, 0x08  };
		
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20, new IvParameterSpec(IV));
		
		// Gerar a chave secreta baseando-se na password
		PBEKeySpec keySpec = new PBEKeySpec(pass.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		SecretKey key = kf.generateSecret(keySpec);
		
		Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
		c.init(Cipher.DECRYPT_MODE, key, paramSpec);
		
		byte[] pass_cif = c.doFinal(encryptedPass);
		//return Base64.getEncoder().encodeToString(pass_cif);
		return Base64.getDecoder().decode(encryptedPass);
	}*/
	
	/*
	public static void PasswordSaltCipherEncrypt(String id, String name, String pass, FileWriter myWriter) throws Exception{

		byte[] salt = { (byte) 0xc9, (byte) 0x36, (byte) 0x78, (byte) 0x99, (byte) 0x52,
				(byte) 0x3e, (byte) 0xea, (byte) 0xf2 };

		byte[] IV = new byte[] { 0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x08  };

		byte[] encryptedPass = pass.getBytes();
		
		// Indicar o salt e número de iterações
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20, new IvParameterSpec(IV));

		// Gerar a chave secreta baseando-se na password
		PBEKeySpec keySpec = new PBEKeySpec(pass.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		SecretKey key = kf.generateSecret(keySpec);

		Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
		c.init(Cipher.ENCRYPT_MODE, key, paramSpec);
		
		
		byte[] passInBytes = c.doFinal(encryptedPass);
		String s = new String(passInBytes);
		System.out.println(s);

		myWriter.write(id + ";" + name +";" + s);
		myWriter.close();


	}
	
	public static String PasswordSaltCipherDecrypt(String pass, String id) throws Exception{
		
		byte[] salt = { (byte) 0xc9, (byte) 0x36, (byte) 0x78, (byte) 0x99, (byte) 0x52,
				(byte) 0x3e, (byte) 0xea, (byte) 0xf2 };
		
		byte[] IV = new byte[] { 0x01, 0x02, 0x03, 0x04,
			    0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
			    0x05, 0x06, 0x07, 0x08  };
				
		File file_pass = new File("passwords.txt");
		Scanner myReader = new Scanner(file_pass);
		
		String teste = "qwertyqewrtyyqew";
		byte[] encryptedPass = teste.getBytes();
		
		//byte[] encryptedPass = null;
		Boolean idFound = false;
		
		while (myReader.hasNextLine() && !idFound) {
			String data = myReader.nextLine();
			String[] userData =  data.split(";");

			if(userData[0].equals(id)){
				encryptedPass = userData[2].getBytes();

				idFound = true;
			}
		}
		myReader.close();
		
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20, new IvParameterSpec(IV));
		
		// Gerar a chave secreta baseando-se na password
		PBEKeySpec keySpec = new PBEKeySpec(pass.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		SecretKey key = kf.generateSecret(keySpec);
		
		Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
		c.init(Cipher.DECRYPT_MODE, key, paramSpec);
		byte[] pass_cif = c.doFinal(encryptedPass);
		
		//byte[] pass_cif1 = Base64.getDecoder().decode(pass_cif);
		
		return new String(pass_cif);

		
	}
	*/
	
	
	public void startServer () throws Exception{
		
		
		ServerSocket sSoc = null;

		try {
			//sSoc = new ServerSocket(23456);
			System.setProperty("javax.net.ssl.keyStore", "keystore.server");
			System.setProperty("javax.net.ssl.keyStorePassword", "ninis");
			
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
					//SSLServerSocketFactory.createServerSocket(23456);
			sSoc = ssf.createServerSocket(23456);
			
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		File file_pass = new File("passwords.txt");

		if(!(file_pass.isFile())){
			Scanner obj = new Scanner(System.in);  // Create a Scanner object
			System.out.println("Enter the admin password: ");
			String pass = obj.nextLine();  // Read user input
			obj.close();

			file_pass.createNewFile();
			FileWriter myWriter = new FileWriter(file_pass);
			PasswordHash("1", "Admin", pass, myWriter );
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
		//sSoc.close();
	}


	//Threads utilizadas para comunicacao com os clientes
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

		private boolean userVerified(String id, String pwd) throws FileNotFoundException {

			File file_pass = new File("passwords.txt");
			Scanner myReader = new Scanner(file_pass);

			if(id.equals("1")){ //admin
				String data = myReader.nextLine();
				String[] userData =  data.split(";");

				if(userData[0].equals(id) && userData[2].equals(pwd)){
					myReader.close();
					return true;
				} else {
					myReader.close();
					return false;
				}
			}
			myReader.nextLine(); //passa a linha do admin à frente

			while (myReader.hasNextLine()) {
				String data = myReader.nextLine();
				String[] userData =  data.split(";");

				if(userData[0].equals(id) && userData[2].equals(pwd)){
					myReader.close();
					return true;
				}
			}
			myReader.close();
			return false;
		}
		
		public void sendsSignedFilesToClient(List<String> serverFiles, String userId, ObjectOutputStream outStream) 
	    		throws IOException {
			for(int i = 0; i < serverFiles.size(); i++){

				BufferedInputStream fileClientBIS = new BufferedInputStream(new FileInputStream("./user_directories/data/" + userId + "/" + serverFiles.get(i)));
				byte[] array = new byte[1024];

				int x = 0;
				while((x = fileClientBIS.read(array, 0, 1024)) > 0) {
					outStream.write(array, 0, x);
				}
				System.out.println("File: " + serverFiles.get(i) +  " sent to user: " + userId);
				fileClientBIS.close();
			}
		}
		public void sendsFile(String fileName, int temp, String id, ObjectOutputStream outStream) throws IOException { 
				BufferedInputStream fileBIS = new BufferedInputStream(new FileInputStream("./user_directories/data/" + id + "/" + fileName + "-hash." + id));
				byte[] array = new byte[1024];
				outStream.writeObject(temp); //sends file size
				int x = 0;
				while((x = fileBIS.read(array, 0, 1024)) > 0) {
					outStream.write(array, 0, x);
					outStream.flush();
				}
				System.out.println("File: " + fileName +  " sent to user: " + id);
				fileBIS.close();
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

					if(PasswordHashVerification(String.valueOf(id), pwd)) {
						File file_pass = new File("passwords.txt");
						FileWriter myWriter = new FileWriter(file_pass, true);
						
						if(!userExists(idUser)) { 
							PasswordHash(idUser, name, password, myWriter );
							new File("./user_directories/data/" + idUser).mkdirs();
							System.out.println("User named " + name + " and id " + idUser + " was successfully created");
							outStream.writeObject((Boolean) true);
							
						}else {
							System.out.println("User named " + name + " and id " + idUser + " already exists");
							outStream.writeObject((Boolean) false);
						}
					}else {
						System.out.println("Admin given password is incorrect");
					}

					Cifra.main(String.valueOf(idUser), password);
		
				} else if(option.equals("l")) {
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();
					if(!PasswordHashVerification(String.valueOf(id), pwd)) {
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

				} else if(option.equals("e")) { //recebe e guarda ficheiros
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();
					
					if(!PasswordHashVerification(String.valueOf(id), pwd)) {
						throw new Exception("invalid user");
					}

					List<String> ficheiros = (List<String>) inStream.readObject();
					List<Long> dimensoes = (List<Long>) inStream.readObject();
					List<String> ficheirosServidor = new ArrayList<String>(); //ficheiros que ja existem no server

					for(int f = 0; f < ficheiros.size(); f++){
						File fileClient = new File("./user_directories/data/" + id + "/" + ficheiros.get(f));
						if(fileClient.isFile()) {
							ficheirosServidor.add(ficheiros.get(f));
						}
					}

					outStream.writeObject(ficheirosServidor);
					for(int i = 0; i < ficheiros.size(); i++){

						File fileClient = new File("./user_directories/data/" + id + "/" + ficheiros.get(i));

						if(!fileClient.isFile()) {							
							FileInputStream kfile = new FileInputStream("keystore.server");  //keystore
							KeyStore kstore = KeyStore.getInstance("JKS");
							kstore.load(kfile, "ninis".toCharArray());           //password
			
							Key myPrivateKey = kstore.getKey(String.valueOf(id), pwd.toCharArray()); 
							PrivateKey pk = (PrivateKey) myPrivateKey;
			
							Signature sig = Signature.getInstance("SHA256withRSA");
							sig.initSign(pk);

							BufferedOutputStream fich_serverB = new BufferedOutputStream(new FileOutputStream("./user_directories/data/" + id + "/" + ficheiros.get(i) + ".sign." + id));

							byte[] array = new byte[1024];
							int temp = dimensoes.get(i).intValue();
							int x = 0;
							while(temp > 0) {
								x = inStream.read(array, 0, temp > 1024 ? 1024 : temp);
								sig.update(array, 0, x);
								fich_serverB.write(array, 0, x);

								temp -= x;
							}
							fich_serverB.write(sig.sign());
							fich_serverB.close();
							kfile.close();
							
							File filesigned = new File("./user_directories/data/" + id + "/" + ficheiros.get(i) + ".sign." + id);					
							
							BufferedInputStream fileSigned = new BufferedInputStream(new FileInputStream("./user_directories/data/" + id + "/" + ficheiros.get(i) + ".sign." + id));
							
							Long temp1 = filesigned.length();
							int tempint = temp1.intValue();
							
							byte[] array2 = new byte[1024];
							x = 0;
							outStream.writeObject(filesigned.length());
							outStream.flush();
							while(tempint > 0) {	
								x = fileSigned.read(array2, 0, tempint > 1024 ? 1024 : tempint);
								outStream.write(array2, 0, x);
								outStream.flush();
								tempint -= x;
							}
							fileSigned.close();
							
							System.out.println("Saved file: " + ficheiros.get(i) + " in user: " + id);
						} else {
							System.out.println("Can't overwrite the file: " + ficheiros.get(i) + " of user " + id);
						}
					}
					//sendsSignedFilesToClient(ficheirosServidor, String.valueOf(id), outStream);
					
				} else if(option.equals("d")) { //envia ficheiros
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();

					if(!PasswordHashVerification(String.valueOf(id), pwd)) {
						throw new Exception("invalid user");
					}
					
					//String decryptedPass = PasswordSaltCipherDecrypt(pwd, String.valueOf(id));
					/*
					boolean userVerified = userVerified(String.valueOf(id), decryptedPass);
					if(!userVerified){
						throw new Exception("user is not valid");
					}*/

					List<String> ficheiros = (List<String>) inStream.readObject();
					List<String> ficheirosServidor = new ArrayList<String>(); //ficheiros que existem no server
					List<Long> dimensao = new ArrayList<Long>();

					for(int i = 0; i < ficheiros.size(); i++){

						File fileClient = new File("./user_directories/data/" + id + "/" + ficheiros.get(i));
						if(fileClient.isFile()) {//verifica se o ficheiro existe no server
							Long file_size = (Long) fileClient.length();
							dimensao.add(file_size);
							ficheirosServidor.add(ficheiros.get(i));
							ficheiros.remove(ficheiros.get(i)); //lista 'ficheiros' files q n existem no server

						} else {
							System.out.println("the file: " + fileClient+  " doesn't exist");
						}

					}
					outStream.writeObject(ficheiros);
					outStream.writeObject(dimensao);
					outStream.writeObject(ficheirosServidor);
					sendsSignedFilesToClient(ficheirosServidor, String.valueOf(id), outStream);
					/*
					for(int i = 0; i < ficheirosServidor.size(); i++){

						BufferedInputStream fileClientBIS = new BufferedInputStream(new FileInputStream("./user_directories/data/" + id + "/" + ficheirosServidor.get(i)));
						byte[] array = new byte[1024];

						int x = 0;
						while((x = fileClientBIS.read(array, 0, 1024)) > 0) {
							outStream.write(array, 0, x);
						}
						System.out.println("File: " + ficheirosServidor.get(i) +  " sent to user: " + id);
						fileClientBIS.close();
					}
					*/
				} else if (option.equals("s")){
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();

					if(!PasswordHashVerification(String.valueOf(id), pwd)) {
						throw new Exception("invalid user");
					}
					
					FileInputStream kfile = new FileInputStream("keystore.server");  //keystore
					KeyStore kstore = KeyStore.getInstance("JKS");
					kstore.load(kfile, "ninis".toCharArray());           //password
	
					Key myPrivateKey = kstore.getKey(String.valueOf(id), pwd.toCharArray()); 
					PrivateKey pk = (PrivateKey) myPrivateKey;
	
					Signature sig = Signature.getInstance("SHA256withRSA");
					sig.initSign(pk);
					
					int numberOfFiles = (int) inStream.readObject();
					for(int i = 1; i <= numberOfFiles; i++){
						Boolean fileExists = (Boolean) inStream.readObject();

						if(fileExists){
							String fileName = (String) inStream.readObject();
							//BufferedOutputStream fileBOS = new BufferedOutputStream(new FileOutputStream("./user_directories/data/" + id + "/" + fileName + "-hash." + id));

							//Long fileSize = (Long) inStream.readObject(); //file size 
							//int temp = fileSize.intValue(); //file size
							int x = 0;
							byte[] array = new byte[1024];
							while((x = inStream.read(array, 0, 1024)) > 0) {
							//int temp = 256;
							//while(temp > 0) {
								//x = inStream.read(array, 0, temp > 16 ? 16 : temp);
								sig.update(array, 0, x);
								//outStream.write(array, 0, x);
								//outStream.flush();
								//temp -= x;
							}
							outStream.write(sig.sign());
							outStream.flush();
							//sendsFile(fileName, temp, String.valueOf(id), outStream);
							
						}else{
							String fileName = (String) inStream.readObject();
							System.out.println("The file: " + fileName + " doesn't exist in client");
						}
					}


				} else if (option.equals("v")){
					int id = (int) inStream.readObject();
					String pwd = (String) inStream.readObject();
					
					if(!PasswordHashVerification(String.valueOf(id), pwd)) {
						throw new Exception("invalid user");
					}
					int numberOfFiles = (int) inStream.readObject();

					for(int i = 1; i <= numberOfFiles; i++){

						Boolean fileExists = (Boolean) inStream.readObject();

						//sintese
						if(fileExists){
							String fileName = (String) inStream.readObject();
							/*
							Long fileSize = (Long) inStream.readObject(); //file size 
							int temp = fileSize.intValue(); //file size
							int x = 0;
							byte[] array = new byte[1024];
							while(temp > 0) {
								x = inStream.read(array, 0, temp > 1024 ? 1024 : temp);
								temp -= x;
							}
							
							*/
							//assinatura
							FileInputStream fis;
								
							fis = new FileInputStream("./user_directories/data/" + id + "/" + fileName + ".sign." + id);
							long dataLen = new File("./user_directories/data/" + id + "/" + fileName + ".sign." + id).length() - 256; //alterarrrrrr

							FileInputStream kfile = new FileInputStream("keystore.server"); //keystore
							KeyStore kstore = KeyStore.getInstance("JKS");
							kstore.load(kfile, "ninis".toCharArray()); //password
								
							Certificate c = (Certificate) kstore.getCertificate(String.valueOf(id)); 
							PublicKey pubk = c.getPublicKey();

							//verifica a assinatura e a sintese
							Signature sig = Signature.getInstance("SHA256withRSA");
							sig.initVerify(pubk);
								
							byte[] b = new byte[16];
							
							int len = 0;
							while(dataLen > 0) {
								len = fis.read(b, 0, (int) dataLen > b.length ? b.length : (int) dataLen);
								dataLen -= len;
							}
							
							byte[] signature = new byte[256];
							len = fis.read(signature);
							/*
							//le a sintese já existente no servidor
							String new_mac = new String(array);

							Long fileSize_mac = new File("./user_directories/data/" + id + "/" + fileName + ".signed." + id).length(); //file size 
							int temp_mac = fileSize_mac.intValue(); //file size
							x = 0;
							byte[] array_mac = new byte[1024];
							while(temp > 0) {
								x = inStream.read(array, 0, temp > 1024 ? 1024 : temp);
								temp -= x;
							}

							String old_mac = new String(array_mac);
							*/
							//if (sig.verify(signature) && old_mac.equals(new_mac)) {
							if(sig.verify(signature)) {
								outStream.writeObject("Message is valid");
								outStream.flush();
							} else {
								outStream.writeObject("Message was corrupted");
								outStream.flush();
								System.out.println("sig.verify(signature)" + sig.verify(signature));
								//System.out.println("old_mac.equals(new_mac)" + old_mac.equals(new_mac));
							}
						
							fis.close();

						}
					}
					//String decryptedPass = PasswordSaltCipherDecrypt(pwd, String.valueOf(id));

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
