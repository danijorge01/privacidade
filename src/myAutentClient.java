import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class myAutentClient {
    /**
     * @param args
     * @throws Exception
     * @throws IOException
     */
    public static void main(String[] args) throws Exception, IOException {
        int userId = Integer.parseInt(args[1]);
		String password = args[2];
        String nameReceiver = args[3];
        String address = "localhost";
        int port = 23456;

        System.setProperty("javax.net.ssl.trustStore", "keystore.server");
        System.setProperty("javax.net.ssl.trustStorePassword", "ninis1234");

        SocketFactory sf = SSLSocketFactory.getDefault();
        Socket socket = sf.createSocket(address, port);
                
		ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
		ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());

		String fileName = "aaa";
		// check if the client wants to send messages
		sendFileMessage(userId, password, nameReceiver, inStream, outStream, sf);
		// see if there's new messages to receive
		//recievesFile(userId, password, fileName, inStream2, outStream2, temp);
	}
			private static void sendFileMessage(int userId, String password, String nameReceiver, ObjectInputStream inStream, ObjectOutputStream outStream, SocketFactory sf){ //SEND FILES
	            
				// connection between client and server

				File kfile = new File("keystore." + userId);  //keystore
				if(!kfile.isFile()) { 
					Cifra.main(String.valueOf(userId), password);					
				} 

				FileInputStream kfilein = new FileInputStream("keystore." + userId);  //keystore
				KeyStore kstore = KeyStore.getInstance("JKS");
				kstore.load(kfilein, password.toCharArray());
				outStream.writeObject(kstore.aliases()); // nome

				Map<String, Socket> availableClients = (HashMap<String, Socket>) inStream.readObject(); // names and addresses of clients
				
				Socket clientSocket;
				// choose a client to chat
				if(availableClients.get(nameReceiver) != null) {
					clientSocket = availableClients.get(nameReceiver);
				} else {
					System.out.println("This user doesn't exist.");
				}
				Socket newSocket = sf.createSocket(clientSocket.getInetAddress(), clientSocket.getPort());

				ObjectInputStream inStream2 = new ObjectInputStream(newSocket.getInputStream());
				ObjectOutputStream outStream2 = new ObjectOutputStream(newSocket.getOutputStream());

				// the clients send their public keys
				PublicKey pubk_receiver = (PublicKey) inStream2.readObject();
				Certificate c = (Certificate) kstore.getCertificate(String.valueOf(userId)); 
				PublicKey pubk = c.getPublicKey();
				outStream2.writeObject(pubk); //sends public key to receiver

				Scanner myObj = new Scanner(System.in);
    			System.out.println("Enter message: ");
				String message = myObj.nextLine();

				// Create Hash of the message

				PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
				SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
				SecretKey key_Mac = kf.generateSecret(keySpec);

				Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(key_Mac);

				//BufferedOutputStream oos = new BufferedOutputStream(new FileOutputStream("message_hash.txt"));
				byte buf[] = message.getBytes();
				mac.update(buf);
				outStream2.writeObject(mac.doFinal());
				//oos.close();

				//Gerar chave de sessão p/ comunicação com determinado(s) cliente(s) 

				//GET RANDOM AES KEY
				KeyGenerator kg = KeyGenerator.getInstance("AES"); //generate random key for AES
				kg.init(128);
				SecretKey key = kg.generateKey();

				//CIPHER FILE WITH AES KEY
				Cipher cAES = Cipher.getInstance("AES");
				cAES.init(Cipher.ENCRYPT_MODE, key);
				FileOutputStream newServerFileFOS = new FileOutputStream("./user_directories/data/" + userId +".cif");
				CipherOutputStream newServerFileCOS = new CipherOutputStream(newServerFileFOS, cAES);
				byte[] array = new byte[1024];
				int temp = message.getBytes().length; //SE DER MAL PODE SER ISTO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				int x = 0;
				while(temp > 0) {
					x = inStream.read(array, 0, temp > 1024 ? 1024 : temp);
					newServerFileCOS.write(array, 0, x); //writes file data
					temp -= x;
				}
				newServerFileCOS.close();
				kfilein.close();

				// Encrypt the AES key with the public key of the receiver 

				// PERGUNTAR AO PROFESSORR!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				
				Cipher cRSA = Cipher.getInstance("RSA");
				cRSA.init(Cipher.WRAP_MODE, pubk_receiver);
				byte[] wrappedKey = cRSA.wrap(key);
				outStream2.writeObject(wrappedKey);

				//order of stuff received: list of available clients, public key of receiver
				//order of stuff sent: public key, hashed file, cipher file, wrapped AES key (shared key)

	        }

			private void receivesFile(String userId, String password, String fileName, ObjectInputStream inStream2, ObjectOutputStream outStream2, int temp) throws IOException, Exception {
 				
				File kfile = new File("keystore." + userId);  //keystore
				if(!kfile.isFile()) { 
					Cifra.main(String.valueOf(userId), password);					
				} 

				FileInputStream kfilein = new FileInputStream("keystore." + userId);  //keystore
				KeyStore kstore = KeyStore.getInstance("JKS");
				kstore.load(kfilein, password.toCharArray());

				Certificate c = (Certificate) kstore.getCertificate(String.valueOf(userId)); 
				PublicKey pubk = c.getPublicKey();
				outStream2.writeObject(pubk); //sends public key to sender

				PublicKey pubk_sender = (PublicKey) inStream2.readObject();

				// old mac
				byte[] array3 = (byte[]) inStream2.readObject();

				//Recieves the file
				
				BufferedOutputStream fileBOS = new BufferedOutputStream(new FileOutputStream("./client/" + userId + "/" + fileName + ".cif"));
 				int x = 0;
 				byte[] array = new byte[1024];
 				while(temp > 0) {
 					x = inStream2.read(array, 0, temp > 1024 ? 1024 : temp);
 					fileBOS.write(array, 0, x);
 					temp -= x;	
				}
 				fileBOS.close();

				// Decrypt the file

				//READ WRAPPED KEY
				byte[] keyEncoded = (byte[]) inStream2.readObject();

				//GET PRIVATE KEY
				Key myPrivateKey = kstore.getKey(String.valueOf(userId), password.toCharArray()); 

				//GET RANDOM AES KEY CREATED IN CIPHER
				Cipher cRSA = Cipher.getInstance("RSA");
				cRSA.init(Cipher.UNWRAP_MODE, myPrivateKey); 
				Key keyAES = cRSA.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);

				//DECRYPT CIPHER
				Cipher cAES = Cipher.getInstance("AES");
	   			cAES.init(Cipher.DECRYPT_MODE, keyAES);

				//DECRYPT FILE WITH AES KEY
				FileInputStream fileFIS = new FileInputStream("./user_directories/data/" + userId + "/" + fileName + ".cif");
				CipherOutputStream fileCOS = new CipherOutputStream(outStream2, cAES);
				byte[] array2 = new byte[1024];
				//outStream2.writeObject(temp); //sends file size
				int x1 = 0;
				while((x1 = fileFIS.read(array2, 0, 1024)) > 0) {
					fileCOS.write(array2, 0, x1);
					fileCOS.flush();
				}
				System.out.println("Message: " + fileName +  " sent to client of id: " + userId);
				fileFIS.close();
				fileCOS.close();
				
				// Hash para testar a integridade

				PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
				SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
				SecretKey key = kf.generateSecret(keySpec);

				// new mac
				Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(key);
				mac.update(array2);
				byte[] arrayFinal = mac.doFinal();

				String new_mac = new String(array2);
				String old_mac = new String(array3);
				if(old_mac.equals(new_mac)) {
					System.out.println("MAC of message is correct");
				} else{
					throw new Exception("MAC of the message is invalid");
				}

 			}

}
