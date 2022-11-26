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
        // String[] serverAddress = args[3].split(":");
        String address = "localhost";
        int port = 23456;

        System.setProperty("javax.net.ssl.trustStore", "keystore.server");
        System.setProperty("javax.net.ssl.trustStorePassword", "ninis1234");

        SocketFactory sf = SSLSocketFactory.getDefault();
        Socket socket = sf.createSocket(address, port);
                
		ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
		ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());

		sendFileMessage(userId, password, inStream, outStream, sf);
		
		// if(args.length <= 4) {
		// 	System.out.println("Not enough arguments");
		// 	outStream.writeObject("notenough");
		// } else {
	    //     String password;
	    //     int a = 4;
	    //     if(args.length > 4 && args[4].equals("-p"))  {
	    //         password = args[5];
	    //         a = 6;
	        // } else {
	            // Scanner obj = new Scanner(System.in);
	            // System.out.println("Enter a password: ");
	            // password = obj.nextLine();
	            // obj.close();
	        // }
	        // if(args[a].equals("-c") && userId == 1){ //SEND DATA FOR NEW USER
	        //     outStream.writeObject("c");
	        //     outStream.writeObject(userId); //id admin
	        //     outStream.writeObject(password); //password admin
	        //     outStream.writeObject(args[a+1]); //id of the new user
	        //     outStream.writeObject(args[a+2]); //name of the new user
	        //     outStream.writeObject(args[a+3]); //password of the new user
	            
	        //     Boolean resp = (Boolean) inStream.readObject();
	        //     if(resp) {
	        //     	System.out.println("User named " + args[a+2] + " with id " + args[a+1] + " was successfully created");
			// 		File dir_user = new File("./client/" + args[a+1]);
			// 		if(!(dir_user.isDirectory())){ 
			// 			new File("./client/" + args[a+1]).mkdirs(); 
			// 			System.out.println("New directory was created for user " + args[a+1] + " in '/client'");
			// 		}
	        //     } else {
	        //     	System.out.println("User " + args[a+2] + " with id " + args[a+1] + " already exists"); 
	        //     }
	        // }
	        // else if(args[a].equals("-l")){ //LIST
	        //     outStream.writeObject("l");
	        //     outStream.writeObject(userId);
	        //     outStream.writeObject(password);
	            
	        //     int numfiles = (int) inStream.readObject();
	        //     if(numfiles == 0){
			// 		System.out.println("user doesn't have files");
			// 	}
	        //     else{
	        //         List<String> file_list = (List<String>) inStream.readObject(); //recebe lista 
	        //         for(int i = 0; i < file_list.size(); i++) {
	        //             System.out.println(file_list.get(i));
	        //         }
	        //     }
	        // }
	}


			private static void sendFileMessage(int userId, String password, ObjectInputStream inStream, ObjectOutputStream outStream, SocketFactory sf){ //SEND FILES
	            // outStream.writeObject("e");

				File kfile = new File("keystore." + userId);  //keystore
				if(!kfile.isFile()) { 
					Cifra.main(String.valueOf(userId), password);					
				} 

				FileInputStream kfilein = new FileInputStream("keystore." + userId);  //keystore
				KeyStore kstore = KeyStore.getInstance("JKS");
				kstore.load(kfilein, password.toCharArray());
				outStream.writeObject(kstore.aliases()); // nome

				Map<String, Socket> availableClients = (HashMap<String, Socket>) inStream.readObject(); // names and addresses of clients
				
				// choose a client to chat
				Socket clientSocket = availableClients.get("Katrina");
				Socket newSocket = sf.createSocket(clientSocket.getInetAddress(), clientSocket.getPort());

				ObjectInputStream inStream2 = new ObjectInputStream(newSocket.getInputStream());
				ObjectOutputStream outStream2 = new ObjectOutputStream(newSocket.getOutputStream());

				Scanner myObj = new Scanner(System.in);  // Create a Scanner object
    			System.out.println("Enter message: ");
				String message = myObj.nextLine();

				Key myPrivateKey = kstore.getKey(String.valueOf(userId), password.toCharArray()); 

				//Gerar chave de sessão p/ comunicação com determinado(s) cliente(s) 

				//GET RADOM AES KEY
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

				// Get public key

				Certificate c = (Certificate) kstore.getCertificate(String.valueOf(userId)); 
				PublicKey pubk = c.getPublicKey();
					
				outStream2.writeObject(pubk); //sends public key to receiver

	        }


	//         public void sendFileMessage(){ //RECIEVES FILES
	//             outStream.writeObject("d");
	//             outStream.writeObject(userId);
	//             outStream.writeObject(password);
	//             outStream.writeObject(args.length - a - 1); //number of files
	            
	// 			for(int f = a + 1; f < args.length; f++) {
					
	// 				File fileExistsInClient = new File("./client/" + userId + "/" + args[f] + "_signed." + String.valueOf(userId));
	// 				if(!fileExistsInClient.isFile()) { 
	// 					outStream.writeObject(args[f]); //file name
	// 					outStream.writeObject(false); //file doens't exist in client
					
	// 					Boolean fileExistsInServer = (Boolean) inStream.readObject(); //file exists in server
	// 					if(fileExistsInServer) {
	// 						int temp = (int) inStream.readObject();
							
	// 						receivesFile(String.valueOf(userId), args[f] + "_signed." + userId, inStream, temp);
	// 					}else {
	// 						System.out.println("The file: " + args[f] +  " doesn't exist in server");
	// 					}
	// 				}else {
	// 					outStream.writeObject(true); //file already exist in client
	// 					System.out.println("The file: " + args[f]+ "_signed." + String.valueOf(userId) + " already exist in client: can't overwrite");
	// 				}
	// 			}
	//         }if(args[a].equals("-s")){ //HASH FILES
	// 			outStream.writeObject("s");
	//             outStream.writeObject(userId);
	//             outStream.writeObject(password);

	// 			PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray( ));
	// 			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
	// 			SecretKey key = kf.generateSecret(keySpec);
	// 			Mac mac = Mac.getInstance("HmacSHA256");
	// 			mac.init(key);

	// 			outStream.writeObject(args.length - a - 1); //number of files
	// 			for(int f = a + 1; f < args.length; f++){
					
	// 				File fileClient = new File("./client/" + userId + "/" + args[f]);
	// 				File recieved = new File("./client/" + userId + "/" + args[f] + "_hash_signed." + userId);
	//                 if(fileClient.isFile() && !recieved.isFile()) {
	// 					outStream.writeObject((Boolean)true); //file exists
						
	// 					//Hash file from client and sends to server
	// 					BufferedInputStream fileBIS = new BufferedInputStream(new FileInputStream("./client/" + userId + "/" + args[f]));
	// 		            byte[] array = new byte[1024];
	// 		            int x = 0;
	// 		            while((x = fileBIS.read(array, 0, 1024)) > 0) {
	// 						mac.update(array, 0, x);
	// 		            }
	// 		            byte[] hash = mac.doFinal();
	// 		            outStream.writeObject(hash.length);
	// 		            outStream.write(hash);
	// 		            System.out.println("hashMac -s: " + new String(hash));
	// 		            outStream.flush();
	// 					fileBIS.close();
						
	// 					//recieves signed hash
	// 					BufferedOutputStream fileBOS = new BufferedOutputStream(new FileOutputStream("./client/" + userId + "/" + args[f] + "_hash_signed." + userId));
	// 					fileBOS.write((byte[]) inStream.readObject());
	// 					fileBOS.close();

	// 				}else{
	// 					outStream.writeObject((Boolean)false); //file doesn't exist
	// 					outStream.writeObject(args[f]); 
	// 					System.out.println("The file: " + args[f] + " doesn't exist");
	// 				}
	// 			}
	// 		}else if(args[a].equals("-v")){ 
	// 			outStream.writeObject("v");
	//             outStream.writeObject(userId);
	//             outStream.writeObject(password);
	
	// 			PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
	// 			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
	// 			SecretKey key = kf.generateSecret(keySpec);
	
	// 			outStream.writeObject(args.length - a - 1); //number of files
	// 			for(int f = a + 1; f < args.length; f++){
	// 				Mac mac = Mac.getInstance("HmacSHA256");
	// 				mac.init(key);
	
	// 				File fileClient = new File("./client/" + userId + "/" + args[f]);
	//                 if(fileClient.isFile()) {
	// 					outStream.writeObject((Boolean)true); //file exists
	//                 	String fileName = fileClient.getName();
	
	// 					//Hash file from client
	// 					BufferedInputStream fileBIS = new BufferedInputStream(new FileInputStream("./client/" + userId + "/" + fileName));
	// 		            byte[] array = new byte[1024];
	// 		            int x = 0;
	// 		            while((x = fileBIS.read(array, 0, 1024)) > 0) {
	// 						mac.update(array, 0, x);
	// 		            }
	// 		            byte[] hashMac = mac.doFinal();
	// 		            fileBIS.close();
	// 		            outStream.writeObject(hashMac);
			            
	// 					//Sends signature to server
	// 					BufferedInputStream fileSignedBIS = new BufferedInputStream(new FileInputStream("./client/" + userId + "/" + fileName + "_hash_signed." + userId));

	// 					byte[] signature = new byte[256]; //read signature
	// 					fileSignedBIS.read(signature);
						
	// 					outStream.writeObject(signature);
	// 					outStream.flush();
	// 					fileSignedBIS.close();
						
	// 					System.out.println((String)inStream.readObject());
	//                 }	 
	// 			}
	// 		}else {
	//         	socket.close();
	//         	throw new Exception("user != 1 can't create other users");
	// 		}
    //     outStream.close();
	// 	inStream.close();
	// 	socket.close();
	// }
		// public void receivesFile(String id, String fileName, ObjectInputStream inStream, int temp) throws IOException, Exception {
		// 		BufferedOutputStream fileBOS = new BufferedOutputStream(new FileOutputStream("./client/" + id + "/" + fileName));
		// 		int x = 0;
		// 		byte[] array = new byte[1024];
		// 		while(temp > 0) {
		// 			x = inStream.read(array, 0, temp > 1024 ? 1024 : temp);
		// 			fileBOS.write(array, 0, x);
		// 			temp -= x;	
		// 		}
		// 		fileBOS.close();
		// }

}
