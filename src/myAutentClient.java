import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class myAutentClient {
    public static void main(String[] args) throws Exception, IOException {

    	//#try-catch? 17-28
    	//10.101.148.201
        int userId = Integer.parseInt(args[1]);

        String[] serverAddress = args[3].split(":");
        String address = serverAddress[0];
        int port = Integer.parseInt(serverAddress[1]);

        System.setProperty("javax.net.ssl.trustStore", "keystore.server");
        System.setProperty("javax.net.ssl.trustStorePassword", "ninis");
        
        //Socket socket = new Socket(address, port);
        SocketFactory sf = SSLSocketFactory.getDefault( );
        Socket socket = sf.createSocket("127.0.0.1", 23456);
                
		ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
		ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
		
		if(args.length <= 4) {
			System.out.println("Not enough arguments");
			outStream.writeObject("notenough");
			
		} else {
        
	        String password;
	        int a = 4;
	        if(args.length > 4 && args[4].equals("-p"))  {
	            password = args[5];
	            a = 6;
	        } else {
	            Scanner obj = new Scanner(System.in);
	            System.out.println("Enter a password: ");
	            password = obj.nextLine();
	            obj.close();
	        }
	
	        if(args[a].equals("-c") && userId == 1){ //envia ao server os dados para um novo user
	            outStream.writeObject("c");
	            outStream.writeObject(userId); //id admin
	            outStream.writeObject(password); //password admin
	            outStream.writeObject(args[a+1]); //id of the new user
	            outStream.writeObject(args[a+2]); //nome of the new user
	            outStream.writeObject(args[a+3]); //password of the new user
	            
	            Boolean resp = (Boolean) inStream.readObject();
	            
	            if(resp) {
	            	System.out.println("User named " + args[a+2] + " with id " + args[a+1] + " was successfully created");
					File dir_user = new File("./client/" + args[a+1]);
					if(!(dir_user.isDirectory())){ 
						new File("./client/" + args[a+1]).mkdirs(); 
						System.out.println("New directory was created for user " + args[a+1] + " in '/client'");
					}
	            } else {
	            	System.out.println("User " + args[a+2] + " with id " + args[a+1] + " already exists"); 
	            }
	        }
	        
	        else if(args[a].equals("-l")){ //pede lista
	            outStream.writeObject("l");
	            outStream.writeObject(userId); //id
	            outStream.writeObject(password);
	            
	            int numfiles = (int) inStream.readObject();
	            if(numfiles == 0){
					System.out.println("user doesn't have files");
				}
	            else{
	                List<String> file_list = (List<String>) inStream.readObject(); //recebe lista 
	                
	                for(int i = 0; i < file_list.size(); i++) {
	                    System.out.println(file_list.get(i));
	                }
	            }
	        }
	        
	        else if(args[a].equals("-e")){ //envia ficheiros
	
	            outStream.writeObject("e");
	            outStream.writeObject(userId);
	            outStream.writeObject(password);
	            
	            List<String> ficheiros = new ArrayList<String>();
	            List<Long> dimensao = new ArrayList<Long>();
	
	            for(int f = a + 1; f < args.length; f++){
	                
	                File fileClient = new File("./client/" + userId + "/" + args[f]);
	                	                
	                if(fileClient.isFile()) {
	                	String file_name = fileClient.getName();
	                	Long size = (Long) fileClient.length();
	                	ficheiros.add(file_name);
	                	dimensao.add(size); 
	                }else {
	                	System.out.println("the file: " + args[f] +  " doesn't exist in directory: /client/" + userId + "/");
	                }
	            }
	            
	            outStream.writeObject(ficheiros);
	            outStream.writeObject(dimensao);
	            List<String> ficheirosServidor = (List<String>) inStream.readObject();
	            
				
	            for(int i = 0; i < ficheiros.size(); i++){
	            	if(ficheirosServidor.contains(ficheiros.get(i))) {
	            		ficheiros.remove(ficheiros.get(i)); //lista 'ficheiros' files q n existem no server (!!!)
	            		dimensao.remove(ficheiros.get(i));
	            		System.out.println("Can't overwrite the file: " + ficheiros.get(i) + " of user " + userId);
	            	}else {
			            BufferedInputStream fileClientBIS = new BufferedInputStream(new FileInputStream("./client/" + userId + "/" + ficheiros.get(i)));

			            byte[] array = new byte[1024];
			            int x = 0;
			            int temp = dimensao.get(i).intValue();
			            while(temp > 0) {
			                x = fileClientBIS.read(array, 0, temp > 1024 ? 1024 : temp);
			                outStream.write(array, 0, x);
			                outStream.flush();
			            	temp -= x;
			            }
			            System.out.println("Saved file: " + ficheiros.get(i) + " in server");
			            fileClientBIS.close();			            
			            
						BufferedOutputStream fileSignedByServer = new BufferedOutputStream(new FileOutputStream("./client/" + userId + "/" + ficheiros.get(i) + ".sign." + userId));
						Long tempL = (Long) inStream.readObject();
						temp = tempL.intValue();
						byte[] array2 = new byte[1024];
						x = 0;
						while(temp > 0) {
							x = inStream.read(array2, 0, temp > 1024 ? 1024 : temp);
							fileSignedByServer.write(array2, 0, x);
							
							temp -= x;
						}
						fileSignedByServer.close();
	            	}
	            }
	            //asksServerForSignedFiles(ficheiros, dimensao, String.valueOf(userId), password, inStream);
				
	        }
	
	        else if(args[a].equals("-d")){ //recebe ficheiros
	        	
	            outStream.writeObject("d");
	            outStream.writeObject(userId);
	            outStream.writeObject(password);
	
				List<String> ficheiros = new ArrayList<String>();
							
				for(int i = a + 1; i < args.length; i++) {
					ficheiros.add(args[i]);
				}
				
				outStream.writeObject(ficheiros);
				
				List<String> ficheirosNaoExistentes = (List<String>) inStream.readObject();
				List<Long> dimensoes = (List<Long>) inStream.readObject();	
				List<String> ficheirosServidor = (List<String>) inStream.readObject();
				
				for(int n = 0; n < ficheirosNaoExistentes.size(); n++) {
					System.out.println("The file: " + ficheirosNaoExistentes.get(n) + " doesn't exist in server");
				}
				
				asksServerForSignedFiles(ficheirosServidor, dimensoes, String.valueOf(userId), password, inStream);
				/*
				for(int f = 0; f < ficheirosServidor.size(); f++){

					if(new File("./client/" + userId + "/" + ficheirosServidor.get(f)).isFile()){
						System.out.println("Can't overwrite the file: " + ficheirosServidor.get(f) + " of user " + userId);
					} else {

						FileOutputStream fich_serverO = new FileOutputStream("./client/" + userId + "/" + ficheirosServidor.get(f));
						BufferedOutputStream fich_serverB = new BufferedOutputStream(fich_serverO);
		
						byte[] array = new byte[1024];
						int temp = dimensoes.get(f).intValue();
						int x;
						
						while(temp > 0) {
							
							x = inStream.read(array, 0, temp > 1024 ? 1024 : temp);
							fich_serverB.write(array, 0, x);
							temp -= x;	
						}
						System.out.println("New file added to '/client': " + ficheirosServidor.get(f) + " of user: " + userId);
						fich_serverB.close();
						fich_serverO.close();
					}
				} */
				
					
	        } 
			
			else if(args[a].equals("-s")){ //gera a sintese dos ficheiros

				outStream.writeObject("s");
	            outStream.writeObject(userId);
	            outStream.writeObject(password);

				PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray( ));
				SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
				SecretKey key = kf.generateSecret(keySpec);
				Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(key);

				outStream.writeObject(args.length - a - 1); //number of files
				for(int f = a + 1; f < args.length; f++){
					
					File fileClient = new File("./client/" + userId + "/" + args[f]);
					File recieved = new File("./client/" + userId + "/" + args[f] + "_signed." + userId);
	                if(fileClient.isFile() && !recieved.isFile()) {
						outStream.writeObject((Boolean)true); //file exists
						outStream.writeObject(args[f]); //file name
						
						//Hash file from client and sends to server
						BufferedInputStream fileBIS = new BufferedInputStream(new FileInputStream("./client/" + userId + "/" + args[f]));
			            byte[] array = new byte[1024];
			            int x = 0;
			            while((x = fileBIS.read(array, 0, 1024)) > 0) {
							mac.update(array, 0, x);
			            }
			            outStream.writeObject(mac.doFinal());
			            outStream.flush();
						fileBIS.close();
						
						//Sends hashed file to server
						/*
						File fileHash = new File("./client/" + userId + "/" + fileName + "-hash." + userId);		
						
						BufferedInputStream fileHashBIS = new BufferedInputStream(new FileInputStream("./client/" + userId + "/" + fileName + "-hash." + userId));
						byte[] array2 = new byte[1024];
						while((x = fileHashBIS.read(array2, 0, 1024)) > 0) {
			                outStream.write(array2, 0, x);
			                outStream.flush();
			            }
						fileHashBIS.close();
						*/
						
						//recieves signed hash

						receivesFile(String.valueOf(userId), args[f], inStream, 256);

					}else{
						outStream.writeObject((Boolean)false); //file doesn't exist
						outStream.writeObject(args[f]); 
						System.out.println("The file: " + args[f] + " doesn't exist");
					}

				}
				inStream.close();
				outStream.close();

			}else if(args[a].equals("-v")){ 
	
				outStream.writeObject("v");
	            outStream.writeObject(userId);
	            outStream.writeObject(password);
	
				PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
				SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
				SecretKey key = kf.generateSecret(keySpec);
	
				outStream.writeObject(args.length - a - 1); //number of files
				for(int f = a + 1; f < args.length; f++){
	
					Mac mac = Mac.getInstance("HmacSHA256");
					mac.init(key);
	
					File fileClient = new File("./client/" + userId + "/" + args[f]);
	
	                if(fileClient.isFile()) {
						outStream.writeObject((Boolean)true); //file exists
	
	                	String fileName = fileClient.getName();
						outStream.writeObject(fileName); 
						int x = 0;
						/*
						//Hash file from client
						ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("./client/" + userId + "/" + fileName + "-hash." + userId));
						BufferedInputStream fileBIS = new BufferedInputStream(new FileInputStream("./client/" + userId + "/" + fileName));
			            byte[] array = new byte[1024];
			            int x = 0;
			            while((x = fileBIS.read(array, 0, 1024)) > 0) {
							mac.update(array, 0, x);
			                //oos.write(array, 0, x);
			            }
						oos.writeObject(mac.doFinal());
						oos.close();
						fileBIS.close();
						
						//Sends hashed file to server
						File fileHash = new File("./client/" + userId + "/" + fileName + "-hash." + userId);		
						outStream.writeObject(fileHash.length()); //sends file size
						BufferedInputStream fileHashBIS = new BufferedInputStream(new FileInputStream("./client/" + userId + "/" + fileName + "-hash." + userId));
						byte[] array2 = new byte[1024];
						while((x = fileHashBIS.read(array2, 0, 1024)) > 0) {
			                outStream.write(array2, 0, x);
							outStream.flush();
			            }
						fileHashBIS.close();
						*/
						//Sends signed file to server
						File fileSigned = new File("./client/" + userId + "/" + fileName + ".sign." + userId);		
						outStream.writeObject(fileSigned.length()); //sends file size
						BufferedInputStream fileSignedBIS = new BufferedInputStream(new FileInputStream("./client/" + userId + "/" + fileName + ".sign." + userId));
						byte[] array3 = new byte[1024];
						x = 0;
						while((x = fileSignedBIS.read(array3, 0, 1024)) > 0) {
			                outStream.write(array3, 0, x);
							outStream.flush();
			            }
						fileSignedBIS.close();
						
						System.out.println((String)inStream.readObject());
					//outStream.writeObject(args[f]);

	                }	 
				}
			}else {
	        	socket.close();
	        	throw new Exception("user != 1 can't create other users");
			}
		}

        //Boolean resp = (Boolean) inStream.readObject();
        outStream.close();
		inStream.close();
		
		//System.out.println(resp);
		
		socket.close();
		

	}

    public static void asksServerForSignedFiles(List<String> serverFiles, List<Long> filesDimension, String userId, String pwd, ObjectInputStream inStream) 
    		throws IOException {
    	for(int f = 0; f < serverFiles.size(); f++){
    		
			if(new File("./client/" + userId + "/" + serverFiles.get(f) + ".sign." + userId).isFile()){
				System.out.println("Can't overwrite the file: " + serverFiles.get(f)+ ".sign." + userId + " of user " + userId);
			} else {

				FileOutputStream fich_serverO = new FileOutputStream("./client/" + userId + "/" + serverFiles.get(f) + ".sign." + userId);
				BufferedOutputStream fich_serverB = new BufferedOutputStream(fich_serverO);

				byte[] array = new byte[1024];
				int temp = filesDimension.get(f).intValue();
				int x;
				
				while(temp > 0) {
					
					x = inStream.read(array, 0, temp > 1024 ? 1024 : temp);
					fich_serverB.write(array, 0, x);
					temp -= x;	
				}
				System.out.println("New file added to '/client': " + serverFiles.get(f) + " of user: " + userId);
				fich_serverB.close();
				fich_serverO.close();
			}
		}
    }
    public static void receivesFile(String id, String fileName, ObjectInputStream inStream, int readSize) throws IOException, Exception {
	    	BufferedOutputStream fileBOS = new BufferedOutputStream(new FileOutputStream("./client/" + id + "/" + fileName + "_signed." + id));
	
			int x = 0;
			byte[] array = new byte[1024];
			int temp = readSize;
			while(temp > 0) {
				x = inStream.read(array, 0, temp > 1024 ? 1024 : temp);
				fileBOS.write(array, 0, x);
				temp -= x;	
			}
	    	fileBOS.close();
		
    }
    
}
