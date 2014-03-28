
import java.io.*;
import java.net.*;

class Client 
{
	   static BufferedReader inFromUser =
	         new BufferedReader(
             new InputStreamReader(System.in));

	   static DatagramSocket clientSocket;
	   static InetAddress IPAddress;
	   static int port;
	   static byte[] sendData = new byte[1024];
	   static byte[] receiveData = new byte[1024];
	  
    static Thread t1 = new Thread(){
    // for sending packet 
	   public void run(){
		try{ 
			while(true){
		      String packet = inFromUser.readLine();
		      sendData = packet.getBytes();
		      DatagramPacket sendPacket =
		      new DatagramPacket(sendData, sendData.length,
		      IPAddress,port);
		      clientSocket.send(sendPacket);
		      }
		}
		catch(Exception e){
			e.getMessage();
		}
	   }
  };

  
 static Thread t2 = new Thread(){
	// for receiving packet 
	   public void run(){
		try{  
			while(true){
				 DatagramPacket receivePacket =
				 new DatagramPacket(receiveData, receiveData.length);
				 clientSocket.receive(receivePacket);
                 String message = new String(receivePacket.getData(),
				 0, receivePacket.getLength());
                 System.out.println(message);
		      }
		}
		catch(Exception e){
			e.getMessage();
		}
	   }
 };

 
 public static void main(String args[]) throws Exception
 {      
	   clientSocket = new DatagramSocket();          // creating client socket
	   IPAddress = InetAddress.getByName(args[0]);  // Getting IPAddress from command line
	   port= Integer.parseInt(args[1]);            // Getting port number from command line
     
	      String sentence = "Greeting";
	      sendData = sentence.getBytes();
	      DatagramPacket sendPacket =
	      new DatagramPacket(sendData, sendData.length,
	                            IPAddress,port);
	        clientSocket.send(sendPacket);       // sending the first packet
	    
		t1.start();
		t2.start();	    
 }
}
	   
