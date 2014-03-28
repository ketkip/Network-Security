
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;

public class Server {
	  static DatagramSocket serverSocket;
	  static DatagramPacket receivePacket;
	  static  byte[] receiveData = new byte[1024];
	  static ArrayList<InetAddress> list = new ArrayList<InetAddress>();
	  static ArrayList<Integer> list2 = new ArrayList<Integer>();
	 
	
	  public static void main(String args[]) throws Exception
	    {
          int portSer= Integer.parseInt(args[0]);
	      serverSocket = new DatagramSocket(portSer);
	      byte[] receiveData = new byte[1024];
	      System.out.println("Server Initialized...");
	      
	        while(true)
	        {   
	    	  //Receives packets
	          receivePacket =new DatagramPacket(receiveData, receiveData.length);
	          serverSocket.receive(receivePacket);
	          InetAddress  IPAddress = receivePacket.getAddress();  
	          int port = receivePacket.getPort();
	         
	         
	         if(!list2.contains(port))  
	 		{
	        list2.add(port);       //adds port to the list 
	 		list.add(IPAddress);  // adds IPaddress to the list
	 		
	 		//Receives packet
	 		receivePacket= new DatagramPacket(receiveData, receiveData.length);  
	 		serverSocket.receive(receivePacket);
	 		IPAddress = receivePacket.getAddress();  
	        port = receivePacket.getPort();
	 		}
	 	  
	         //Fetches message from the packet
	         String sentence = new String(receivePacket.getData(),
	    	 0, receivePacket.getLength());
	             
	         String s= "<From "+IPAddress.toString().substring(1)+ ":" + port + ">: " + sentence ;
	          
	         //sends message to all the clients
	         sendAll(s);   
            
	      }
	         
	      }


	private static void sendAll(String s) throws IOException {
		
		 byte[] sendData = new byte[1024]; 
         sendData = s.getBytes();
            
         for(int i=0;i< list2.size(); i++)        // Traverses list
         {
         DatagramPacket sendPacket =
          new DatagramPacket(sendData, sendData.length,list.get(i),list2.get(i)); 
         serverSocket.send(sendPacket);          //sends packet
         
         }
         
	}



}
	
