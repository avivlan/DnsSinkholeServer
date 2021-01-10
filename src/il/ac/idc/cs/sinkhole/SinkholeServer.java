package il.ac.idc.cs.sinkhole;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

public class SinkholeServer {

    static boolean isBlockList = false;
    static final int UDPDNS_SIZE = 512;
    static HashSet<String> blockList;

    public static void main(String[] args) {

        //check if block list is required
        if (args.length != 0)
        {
            String blockListFile = args[0];
            blockList = createBlockList(blockListFile);
            isBlockList = true;
        }

        startServer();
    }

    private static void startServer() {

        DatagramSocket serverSocket = null;
        try {
            serverSocket = new DatagramSocket(5300); // listen on port 5300
            DatagramPacket receiverPacket = new DatagramPacket(new byte[UDPDNS_SIZE], UDPDNS_SIZE);
            serverSocket.receive(receiverPacket);
            InetAddress clientAddress = receiverPacket.getAddress();
            int clientPort = receiverPacket.getPort();
            byte[] packetData = receiverPacket.getData();
            String nameFromDns = getNameFromPacket(receiverPacket);
            if (isBlockList && blockList.contains(nameFromDns)) // block the request
            {

            }
            else
            {
                InetAddress rootServerIP = getRandomRootServer();
                DatagramPacket dnsPacketToRoot = new DatagramPacket(packetData, packetData.length, rootServerIP, 53);
                serverSocket.send(dnsPacketToRoot);
                serverSocket.receive(receiverPacket);
                packetData = receiverPacket.getData();
                int iterationLimit = 0;
                while (checkConditions(packetData) && iterationLimit < 16) {


                }
            }
        }
        catch (SocketException ex)
        {
            System.err.println("Unable to create UDP socket " + ex.getMessage());
        }
        catch (UnknownHostException ex)
        {
            System.err.println("Unable to get root server " + ex.getMessage());
        }
        catch (IOException ex)
        {
            System.err.println("Unable to receive packet " + ex.getMessage());
        }
        finally {
            serverSocket.close();
        }
    }

    private static boolean checkConditions(byte[] packetDataToCheck) {
        boolean conditionsOK = false;
        boolean errorOK;
        boolean answerOK;
        boolean authorityOK;
        errorOK = (packetDataToCheck[3] == 0); // check NOERROR
        answerOK = (((packetDataToCheck[6] << 8) | (packetDataToCheck[7] & 0xff)) == 0); // check ANSWER
        authorityOK = (((packetDataToCheck[8] << 8) | (packetDataToCheck[9] & 0xff)) > 0); // check AUTHORITY
        conditionsOK = errorOK && answerOK && authorityOK;

        return  conditionsOK;
    }

    private static String getNameFromPacket(DatagramPacket packet) {
        int indexToStart = 12; // UDP header size
        byte[] packetData = packet.getData();
        StringBuilder name = new StringBuilder();
        // start going over packet data to find the domain name
        while (packetData[indexToStart] != 0) {
            int len = packetData[indexToStart] & 0xff;
            if ((len & 0xc0) == 0xc0)
            {
                indexToStart = packetData[indexToStart + 1];
                len = packetData[indexToStart];
            }
            indexToStart += 1;
            for (int i = 0; i < len; i ++) {
                name.append((char)(int) packetData[indexToStart + i]);
            }
            indexToStart += len;
            name.append(".");
        }

        String domainName = name.toString().substring(0, name.length() - 1);

        return domainName;
    }

    private static InetAddress getRandomRootServer() throws UnknownHostException {
        //int lettersRange = 'm' - 'a';
        //int rangeStart = 'a';
        //char letter = (char) (rand.nextInt(lettersRange) + rangeStart);
        //InetAddress rootIP = InetAddress.getByName(letter + ".root-servers.net");
        char[] letterArray = new char[] {'a' , 'b' , 'c', 'd' ,'e' , 'f' , 'g', 'h', 'i', 'j' , 'k' , 'l' ,'m'};
        Random rand = new Random();
        int randIndex = rand.nextInt(letterArray.length);
        InetAddress rootIP = InetAddress.getByName(letterArray[randIndex] + ".root-servers.net");

        return rootIP;
    }

    private static HashSet<String> createBlockList(String filePath)
    {
        HashSet<String> blockList = new HashSet<String>();
        // using try with resources to efficiently read the file
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line = br.readLine();
            while (line != null)
            {
                blockList.add(line);
                line = br.readLine();
            }
        }
        catch (Exception ex) {
            System.err.println("Unable to read block list file");
        }

        return blockList;
    }
}