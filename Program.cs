using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Crypto
{
    class Program
    {
        static void Main(string[] args)
        {
            string atoz = "abcdefghijkmnopqrstuvwxyz";
            foreach (var data in atoz) {
               var q= data.ToString();
            }
                var dt = GetNetworkTime();
            #region RSA Crypto
            RSAKeyCreate();
            UnicodeEncoding ByteConverter = new UnicodeEncoding();

            byte[] dataToEncrypt = ByteConverter.GetBytes("Data to Encrypt Test");
            byte[] encryptedData;
            byte[] decryptedData;

            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {

                encryptedData = RSAEncrypt(dataToEncrypt, RSA.ExportParameters(false), false);

                decryptedData = RSADecrypt(encryptedData, RSA.ExportParameters(true), false);

                Console.WriteLine("Decrypted RSA: {0}", ByteConverter.GetString(decryptedData));
            }
            #endregion
            #region QIV Crypto
            string iv = CreateRandomIV(16);
            string key = "12345678901234567890123456789012";
            string strEncrypt = "RijndaelManaged for CBC";
            string encrypt = Encrypt(strEncrypt, key, iv);
            string decrypt = Decrypt(encrypt, key, iv);
            Console.WriteLine("Decrypted QIV: {0}", decrypt);

            #endregion

            Console.Read();
        }

        private static void RSAKeyCreate()
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            using (StreamWriter writer = new StreamWriter("PrivateKey.xml"))  //這個文件要保密
            {

                writer.WriteLine(rsa.ToXmlString(true));


            }
            using (StreamWriter writer = new StreamWriter("PublicKey.xml"))
            {

                writer.WriteLine(rsa.ToXmlString(false));
            }
        }


        public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Import the RSA Key information. This only needs
                    //toinclude the public key information.
                    string xml = File.ReadAllText("PublicKey.xml");
                    RSA.FromXmlString(xml);//.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }

        }

        public static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs
                    //to include the private key information.
                    string xml = File.ReadAllText("PrivateKey.xml");
                    RSA.FromXmlString(xml);//.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }

        }


        public static string HMACSHA1Text(string message, string key)
        {


            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();

            byte[] keyByte = encoding.GetBytes(key);



            HMACMD5 hmacmd5 = new HMACMD5(keyByte);

            HMACSHA1 hmacsha1 = new HMACSHA1(keyByte);



            byte[] messageBytes = encoding.GetBytes(message);

            byte[] hashmessage = hmacsha1.ComputeHash(messageBytes);

            return ByteToString(hashmessage);

        }

        public static string ByteToString(byte[] buff)
        {

            string sbinary = "";



            for (int i = 0; i < buff.Length; i++)
            {

                sbinary += buff[i].ToString("X2"); // hex format

            }

            return (sbinary);

        }

        private static readonly Regex _rx = new Regex(
           @"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)?$",
           RegexOptions.Compiled);
        public static byte[] Base64TryParse(string s)
        {
            if (s == null) throw new ArgumentNullException("s");

            if ((s.Length % 4 == 0) && _rx.IsMatch(s))
            {
                try
                {
                    return Convert.FromBase64String(s);
                }
                catch (FormatException)
                {
                    // ignore
                }
            }
            return null;
        }
        public static DateTime GetNetworkTime()
        {
            try
            {
                const string ntpServer = "time.windows.com";

                var ntpData = new byte[48];

                ntpData[0] = 0x1B;

                var addresses = Dns.GetHostEntry(ntpServer).AddressList;

                IPEndPoint ipEndPoint = new IPEndPoint(addresses[0], 123);
                Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

                socket.Connect(ipEndPoint);
                socket.ReceiveTimeout = 3000;

                socket.Send(ntpData);
                socket.Receive(ntpData);
                socket.Close();

                const byte serverReplyTime = 40;

                ulong intPart = BitConverter.ToUInt32(ntpData, serverReplyTime);

                ulong fractPart = BitConverter.ToUInt32(ntpData, serverReplyTime + 4);

                intPart = SwapEndianness(intPart);
                fractPart = SwapEndianness(fractPart);

                var milliseconds = (intPart * 1000) + ((fractPart * 1000) / 0x100000000L);

                var networkDateTime = (new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds((long)milliseconds);

                return networkDateTime;
            }
            catch (Exception EX)
            {

                throw EX;
            }

        }

        private static uint SwapEndianness(ulong x)
        {
            return (uint)(((x & 0x000000ff) << 24) +
                           ((x & 0x0000ff00) << 8) +
                           ((x & 0x00ff0000) >> 8) +
                           ((x & 0xff000000) >> 24));
        }

        #region QIV Crypto

        public static string Encrypt(string toEncrypt, string key, string iv)
        {
            return Encrypt(key.Length * 8, iv.Length * 8, toEncrypt, key, iv);
        }
        public static string Encrypt(int keySize, int blockSize, string toEncrypt, string key, string iv)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] ivArray = Encoding.ASCII.GetBytes(iv);
            byte[] toEncryptArray = Encoding.UTF8.GetBytes(toEncrypt);

            RijndaelManaged rDel = new RijndaelManaged();
            rDel.KeySize = keySize;
            rDel.BlockSize = blockSize;
            rDel.Key = keyArray;
            rDel.IV = ivArray;
            rDel.Mode = CipherMode.CBC;
            rDel.Padding = PaddingMode.Zeros;

            ICryptoTransform cTransform = rDel.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }
        public static string Decrypt(string toDecrypt, string key, string iv, PaddingMode paddingMode = PaddingMode.Zeros)
        {
            return Decrypt(key.Length * 8, iv.Length * 8, toDecrypt, key, iv, paddingMode);
        }
        public static string Decrypt(int keySize, int blockSize, string toDecrypt, string key, string iv, PaddingMode paddingMode = PaddingMode.Zeros)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] ivArray = Encoding.ASCII.GetBytes(iv);
            byte[] toDecryptArray = Base64TryParse(toDecrypt);
            if (toDecryptArray == null) return "";

            RijndaelManaged rDel = new RijndaelManaged();
            rDel.KeySize = keySize;
            rDel.BlockSize = blockSize;
            rDel.Key = keyArray;
            rDel.IV = ivArray;
            rDel.Mode = CipherMode.CBC;
            rDel.Padding = paddingMode;

            ICryptoTransform cTransform = rDel.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toDecryptArray, 0, toDecryptArray.Length);

            return Encoding.UTF8.GetString(resultArray);
        }

        public static string CreateRandomIV(int ivLength)
        {
            string allowedChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789!@$?_-";
            char[] chars = new char[ivLength];
            Random rd = new Random();

            for (int i = 0; i < ivLength; i++)
                chars[i] = allowedChars[rd.Next(0, allowedChars.Length)];

            return new string(chars);
        }
        #endregion
    }
}