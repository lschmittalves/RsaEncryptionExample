using Microsoft.VisualBasic;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RsaEncrypt.Client
{
    class Program
    {
        static readonly string SERVER_ENDPOINT = @"http://localhost:28288";

        static readonly string publicKeyFile = $"{AppDomain.CurrentDomain.BaseDirectory}\\public-key.json";
        static readonly HttpClient theWebClient = new HttpClient();
        static readonly RSACryptoServiceProvider theCryptoServiceProvider = new RSACryptoServiceProvider(2048);

        static async Task Main()
        {

            // control flag to stop the program execution
            var stopExecution = false;
            var publicKeyAsString = GetClientPublicKey();

            // initialize the web client base address
            theWebClient.BaseAddress = new Uri(SERVER_ENDPOINT);


            Console.WriteLine("-----------------------------------RSA PUBLIC KEY----------------------------------------------");
            File.WriteAllText(publicKeyFile, JsonConvert.SerializeObject(new RsaPublicKey(){
                ClientName = Environment.MachineName,
                PublicKey = publicKeyAsString
            }), Encoding.UTF8);
            Console.WriteLine(new FileInfo(publicKeyFile).FullName);
            Console.WriteLine("-----------------------------------------------------------------------------------------------");

            do
            {
                try
                {
                    Console.WriteLine("Press ENTER to check for new messages, or write 'exit' to stop the program");
                    var lastInputLine = Console.ReadLine();
                    stopExecution = lastInputLine.ToLower() == "exit";

                    if (stopExecution)
                        continue;

                    var thePendingMessages = await GetMessages();

                    if (thePendingMessages.Any())
                    {
                        Console.WriteLine($"Client {Environment.MachineName} has {thePendingMessages.Count} pending message(s)");

                        // decrypt and print the messages
                        thePendingMessages.ForEach(a => Console.WriteLine($"{a.UpdateDate}->{DecryptMessage(a.Message)}"));
                    }
                    else
                    {
                        Console.WriteLine($"Client {Environment.MachineName} doesn't have pending messages");
                    }

                }
                catch (Exception ex)
                {
                    Console.WriteLine($"ERROR -> {ex.Message}");
                }

                Console.WriteLine("-----------------------------------------------------------------------------------------------");

            } while (!stopExecution);


            Console.WriteLine("Hello World!");
        }


        /// <summary>
        /// Clear all the messages of the client 
        /// </summary>
        /// <param name="theEncryptMessage"></param>
        /// <param name="theHttpResponseCode"></param>
        /// <returns></returns>
        private async static Task<List<RsaMessage>> GetMessages()
        {
            using (HttpResponseMessage response = await theWebClient.GetAsync($"message/{Environment.MachineName}")) // get all the messages of the current client
            {
                response.EnsureSuccessStatusCode(); // throw a exeption if something is not right on the response

                var content = await response.Content.ReadAsStringAsync();
                return JsonConvert.DeserializeObject<List<RsaMessage>>(content);

            }
        }

        /// <summary>
        /// Encrypt the mssage using the RSA public key
        /// </summary>
        /// <param name="theMessage"></param>
        /// <returns></returns>
        private static string EncryptMessage(string theMessage, string thePublicKeyAsString)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(theMessage);// encode the message with UTF8

            using (var theRsaEncrypt = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    theRsaEncrypt.FromXmlString(thePublicKeyAsString); // initializing the rsa with the serialized key
                    var encryptedData = theRsaEncrypt.Encrypt(bytesToEncrypt, true); // encrypt the data, it will return a array of bytes
                    var base64Encrypted = Convert.ToBase64String(encryptedData); // then we convert the array of bytes in a string
                    return base64Encrypted;
                }
                finally
                {
                    // we dont wanna persist the key
                    theRsaEncrypt.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Decrypt message using the private key
        /// </summary>
        /// <param name="messageToDecrypt"></param>
        /// <returns></returns>
        public static string DecryptMessage(string messageToDecrypt)
        {
            var thePrivateKey = theCryptoServiceProvider.ExportParameters(true); //get the public key
            var thePrivateKeyAsString = GetKeyString(thePrivateKey); // parsing the key in a string

            var bytesToDescrypt = Encoding.UTF8.GetBytes(messageToDecrypt);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    // server decrypting data with private key                    
                    rsa.FromXmlString(thePrivateKeyAsString);

                    var resultBytes = Convert.FromBase64String(messageToDecrypt);
                    var decryptedBytes = rsa.Decrypt(resultBytes, true);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData.ToString();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
        /// <summary>
        /// Serialize the RSA key in a string
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string GetKeyString(RSAParameters publicKey)
        {
            using (var stringWriter = new System.IO.StringWriter())
            {
                var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                xmlSerializer.Serialize(stringWriter, publicKey);
                return stringWriter.ToString();
            }
        }

        /// <summary>
        /// Get the client public key
        /// </summary>
        /// <returns></returns>
        public static string GetClientPublicKey()
        {
            var thePublicKey = theCryptoServiceProvider.ExportParameters(false); //get the public key
            var thePublicKeyAsString = GetKeyString(thePublicKey); // parsing the key in a string

            return thePublicKeyAsString;
        }


        public class RsaMessage
        {
            public DateTime UpdateDate { get; set; }
            public string ClientName { get; set; }
            public string Message { get; set; }
        }

        public class RsaPublicKey
        {
            public string ClientName { get; set; }
            public string PublicKey { get; set; }
        }
    }
}
