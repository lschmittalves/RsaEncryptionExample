using Microsoft.VisualBasic;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
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
        static string SERVER_ENDPOINT = @"http://localhost:5050";
        static readonly HttpClient theWebClient = new HttpClient();
        static readonly RSACryptoServiceProvider theCryptoServiceProvider = new RSACryptoServiceProvider(2048);

        static async Task Main()
        {

            // control flag to stop the program execution
            var stopExecution = false;

            // initialize the web client base address
            theWebClient.BaseAddress = new Uri(SERVER_ENDPOINT);

            do
            {
                try
                {
                    Console.WriteLine("Press any key to check for new messages, or write 'exit' to stop the program");
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

                        // then clear all the messages from the server because the client processed all of them
                        await ClearAllTheMessages();
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
        /// Clear all the messages of the client 
        /// </summary>
        /// <param name="theEncryptMessage"></param>
        /// <param name="theHttpResponseCode"></param>
        /// <returns></returns>
        private async static Task ClearAllTheMessages()
        {
            var theJsonMessage = new
            {
                ClientName = Environment.MachineName,
                Message = EncryptMessage("**CLEAR_MESSAGES**") // generate the clear messages command
            };

            using (HttpResponseMessage response = await theWebClient.PostAsJsonAsync(@"message/clear", theJsonMessage))
            {
                response.EnsureSuccessStatusCode(); // throw a exeption if something is not right on the response
            }
        }

        /// <summary>
        /// Encrypt the mssage using the RSA public key
        /// </summary>
        /// <param name="theMessage"></param>
        /// <returns></returns>
        private static string EncryptMessage(string theMessage)
        {
            var thePublicKey = theCryptoServiceProvider.ExportParameters(false); //get the public key
            var thePublicKeyAsString = GetKeyString(thePublicKey); // parsing the key in a string

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





        public class RsaMessage
        {
            public DateTime UpdateDate { get; set; }
            public string ClientName { get; set; }
            public string Message { get; set; }
        }
    }
}
