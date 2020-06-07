using System;
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

            // hold the last input text by the user
            var lastInputLine = "";

            // initialize the web client base address
            theWebClient.BaseAddress = new Uri(SERVER_ENDPOINT);

            do
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(lastInputLine))
                    {
                        Console.WriteLine("Please, input the message to be send to the server.");
                    }
                    else
                    {
                        var theEncryptMessage = EncryptMessageUsingPrivateKey(lastInputLine);
                        Console.WriteLine($"RSA encrypt message {theEncryptMessage}");
                        Console.WriteLine($"Posting message to the Server...");


                        if (await PostEncryptMessage(theEncryptMessage))
                            Console.WriteLine($"Message successfully posted!");
                        else
                            Console.WriteLine($"Message posting failled");
                    }

                    lastInputLine = Console.ReadLine();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"ERROR -> {ex.Message}");
                }

            } while (lastInputLine.ToUpper() != "exit");


            Console.WriteLine("Hello World!");
        }

        /// <summary>
        /// Post the encrypt message to the webservice and catch the response
        /// </summary>
        /// <param name="theEncryptMessage"></param>
        /// <param name="theHttpResponseCode"></param>
        /// <returns></returns>
        private async static Task<bool> PostEncryptMessage(string theEncryptMessage)
        {
            using (HttpResponseMessage response = await theWebClient.PostAsync("Message", new StringContent(theEncryptMessage, Encoding.UTF8, "text/plain")))
            {
                return response.IsSuccessStatusCode;
            }
        }

        /// <summary>
        /// Encrypt the mssage using the RSA private key
        /// </summary>
        /// <param name="lastInputLine"></param>
        /// <returns></returns>
        private static string EncryptMessageUsingPrivateKey(string lastInputLine)
        {
            var thePrivateKey = theCryptoServiceProvider.ExportParameters(true); //get the private key
            var thePrivateKeyAsString = GetKeyString(thePrivateKey); // parsing the key in a string
            
            var bytesToEncrypt = Encoding.UTF8.GetBytes(lastInputLine);// encode the message with UTF8

            using (var theRsaEncrypt = new RSACryptoServiceProvider(2048)) 
            {
                try
                {
                    theRsaEncrypt.FromXmlString(thePrivateKeyAsString); // initializing the rsa with the serialized key
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
    }
}
