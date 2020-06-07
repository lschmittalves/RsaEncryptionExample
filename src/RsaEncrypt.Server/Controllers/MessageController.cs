using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using RsaEncrypt.Server.Models;

namespace RsaEncrypt.Server.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class MessageController : ControllerBase
    {
        private readonly IDictionary<string, string> publicKeysByClient;
        private readonly IDictionary<string, List<RsaMessage>> messagesByClient;
        private readonly ILogger<MessageController> logger;
        private readonly RSACryptoServiceProvider theCryptoServiceProvider;

        public MessageController(ILogger<MessageController> logger, RSACryptoServiceProvider theCryptoServiceProvider)
        {
            this.logger = logger;
            this.theCryptoServiceProvider = theCryptoServiceProvider;

            // initialize the dictionary of public keys using the server name and key
            this.publicKeysByClient = new Dictionary<string, string>() { { Environment.MachineName, GetLocalServerPublicKey() } };
            this.messagesByClient = new Dictionary<string, List<RsaMessage>>();

        }

        /// <summary>
        /// get the crypt message of the client sent as parameter
        /// </summary>
        /// <param name="theClientName"></param>
        /// <returns></returns>
        [HttpGet("[controller]/{theClientName}")]
        public IActionResult Get(string theClientName)
        {
            if (messagesByClient.ContainsKey(theClientName))
                return Ok(messagesByClient[theClientName]);

            return Unauthorized(); // the client is not regiter on the server, so we return an unautorized status code
        }


        /// <summary>
        /// Receives and store a new message to one of the client
        /// </summary>
        /// <param name="theMessage"></param>
        /// <returns></returns>
        [HttpPost("[controller]/add")]
        public IActionResult AddMessage([FromBody] RsaMessage theMessage)
        {

            if (theMessage == null)
                throw new ArgumentNullException(nameof(theMessage));

            if (!publicKeysByClient.ContainsKey(theMessage.ClientName)) // the client is not regiter on the server, so we return an unautorized status code
                return Unauthorized();


            if (!messagesByClient.ContainsKey(theMessage.ClientName))
                messagesByClient.Add(theMessage.ClientName, new List<RsaMessage>());

            // now we get the new message and encrypt the message
            theMessage.Message = EncryptMessage(theMessage.Message, publicKeysByClient[theMessage.ClientName]); // encrypt the message using the pre stored public key
            theMessage.UpdateDate = DateTime.UtcNow;

            // adding the message to the cache list
            messagesByClient[theMessage.ClientName].Add(theMessage);

            return Ok();
        }

        /// <summary>
        /// Clear all the messages of a client
        /// </summary>
        /// <param name="theMessage"></param>
        /// <returns></returns>
        [HttpPost("[controller]/clear")]
        public IActionResult ClearMessages([FromBody] RsaMessage theMessage)
        {

            if (theMessage == null)
                throw new ArgumentNullException(nameof(theMessage));

            if (!publicKeysByClient.ContainsKey(theMessage.ClientName)) // the client is not regiter on the server, so we return an unautorized status code
                return Unauthorized();

            if (!messagesByClient.ContainsKey(theMessage.ClientName))
                messagesByClient.Add(theMessage.ClientName, new List<RsaMessage>());

            // we generate a encrypt the command clear using the client public key
            var theCommandClear = EncryptMessage("**CLEAR_MESSAGES**", publicKeysByClient[theMessage.ClientName]);

            // now we compare the received message with the encryp message, if we have a match means that both messages were generate using the same public key

            if (theCommandClear == theMessage.Message)
                messagesByClient[theMessage.ClientName].Clear();  // clear all the messages
            else
                Unauthorized(); // if not we returnt he unauthorized status code

            return Ok();
        }

        /// <summary>
        /// Encrypt the mssage using the RSA public key
        /// </summary>
        /// <param name="lastInputLine"></param>
        /// <returns></returns>
        private static string EncryptMessage(string lastInputLine, string theClientPublicKeyAsString)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(lastInputLine);// encode the message with UTF8

            using (var theRsaEncrypt = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    theRsaEncrypt.FromXmlString(theClientPublicKeyAsString); // initializing the rsa with the serialized key
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
        /// Get the server public key
        /// </summary>
        /// <returns></returns>
        public string GetLocalServerPublicKey()
        {
            var thePublicKey = theCryptoServiceProvider.ExportParameters(false); //get the public key
            var thePublicKeyAsString = GetKeyString(thePublicKey); // parsing the key in a string

            return thePublicKeyAsString;
        }

        /// <summary>
        /// Serialize the RSA key in a string
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public string GetKeyString(RSAParameters publicKey)
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
