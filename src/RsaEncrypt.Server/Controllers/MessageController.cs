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
        private static readonly IDictionary<string, RsaPublicKey> publicKeysByClient = new Dictionary<string, RsaPublicKey>();
        private static readonly IDictionary<string, List<RsaMessage>> messagesByClient = new Dictionary<string, List<RsaMessage>>();

        private readonly ILogger<MessageController> logger;
        private readonly RSACryptoServiceProvider theCryptoServiceProvider;

        public MessageController(ILogger<MessageController> logger, RSACryptoServiceProvider theCryptoServiceProvider)
        {
            this.logger = logger;
            this.theCryptoServiceProvider = theCryptoServiceProvider;

        }

        /// <summary>
        /// get the crypt message of the client sent as parameter
        /// </summary>
        /// <param name="theClientName"></param>
        /// <returns></returns>
        [HttpGet("{theClientName}")]
        public IActionResult Get(string theClientName)
        {
            if (!publicKeysByClient.ContainsKey(theClientName)) // the client is not regiter on the server, so we return an unautorized status code
                return Unauthorized();

            if (messagesByClient.ContainsKey(theClientName))
                return Ok(messagesByClient[theClientName]);

            return Ok();
        }

        /// <summary>
        /// Receives and store a new public key
        /// </summary>
        /// <param name="theMessage"></param>
        /// <returns></returns>
        [HttpPost("addkey")]
        public IActionResult AddPublicKey([FromBody] RsaPublicKey theRsaPublicKey)
        {

            if (theRsaPublicKey == null)
                throw new ArgumentNullException(nameof(theRsaPublicKey));

            // initialize the dictionary of public keys using the server name and key
            if (!publicKeysByClient.ContainsKey(theRsaPublicKey.ClientName))
                publicKeysByClient.Add(theRsaPublicKey.ClientName, theRsaPublicKey);
            else
                publicKeysByClient[theRsaPublicKey.ClientName] = theRsaPublicKey;

            return Ok($"Public Key added to the client {theRsaPublicKey.ClientName}!");
        }


        /// <summary>
        /// Receives and store a new message to one of the client
        /// </summary>
        /// <param name="theMessage"></param>
        /// <returns></returns>
        [HttpPost("add")]
        public IActionResult AddMessage([FromBody] RsaMessage theMessage)
        {

            if (theMessage == null)
                throw new ArgumentNullException(nameof(theMessage));

            if (!publicKeysByClient.ContainsKey(theMessage.ClientName)) // the client is not regiter on the server, so we return an unautorized status code
                return Unauthorized();


            if (!messagesByClient.ContainsKey(theMessage.ClientName))
                messagesByClient.Add(theMessage.ClientName, new List<RsaMessage>());

            // now we get the new message and encrypt the message
            theMessage.Message = EncryptMessage(theMessage.Message, publicKeysByClient[theMessage.ClientName].PublicKey); // encrypt the message using the pre stored public key
            theMessage.UpdateDate = DateTime.UtcNow;

            // adding the message to the cache list
            messagesByClient[theMessage.ClientName].Add(theMessage);

            return Ok($"Message Added to the client {theMessage.ClientName}!");
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


    }
}
