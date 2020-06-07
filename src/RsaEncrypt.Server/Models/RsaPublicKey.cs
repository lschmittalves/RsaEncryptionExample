using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RsaEncrypt.Server.Models
{
    public class RsaPublicKey
    {
        public string ClientName { get; set; }
        public string PublicKey { get; set; }
    }
}
