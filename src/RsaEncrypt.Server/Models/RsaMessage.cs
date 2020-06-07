using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RsaEncrypt.Server.Models
{
    public class RsaMessage
    {
        public DateTime UpdateDate { get; set; }
        public string ClientName {get;set;}
        public string Message { get; set; }
    }
}
