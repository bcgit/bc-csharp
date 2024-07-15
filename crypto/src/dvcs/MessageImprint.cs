using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.dvcs
{
    public class MessageImprint
    {
        private readonly DigestInfo messageImprint;

        public MessageImprint(DigestInfo messageImprint)
        {
            this.messageImprint = messageImprint;
        }

        public DigestInfo ToASN1Structure()
        {
            return messageImprint;
        }

        public override bool Equals(object o)
        {
            if (o == this)
            {
                return true;
            }

            if (o is MessageImprint)
            {
                return messageImprint.Equals(((MessageImprint)o).messageImprint);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return messageImprint.GetHashCode();
        }
    }
}
