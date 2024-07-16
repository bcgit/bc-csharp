using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;

namespace Org.BouncyCastle.dvcs
{
    public class MessageImprintBuilder
    {

        private readonly IDigest digestCalculator;


        public MessageImprintBuilder(IDigest calculator)
        {
            this.digestCalculator = calculator;
        }

        public MessageImprint Build(byte[] message)

        {
            try
            {
                //Stream dOut = digestCalculator.get;

                //dOut.Write(message);

                //dOut.Close();

                //return new MessageImprint(new DigestInfo(digestCalculator., digestCalculator.getDigest()));
            }
            catch (Exception e)
            {
                throw new DVCSException("unable to build MessageImprint: " + e.getMessage(), e);
            }
        }
    }
}
