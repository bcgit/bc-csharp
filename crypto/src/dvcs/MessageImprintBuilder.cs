using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;

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
                var digestoid = DigestUtilities.GetObjectIdentifier(digestCalculator.AlgorithmName);
               
                digestCalculator.BlockUpdate(message, 0, message.Length);
                byte[] result = new byte[digestCalculator.GetDigestSize()];

                digestCalculator.DoFinal(result, 0);
                return new MessageImprint(new DigestInfo(new AlgorithmIdentifier(digestoid), result));
            }
            catch (Exception e)
            {
                throw new DVCSException("unable to build MessageImprint: " + e.Message, e);
            }

            return null;
        }
    }
}
