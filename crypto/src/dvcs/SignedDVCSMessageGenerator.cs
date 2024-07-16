using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;

namespace Org.BouncyCastle.dvcs
{
    public class SignedDVCSMessageGenerator
    {
        private readonly CmsSignedDataGenerator signedDataGen;


        public SignedDVCSMessageGenerator(CmsSignedDataGenerator signedDataGen)
        {
            this.signedDataGen = signedDataGen;
        }

        public CmsSignedData Build(DVCSMessage message)

        {
            try
            {
                byte[] encapsulatedData = message.GetContent().ToAsn1Object().GetEncoded(Asn1Encodable.Der);

                return signedDataGen.Generate(new CmsProcessableByteArray(message.ContentType, encapsulatedData), true);
            }
            catch (CmsException e)
            {
                throw new DVCSException("Could not sign DVCS request", e);
            }
            catch (IOException e)
            {
                throw new DVCSException("Could not encode DVCS request", e);
            }
        }
    }
}
