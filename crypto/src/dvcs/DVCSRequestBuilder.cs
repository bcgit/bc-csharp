using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.dvcs
{
    public abstract class DVCSRequestBuilder
    {
        private readonly X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();
        private readonly CmsSignedDataGenerator signedDataGen = new CmsSignedDataGenerator();


        protected readonly DVCSRequestInformationBuilder requestInformationBuilder;


        protected DVCSRequestBuilder(DVCSRequestInformationBuilder requestInformationBuilder)
        {
            this.requestInformationBuilder = requestInformationBuilder;
        }

        public void SetNonce(BigInteger nonce)
        {
            requestInformationBuilder.Nonce = nonce;
        }

        public void SetRequester(GeneralName requester)
        {
            requestInformationBuilder.SetRequestor(requester);
        }

        public void SetDVCS(GeneralName dvcs)
        {
            requestInformationBuilder.SetDvcs(dvcs);
        }
        public void SetDVCS(GeneralNames dvcs)
        {
            requestInformationBuilder.SetDvcs(dvcs);
        }


        public void SetDataLocations(GeneralName dataLocation)
        {
            requestInformationBuilder.SetDataLocations(dataLocation);
        }

        public void SetDataLocations(GeneralNames dataLocation)
        {
            requestInformationBuilder.SetDataLocations(dataLocation);
        }

        public void AddExtension(
            DerObjectIdentifier oid,
            bool isCritical,
            Asn1Encodable value)

        {
            try
            {
                extGenerator.AddExtension(oid, isCritical, value);
            }
            catch (IOException e)
            {
                throw new DVCSException("cannot encode extension: " + e.Message, e);
            }
        }

        protected DVCSRequest CreateDVCRequest(Data data)

        {
            if (!extGenerator.IsEmpty)
            {
                requestInformationBuilder.Extensions = extGenerator.Generate();
            }

            Org.BouncyCastle.asn1.dvcs.DVCSRequest request = new Org.BouncyCastle.asn1.dvcs.DVCSRequest(requestInformationBuilder.Build(), data);

            return new DVCSRequest(new ContentInfo(DVCSObjectIdentifiers.id_ct_DVCSRequestData, request));
        }

    }
}
