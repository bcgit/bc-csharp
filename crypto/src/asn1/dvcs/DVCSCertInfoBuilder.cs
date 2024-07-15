using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.asn1.dvcs
{
 /**
 * <pre>
 *     DVCSCertInfo::= SEQUENCE  {
 *         version             Integer DEFAULT 1 ,
 *         dvReqInfo           DVCSRequestInformation,
 *         messageImprint      DigestInfo,
 *         serialNumber        Integer,
 *         responseTime        DVCSTime,
 *         dvStatus            [0] PKIStatusInfo OPTIONAL,
 *         policy              [1] PolicyInformation OPTIONAL,
 *         reqSignature        [2] SignerInfos  OPTIONAL,
 *         certs               [3] SEQUENCE SIZE (1..MAX) OF
 *                                 TargetEtcChain OPTIONAL,
 *         extensions          Extensions OPTIONAL
 *     }
 * </pre>
 */
    public class DVCSCertInfoBuilder 
    {
        private const int DEFAULT_VERSION = 1;
        private const int TAG_DV_STATUS = 0;
        private const int TAG_POLICY = 1;
        private const int TAG_REQ_SIGNATURE = 2;
        private const int TAG_CERTS = 3;

        private int version = DEFAULT_VERSION;
        private DVCSRequestInformation dvReqInfo;
        private DigestInfo messageImprint;
        private DerInteger serialNumber;
        private DVCSTime responseTime;
        private PkiStatusInfo dvStatus;
        private PolicyInformation policy;
        private Asn1Set reqSignature;
        private Asn1Sequence certs;
        private X509Extensions extensions;


        public int Version
        {
            get { return version; }
            set { version = value; }
        }

        public DVCSRequestInformation DVReqInfo
        {
            get { return dvReqInfo; }
            set { dvReqInfo = value; }
        }


        public DigestInfo MessageImprint
        {
            get { return messageImprint;  }
            set { messageImprint = value; }
        }

        public DerInteger SerialNumber
        {
            get { return serialNumber; }
            set { serialNumber = value; }
        }

        public DVCSTime ResponseTime
        {
            get { return responseTime; }
            set { responseTime = value; }
        }

        public PkiStatusInfo DvStatus
        {
            get { return dvStatus; }
            set { dvStatus = value; }
        }

        public PolicyInformation Policy
        {
            get { return policy; }
            set { policy = value; }
        }

        public Asn1Set RequestSignature
        {
            get { return reqSignature; }
            set { reqSignature = value; }
        }


        public Asn1Sequence Certs
        {
            get { return certs; }
            set { certs = value; }
        }

        public X509Extensions Extensions
        {
            get { return extensions; }
            set { extensions = value; }
        }

        public DVCSCertInfoBuilder(
            DVCSRequestInformation dvReqInfo,
            DigestInfo messageImprint,
            DerInteger serialNumber,
            DVCSTime responseTime)
        {
            this.dvReqInfo = dvReqInfo;
            this.messageImprint = messageImprint;
            this.serialNumber = serialNumber;
            this.responseTime = responseTime;
        }


        public DVCSCertInfo Build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(10);

            if (version != DEFAULT_VERSION)
            {
                v.Add(new DerInteger(version));
            }
            v.Add(dvReqInfo);
            v.Add(messageImprint);
            v.Add(serialNumber);
            v.Add(responseTime);
            if (dvStatus != null)
            {
                v.Add(new DerTaggedObject(false, TAG_DV_STATUS, dvStatus));
            }
            if (policy != null)
            {
                v.Add(new DerTaggedObject(false, TAG_POLICY, policy));
            }
            if (reqSignature != null)
            {
                v.Add(new DerTaggedObject(false, TAG_REQ_SIGNATURE, reqSignature));
            }
            if (certs != null)
            {
                v.Add(new DerTaggedObject(false, TAG_CERTS, certs));
            }
            if (extensions != null)
            {
                v.Add(extensions);
            }

            return DVCSCertInfo.GetInstance(new DerSequence(v));
        }



    }
}
