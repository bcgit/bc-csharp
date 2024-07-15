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
    public class DVCSCertInfo : Asn1Object
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
            get { return messageImprint; }
            set { messageImprint = value; }
        }

        public DerInteger SerialNumber
        {
            get { return serialNumber; }
           
        }

        public DVCSTime ResponseTime
        {
            get { return responseTime; }
            
        }

        public PkiStatusInfo DvStatus
        {
            get { return dvStatus; }
         
        }

        public PolicyInformation Policy
        {
            get { return policy; }
          
        }

        public Asn1Set RequestSignature
        {
            get { return reqSignature; }
          
        }


        public TargetEtcChain[] Certs
        {
            get
            {
                if (certs != null)
                {
                    return TargetEtcChain.ArrayFromSequence(certs);
                }
                return null;
            }
        }

        public X509Extensions Extensions
        {
            get { return extensions; }
          
        }


        public DVCSCertInfo(
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

        private DVCSCertInfo(Asn1Sequence seq)
        {
            int i = 0;
            Asn1Encodable x = seq[i++];
            try
            {
                DerInteger encVersion = DerInteger.GetInstance(x);
                this.version = encVersion.IntValueExact;
                x = seq[i++];
            }
            catch (ArgumentException e)
            {
            }

            this.dvReqInfo = DVCSRequestInformation.GetInstance(x);
            x = seq[i++];
            this.messageImprint = DigestInfo.GetInstance(x);
            x = seq[i++];
            this.serialNumber = DerInteger.GetInstance(x);
            x = seq[i++];
            this.responseTime = DVCSTime.GetInstance(x);

            while (i < seq.Count)
            {

                x = seq[i++];

                if (x is Asn1TaggedObject)
                {
                    Asn1TaggedObject t = Asn1TaggedObject.GetInstance(x);
                    int tagNo = t.TagNo;

                    switch (tagNo)
                    {
                        case TAG_DV_STATUS:
                            this.dvStatus = PkiStatusInfo.GetInstance(t, false);
                            break;
                        case TAG_POLICY:
                            this.policy = PolicyInformation.GetInstance(Asn1Sequence.GetInstance(t, false));
                            break;
                        case TAG_REQ_SIGNATURE:
                            this.reqSignature = Asn1Set.GetInstance(t, false);
                            break;
                        case TAG_CERTS:
                            this.certs = Asn1Sequence.GetInstance(t, false);
                            break;
                        default:
                            throw new ArgumentException("Unknown tag encountered: " + tagNo);
                    }

                    continue;
                }

                try
                {
                    this.extensions = X509Extensions.GetInstance(x);
                }
                catch (ArgumentException e)
                {
                }

            }

        }

        public static DVCSCertInfo GetInstance(Object obj)
        {
            if (obj is DVCSCertInfo)
            {
                return (DVCSCertInfo)obj;
            }
            else if (obj != null)
            {
                return new DVCSCertInfo(Asn1Sequence.GetInstance(obj));
            }

            return null;
        }

        public static DVCSCertInfo GetInstance(
            Asn1TaggedObject obj,
            bool expl)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, expl));
        }

        public Asn1Object ToASN1Primitive()
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

            return new DerSequence(v);
        }

        public override string ToString()
        {
            StringBuilder s = new StringBuilder();

            s.Append("DVCSCertInfo {\n");

            if (version != DEFAULT_VERSION)
            {
                s.Append("version: " + version + "\n");
            }
            s.Append("dvReqInfo: " + dvReqInfo + "\n");
            s.Append("messageImprint: " + messageImprint + "\n");
            s.Append("serialNumber: " + serialNumber + "\n");
            s.Append("responseTime: " + responseTime + "\n");
            if (dvStatus != null)
            {
                s.Append("dvStatus: " + dvStatus + "\n");
            }
            if (policy != null)
            {
                s.Append("policy: " + policy + "\n");
            }
            if (reqSignature != null)
            {
                s.Append("reqSignature: " + reqSignature + "\n");
            }
            if (certs != null)
            {
                s.Append("certs: " + certs + "\n");
            }
            if (extensions != null)
            {
                s.Append("extensions: " + extensions + "\n");
            }

            s.Append("}\n");
            return s.ToString();
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return ToASN1Primitive().GetEncoding(encoding);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return ToASN1Primitive().GetEncodingImplicit(encoding, tagClass, tagNo); 
        }

        internal override DerEncoding GetEncodingDer()
        {
            return ToASN1Primitive().GetEncodingDer(); 
        }

        internal override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return ToASN1Primitive().GetEncodingDerImplicit(tagClass, tagNo); 
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return ToASN1Primitive().CallAsn1Equals(asn1Object); 
        }

        protected override int Asn1GetHashCode()
        {
            return ToASN1Primitive().CallAsn1GetHashCode(); 
        }
    }
}
