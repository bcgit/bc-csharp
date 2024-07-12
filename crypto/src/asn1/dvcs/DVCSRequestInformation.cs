using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.asn1.dvcs
{
    /**
   * <pre>
   *     DVCSRequestInformation ::= SEQUENCE  {
   *         version                      INTEGER DEFAULT 1 ,
   *         service                      ServiceType,
   *         nonce                        Nonce OPTIONAL,
   *         requestTime                  DVCSTime OPTIONAL,
   *         requester                    [0] GeneralNames OPTIONAL,
   *         requestPolicy                [1] PolicyInformation OPTIONAL,
   *         dvcs                         [2] GeneralNames OPTIONAL,
   *         dataLocations                [3] GeneralNames OPTIONAL,
   *         extensions                   [4] IMPLICIT Extensions OPTIONAL
   *     }
   * </pre>
   */
    public class DVCSRequestInformation : Asn1Object
    {
        private const int DEFAULT_VERSION = 1;
        private const int TAG_REQUESTER = 0;
        private const int TAG_REQUEST_POLICY = 1;
        private const int TAG_DVCS = 2;
        private const int TAG_DATA_LOCATIONS = 3;
        private const int TAG_EXTENSIONS = 4;

        private int version = DEFAULT_VERSION;
        private ServiceType service;
        private BigInteger nonce;
        private DVCSTime requestTime;
        private GeneralNames requester;
        private PolicyInformation requestPolicy;
        private GeneralNames dvcs;
        private GeneralNames dataLocations;
        private X509Extensions extensions;


        private DVCSRequestInformation(Asn1Sequence seq)
        {
            int i = 0;

            if (seq[0] is DerInteger)
            {
                DerInteger encVersion = DerInteger.GetInstance(seq[i++]);
                this.version = encVersion.IntValueExact;
            }
            else
            {
                this.version = 1;
            }

            this.service = ServiceType.GetInstance(seq[i++]);

            while (i < seq.Count)
            {
                Asn1Encodable x = seq[i];

                if (x is DerInteger)
                {
                    this.nonce = DerInteger.GetInstance(x).Value;
                }
                else if (x is Asn1GeneralizedTime)
                {
                    this.requestTime = DVCSTime.GetInstance(x);
                }
                else if (x is Asn1TaggedObject)
                {
                    Asn1TaggedObject t = Asn1TaggedObject.GetInstance(x);
                    int tagNo = t.TagNo;

                    switch (tagNo)
                    {
                        case TAG_REQUESTER:
                            this.requester = GeneralNames.GetInstance(t, false);
                            break;
                        case TAG_REQUEST_POLICY:
                            this.requestPolicy = PolicyInformation.GetInstance(Asn1Sequence.GetInstance(t, false));
                            break;
                        case TAG_DVCS:
                            this.dvcs = GeneralNames.GetInstance(t, false);
                            break;
                        case TAG_DATA_LOCATIONS:
                            this.dataLocations = GeneralNames.GetInstance(t, false);
                            break;
                        case TAG_EXTENSIONS:
                            this.extensions = X509Extensions.GetInstance(t, false);
                            break;
                        default:
                            throw new ArgumentException("unknown tag number encountered: " + tagNo);
                    }
                }
                else
                {
                    this.requestTime = DVCSTime.GetInstance(x);
                }

                i++;
            }
        }

        public static DVCSRequestInformation GetInstance(Object obj)
        {
            if (obj is DVCSRequestInformation)
            {
                return (DVCSRequestInformation)obj;
            }
            else if (obj != null)
            {
                return new DVCSRequestInformation(Asn1Sequence.GetInstance(obj));
            }

            return null;
        }

        public static DVCSRequestInformation GetInstance(
            Asn1TaggedObject obj,
            bool expl)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, expl));
        }

        public Asn1Object ToASN1Primitive()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(9);

            if (version != DEFAULT_VERSION)
            {
                v.Add(new DerInteger(version));
            }
            v.Add(service);
            if (nonce != null)
            {
                v.Add(new DerInteger(nonce));
            }
            if (requestTime != null)
            {
                v.Add(requestTime);
            }

            int[] tags = new int[]{
                TAG_REQUESTER,
                TAG_REQUEST_POLICY,
                TAG_DVCS,
                TAG_DATA_LOCATIONS,
                TAG_EXTENSIONS
            };
            Asn1Encodable[] taggedObjects = new Asn1Encodable[]{
                requester,
                requestPolicy,
                dvcs,
                dataLocations,
                extensions
            };
            for (int i = 0; i < tags.Length; i++)
            {
                int tag = tags[i];
                Asn1Encodable taggedObject = taggedObjects[i];
                if (taggedObject != null)
                {
                    v.Add(new DerTaggedObject(false, tag, taggedObject));
                }
            }

            return new DerSequence(v);
        }


        public override string ToString()
        {

            StringBuilder s = new StringBuilder();

            s.Append("DVCSRequestInformation {\n");

            if (version != DEFAULT_VERSION)
            {
                s.Append("version: " + version + "\n");
            }
            s.Append("service: " + service + "\n");
            if (nonce != null)
            {
                s.Append("nonce: " + nonce + "\n");
            }
            if (requestTime != null)
            {
                s.Append("requestTime: " + requestTime + "\n");
            }
            if (requester != null)
            {
                s.Append("requester: " + requester + "\n");
            }
            if (requestPolicy != null)
            {
                s.Append("requestPolicy: " + requestPolicy + "\n");
            }
            if (dvcs != null)
            {
                s.Append("dvcs: " + dvcs + "\n");
            }
            if (dataLocations != null)
            {
                s.Append("dataLocations: " + dataLocations + "\n");
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


        public int GetVersion()
        {
            return version;
        }

        public ServiceType GetService()
        {
            return service;
        }

        public BigInteger GetNonce()
        {
            return nonce;
        }

        public DVCSTime GetRequestTime()
        {
            return requestTime;
        }

        public GeneralNames GetRequester()
        {
            return requester;
        }

        public PolicyInformation GetRequestPolicy()
        {
            return requestPolicy;
        }

        public GeneralNames GetDVCS()
        {
            return dvcs;
        }

        public GeneralNames GetDataLocations()
        {
            return dataLocations;
        }

        public X509Extensions GetExtensions()
        {
            return extensions;
        }

    }
}
