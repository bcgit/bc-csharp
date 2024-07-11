using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Smime;
using Org.BouncyCastle.Asn1.X509;
using CertStatus = Org.BouncyCastle.Asn1.Ocsp.CertStatus;

namespace Org.BouncyCastle.asn1.dvcs
{ 
    
/**
* <pre>
* CertEtcToken ::= CHOICE {
*         certificate                  [0] IMPLICIT Certificate ,
*         esscertid                    [1] ESSCertId ,
*         pkistatus                    [2] IMPLICIT PKIStatusInfo ,
*         assertion                    [3] ContentInfo ,
*         crl                          [4] IMPLICIT CertificateList,
*         ocspcertstatus               [5] CertStatus,
*         oscpcertid                   [6] IMPLICIT CertId ,
*         oscpresponse                 [7] IMPLICIT OCSPResponse,
*         capabilities                 [8] SMIMECapabilities,
*         extension                    Extension
* }
* </pre>
*/
    public class CertEtcToken : Asn1Object, IAsn1Choice
    {
        public const int TAG_CERTIFICATE = 0;
        public const int TAG_ESSCERTID = 1;
        public const int TAG_ASSERTION = 3;
        public const int TAG_CRL = 4;
        public const int TAG_PKISTATUS = 2;
        public const int TAG_OCSPCERTSTATUS = 5;
        public const int TAG_OCSPCERTID = 6;
        public const int TAG_OCSPRESPONSE = 7;
        public const int TAG_CAPABILITIES = 8;

        public static readonly bool[] explicits =
        {
            false, true, false, true, false, true, false, false, true
        };

        private int tagNo;
        private Asn1Encodable value;
        private X509Extensions extension;

        public CertEtcToken(int tagNo, Asn1Encodable value)
        {
            this.tagNo = tagNo;
            this.value = value;
        }

        public CertEtcToken(X509Extensions extension)
        {
            this.tagNo = -1;
            this.extension = extension;
        }

        private CertEtcToken(Asn1TaggedObject choice)
        {
            this.tagNo = choice.TagNo;

            switch (tagNo)
            {
                case TAG_CERTIFICATE:
                    value = X509CertificateStructure.GetInstance(choice, false);
                    break;
                case TAG_ESSCERTID:
                    value = EssCertID.GetInstance(choice.GetExplicitBaseObject());
                    break;
                case TAG_PKISTATUS:
                    value = PkiStatusInfo.GetInstance(choice, false);
                    break;
                case TAG_ASSERTION:
                    value = ContentInfo.GetInstance(choice.GetExplicitBaseObject());
                    break;
                case TAG_CRL:
                    value = CertificateList.GetInstance(choice, false);
                    break;
                case TAG_OCSPCERTSTATUS:
                    value = CertStatus.GetInstance(choice.GetExplicitBaseObject());
                    break;
                case TAG_OCSPCERTID:
                    value = CertID.GetInstance(choice, false);
                    break;
                case TAG_OCSPRESPONSE:
                    value = OcspResponse.GetInstance(choice, false);
                    break;
                case TAG_CAPABILITIES:
                    value = SmimeCapabilities.GetInstance(choice.GetExplicitBaseObject());
                    break;
                default:
                    throw new ArgumentException("Unknown tag: " + tagNo);
            }
        }
        public static CertEtcToken GetInstance(Object obj)
        {
            if (obj is CertEtcToken)
            {
                return (CertEtcToken)obj;
            }
            else if (obj is Asn1TaggedObject)
            {
                return new CertEtcToken(Asn1TaggedObject.GetInstance(obj,Asn1Tags.ContextSpecific));
            }
            else if (obj != null)
            {
                return new CertEtcToken(X509Extensions.GetInstance(obj));
            }

            return null;
        }
        public static CertEtcToken[] ArrayFromSequence(Asn1Sequence seq)
        {
            CertEtcToken[] tmp = new CertEtcToken[seq.Count];

            for (int i = 0; i != tmp.Length; i++)
            {
                tmp[i] = CertEtcToken.GetInstance(seq[i]);
            }

            return tmp;
        }


        public Asn1Object ToASN1Primitive()
        {
            if (extension == null)
            {
                return new DerTaggedObject(explicits[tagNo], tagNo, value);
            }
            else
            {
                return extension.ToAsn1Object();
            }
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
           return  ToASN1Primitive().CallAsn1Equals(asn1Object);
        }

        protected override int Asn1GetHashCode()
        {
            return ToASN1Primitive().GetHashCode();
        }

        public override string ToString()
        {
            return "CertEtcToken {\n" + value + "}\n";
        }
    }
}
