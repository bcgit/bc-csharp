using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class CertReqMessages
        : Asn1Encodable
    {
        private readonly Asn1Sequence content;

        private CertReqMessages(Asn1Sequence seq)
        {
            content = seq;
        }

        public static CertReqMessages GetInstance(object obj)
        {
            if (obj is CertReqMessages)
                return (CertReqMessages)obj;

            if (obj is Asn1Sequence)
                return new CertReqMessages((Asn1Sequence)obj);

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), "obj");
        }

		public CertReqMessages(params CertReqMsg[] msgs)
        {
            content = new DerSequence(msgs);
        }

        public virtual CertReqMsg[] ToCertReqMsgArray()
        {
            return content.MapElements(CertReqMsg.GetInstance);
        }

        /**
         * <pre>
         * CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            return content;
        }
    }
}
