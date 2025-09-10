using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class ResponseBytes
        : Asn1Encodable
    {
        public static ResponseBytes GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ResponseBytes responseBytes)
                return responseBytes;
            return new ResponseBytes(Asn1Sequence.GetInstance(obj));
        }

        public static ResponseBytes GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new ResponseBytes(Asn1Sequence.GetInstance(obj, explicitly));

        public static ResponseBytes GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is ResponseBytes responseBytes)
                return responseBytes;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new ResponseBytes(asn1Sequence);

            return null;
        }

        public static ResponseBytes GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ResponseBytes(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_responseType;
        private readonly Asn1OctetString m_response;

        public ResponseBytes(DerObjectIdentifier responseType, Asn1OctetString response)
        {
            m_responseType = responseType ?? throw new ArgumentNullException(nameof(responseType));
            m_response = response ?? throw new ArgumentNullException(nameof(response));
        }

        private ResponseBytes(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_responseType = DerObjectIdentifier.GetInstance(seq[0]);
            m_response = Asn1OctetString.GetInstance(seq[1]);
        }

        public DerObjectIdentifier ResponseType => m_responseType;

        public Asn1OctetString Response => m_response;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * ResponseBytes ::=       Sequence {
         *     responseType   OBJECT IDENTIFIER,
         *     response       OCTET STRING }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_responseType, m_response);
    }
}
