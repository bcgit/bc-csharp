using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class OcspResponse
        : Asn1Encodable
    {
        public static OcspResponse GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OcspResponse ocspResponse)
				return ocspResponse;
            return new OcspResponse(Asn1Sequence.GetInstance(obj));
		}

        public static OcspResponse GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new OcspResponse(Asn1Sequence.GetInstance(obj, explicitly));

        public static OcspResponse GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspResponse(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly OcspResponseStatus m_responseStatus;
        private readonly ResponseBytes m_responseBytes;

        public OcspResponse(OcspResponseStatus responseStatus, ResponseBytes responseBytes)
        {
			m_responseStatus = responseStatus ?? throw new ArgumentNullException(nameof(responseStatus));
            m_responseBytes = responseBytes;
        }

        private OcspResponse(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_responseStatus = new OcspResponseStatus(DerEnumerated.GetInstance(seq[pos++]));
            m_responseBytes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, ResponseBytes.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public OcspResponseStatus ResponseStatus => m_responseStatus;

        public ResponseBytes ResponseBytes => m_responseBytes;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OcspResponse ::= Sequence {
         *     responseStatus         OcspResponseStatus,
         *     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_responseStatus);
            v.AddOptionalTagged(true, 0, m_responseBytes);
            return new DerSequence(v);
        }
    }
}
