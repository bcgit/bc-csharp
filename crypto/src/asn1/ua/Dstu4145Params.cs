using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.UA
{
    public class Dstu4145Params
        : Asn1Encodable
    {
        private static readonly byte[] DefaultDke =
        {
            0xa9, 0xd6, 0xeb, 0x45, 0xf1, 0x3c, 0x70, 0x82,
            0x80, 0xc4, 0x96, 0x7b, 0x23, 0x1f, 0x5e, 0xad,
            0xf6, 0x58, 0xeb, 0xa4, 0xc0, 0x37, 0x29, 0x1d,
            0x38, 0xd9, 0x6b, 0xf0, 0x25, 0xca, 0x4e, 0x17,
            0xf8, 0xe9, 0x72, 0x0d, 0xc6, 0x15, 0xb4, 0x3a,
            0x28, 0x97, 0x5f, 0x0b, 0xc1, 0xde, 0xa3, 0x64,
            0x38, 0xb5, 0x64, 0xea, 0x2c, 0x17, 0x9f, 0xd0,
            0x12, 0x3e, 0x6d, 0xb8, 0xfa, 0xc5, 0x79, 0x04,
        };

        public static Asn1OctetString GetDefaultDke() => DerOctetString.FromContents(DefaultDke);

        public static Dstu4145Params GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Dstu4145Params dstu4145Params)
                return dstu4145Params;
            return new Dstu4145Params(Asn1Sequence.GetInstance(obj));
        }

        public static Dstu4145Params GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145Params(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Dstu4145Params GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Dstu4145Params dstu4145Params)
                return dstu4145Params;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new Dstu4145Params(asn1Sequence);

            return null;
        }

        public static Dstu4145Params GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145Params(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_namedCurve;
        private readonly Dstu4145ECBinary m_ecBinary;
        private readonly Asn1OctetString m_dke;

        public Dstu4145Params(DerObjectIdentifier namedCurve)
            : this(namedCurve, GetDefaultDke())
        {
        }

        public Dstu4145Params(DerObjectIdentifier namedCurve, Asn1OctetString dke)
        {
            if (dke.GetOctetsLength() != DefaultDke.Length)
                throw new ArgumentException("Invalid length for DKE octet string", nameof(dke));

            m_namedCurve = namedCurve;
            m_ecBinary = null;
            m_dke = dke;
        }

        public Dstu4145Params(Dstu4145ECBinary ecBinary)
        {
            m_namedCurve = null;
            m_ecBinary = ecBinary;
            m_dke = GetDefaultDke();
        }

        private Dstu4145Params(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            DerObjectIdentifier namedCurve = null;
            Dstu4145ECBinary ecBinary = null;
            Asn1OctetString dke = null;

            if (DerObjectIdentifier.GetOptional(seq[0]) is var oid)
            {
                namedCurve = oid;
            }
            else
            {
                ecBinary = Dstu4145ECBinary.GetInstance(seq[0]);
            }

            if (seq.Count > 1)
            {
                dke = Asn1OctetString.GetInstance(seq[1]);

                if (dke.GetOctetsLength() != DefaultDke.Length)
                    throw new ArgumentException("Invalid length for DKE octet string", nameof(seq));
            }

            m_namedCurve = namedCurve;
            m_ecBinary = ecBinary;
            m_dke = dke;
        }

        public bool IsNamedCurve => m_namedCurve != null;

        public Dstu4145ECBinary ECBinary => m_ecBinary;

        public Asn1OctetString Dke => m_dke;

        public DerObjectIdentifier NamedCurve => m_namedCurve;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);

            if (m_namedCurve != null)
            {
                v.Add(m_namedCurve);
            }
            else
            {
                v.Add(m_ecBinary);
            }

            if (!Arrays.AreEqual(m_dke.GetOctets(), DefaultDke))
            {
                v.Add(m_dke);
            }

            return new DerSequence(v);
        }
    }
}
