using System;

using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Asn1.UA
{
    public class Dstu4145PublicKey
        : Asn1Encodable
    {
        public static Dstu4145PublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Dstu4145PublicKey dstu4145PublicKey)
                return dstu4145PublicKey;
            return new Dstu4145PublicKey(Asn1OctetString.GetInstance(obj));
        }

        public static Dstu4145PublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145PublicKey(Asn1OctetString.GetInstance(taggedObject, declaredExplicit));

        public static Dstu4145PublicKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Dstu4145PublicKey dstu4145PublicKey)
                return dstu4145PublicKey;

            Asn1OctetString asn1OctetString = Asn1OctetString.GetOptional(element);
            if (asn1OctetString != null)
                return new Dstu4145PublicKey(asn1OctetString);

            return null;
        }

        public static Dstu4145PublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145PublicKey(Asn1OctetString.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_pubKey;

        public Dstu4145PublicKey(ECPoint pubKey)
        {
            // We always use big-endian in parameter encoding
            m_pubKey = new DerOctetString(Dstu4145PointEncoder.EncodePoint(pubKey));
        }

        private Dstu4145PublicKey(Asn1OctetString pubKey)
        {
            m_pubKey = pubKey;
        }

        public override Asn1Object ToAsn1Object() => m_pubKey;
    }
}
