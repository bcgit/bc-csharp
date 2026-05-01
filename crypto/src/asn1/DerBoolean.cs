using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class DerBoolean
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerBoolean), Asn1Tags.Boolean) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

        public static readonly DerBoolean False = new DerBoolean(0x00);
        public static readonly DerBoolean True = new DerBoolean(0xFF);

        public static DerBoolean FromContents(byte contents) => CreatePrimitive(contents);

        public static DerBoolean FromContents(byte[] contents) =>
            CreatePrimitive(contents ?? throw new ArgumentNullException(nameof(contents)));

        public static DerBoolean GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerBoolean derBoolean)
                return derBoolean;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerBoolean converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerBoolean)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct boolean from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj));
        }

        public static DerBoolean GetInstance(bool value) => value ? True : False;

        public static DerBoolean GetInstance(int value) => value != 0 ? True : False;

        public static DerBoolean GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            (DerBoolean)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);

        public static DerBoolean GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerBoolean existing)
                return existing;

            return null;
        }

        public static DerBoolean GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            (DerBoolean)Meta.Instance.GetTagged(taggedObject, declaredExplicit);

        private readonly byte m_contents;

        private DerBoolean(byte contents)
        {
            m_contents = contents;
        }

        [Obsolete("Use 'FromContents(byte[])' instead")]
        public DerBoolean(byte[] val)
        {
            if (val == null)
                throw new ArgumentNullException(nameof(val));

            CheckContentsLength(val.Length);

            m_contents = val[0];
        }

        public bool IsFalse => m_contents == 0x00;

        public bool IsTrue => m_contents != 0x00;

        internal override IAsn1Encoding GetEncoding(int encoding) =>
            new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.Boolean, GetContents(encoding));

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo) =>
            new PrimitiveEncoding(tagClass, tagNo, GetContents(encoding));

        internal sealed override DerEncoding GetEncodingDer() =>
            new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.Boolean, GetContents(Asn1OutputStream.EncodingDer));

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo) =>
            new PrimitiveDerEncoding(tagClass, tagNo, GetContents(Asn1OutputStream.EncodingDer));

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return asn1Object is DerBoolean that
                && this.IsTrue == that.IsTrue;
        }

        protected override int Asn1GetHashCode() => IsTrue.GetHashCode();

        public override string ToString() => IsTrue ? "TRUE" : "FALSE";

        internal static void CheckContentsLength(int contentsLength)
        {
            if (contentsLength != 1)
                throw new ArgumentException("BOOLEAN value should have 1 byte in it", nameof(contentsLength));
        }

        internal static DerBoolean CreatePrimitive(DefiniteLengthInputStream defIn)
        {
            CheckContentsLength(defIn.Remaining);
            return CreatePrimitive(Convert.ToByte(defIn.ReadByte()));
        }

        private static DerBoolean CreatePrimitive(byte[] contents)
        {
            CheckContentsLength(contents.Length);
            return CreatePrimitive(contents[0]);
        }

        private static DerBoolean CreatePrimitive(byte b) => b == 0x00 ? False : b == 0xFF ? True : new DerBoolean(b);

        private byte[] GetContents(int encoding)
        {
            byte contents = m_contents;
            if (Asn1OutputStream.EncodingDer == encoding && IsTrue)
            {
                contents = 0xFF;
            }

            return new byte[]{ contents };
        }
    }
}
