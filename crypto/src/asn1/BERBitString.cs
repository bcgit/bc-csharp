using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class BerBitString
        : DerBitString
    {
        public BerBitString(byte[] data, int padBits)
            : base(data, padBits)
		{
		}

		public BerBitString(byte[] data)
            : base(data)
		{
		}

        public BerBitString(int namedBits)
            : base(namedBits)
        {
        }

        public BerBitString(Asn1Encodable obj)
            : base(obj)
		{
		}

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (asn1Out.IsBer)
            {
                asn1Out.WriteEncodingDL(withID, Asn1Tags.BitString, (byte)mPadBits, mData, 0, mData.Length);
            }
            else
            {
                base.Encode(asn1Out, withID);
            }
        }
    }
}
