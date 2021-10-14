using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class DerGeneralString
        : DerStringBase
    {
        private readonly string str;

        public static DerGeneralString GetInstance(
            object obj)
        {
            if (obj == null || obj is DerGeneralString)
            {
                return (DerGeneralString) obj;
            }

			throw new ArgumentException("illegal object in GetInstance: "
                    + Platform.GetTypeName(obj));
        }

        public static DerGeneralString GetInstance(
            Asn1TaggedObject	obj,
            bool				isExplicit)
        {
			Asn1Object o = obj.GetObject();

			if (isExplicit || o is DerGeneralString)
			{
				return GetInstance(o);
			}

			return new DerGeneralString(((Asn1OctetString)o).GetOctets());
        }

        public DerGeneralString(
			byte[] str)
			: this(Strings.FromAsciiByteArray(str))
        {
        }

		public DerGeneralString(
			string str)
        {
			if (str == null)
				throw new ArgumentNullException("str");

			this.str = str;
        }

        public override string GetString()
        {
            return str;
        }

		public byte[] GetOctets()
        {
            return Strings.ToAsciiByteArray(str);
        }

        internal override int EncodedLength(bool withID)
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(withID, str.Length);
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            asn1Out.WriteEncodingDL(withID, Asn1Tags.GeneralString, GetOctets());
        }

		protected override bool Asn1Equals(
			Asn1Object asn1Object)
        {
			DerGeneralString other = asn1Object as DerGeneralString;

			if (other == null)
				return false;

			return this.str.Equals(other.str);
        }
    }
}
