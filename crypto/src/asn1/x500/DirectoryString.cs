using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X500
{
    public class DirectoryString
		: Asn1Encodable, IAsn1Choice, IAsn1String
	{
		public static DirectoryString GetInstance(object obj)
		{
            if (obj == null)
                return null;

            if (obj is Asn1Encodable element)
            {
                var result = GetOptional(element);
                if (result != null)
                    return result;
            }

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static DirectoryString GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

        public static DirectoryString GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DirectoryString directoryString)
                return directoryString;

			var innerObject = GetOptionalInnerObject(element);
			if (innerObject != null)
				return new DirectoryString(innerObject);

			return null;
        }

        public static DirectoryString GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

		private static DerStringBase GetOptionalInnerObject(Asn1Encodable element)
		{
            return DerT61String.GetOptional(element)
                ?? DerPrintableString.GetOptional(element)
                ?? DerUniversalString.GetOptional(element)
                ?? DerUtf8String.GetOptional(element)
                ?? DerBmpString.GetOptional(element)
				?? (DerStringBase)null;
        }

        private readonly DerStringBase m_str;

        private DirectoryString(DerStringBase str)
		{
			m_str = str;
		}

		public DirectoryString(string str)
		{
			m_str = new DerUtf8String(str);
		}

		public string GetString() => m_str.GetString();

		/**
		 * <pre>
		 *  DirectoryString ::= CHOICE {
		 *    teletexString               TeletexString (SIZE (1..MAX)),
		 *    printableString             PrintableString (SIZE (1..MAX)),
		 *    universalString             UniversalString (SIZE (1..MAX)),
		 *    utf8String                  UTF8String (SIZE (1..MAX)),
		 *    bmpString                   BMPString (SIZE (1..MAX))  }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object() => m_str.ToAsn1Object();
	}
}
