using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * <code>DisplayText</code> class, used in
     * <code>CertificatePolicies</code> X509 V3 extensions (in policy qualifiers).
     *
     * <p>It stores a string in a chosen encoding.
     * <pre>
     * DisplayText ::= CHOICE {
     *      ia5String        IA5String      (SIZE (1..200)),
     *      visibleString    VisibleString  (SIZE (1..200)),
     *      bmpString        BMPString      (SIZE (1..200)),
     *      utf8String       UTF8String     (SIZE (1..200)) }
     * </pre></p>
     * @see PolicyQualifierInfo
     * @see PolicyInformation
     */
    public class DisplayText
        : Asn1Encodable, IAsn1Choice
    {
        /**
         * Constant corresponding to ia5String encoding.
         *
         */
        public const int ContentTypeIA5String = 0;
        /**
         * Constant corresponding to bmpString encoding.
         *
         */
        public const int ContentTypeBmpString = 1;
        /**
         * Constant corresponding to utf8String encoding.
         *
         */
        public const int ContentTypeUtf8String = 2;
        /**
         * Constant corresponding to visibleString encoding.
         *
         */
        public const int ContentTypeVisibleString = 3;
        /**
         * Describe constant <code>DisplayTextMaximumSize</code> here.
         *
         */
        public const int DisplayTextMaximumSize = 200;

        public static DisplayText GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static DisplayText GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static DisplayText GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DisplayText displayText)
                return displayText;

            var innerObject = GetOptionalInnerObject(element);
            if (innerObject != null)
                return new DisplayText(innerObject);

            return null;
        }

        public static DisplayText GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static DerStringBase GetOptionalInnerObject(Asn1Encodable element)
        {
            return DerIA5String.GetOptional(element)
                ?? DerVisibleString.GetOptional(element)
                ?? DerBmpString.GetOptional(element)
                ?? DerUtf8String.GetOptional(element)
                ?? (DerStringBase)null;
        }

        internal readonly int contentType;
        internal readonly IAsn1String contents;

        /**
         * Creates a new <code>DisplayText</code> instance.
         *
         * @param type the desired encoding type for the text.
         * @param text the text to store. Strings longer than 200
         * characters are truncated.
         */
        public DisplayText(
            int type,
            string text)
        {
            if (text.Length > DisplayTextMaximumSize)
            {
                // RFC3280 limits these strings to 200 chars
                // truncate the string
                text = text.Substring(0, DisplayTextMaximumSize);
            }

            contentType = type;
            switch (type)
            {
            case ContentTypeIA5String:
                contents = (IAsn1String)new DerIA5String(text);
                break;
            case ContentTypeUtf8String:
                contents = (IAsn1String)new DerUtf8String(text);
                break;
            case ContentTypeVisibleString:
                contents = (IAsn1String)new DerVisibleString(text);
                break;
            case ContentTypeBmpString:
                contents = (IAsn1String)new DerBmpString(text);
                break;
            default:
                contents = (IAsn1String)new DerUtf8String(text);
                break;
            }
        }

        /**
         * Creates a new <code>DisplayText</code> instance.
         *
         * @param text the text to encapsulate. Strings longer than 200
         * characters are truncated.
         */
        public DisplayText(
            string text)
        {
            // by default use UTF8String
            if (text.Length > DisplayTextMaximumSize)
            {
                text = text.Substring(0, DisplayTextMaximumSize);
            }

            contentType = ContentTypeUtf8String;
            contents = new DerUtf8String(text);
        }

        /**
         * Creates a new <code>DisplayText</code> instance.
         * <p>Useful when reading back a <code>DisplayText</code> class
         * from it's Asn1Encodable form.</p>
         *
         * @param contents an <code>Asn1Encodable</code> instance.
         */
        public DisplayText(
            IAsn1String contents)
        {
            this.contents = contents;
        }

        public override Asn1Object ToAsn1Object()
        {
            return (Asn1Object)contents;
        }

        /**
         * Returns the stored <code>string</code> object.
         *
         * @return the stored text as a <code>string</code>.
         */
        public string GetString()
        {
            return contents.GetString();
        }
    }
}
