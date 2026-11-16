using System;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Constants for the tag numbers of the universal ASN.1 types.</summary>
    public class Asn1Tags
    {
        /// <summary>The <c>Boolean</c> constant, with the value <c>0x01</c>.</summary>
        // 0x00: Reserved for use by the encoding rules
        public const int Boolean = 0x01;
        /// <summary>The <c>Integer</c> constant, with the value <c>0x02</c>.</summary>
        public const int Integer = 0x02;
        /// <summary>The <c>BitString</c> constant, with the value <c>0x03</c>.</summary>
        public const int BitString = 0x03;
        /// <summary>The <c>OctetString</c> constant, with the value <c>0x04</c>.</summary>
        public const int OctetString = 0x04;
        /// <summary>The <c>Null</c> constant, with the value <c>0x05</c>.</summary>
        public const int Null = 0x05;
        /// <summary>The <c>ObjectIdentifier</c> constant, with the value <c>0x06</c>.</summary>
        public const int ObjectIdentifier = 0x06;
        /// <summary>The <c>ObjectDescriptor</c> constant, with the value <c>0x07</c>.</summary>
        public const int ObjectDescriptor = 0x07;
        /// <summary>The <c>External</c> constant, with the value <c>0x08</c>.</summary>
        public const int External = 0x08;
        /// <summary>The <c>Real</c> constant, with the value <c>0x09</c>.</summary>
        public const int Real = 0x09;
        /// <summary>The <c>Enumerated</c> constant, with the value <c>0x0a</c>.</summary>
        public const int Enumerated = 0x0a;
        /// <summary>The <c>EmbeddedPdv</c> constant, with the value <c>0x0b</c>.</summary>
        public const int EmbeddedPdv = 0x0b;
        /// <summary>The <c>Utf8String</c> constant, with the value <c>0x0c</c>.</summary>
        public const int Utf8String = 0x0c;
        /// <summary>The <c>RelativeOid</c> constant, with the value <c>0x0d</c>.</summary>
        public const int RelativeOid = 0x0d;
        /// <summary>The <c>Time</c> constant, with the value <c>0x0e</c>.</summary>
        public const int Time = 0x0e;
        /// <summary>The <c>Sequence</c> constant, with the value <c>0x10</c>.</summary>
        // 0x0f: Reserved for future editions of this Recommendation | International Standard
        public const int Sequence = 0x10;
        /// <summary>The <c>SequenceOf</c> constant, with the value <c>0x10</c>.</summary>
        public const int SequenceOf = 0x10; // for completeness
        /// <summary>The <c>Set</c> constant, with the value <c>0x11</c>.</summary>
        public const int Set = 0x11;
        /// <summary>The <c>SetOf</c> constant, with the value <c>0x11</c>.</summary>
        public const int SetOf = 0x11; // for completeness
        /// <summary>The <c>NumericString</c> constant, with the value <c>0x12</c>.</summary>
        public const int NumericString = 0x12;
        /// <summary>The <c>PrintableString</c> constant, with the value <c>0x13</c>.</summary>
        public const int PrintableString = 0x13;
        /// <summary>The <c>T61String</c> constant, with the value <c>0x14</c>.</summary>
        public const int T61String = 0x14;
        /// <summary>The <c>VideotexString</c> constant, with the value <c>0x15</c>.</summary>
        public const int VideotexString = 0x15;
        /// <summary>The <c>IA5String</c> constant, with the value <c>0x16</c>.</summary>
        public const int IA5String = 0x16;
        /// <summary>The <c>UtcTime</c> constant, with the value <c>0x17</c>.</summary>
        public const int UtcTime = 0x17;
        /// <summary>The <c>GeneralizedTime</c> constant, with the value <c>0x18</c>.</summary>
        public const int GeneralizedTime = 0x18;
        /// <summary>The <c>GraphicString</c> constant, with the value <c>0x19</c>.</summary>
        public const int GraphicString = 0x19;
        /// <summary>The <c>VisibleString</c> constant, with the value <c>0x1a</c>.</summary>
        public const int VisibleString = 0x1a;
        /// <summary>The <c>GeneralString</c> constant, with the value <c>0x1b</c>.</summary>
        public const int GeneralString = 0x1b;
        /// <summary>The <c>UniversalString</c> constant, with the value <c>0x1c</c>.</summary>
        public const int UniversalString = 0x1c;
        /// <summary>The <c>UnrestrictedString</c> constant, with the value <c>0x1d</c>.</summary>
        public const int UnrestrictedString = 0x1d;
        /// <summary>The <c>BmpString</c> constant, with the value <c>0x1e</c>.</summary>
        public const int BmpString = 0x1e;
        /// <summary>The <c>Date</c> constant, with the value <c>0x1f</c>.</summary>
        public const int Date = 0x1f;
        /// <summary>The <c>TimeOfDay</c> constant, with the value <c>0x20</c>.</summary>
        public const int TimeOfDay = 0x20;
        /// <summary>The <c>DateTime</c> constant, with the value <c>0x21</c>.</summary>
        public const int DateTime = 0x21;
        /// <summary>The <c>Duration</c> constant, with the value <c>0x22</c>.</summary>
        public const int Duration = 0x22;
        /// <summary>The <c>ObjectIdentifierIri</c> constant, with the value <c>0x23</c>.</summary>
        public const int ObjectIdentifierIri = 0x23;
        /// <summary>The <c>RelativeOidIri</c> constant, with the value <c>0x24</c>.</summary>
        public const int RelativeOidIri = 0x24;
        // 0x25..: Reserved for addenda to this Recommendation | International Standard

        /// <summary>The <c>Constructed</c> constant, with the value <c>0x20</c>.</summary>
        public const int Constructed = 0x20;

        /// <summary>The <c>Universal</c> constant, with the value <c>0x00</c>.</summary>
        public const int Universal = 0x00;
        /// <summary>The <c>Application</c> constant, with the value <c>0x40</c>.</summary>
        public const int Application = 0x40;
        /// <summary>The <c>ContextSpecific</c> constant, with the value <c>0x80</c>.</summary>
        public const int ContextSpecific = 0x80;
        /// <summary>The <c>Private</c> constant, with the value <c>0xC0</c>.</summary>
        public const int Private = 0xC0;

        /// <summary>The <c>Flags</c> constant, with the value <c>0xE0</c>.</summary>
        public const int Flags = 0xE0;
    }
}
