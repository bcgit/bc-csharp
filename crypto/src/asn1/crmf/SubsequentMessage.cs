using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class SubsequentMessage
        : DerInteger
    {
        public static readonly SubsequentMessage encrCert = new SubsequentMessage(0);
        public static readonly SubsequentMessage challengeResp = new SubsequentMessage(1);
    
        private SubsequentMessage(int value)
#pragma warning disable CS0618 // Type or member is obsolete
            : base(value)
#pragma warning restore CS0618 // Type or member is obsolete
        {
        }

        public static new SubsequentMessage ValueOf(int value)
        {
            if (value == 0)
                return encrCert;

            if (value == 1)
                return challengeResp;

            throw new ArgumentException("unknown value: " + value, "value");
        }
    }
}
