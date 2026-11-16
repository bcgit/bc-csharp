using System;

namespace Org.BouncyCastle.Asn1.Microsoft
{
    /// <summary>Object identifiers for Microsoft.</summary>
    // TODO[api] Make static
    public abstract class MicrosoftObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.3.6.1.4.1.311</c>.</summary>
        //
        // Microsoft
        //       iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) Microsoft(311)
        //
        public static readonly DerObjectIdentifier Microsoft               = new DerObjectIdentifier("1.3.6.1.4.1.311");
        /// <summary>The object identifier <c>1.3.6.1.4.1.311.20.2</c>.</summary>
        public static readonly DerObjectIdentifier MicrosoftCertTemplateV1 = Microsoft.Branch("20.2");
        /// <summary>The object identifier <c>1.3.6.1.4.1.311.21.1</c>.</summary>
        public static readonly DerObjectIdentifier MicrosoftCAVersion      = Microsoft.Branch("21.1");
        /// <summary>The object identifier <c>1.3.6.1.4.1.311.21.2</c>.</summary>
        public static readonly DerObjectIdentifier MicrosoftPrevCACertHash = Microsoft.Branch("21.2");
        /// <summary>The object identifier <c>1.3.6.1.4.1.311.21.4</c>.</summary>
        public static readonly DerObjectIdentifier MicrosoftCrlNextPublish = Microsoft.Branch("21.4");
        /// <summary>The object identifier <c>1.3.6.1.4.1.311.21.7</c>.</summary>
        public static readonly DerObjectIdentifier MicrosoftCertTemplateV2 = Microsoft.Branch("21.7");
        /// <summary>The object identifier <c>1.3.6.1.4.1.311.21.10</c>.</summary>
        public static readonly DerObjectIdentifier MicrosoftAppPolicies    = Microsoft.Branch("21.10");

        /// <summary>The object identifier <c>1.3.6.1.4.1.311.3.2.1</c>.</summary>
        public static readonly DerObjectIdentifier MicrosoftTimeStampRequest = Microsoft.Branch("3.2.1");
    }
}
