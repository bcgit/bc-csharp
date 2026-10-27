using System;

namespace Org.BouncyCastle.Asn1.Icao
{
    /// <summary>Object identifiers for ICAO machine readable travel documents.</summary>
    // TODO[api] Make static
    public abstract class IcaoObjectIdentifiers
    {
        /// <summary>The object identifier <c>2.23.136</c>.</summary>
        //
        // base id
        //
        public static readonly DerObjectIdentifier IdIcao = new DerObjectIdentifier("2.23.136");

        /// <summary>The object identifier <c>2.23.136.1</c>.</summary>
        public static readonly DerObjectIdentifier IdIcaoMrtd = IdIcao.Branch("1");
        /// <summary>The object identifier <c>2.23.136.1.1</c>.</summary>
        public static readonly DerObjectIdentifier IdIcaoMrtdSecurity = IdIcaoMrtd.Branch("1");

        /// <summary>The object identifier <c>2.23.136.1.1.1</c>.</summary>
        // LDS security object, see ICAO Doc 9303-Volume 2-Section IV-A3.2
        public static readonly DerObjectIdentifier IdIcaoLdsSecurityObject = IdIcaoMrtdSecurity.Branch("1");

        /// <summary>The object identifier <c>2.23.136.1.1.2</c>.</summary>
        // CSCA master list, see TR CSCA Countersigning and Master List issuance
        public static readonly DerObjectIdentifier IdIcaoCscaMasterList = IdIcaoMrtdSecurity.Branch("2");
        /// <summary>The object identifier <c>2.23.136.1.1.3</c>.</summary>
        public static readonly DerObjectIdentifier IdIcaoCscaMasterListSigningKey = IdIcaoMrtdSecurity.Branch("3");

        /// <summary>The object identifier <c>2.23.136.1.1.4</c>.</summary>
        // document type list, see draft TR LDS and PKI Maintenance, par. 3.2.1
        public static readonly DerObjectIdentifier IdIcaoDocumentTypeList = IdIcaoMrtdSecurity.Branch("4");

        /// <summary>The object identifier <c>2.23.136.1.1.5</c>.</summary>
        // Active Authentication protocol, see draft TR LDS and PKI Maintenance,
        // par. 5.2.2
        public static readonly DerObjectIdentifier IdIcaoAAProtocolObject = IdIcaoMrtdSecurity.Branch("5");

        /// <summary>The object identifier <c>2.23.136.1.1.6</c>.</summary>
        // CSCA name change and key reoll-over, see draft TR LDS and PKI
        // Maintenance, par. 3.2.1
        public static readonly DerObjectIdentifier IdIcaoExtensions = IdIcaoMrtdSecurity.Branch("6");
        /// <summary>The object identifier <c>2.23.136.1.1.6.1</c>.</summary>
        public static readonly DerObjectIdentifier IdIcaoExtensionsNamechangekeyrollover = IdIcaoExtensions.Branch("1");
    }
}
