"""Collection of common oids.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

# rfc5280
# http://www.oid-info.com/

OIDS = {
    "0.9.2342.19200300.100.1.25": "id-domainComponent",
    "1.2.840.10040.4.1": "dsa12",
    "1.2.840.10040.4.3": "dsa12-with-sha1",
    "1.2.840.10045.1.1": "prime-field",
    "1.2.840.10045.1.2": "characteristic-two-field",
    "1.2.840.10045.2.1": "ecPublicKey",
    "1.2.840.10045.3.1.1": "prime192v1", # secp192r1
    "1.2.840.10045.3.1.2": "prime192v2",
    "1.2.840.10045.3.1.3": "prime192v3",
    "1.2.840.10045.3.1.4": "prime239v1",
    "1.2.840.10045.3.1.5": "prime239v2",
    "1.2.840.10045.3.1.6": "prime239v3",
    "1.2.840.10045.3.1.7": "prime256v1", # secp256r1
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.2": "ecdsa-with-Recommended",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.113533.7.65.0": "nsn-ce-0",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.3": "md4withRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1-with-rsa-signature",
    "1.2.840.113549.1.1.6": "rsaOAEPEncryptionSET",
    "1.2.840.113549.1.1.7": "id-RSAES-OAEP",
    "1.2.840.113549.1.1.8": "id-mgf1",
    "1.2.840.113549.1.1.9": "id-pSpecified",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.9.1": "id-emailAddress",
    "1.2.840.113549.1.9.2": "unstructuredName",
    "1.2.840.113549.1.9.8": "unstructuredAddress",
    "1.2.840.113549.1.9.15": "sMIMECapabilities",
    "1.2.840.113549.3.2": "rc2-cbc",
    "1.2.840.113549.3.3": "rc2ECB",
    "1.2.840.113549.3.4": "rc4",
    "1.2.840.113549.3.5": "rc4WithMAC",
    "1.2.840.113549.3.6": "desx-CBC",
    "1.2.840.113549.3.7": "des-ede3-cbc",
    "1.2.840.113549.3.8": "rc5CBC",
    "1.2.840.113549.3.9": "rc5-CBCPad",
    "1.2.840.113549.3.10": "desCDMF",
    "1.3.6.1.4.1.11129.2.4.2": "rfc6962-signed-certificate-timestamp",
    "1.3.6.1.5.5.7.0.18": "PKIX1Explicit88",
    "1.3.6.1.5.5.7.1.1": "id-pe-authorityInfoAccess",
    "1.3.6.1.5.5.7.1.11": "id-pe-subjectInfoAccess",
    "1.3.6.1.5.5.7.1.12": "id-pe-logotype",
    "1.3.6.1.5.5.7.2.1": "id-qt-cps",
    "1.3.6.1.5.5.7.2.2": "id-qt-unotice",
    "1.3.6.1.5.5.7.3.1": "id-kp-serverAuth",
    "1.3.6.1.5.5.7.3.2": "id-kp-clientAuth",
    "1.3.6.1.5.5.7.3.3": "id-kp-codeSigning",
    "1.3.6.1.5.5.7.3.4": "id-kp-emailProtection",
    "1.3.6.1.5.5.7.3.5": "id-kp-ipsecEndSystem",
    "1.3.6.1.5.5.7.3.6": "id-kp-ipsecTunnel",
    "1.3.6.1.5.5.7.3.7": "id-kp-ipsecUser",
    "1.3.6.1.5.5.7.3.8": "id-kp-timeStamping",
    "1.3.6.1.5.5.7.3.9": "id-kp-OCSPSigning",
    "1.3.6.1.5.5.7.3.17": "id-kp-ipsecIKE",
    "1.3.6.1.5.5.7.3.21": "id-kp-sshClient",
    "1.3.6.1.5.5.7.3.22": "id-kp-sshServer",
    "1.3.6.1.5.5.7.8.1": "id-on-personalData",
    "1.3.6.1.5.5.7.8.2": "id-on-userGroup",
    "1.3.6.1.5.5.7.8.3": "id-on-permanentIdentifier",
    "1.3.6.1.5.5.7.8.4": "id-on-hardwareModuleName",
    "1.3.6.1.5.5.7.8.5": "id-on-xmppAddr",
    "1.3.6.1.5.5.7.48.1": "id-ad-ocsp",
    "1.3.6.1.5.5.7.48.2": "id-ad-caIssuers",
    "1.3.6.1.5.5.7.48.3": "id-ad-timeStamping",
    "1.3.6.1.5.5.7.48.5": "id-ad-caRepository",
    "1.3.14.3.2.2": "md4WitRSA",
    "1.3.14.3.2.3": "md5WithRSA",
    "1.3.14.3.2.4": "md4WithRSAEncryption",
    "1.3.14.3.2.6": "desECB",
    "1.3.14.3.2.7": "desCBC",
    "1.3.14.3.2.8": "desOFB",
    "1.3.14.3.2.9": "desCFB",
    "1.3.14.3.2.10": "desMAC",
    "1.3.14.3.2.12": "dsa",
    "1.3.14.3.2.13": "dsaWithSHA",
    "1.3.14.3.2.14": "mdc2WithRSASignature",
    "1.3.14.3.2.15": "shaWithRSASignature",
    "1.3.14.3.2.16": "dhWithCommonModulus",
    "1.3.14.3.2.17": "desEDE",
    "1.3.14.3.2.18": "sha",
    "1.3.14.3.2.19": "mdc-2",
    "1.3.14.3.2.20": "dsaCommon",
    "1.3.14.3.2.21": "dsaCommonWithSHA",
    "1.3.14.3.2.22": "rsa-key-transport",
    "1.3.14.3.2.23": "keyed-hash-seal",
    "1.3.14.3.2.24": "md2WithRSASignature",
    "1.3.14.3.2.25": "md5WithRSASignature",
    "1.3.14.3.2.26": "hashAlgorithmIdentifier",
    "1.3.14.3.2.27": "dsaWithSHA1",
    "1.3.14.3.2.28": "dsaWithCommonSHA1",
    "1.3.14.3.2.29": "sha-1WithRSAEncryption",
    "1.3.132.0.1": "sect163k1",
    "1.3.132.0.2": "sect163r1",
    "1.3.132.0.3": "sect239k1",
    "1.3.132.0.4": "sect113r1",
    "1.3.132.0.5": "sect113r2",
    "1.3.132.0.6": "secp112r1",
    "1.3.132.0.7": "secp112r2",
    "1.3.132.0.8": "secp160r1",
    "1.3.132.0.9": "secp160k1",
    "1.3.132.0.10": "secp256k1",
    "1.3.132.0.15": "sect163r2",
    "1.3.132.0.16": "sect283k1",
    "1.3.132.0.17": "sect283r1",
    "1.3.132.0.22": "sect131r1",
    "1.3.132.0.24": "sect193r1",
    "1.3.132.0.25": "sect193r2",
    "1.3.132.0.26": "sect233k1",
    "1.3.132.0.27": "sect233r1",
    "1.3.132.0.28": "secp128r1",
    "1.3.132.0.29": "secp128r2",
    "1.3.132.0.30": "secp160r2",
    "1.3.132.0.31": "secp192k1",
    "1.3.132.0.32": "secp224k1",
    "1.3.132.0.33": "secp224r1",
    "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1",
    "1.3.132.0.36": "sect409k1",
    "1.3.132.0.37": "sect409r1",
    "1.3.132.0.38": "sect571k1",
    "1.3.132.0.39": "sect571r1",
    "2.2.840.10040.2.1": "id-holdinstruction-none",
    "2.2.840.10040.2.2": "id-holdinstruction-callissuer",
    "2.2.840.10040.2.3": "id-holdinstruction-reject",
    "2.5.4.0": "id-at-objectClass",
    "2.5.4.1": "id-at-aliasedEntryname",
    "2.5.4.2": "id-at-knoelwdgeInformation",
    "2.5.4.3": "id-at-commonName",
    "2.5.4.4": "id-at-surname",
    "2.5.4.5": "id-at-serialNumber",
    "2.5.4.6": "id-at-countryName",
    "2.5.4.7": "id-at-localityName",
    "2.5.4.8": "id-at-stateOrProvinceName",
    "2.5.4.9": "id-at-streetAddress",
    "2.5.4.10": "id-at-organizationName",
    "2.5.4.11": "id-at-organizationalUnitName",
    "2.5.4.12": "id-at-title",
    "2.5.4.13": "id-at-description",
    "2.5.4.14": "id-at-searchGuide",
    "2.5.4.15": "id-at-businessCategory",
    "2.5.4.16": "id-at-postalAddress",
    "2.5.4.17": "id-at-postalCode",
    "2.5.4.18": "id-at-postOfficeBox",
    "2.5.4.19": "id-at-physicalDeliveryOfficeName",
    "2.5.4.20": "id-at-telephoneNumber",
    "2.5.4.21": "id-at-telexNumber",
    "2.5.4.22": "id-at-telexTerminalIdentifier",
    "2.5.4.23": "id-at-facsimileTelephoneNumber",
    "2.5.4.24": "id-at-x121Address",
    "2.5.4.25": "id-at-internationalISDNNumber",
    "2.5.4.26": "id-at-registeredAddress",
    "2.5.4.27": "id-at-destinationIndicator",
    "2.5.4.28": "id-at-preferredDeliveryMethod",
    "2.5.4.29": "id-at-presentationAddress",
    "2.5.4.30": "id-at-supportedApplicationContext",
    "2.5.4.31": "id-at-member",
    "2.5.4.32": "id-at-owner",
    "2.5.4.33": "id-at-roleOccupant",
    "2.5.4.34": "id-at-seeAlso",
    "2.5.4.35": "id-at-userPassword",
    "2.5.4.36": "id-at-userCertificate",
    "2.5.4.37": "id-at-cACertificate",
    "2.5.4.38": "id-at-authorityRevocationList",
    "2.5.4.39": "id-at-certificateRevocationList",
    "2.5.4.40": "id-at-crossCertificatePair",
    "2.5.4.41": "id-at-name",
    "2.5.4.42": "id-at-givenName",
    "2.5.4.43": "id-at-initials",
    "2.5.4.44": "id-at-generationQualifier",
    "2.5.4.46": "id-at-dnQualifier",
    "2.5.4.65": "id-at-pseudonym",
    "2.5.29.1": "id-ce-authorityKeyIdentifier-obsolete",
    "2.5.29.9": "id-ce-subjectDirectoryAttributes",
    "2.5.29.14": "id-ce-subjectKeyIdentifier",
    "2.5.29.15": "id-ce-keyUsage",
    "2.5.29.16": "id-ce-privateKeyUsagePeriod",
    "2.5.29.17": "id-ce-subjectAltName",
    "2.5.29.18": "id-ce-issuerAltName",
    "2.5.29.19": "id-ce-basicConstraints",
    "2.5.29.20": "id-ce-cRLNumber",
    "2.5.29.21": "id-ce-cRLReasons",
    "2.5.29.23": "id-ce-holdInstructionCode",
    "2.5.29.24": "id-ce-invalidityDate",
    "2.5.29.27": "id-ce-deltaCRLIndicator",
    "2.5.29.28": "id-ce-issuingDistributionPoint",
    "2.5.29.29": "id-ce-certificateIssuer",
    "2.5.29.30": "id-ce-nameConstraints",
    "2.5.29.31": "id-ce-cRLDistributionPoints",
    "2.5.29.32": "id-ce-certificatePolicies",
    "2.5.29.33": "id-ce-policyMappings",
    "2.5.29.35": "id-ce-authorityKeyIdentifier",
    "2.5.29.36": "id-ce-policyConstraints",
    "2.5.29.37": "id-ce-extKeyUsage",
    "2.5.29.37.0": "id-ce-extKeyUsage-any",
    "2.5.29.46": "id-ce-freshestCRL",
    "2.5.29.54": "id-ce-inhibitAnyPolicy",
    "2.16.840.1.101.3.4.1.1": "aes128-ECB",
    "2.16.840.1.101.3.4.1.2": "aes128-CBC",
    "2.16.840.1.101.3.4.1.3": "aes128-OFB",
    "2.16.840.1.101.3.4.1.4": "aes128-CFB",
    "2.16.840.1.101.3.4.1.5": "id-aes128-wrap",
    "2.16.840.1.101.3.4.1.6": "aes128-GCM",
    "2.16.840.1.101.3.4.1.7": "aes128-CCM",
    "2.16.840.1.101.3.4.1.8": "aes128-wrap-pad",
    "2.16.840.1.101.3.4.1.21": "aes192-ECB",
    "2.16.840.1.101.3.4.1.22": "aes192-CBC",
    "2.16.840.1.101.3.4.1.23": "aes192-OFB",
    "2.16.840.1.101.3.4.1.24": "aes192-CFB",
    "2.16.840.1.101.3.4.1.25": "id-aes192-wrap",
    "2.16.840.1.101.3.4.1.26": "aes192-GCM",
    "2.16.840.1.101.3.4.1.27": "aes192-CCM",
    "2.16.840.1.101.3.4.1.28": "aes192-wrap-pad",
    "2.16.840.1.101.3.4.1.41": "aes256-ECB",
    "2.16.840.1.101.3.4.1.42": "aes256-CBC",
    "2.16.840.1.101.3.4.1.43": "aes256-OFB",
    "2.16.840.1.101.3.4.1.44": "aes256-CFB",
    "2.16.840.1.101.3.4.1.45": "id-aes256-wrap",
    "2.16.840.1.101.3.4.1.46": "aes256-GCM",
    "2.16.840.1.101.3.4.1.47": "aes256-CCM",
    "2.16.840.1.101.3.4.1.48": "aes256-wrap-pad",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.5": "sha512-224",
    "2.16.840.1.101.3.4.2.6": "sha512-256",
    "2.16.840.1.101.3.4.2.7": "sha3-224",
    "2.16.840.1.101.3.4.2.8": "sha3-256",
    "2.16.840.1.101.3.4.2.9": "sha3-384",
    "2.16.840.1.101.3.4.2.10": "sha3-512",
    "2.16.840.1.101.3.4.2.11": "shake128",
    "2.16.840.1.101.3.4.2.11": "shake256",
    "2.16.840.1.113719.1.9.4.1": "novell-securityAttributes",
    "2.16.840.1.113730.1.1": "netscape-cert-type",
    "2.16.840.1.113730.1.2": "netscape-base-url",
    "2.16.840.1.113730.1.3": "netscape-revocation-url",
    "2.16.840.1.113730.1.4": "netscape-ca-revocation-url",
    "2.16.840.1.113730.1.5": "netscape-ca-crl-url",
    "2.16.840.1.113730.1.6": "netscape-ca-cert-url",
    "2.16.840.1.113730.1.7": "netscape-renewal-url",
    "2.16.840.1.113730.1.8": "netscape-ca-policy-url",
    "2.16.840.1.113730.1.9": "netscape-homepage-url",
    "2.16.840.1.113730.1.10": "netscape-entity-logo",
    "2.16.840.1.113730.1.11": "netscape-user-picture",
    "2.16.840.1.113730.1.12": "netscape-ssl-server-name",
    "2.16.840.1.113730.1.13": "netscape-comment",
    "2.16.840.1.113730.1.14": "netscape-lost-password-url",
    "2.16.840.1.113730.1.15": "netscape-cert-renewal-time",
    "2.16.840.1.113730.1.16": "netscape-aia",
    "2.16.840.1.113730.1.17": "netscape-cert-scope-of-use",
    "2.23.42.7.0": "sec-el-tx-7-0",
    "2.23.140.1.1": "cab-ev-guidelines",
    "2.23.140.1.2.1": "cab-domain-validated",
    "2.23.140.1.2.2": "cab-subject-identity-validated",
}

PREFIXES = {
    "1.2.36.": "iso-au-",
    "1.2.398.": "iso-kz-",
    "1.3.6.1.4.1.311.": "ms-",
    "1.3.6.1.4.1.6449.": "comodo-",
    "1.3.6.1.4.1.23223.": "startcom-",
    "2.16.76.": "br-",
    "2.16.840.1.113733.": "symantec-",
    "2.16.840.1.114027.": "entrust-",
    "2.16.840.1.114334.": "identicrypt-",
    "2.16.840.1.114412.": "digicert-",
    "2.16.840.1.114413.": "godaddy-",
    "2.16.886.": "bad-tw-",
}

def _check():
    rev = {}
    for k, v in OIDS.items():
        if v in rev:
            print("name conflict '%s' - %s and %s" % (v, k, rev[v]))
        else:
            rev[v] = k
_check()
del _check


