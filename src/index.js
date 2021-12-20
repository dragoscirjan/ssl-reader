const fs = require('fs');
const path = require('path');

const {Command} = require('commander');
const forge = require('node-forge');

const program = new Command();

program
  .option('-f, --file <file>', 'Files to inspect', (value, acc) => [...acc, value], [])
  .option('-p, --password <password>', '')
  .option('-o, --out-format <out-format>', 'PEM');

program.parse(process.argv);

const options = program.opts();

const decodeFromDer = (content, doThrow = false) => {
  if (!content || content.length <= 1) {
    throw new Error('Invalid certificate file: empty');
  }

  if (content.match(/^\-+BEGIN (CERTIFICATE|PRIVATE KEY|PKCS\d+)\-+/gi)) {
    throw new Error('File not in DER format');
  }

  try {
    const fromDer = forge.asn1.fromDer(content);

    try {
      return {
        certificate: forge.pki.certificateFromAsn1(fromDer),
      };
    } catch (e) {
      if (doThrow) {
        throw e;
      }
    }

    try {
      return {
        privateKey: forge.pki.privateKeyFromAsn1(fromDer),
      };
    } catch (e) {
      if (doThrow) {
        throw e;
      }
    }
  } catch (e) {
    if (doThrow) {
      throw e;
    }
  }

  // maybe DER content is Base64 encoded
  return decodeFromDer(forge.util.decode64(content), true);
};

const decodeFromPkcs7 = (content) => {
  if (!content.match(/^\-+BEGIN (PKCS7)\-+/gi)) {
    throw new Error('File not in PKCS7 format');
  }

  try {
    return {
      certificate: forge.p7.findRecipient(content)[0],
    };
  } catch (e) {}

  throw new Error('Not PKCS#7 format. Could not parse certificate...');
};

const decodeFromPkcs12 = (content) => {
  if (!content || content.length <= 1) {
    throw new Error('Invalid certificate file: empty');
  }

  if (content.match(/^\-+BEGIN (CERTIFICATE|PRIVATE KEY|PKCS\d+)\-+/gi)) {
    throw new Error('File not in PKCS12 format');
  }

  try {
    const fromDer = forge.asn1.fromDer(content);
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(fromDer, 'test');

    return {
      // certificate: pkcs12.safeContents
      //   .find((co) => co.encrypted)
      //   .safeBags.find((c) => c.cert.extensions && !c.cert.extensions.find((e) => e.cA)).cert,
      certificate: pkcs12.safeContents
        .find((co) => co.safeBags.find((b) => b.cert))
        .safeBags.find((c) => c.cert.extensions && !c.cert.extensions.find((e) => e.cA)).cert,
      // privateKey: pkcs12.safeContents.find((c) => !c.encrypted).safeBags[0].key,
      privateKey: pkcs12.safeContents.find((c) => c.safeBags.find((b) => b.key)).safeBags[0].key,
    };
  } catch (e) {
    console.log(`!! Failed parsing PKCS12: ${e.message}`);
  }

  throw new Error('Not PKCS12 format. Could not parse certificate nor key...');
};

const decodeFromPem = (content) => {
  if (!content.match(/^\-+BEGIN (CERTIFICATE|(ENCRYPTED )?PRIVATE KEY)\-+/gi)) {
    throw new Error('File not in PEM format');
  }

  try {
    return {
      certificate: forge.pki.certificateFromPem(content),
    };
  } catch (e) {}

  try {
    return {
      privateKey: forge.pki.decryptRsaPrivateKey(content, 'test'),
    };
  } catch (e) {}

  throw new Error('Not PEM format. Could not parse certificate nor key...');
};

const objects = options.file.map((file) => {
  let obj = {};
  let content = fs.readFileSync(file, 'binary');

  try {
    obj = {
      ...decodeFromDer(content),
      format: 'DER',
    };
  } catch (e) {
    console.error(`!! Not DER file: ${e.message}`);
  }

  // if (Object.keys(obj).length === 0) {
  //   try {
  //     obj = {
  //       ...decodeFromPkcs7(content),
  //       format: 'PKCS7',
  //     };
  //   } catch (e) {
  //     console.error(`!! Not PKCS7 file: ${e.message}`);
  //   }
  // }

  if (Object.keys(obj).length === 0) {
    try {
      obj = {
        ...decodeFromPkcs12(content),
        format: 'PKCS12',
      };
    } catch (e) {
      console.error(`!! Not PKCS12 file: ${e.message}`);
    }
  }

  if (Object.keys(obj).length === 0) {
    try {
      obj = {
        ...decodeFromPem(content),
        format: 'PEM',
      };
    } catch (e) {
      console.error(`!! Not PEM file: ${e.message}`);
    }
  }

  return {
    ext: path.extname(file),
    content,
    file,
    ...obj,
  };
});

// console.log(objects);

objects.forEach((obj) => {
  console.log(`From ${obj.format}:`);
  if (obj.certificate) {
    console.log(forge.pki.certificateToPem(obj.certificate));
  }
  if (obj.privateKey) {
    console.log(forge.pki.privateKeyToPem(obj.privateKey));
  }
});
