import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import selfsigned from 'selfsigned';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CERTS_DIR = path.join(__dirname, '..', 'certs');
const KEY_PATH = path.join(CERTS_DIR, 'key.pem');
const CERT_PATH = path.join(CERTS_DIR, 'cert.pem');

export const getCertificates = () => {
    if (fs.existsSync(KEY_PATH) && fs.existsSync(CERT_PATH)) {
        console.log('📜 Using existing SSL certificates');
        return {
            key: fs.readFileSync(KEY_PATH, 'utf8'),
            cert: fs.readFileSync(CERT_PATH, 'utf8'),
            keyPath: KEY_PATH,
            certPath: CERT_PATH
        };
    }

    console.log('🔐 Generating self-signed SSL certificates...');
    
    if (!fs.existsSync(CERTS_DIR)) {
        fs.mkdirSync(CERTS_DIR, { recursive: true });
    }

    const attrs = [
        { name: 'commonName', value: 'localhost' },
        { name: 'countryName', value: 'ZA' },
        { name: 'organizationName', value: 'International Payments Portal' }
    ];

    const options = {
        keySize: 2048,
        days: 365,
        algorithm: 'sha256',
        extensions: [
            {
                name: 'subjectAltName',
                altNames: [
                    { type: 2, value: 'localhost' },
                    { type: 7, ip: '127.0.0.1' }
                ]
            }
        ]
    };

    const pems = selfsigned.generate(attrs, options);

    fs.writeFileSync(KEY_PATH, pems.private);
    fs.writeFileSync(CERT_PATH, pems.cert);

    console.log('✅ SSL certificates generated successfully');
    console.log(`   Key:  ${KEY_PATH}`);
    console.log(`   Cert: ${CERT_PATH}`);

    return {
        key: pems.private,
        cert: pems.cert,
        keyPath: KEY_PATH,
        certPath: CERT_PATH
    };
};

export const getCertificatePaths = () => {
    const customKeyPath = process.env.SSL_KEY_PATH;
    const customCertPath = process.env.SSL_CERT_PATH;

    if (customKeyPath && customCertPath && fs.existsSync(customKeyPath) && fs.existsSync(customCertPath)) {
        console.log('📜 Using custom SSL certificates from environment variables');
        return {
            key: fs.readFileSync(customKeyPath, 'utf8'),
            cert: fs.readFileSync(customCertPath, 'utf8'),
            keyPath: customKeyPath,
            certPath: customCertPath
        };
    }

    return getCertificates();
};
