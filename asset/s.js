/* asset/script.js
   Cleaned and upgraded:
   - Removes default Version:/Comment: metadata from armored outputs
   - Allows inserting a custom metadata Comment
   - Supports key generation WITHOUT requiring an email
   - Fully compatible with OpenPGP.js v4.x
*/

/* ============================================================
   Metadata helpers
============================================================ */

/* Remove Version:/Comment: lines */
function removeMetadata(armored) {
    if (!armored) return armored;

    return armored
        .split("\n")
        .filter(line => {
            const trimmed = line.trim();
            return !(trimmed.startsWith("Version:") || trimmed.startsWith("Comment:"));
        })
        .join("\n");
}

/* Replace metadata with a custom Comment line */
function rewriteMetadata(armored, commentText) {
    if (!armored) return armored;

    let cleaned = armored
        .split("\n")
        .filter(line => {
            const t = line.trim();
            return !(t.startsWith("Version:") || t.startsWith("Comment:"));
        })
        .join("\n");

    return cleaned.replace(
        /^-----BEGIN PGP [A-Z ]+-----/m,
        header => `${header}\nKCRA${commentText}`
    );
}

/* Default comment used when generating keys, signing, encrypting */
const DEFAULT_COMMENT = "♾️";

/* ============================================================
   UI utilities
============================================================ */

function toggleSection(sectionId) {
    const sections = document.querySelectorAll('.section-content');
    sections.forEach(section => {
        if (section.id !== sectionId) section.style.display = 'none';
    });

    const selected = document.getElementById(sectionId);
    selected.style.display = selected.style.display === 'block' ? 'none' : 'block';
}

function showCopyMessage(message) {
    const msg = document.createElement('div');
    msg.textContent = message;
    msg.style.position = 'fixed';
    msg.style.bottom = '20px';
    msg.style.right = '20px';
    msg.style.backgroundColor = 'rgba(0,0,0,0.7)';
    msg.style.color = 'white';
    msg.style.padding = '10px';
    msg.style.borderRadius = '5px';
    msg.style.zIndex = '1000';
    document.body.appendChild(msg);

    setTimeout(() => {
        if (msg.parentNode) msg.remove();
    }, 2000);
}

function copyToClipboard(elementId) {
    const elem = document.getElementById(elementId);
    if (!elem) return;

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(elem.value)
            .then(() => showCopyMessage("Copied to clipboard!"))
            .catch(() => fallbackCopy());
    } else fallbackCopy();

    function fallbackCopy() {
        elem.select();
        elem.setSelectionRange(0, 99999);
        document.execCommand("copy");
        showCopyMessage("Copied to clipboard!");
    }
}

function downloadKey(elementId) {
    const key = document.getElementById(elementId).value;
    const fileName = `${elementId}.txt`;

    const a = document.createElement('a');
    a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(key);
    a.download = fileName;
    a.style.display = 'none';

    document.body.appendChild(a);
    a.click();
    a.remove();
}

function importKey(elementId) {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.txt';
    input.onchange = async evt => {
        const file = evt.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = e => {
            document.getElementById(elementId).value = e.target.result;
        };
        reader.readAsText(file);
    };

    input.click();
}

/* ============================================================
   PGP Operations
============================================================ */

async function encryptMessage() {
    try {
        const publicKey = document.getElementById("publicKeyEncrypt").value.trim();
        const plainText = document.getElementById("plainText").value;

        if (!publicKey) return alert("Please provide a public key.");

        const { keys: [pub] } = await openpgp.key.readArmored(publicKey);

        const { data: cipherText } = await openpgp.encrypt({
            message: openpgp.message.fromText(plainText),
            publicKeys: [pub]
        });

        document.getElementById("cipherText").value =
            rewriteMetadata(cipherText, DEFAULT_COMMENT);

    } catch (err) {
        console.error(err);
        alert("Encryption failed: " + err.message);
    }
}

async function decryptMessage() {
    try {
        const privateKey = document.getElementById("privateKeyDecrypt").value.trim();
        const passphrase = document.getElementById("passphraseDecrypt").value;
        const cipherText = document.getElementById("cipherTextDecrypt").value;

        if (!privateKey) return alert("Please provide a private key.");

        const { keys } = await openpgp.key.readArmored(privateKey);
        const priv = keys[0];

        if (!priv.isDecrypted()) await priv.decrypt(passphrase);

        const { data: decryptedText } = await openpgp.decrypt({
            message: await openpgp.message.readArmored(cipherText),
            privateKeys: [priv]
        });

        document.getElementById("plainTextDecrypt").value = decryptedText;

    } catch (err) {
        console.error(err);
        alert("Decryption failed: " + err.message);
    }
}

async function signMessage() {
    try {
        const privateKey = document.getElementById("privateKeySign").value.trim();
        const passphrase = document.getElementById("passphraseSign").value;
        const plainText = document.getElementById("plainTextSign").value;

        if (!privateKey) return alert("Please provide a private key.");

        const { keys } = await openpgp.key.readArmored(privateKey);
        const priv = keys[0];

        if (!priv.isDecrypted()) await priv.decrypt(passphrase);

        const { data: signedMessage } = await openpgp.sign({
            message: openpgp.cleartext.fromText(plainText),
            privateKeys: [priv]
        });

        document.getElementById("signedMessage").value =
            rewriteMetadata(signedMessage, DEFAULT_COMMENT);

    } catch (err) {
        console.error(err);
        alert("Signing failed: " + err.message);
    }
}

async function verifyMessage() {
    try {
        const publicKey = document.getElementById("publicKeyVerify").value.trim();
        const signedMessage = document.getElementById("signedMessageVerify").value;

        if (!publicKey) return alert("Please provide a public key.");

        const { keys: [pub] } = await openpgp.key.readArmored(publicKey);

        const verified = await openpgp.verify({
            message: await openpgp.cleartext.readArmored(signedMessage),
            publicKeys: pub
        });

        const good = verified.signatures[0].valid;
        const out = document.getElementById("verifyResult");

        if (good) {
            out.style.color = 'green';
            const userIds = pub.getUserIds ? pub.getUserIds() : [];
            out.innerText = `Signed by ${userIds.join(', ')}\nSignature is valid.`;
        } else {
            out.style.color = 'red';
            out.innerText = "Invalid signature.";
        }

    } catch (err) {
        console.error(err);
        alert("Verification failed: " + err.message);
    }
}

/* ============================================================
   Key Generation — NOW Supports Keys Without Email
============================================================ */

async function generateKeys() {
    try {
        const name = document.getElementById("name").value.trim();
        const email = document.getElementById("email").value.trim();
        const passphrase = document.getElementById("passphrase").value;

        let userIdBlock;

        if (!email && !name) {
            // Allowed: fully anonymous key
            userIdBlock = [{}];
        } else if (!email) {
            // Name only
            userIdBlock = [{ name }];
        } else {
            // Normal name + email
            userIdBlock = [{ name, email }];
        }

        const { privateKeyArmored, publicKeyArmored } = await openpgp.generateKey({
            userIds: userIdBlock,
            numBits: 2048,
            passphrase
        });

        document.getElementById("privateKey").value =
            rewriteMetadata(privateKeyArmored, DEFAULT_COMMENT);

        document.getElementById("publicKey").value =
            rewriteMetadata(publicKeyArmored, DEFAULT_COMMENT);

    } catch (err) {
        console.error(err);
        alert("Key generation failed: " + err.message);
    }
}

/* ============================================================
   Initial state
============================================================ */

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".section-content").forEach(sec => {
        sec.style.display = "none";
    });
});
