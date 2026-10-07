const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, Timestamp } = require('firebase-admin/firestore');
const { createHash, randomUUID } = require('node:crypto');

initializeApp();
const db = getFirestore();

function normalizePhone(value) {
  let digits = String(value || '').replace(/\D/g, '');
  if (digits.length === 10) digits = `91${digits}`;
  if (digits.length < 11 || digits.length > 15) return '';
  return `+${digits}`;
}

function isAdultDateOfBirth(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value) return false;
  const today = new Date();
  let age = today.getUTCFullYear() - date.getUTCFullYear();
  if (today.getUTCMonth() < date.getUTCMonth() || (today.getUTCMonth() === date.getUTCMonth() && today.getUTCDate() < date.getUTCDate())) age--;
  return age >= 18;
}

async function checkRateLimit(phone, ip) {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  const buckets = [
    createHash('sha256').update(`phone:${phone}`).digest('hex'),
    createHash('sha256').update(`ip:${ip}`).digest('hex')
  ];
  await db.runTransaction(async tx => {
    const refs = buckets.map(key => db.collection('authRateLimits').doc(key));
    const snaps = await Promise.all(refs.map(ref => tx.get(ref)));
    for (const snap of snaps) {
      const data = snap.exists ? snap.data() : {};
      const start = data.windowStart?.toMillis?.() || 0;
      const count = now - start < windowMs ? (data.count || 0) : 0;
      if (count >= 8) throw new HttpsError('resource-exhausted', 'Too many attempts. Try again later.');
    }
    refs.forEach((ref, i) => {
      const data = snaps[i].exists ? snaps[i].data() : {};
      const start = data.windowStart?.toMillis?.() || 0;
      const inWindow = now - start < windowMs;
      tx.set(ref, {
        count: inWindow ? (data.count || 0) + 1 : 1,
        windowStart: inWindow ? data.windowStart : Timestamp.fromMillis(now)
      });
    });
  });
}

exports.loginWithPhoneAndDob = onCall({ maxInstances: 10 }, async request => {
  const phone = normalizePhone(request.data?.phone);
  const dob = String(request.data?.dateOfBirth || '');
  if (!phone || !/^\d{4}-\d{2}-\d{2}$/.test(dob)) {
    throw new HttpsError('invalid-argument', 'Enter a valid phone number and date of birth.');
  }

  const ip = request.rawRequest.ip || 'unknown';
  await checkRateLimit(phone, ip);

  const matches = await db.collection('privateProfiles').where('phone', '==', phone).limit(2).get();
  if (matches.size !== 1) throw new HttpsError('unauthenticated', 'Phone or date of birth did not match.');

  const privateProfile = matches.docs[0];
  if (privateProfile.data().dateOfBirth !== dob) {
    throw new HttpsError('unauthenticated', 'Phone or date of birth did not match.');
  }

  const customToken = await getAuth().createCustomToken(privateProfile.id);
  return { customToken };
});

exports.registerWithPhoneAndDob = onCall({ maxInstances: 10 }, async request => {
  const phone = normalizePhone(request.data?.phone);
  const dob = String(request.data?.dateOfBirth || '');
  if (!phone || !isAdultDateOfBirth(dob)) {
    throw new HttpsError('invalid-argument', 'Enter a valid phone number and date of birth. Users must be at least 18.');
  }

  const ip = request.rawRequest.ip || 'unknown';
  await checkRateLimit(phone, ip);

  const existingProfiles = await db.collection('privateProfiles').where('phone', '==', phone).limit(1).get();
  if (!existingProfiles.empty) throw new HttpsError('already-exists', 'This phone number is already registered.');

  const uid = randomUUID();
  const phoneKey = createHash('sha256').update(phone).digest('hex');
  const phoneAccountRef = db.collection('phoneAccounts').doc(phoneKey);
  const privateProfileRef = db.collection('privateProfiles').doc(uid);
  await db.runTransaction(async tx => {
    const existingAccount = await tx.get(phoneAccountRef);
    if (existingAccount.exists) throw new HttpsError('already-exists', 'This phone number is already registered.');
    tx.create(phoneAccountRef, { uid, createdAt: Timestamp.now() });
    tx.set(privateProfileRef, { phone, dateOfBirth: dob, email: '', updatedAt: Timestamp.now() });
  });

  try {
    await getAuth().createUser({ uid });
    const customToken = await getAuth().createCustomToken(uid);
    return { customToken };
  } catch (error) {
    await Promise.all([
      db.runTransaction(async tx => {
        const account = await tx.get(phoneAccountRef);
        if (account.exists && account.data().uid === uid) tx.delete(phoneAccountRef);
        tx.delete(privateProfileRef);
      }),
      getAuth().deleteUser(uid).catch(() => {})
    ]);
    throw error;
  }
});
