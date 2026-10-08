const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, Timestamp, FieldPath } = require('firebase-admin/firestore');
const { createHash, randomUUID, createHmac, timingSafeEqual } = require('node:crypto');

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
  const contactPhone = normalizePhone(request.data?.contactPhone);
  const dob = String(request.data?.dateOfBirth || '');
  if (!phone || !contactPhone || !isAdultDateOfBirth(dob)) {
    throw new HttpsError('invalid-argument', 'Enter valid sign-in and contact phone numbers and date of birth. Users must be at least 18.');
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
    tx.set(privateProfileRef, { phone, contactPhone, dateOfBirth: dob, email: '', updatedAt: Timestamp.now() });
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


const ADMIN_EMAIL = 'muzellamedia@gmail.com';
const PREMIUM_PLANS = { 6: 599, 12: 1199 };
const ADMIN_PASSWORD = defineSecret('ADMIN_PASSWORD');
const ADMIN_SESSION_TTL_MS = 60 * 60 * 1000;

function signAdminPayload(encodedPayload) {
  return createHmac('sha256', ADMIN_PASSWORD.value()).update(encodedPayload).digest('base64url');
}

function issueAdminSession() {
  const payload = Buffer.from(JSON.stringify({ email: ADMIN_EMAIL, exp: Date.now() + ADMIN_SESSION_TTL_MS })).toString('base64url');
  return `${payload}.${signAdminPayload(payload)}`;
}

function requireAdmin(request) {
  const token = String(request.data?.adminSession || '');
  const [payload, signature, extra] = token.split('.');
  if (!payload || !signature || extra !== undefined) throw new HttpsError('unauthenticated', 'Administrator session is required.');
  const expected = Buffer.from(signAdminPayload(payload));
  const received = Buffer.from(signature);
  if (expected.length !== received.length || !timingSafeEqual(expected, received)) throw new HttpsError('unauthenticated', 'Administrator session is invalid.');
  let data;
  try { data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); }
  catch { throw new HttpsError('unauthenticated', 'Administrator session is invalid.'); }
  if (data.email !== ADMIN_EMAIL || !Number.isFinite(data.exp) || data.exp <= Date.now()) throw new HttpsError('unauthenticated', 'Administrator session has expired. Sign in again.');
  return data.email;
}

async function checkAdminLoginRateLimit(ip, failed) {
  const ref = db.collection('authRateLimits').doc(createHash('sha256').update(`admin:${ip}`).digest('hex'));
  const now = Date.now(), windowMs = 15 * 60 * 1000;
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref), data = snap.exists ? snap.data() : {};
    const start = data.windowStart?.toMillis?.() || 0;
    const count = now - start < windowMs ? (data.count || 0) : 0;
    if (count >= 5) throw new HttpsError('resource-exhausted', 'Too many attempts. Try again in 15 minutes.');
    if (failed) tx.set(ref, { count: count + 1, windowStart: now - start < windowMs ? data.windowStart : Timestamp.fromMillis(now) });
    else if (snap.exists) tx.delete(ref);
  });
}

exports.adminLogin = onCall({ secrets: [ADMIN_PASSWORD], maxInstances: 3 }, async request => {
  const email = String(request.data?.email || '').trim().toLowerCase();
  const password = String(request.data?.password || '').slice(0, 1024);
  const expected = Buffer.from(ADMIN_PASSWORD.value());
  const supplied = Buffer.from(password);
  const matches = expected.length === supplied.length && timingSafeEqual(expected, supplied);
  const ip = request.rawRequest.ip || 'unknown';
  await checkAdminLoginRateLimit(ip, email !== ADMIN_EMAIL || !matches);
  if (email !== ADMIN_EMAIL || !matches) throw new HttpsError('unauthenticated', 'Email or password was not accepted.');
  return { adminSession: issueAdminSession(), expiresInMs: ADMIN_SESSION_TTL_MS };
});

function addMonthsUtc(start, months) {
  const result = new Date(start.getTime());
  const day = result.getUTCDate();
  result.setUTCDate(1);
  result.setUTCMonth(result.getUTCMonth() + months);
  const finalDay = new Date(Date.UTC(result.getUTCFullYear(), result.getUTCMonth() + 1, 0)).getUTCDate();
  result.setUTCDate(Math.min(day, finalDay));
  return Timestamp.fromDate(result);
}

exports.recordPremiumRequest = onCall({ maxInstances: 10 }, async request => {
  if (!request.auth) throw new HttpsError('unauthenticated', 'Sign in to continue.');
  const months = Number(request.data?.months);
  if (![6, 12].includes(months)) throw new HttpsError('invalid-argument', 'Choose a 6 or 12 month plan.');
  const profileSnap = await db.collection('profiles').doc(request.auth.uid).get();
  if (!profileSnap.exists || profileSnap.data().gender !== 'Man') {
    throw new HttpsError('failed-precondition', 'This premium plan is for male profiles.');
  }
  const now = Timestamp.now();
  const requestRef = db.collection('premiumRequests').doc(request.auth.uid);
  const subscriptionRef = db.collection('premiumSubscriptions').doc(request.auth.uid);
  await db.runTransaction(async tx => {
    const [subscriptionSnap, requestSnap] = await Promise.all([tx.get(subscriptionRef), tx.get(requestRef)]);
    const activeUntil = subscriptionSnap.data()?.activeUntil;
    if (subscriptionSnap.exists && activeUntil?.toMillis?.() > now.toMillis()) {
      throw new HttpsError('already-exists', 'Premium is already active on this account.');
    }
    const lastRequest = requestSnap.data()?.requestedAt?.toMillis?.() || 0;
    if (now.toMillis() - lastRequest < 60 * 1000) {
      throw new HttpsError('resource-exhausted', 'Please wait before selecting a plan again.');
    }
    tx.set(requestRef, {
      uid: request.auth.uid,
      planMonths: months,
      amountInr: PREMIUM_PLANS[months],
      status: 'payment_clicked',
      requestedAt: now,
      updatedAt: now
    });
  });
  return { recorded: true, amountInr: PREMIUM_PLANS[months] };
});

exports.getPremiumStatus = onCall({ maxInstances: 10 }, async request => {
  if (!request.auth) throw new HttpsError('unauthenticated', 'Sign in to continue.');
  const snap = await db.collection('premiumSubscriptions').doc(request.auth.uid).get();
  const activeUntil = snap.data()?.activeUntil;
  return { active: Boolean(activeUntil && activeUntil.toMillis() > Date.now()), activeUntilMillis: activeUntil?.toMillis?.() || null };
});

exports.adminListMembers = onCall({ secrets: [ADMIN_PASSWORD], maxInstances: 5 }, async request => {
  const adminEmail = requireAdmin(request);
  const filter = request.data?.filter === 'payment' ? 'payment' : 'all';
  const cursor = typeof request.data?.cursor === 'string' ? request.data.cursor : '';
  const base = filter === 'payment' ? db.collection('premiumRequests') : db.collection('privateProfiles');
  let query = base.orderBy(FieldPath.documentId()).limit(50);
  if (cursor) query = query.startAfter(cursor);
  const page = await query.get();
  const rows = await Promise.all(page.docs.map(async item => {
    const uid = item.id;
    const [profileSnap, privateSnap, requestSnap, subscriptionSnap] = await Promise.all([
      db.collection('profiles').doc(uid).get(),
      filter === 'payment' ? db.collection('privateProfiles').doc(uid).get() : Promise.resolve(item),
      filter === 'payment' ? Promise.resolve(item) : db.collection('premiumRequests').doc(uid).get(),
      db.collection('premiumSubscriptions').doc(uid).get()
    ]);
    if (!profileSnap.exists && filter === 'payment') return null;
    const profile = profileSnap.data() || {}, privateProfile = privateSnap.data() || {}, premiumRequest = requestSnap.data() || {}, subscription = subscriptionSnap.data() || {};
    return {
      uid, name: profile.name || '', phone: privateProfile.contactPhone || privateProfile.phone || '', gender: profile.gender || '',
      age: Number(profile.age) || null, state: profile.state || '', district: profile.district || '',
      requestStatus: premiumRequest.status || '', planMonths: Number(premiumRequest.planMonths) || null,
      amountInr: Number(premiumRequest.amountInr) || null,
      requestedAtMillis: premiumRequest.requestedAt?.toMillis?.() || null,
      activeUntilMillis: subscription.activeUntil?.toMillis?.() || null,
      premiumActive: Boolean(subscription.activeUntil && subscription.activeUntil.toMillis() > Date.now())
    };
  }));
  return { members: rows.filter(Boolean), nextCursor: page.size === 50 ? page.docs[page.docs.length - 1].id : null };
});

exports.adminActivatePremium = onCall({ secrets: [ADMIN_PASSWORD], maxInstances: 5 }, async request => {
  const adminEmail = requireAdmin(request);
  const uid = String(request.data?.uid || '');
  const months = Number(request.data?.months);
  if (!uid || uid.length > 128 || uid.includes('/') || ![6, 12].includes(months)) {
    throw new HttpsError('invalid-argument', 'Choose a member and a valid 6 or 12 month plan.');
  }
  const profileRef = db.collection('profiles').doc(uid);
  const subscriptionRef = db.collection('premiumSubscriptions').doc(uid);
  const requestRef = db.collection('premiumRequests').doc(uid);
  const now = Timestamp.now();
  const activated = await db.runTransaction(async tx => {
    const [profileSnap, subscriptionSnap, premiumRequestSnap] = await Promise.all([tx.get(profileRef), tx.get(subscriptionRef), tx.get(requestRef)]);
    if (!profileSnap.exists || profileSnap.data().gender !== 'Man') throw new HttpsError('not-found', 'Male member profile was not found.');
    if (!premiumRequestSnap.exists || premiumRequestSnap.data().status !== 'payment_clicked') throw new HttpsError('failed-precondition', 'This member has not selected a premium payment plan.');
    if (Number(premiumRequestSnap.data().planMonths) !== months) throw new HttpsError('failed-precondition', 'The activation duration must match the selected payment plan.');
    const previous = subscriptionSnap.data()?.activeUntil;
    const start = previous && previous.toMillis() > now.toMillis() ? previous.toDate() : now.toDate();
    const activeUntil = addMonthsUtc(start, months);
    tx.set(subscriptionRef, {
      uid, planMonths: months, amountInr: PREMIUM_PLANS[months], activeUntil,
      activatedAt: now, activatedBy: adminEmail, updatedAt: now
    });
    if (premiumRequestSnap.exists) tx.update(requestRef, { status: 'activated', activatedAt: now, activatedBy: adminEmail, activatedPlanMonths: months, updatedAt: now });
    return activeUntil.toMillis();
  });
  return { activeUntilMillis: activated };
});
