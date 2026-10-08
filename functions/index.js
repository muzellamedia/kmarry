const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, Timestamp, FieldPath } = require('firebase-admin/firestore');
const { getStorage } = require('firebase-admin/storage');
const { createHash, randomUUID, createHmac, timingSafeEqual } = require('node:crypto');

initializeApp();
const db = getFirestore();

function normalizePhone(value) {
  let digits = String(value || '').replace(/\D/g, '');
  if (digits.length === 10) digits = `91${digits}`;
  if (digits.length < 11 || digits.length > 15) return '';
  return `+${digits}`;
}

function isDisabledProfile(profile) {
  return Boolean(profile?.disability && profile.disability !== 'Normal person');
}

function requiresPremium(profile) {
  return profile?.gender === 'Man' && !isDisabledProfile(profile);
}

async function requireActiveMember(uid) {
  const snapshot = await db.collection('profiles').doc(uid).get();
  if (!snapshot.exists) throw new HttpsError('failed-precondition', 'Complete your profile first.');
  if (snapshot.data().blocked === true) throw new HttpsError('permission-denied', 'This account is blocked.');
  return snapshot.data();
}

exports.listMatches = onCall({ maxInstances: 10 }, async request => {
  if (!request.auth) throw new HttpsError('unauthenticated', 'Sign in to view matches.');
  const viewer = await requireActiveMember(request.auth.uid);
  if (!viewer.religion) throw new HttpsError('failed-precondition', 'Select a religion in your profile to find matches.');
  const matches = await db.collection('profiles').where('religion', '==', viewer.religion).get();
  const profiles = matches.docs.filter(doc => doc.id !== request.auth.uid).map(doc => doc.data())
    .filter(profile => !isDisabledProfile(viewer) || isDisabledProfile(profile));
  return { profiles };
});

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

  const profile = await db.collection('profiles').doc(privateProfile.id).get();
  if (profile.data()?.blocked === true) throw new HttpsError('permission-denied', 'This account is blocked. Contact the administrator.');

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
    tx.set(privateProfileRef, { phone, contactPhone, dateOfBirth: dob, email: '', createdAt: Timestamp.now(), updatedAt: Timestamp.now() });
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

function indiaDateKeys(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Asia/Kolkata', year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(date);
  const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return { day: `${values.year}${values.month}${values.day}`, month: `${values.year}${values.month}` };
}

function serializeAdminRecord(data = {}) {
  return Object.fromEntries(Object.entries(data).map(([key, value]) => [key, value?.toMillis ? value.toMillis() : value]));
}

async function deleteMemberData(uid) {
  const privateRef = db.collection('privateProfiles').doc(uid);
  const privateSnap = await privateRef.get();
  const phone = privateSnap.data()?.phone;
  const phoneAccountRef = phone ? db.collection('phoneAccounts').doc(createHash('sha256').update(phone).digest('hex')) : null;
  await db.runTransaction(async tx => {
    if (phoneAccountRef) {
      const account = await tx.get(phoneAccountRef);
      if (account.exists && account.data().uid === uid) tx.delete(phoneAccountRef);
    }
    tx.delete(db.collection('profiles').doc(uid));
    tx.delete(privateRef);
    tx.delete(db.collection('premiumRequests').doc(uid));
    tx.delete(db.collection('premiumSubscriptions').doc(uid));
  });
  let paymentPage;
  do {
    paymentPage = await db.collection('premiumPayments').where('uid', '==', uid).limit(200).get();
    if (!paymentPage.empty) {
      const batch = db.batch();
      paymentPage.docs.forEach(payment => {
        const anonymized = { ...payment.data() };
        delete anonymized.uid;
        batch.set(db.collection('premiumPayments').doc(), anonymized);
        batch.delete(payment.ref);
      });
      await batch.commit();
    }
  } while (paymentPage.size === 200);
  for (const field of ['senderUid', 'recipientUid']) {
    let page;
    do {
      page = await db.collection('interests').where(field, '==', uid).limit(400).get();
      if (!page.empty) {
        const batch = db.batch();
        page.docs.forEach(doc => batch.delete(doc.ref));
        await batch.commit();
      }
    } while (page.size === 400);
  }
  await getStorage().bucket().deleteFiles({ prefix: `profilePhotos/${uid}/` }).catch(error => {
    if (error.code !== 404 && error.code !== '404') throw error;
  });
  try { await getAuth().deleteUser(uid); }
  catch (error) { if (error.code !== 'auth/user-not-found') throw error; }
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
  const member = await requireActiveMember(request.auth.uid);
  const months = Number(request.data?.months);
  if (![6, 12].includes(months)) throw new HttpsError('invalid-argument', 'Choose a 6 or 12 month plan.');
  if (!requiresPremium(member)) {
    throw new HttpsError('failed-precondition', 'Premium is available only to men without a disability.');
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
  const [profile, snap] = await Promise.all([
    requireActiveMember(request.auth.uid),
    db.collection('premiumSubscriptions').doc(request.auth.uid).get()
  ]);
  const freeAccess = !requiresPremium(profile);
  const activeUntil = snap.data()?.activeUntil;
  return { active: Boolean(activeUntil && activeUntil.toMillis() > Date.now()), freeAccess, activeUntilMillis: activeUntil?.toMillis?.() || null };
});

exports.deleteMyAccount = onCall({ maxInstances: 5 }, async request => {
  if (!request.auth) throw new HttpsError('unauthenticated', 'Sign in before deleting your account.');
  await deleteMemberData(request.auth.uid);
  return { deleted: true };
});

exports.adminListMembers = onCall({ secrets: [ADMIN_PASSWORD], maxInstances: 5 }, async request => {
  const adminEmail = requireAdmin(request);
  const filter = request.data?.filter === 'payment' ? 'payment' : 'all';
  const cursor = typeof request.data?.cursor === 'string' ? request.data.cursor : '';
  const filters = request.data?.filters && typeof request.data.filters === 'object' ? request.data.filters : {};
  const genderFilter = ['Man', 'Woman'].includes(filters.gender) ? filters.gender : '';
  const religionFilter = typeof filters.religion === 'string' ? filters.religion.trim().slice(0, 80) : '';
  const phoneFilter = String(filters.phone || '').replace(/\D/g, '').slice(-15);
  const premiumOnly = filters.premium === true;
  const newOnly = filters.newUser === true;
  const disabilityOnly = filters.disability === true;
  const base = filter === 'payment' ? db.collection('premiumRequests') : db.collection('privateProfiles');
  const now = Date.now(), newSince = now - 30 * 24 * 60 * 60 * 1000;
  const members = [];
  let lastScanned = cursor, exhausted = false, scanCount = 0;
  while (members.length < 50 && !exhausted && scanCount < 1000) {
    let query = base.orderBy(FieldPath.documentId()).limit(100);
    if (lastScanned) query = query.startAfter(lastScanned);
    const page = await query.get();
    if (page.empty) { exhausted = true; break; }
    scanCount += page.size;
    const ids = page.docs.map(item => item.id);
    const authCreationByUid = new Map();
    const authUsers = await getAuth().getUsers(ids.map(uid => ({ uid })));
    for (const user of authUsers.users) {
      const createdAt = user.metadata?.creationTime ? Date.parse(user.metadata.creationTime) : 0;
      if (createdAt) authCreationByUid.set(user.uid, createdAt);
    }
    const rows = await Promise.all(page.docs.map(async item => {
      const uid = item.id;
      const [profileSnap, privateSnap, requestSnap, subscriptionSnap] = await Promise.all([
        db.collection('profiles').doc(uid).get(),
        filter === 'payment' ? db.collection('privateProfiles').doc(uid).get() : Promise.resolve(item),
        filter === 'payment' ? Promise.resolve(item) : db.collection('premiumRequests').doc(uid).get(),
        db.collection('premiumSubscriptions').doc(uid).get()
      ]);
      if (!profileSnap.exists || !privateSnap.exists) return null;
      const profile = profileSnap.data() || {}, privateProfile = privateSnap.data() || {}, premiumRequest = requestSnap.data() || {}, subscription = subscriptionSnap.data() || {};
      const premiumActive = Boolean(subscription.activeUntil && subscription.activeUntil.toMillis() > now);
      const createdAtMillis = privateProfile.createdAt?.toMillis?.() || authCreationByUid.get(uid) || 0;
      const phoneDigits = [privateProfile.contactPhone, privateProfile.phone].map(value => String(value || '').replace(/\D/g, ''));
      const hasDisability = Boolean(profile.disability && !/^normal person$/i.test(profile.disability.trim()));
      if (genderFilter && profile.gender !== genderFilter) return null;
      if (religionFilter && profile.religion !== religionFilter) return null;
      if (phoneFilter && !phoneDigits.some(value => value.endsWith(phoneFilter))) return null;
      if (premiumOnly && !premiumActive) return null;
      if (newOnly && createdAtMillis < newSince) return null;
      if (disabilityOnly && !hasDisability) return null;
      return {
        uid, name: profile.name || '', phone: privateProfile.contactPhone || privateProfile.phone || '', gender: profile.gender || '',
        age: Number(profile.age) || null, religion: profile.religion || '', disability: profile.disability || '',
        state: profile.state || '', district: profile.district || '',
        requestStatus: premiumRequest.status || '', planMonths: Number(premiumRequest.planMonths) || null,
        amountInr: Number(premiumRequest.amountInr) || null,
        requestedAtMillis: premiumRequest.requestedAt?.toMillis?.() || null,
        createdAtMillis,
        activeUntilMillis: subscription.activeUntil?.toMillis?.() || null,
        premiumActive,
        blocked: profile.blocked === true,
        profile: serializeAdminRecord(profile),
        privateProfile: serializeAdminRecord(privateProfile),
        cursorId: uid
      };
    }));
    for (const row of rows) {
      lastScanned = row?.cursorId || lastScanned;
      if (row) members.push(row);
      if (members.length === 50) break;
    }
    if (members.length < 50) lastScanned = page.docs[page.docs.length - 1].id;
    if (page.size < 100) exhausted = true;
  }
  const hasMore = !exhausted;
  members.forEach(member => delete member.cursorId);
  return { members, nextCursor: hasMore ? lastScanned : null };
});

exports.adminGetDashboardStats = onCall({ secrets: [ADMIN_PASSWORD], maxInstances: 3 }, async request => {
  requireAdmin(request);
  const now = Timestamp.now(), thirtyDaysAgo = Timestamp.fromMillis(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const todayKey = indiaDateKeys().day, monthKey = indiaDateKeys().month;
  const gender = { Man: 0, Woman: 0 }, disability = { Man: 0, Woman: 0 }, religions = {};
  let cursor = null;
  while (true) {
    let pageQuery = db.collection('profiles').select('gender', 'religion', 'disability')
      .orderBy(FieldPath.documentId()).limit(1000);
    if (cursor) pageQuery = pageQuery.startAfter(cursor);
    const page = await pageQuery.get();
    if (page.empty) break;
    for (const doc of page.docs) {
      const profile = doc.data(), memberGender = profile.gender === 'Man' ? 'Man' : profile.gender === 'Woman' ? 'Woman' : '';
      if (!memberGender) continue;
      gender[memberGender]++;
      const hasDisability = Boolean(profile.disability && !/^normal person$/i.test(String(profile.disability).trim()));
      if (hasDisability) disability[memberGender]++;
      const religion = String(profile.religion || 'Not specified').trim().slice(0, 80) || 'Not specified';
      religions[religion] ||= { Man: 0, Woman: 0 };
      religions[religion][memberGender]++;
    }
    cursor = page.docs[page.docs.length - 1];
    if (page.size < 1000) break;
  }

  const [newMembersResult, subscriptionsSnapshot, totalVisitorsResult, todayVisitorsResult, paymentsSnapshot, legacyRequests] = await Promise.all([
    db.collection('privateProfiles').where('createdAt', '>=', thirtyDaysAgo).count().get(),
    db.collection('premiumSubscriptions').get(),
    db.collection('siteVisitors').count().get(),
    db.collection('siteVisitorDays').where('day', '==', todayKey).count().get(),
    db.collection('premiumPayments').get(),
    db.collection('premiumRequests').where('status', '==', 'activated').get()
  ]);
  const premiumMembers = subscriptionsSnapshot.docs.filter(item => item.data().activeUntil?.toMillis?.() > now.toMillis()).length;
  let totalIncome = 0, monthIncome = 0;
  const ledgerUsers = new Set();
  for (const payment of paymentsSnapshot.docs) {
    const data = payment.data(), amount = Number(data.amountInr) || 0;
    if (data.uid) ledgerUsers.add(data.uid);
    totalIncome += amount;
    if (data.paidAt?.toDate && indiaDateKeys(data.paidAt.toDate()).month === monthKey) monthIncome += amount;
  }
  // Older verified requests predate the append-only payment ledger. They are retained
  // in the per-member request record, so include them only until a ledger entry exists.
  const legacyRequestUsers = new Set();
  for (const request of legacyRequests.docs) {
    const data = request.data();
    if (data.paymentLedgerId) continue;
    legacyRequestUsers.add(request.id);
    const amount = Number(data.amountInr) || 0;
    totalIncome += amount;
    if (data.activatedAt?.toDate && indiaDateKeys(data.activatedAt.toDate()).month === monthKey) monthIncome += amount;
  }
  // Pre-ledger manual activations had only the latest subscription document.
  // Include that last recorded plan when no payment request or ledger entry exists.
  for (const subscription of subscriptionsSnapshot.docs) {
    if (ledgerUsers.has(subscription.id) || legacyRequestUsers.has(subscription.id)) continue;
    const data = subscription.data(), amount = Number(data.amountInr) || 0;
    totalIncome += amount;
    if (data.activatedAt?.toDate && indiaDateKeys(data.activatedAt.toDate()).month === monthKey) monthIncome += amount;
  }

  return {
    members: { male: gender.Man, female: gender.Woman, newLast30Days: newMembersResult.data().count },
    disability: { male: disability.Man, female: disability.Woman },
    religions: Object.entries(religions).sort(([a], [b]) => a.localeCompare(b))
      .map(([name, counts]) => ({ name, male: counts.Man, female: counts.Woman })),
    premiumMembers,
    visitors: { total: totalVisitorsResult.data().count, today: todayVisitorsResult.data().count },
    income: { totalInr: totalIncome, monthInr: monthIncome, monthKey }
  };
});

exports.recordSiteVisit = onCall({ maxInstances: 5 }, async request => {
  const visitorId = String(request.data?.visitorId || '');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(visitorId)) {
    throw new HttpsError('invalid-argument', 'A valid visitor identifier is required.');
  }
  const visitorKey = createHash('sha256').update(visitorId).digest('hex');
  const { day } = indiaDateKeys();
  const now = Timestamp.now();
  const ip = String(request.rawRequest?.ip || 'unknown').slice(0, 120);
  const rateKey = createHash('sha256').update(`${day}:${ip}`).digest('hex');
  const visitorRef = db.collection('siteVisitors').doc(visitorKey);
  const dayVisitRef = db.collection('siteVisitorDays').doc(`${day}_${visitorKey}`);
  const rateRef = db.collection('siteVisitRateLimits').doc(rateKey);
  await db.runTransaction(async tx => {
    const [visitorSnap, dayVisitSnap, rateSnap] = await Promise.all([tx.get(visitorRef), tx.get(dayVisitRef), tx.get(rateRef)]);
    if (visitorSnap.exists) tx.update(visitorRef, { lastSeenAt: now });
    else tx.create(visitorRef, { firstSeenAt: now, lastSeenAt: now });
    if (!dayVisitSnap.exists) {
      const dailyNewVisitors = Number(rateSnap.data()?.count) || 0;
      if (dailyNewVisitors >= 1000) throw new HttpsError('resource-exhausted', 'Daily visitor reporting limit reached.');
      tx.create(dayVisitRef, { day, firstSeenAt: now });
      tx.set(rateRef, { count: dailyNewVisitors + 1, updatedAt: now });
    }
  });
  return { recorded: true };
});

exports.adminUpdateMember = onCall({ secrets: [ADMIN_PASSWORD], maxInstances: 5 }, async request => {
  requireAdmin(request);
  const uid = String(request.data?.uid || ''), profileInput = request.data?.profile || {}, privateInput = request.data?.privateProfile || {};
  if (!uid || uid.length > 128 || uid.includes('/') || !profileInput || typeof profileInput !== 'object' || !privateInput || typeof privateInput !== 'object') {
    throw new HttpsError('invalid-argument', 'Choose a member and provide valid profile details.');
  }
  const profileFields = ['name', 'gender', 'height', 'religion', 'community', 'disability', 'state', 'district', 'place', 'education', 'occupation', 'maritalStatus', 'bodyType', 'bodyColour', 'financialStatus', 'childrenStatus', 'employedIn', 'familyStatus', 'familyType', 'about', 'photoUrl'];
  const profileUpdate = {};
  for (const [key, value] of Object.entries(profileInput)) {
    if (!profileFields.includes(key) && !['age', 'brothers', 'sisters'].includes(key)) throw new HttpsError('invalid-argument', `Field ${key} cannot be edited.`);
    if (key === 'age' || key === 'brothers' || key === 'sisters') {
      const age = Number(value);
      if (!Number.isInteger(age) || (key === 'age' ? age < 18 || age > 100 : age < 0 || age > 20)) throw new HttpsError('invalid-argument', key === 'age' ? 'Age must be from 18 to 100.' : 'Sibling counts must be from 0 to 20.');
      profileUpdate[key] = age;
    } else {
      if (typeof value !== 'string' || value.length > (key === 'about' ? 200 : key === 'photoUrl' ? 2000 : key === 'occupation' ? 100 : 120)) throw new HttpsError('invalid-argument', `${key} has an invalid value.`);
      profileUpdate[key] = value.trim();
    }
  }
  for (const key of ['name', 'gender', 'religion', 'disability', 'state', 'district', 'place', 'education', 'maritalStatus']) {
    if (key in profileUpdate && !profileUpdate[key]) throw new HttpsError('invalid-argument', `${key} is required.`);
  }
  if (profileUpdate.about && /\d/.test(profileUpdate.about)) throw new HttpsError('invalid-argument', 'About me cannot contain numbers.');
  const privateUpdate = {};
  if ('phone' in privateInput) {
    const phone = normalizePhone(privateInput.phone);
    if (!phone) throw new HttpsError('invalid-argument', 'Enter a valid registered sign-in phone number.');
    privateUpdate.phone = phone;
  }
  if ('contactPhone' in privateInput) {
    const contactPhone = normalizePhone(privateInput.contactPhone);
    if (!contactPhone) throw new HttpsError('invalid-argument', 'Enter a valid contact phone number.');
    privateUpdate.contactPhone = contactPhone;
  }
  if ('dateOfBirth' in privateInput) {
    const dateOfBirth = String(privateInput.dateOfBirth || '');
    if (!isAdultDateOfBirth(dateOfBirth)) throw new HttpsError('invalid-argument', 'Date of birth must confirm the member is at least 18.');
    privateUpdate.dateOfBirth = dateOfBirth;
    const birthDate = new Date(`${dateOfBirth}T00:00:00.000Z`), now = new Date();
    let age = now.getUTCFullYear() - birthDate.getUTCFullYear();
    if (now.getUTCMonth() < birthDate.getUTCMonth() || (now.getUTCMonth() === birthDate.getUTCMonth() && now.getUTCDate() < birthDate.getUTCDate())) age--;
    profileUpdate.age = age;
  }
  if (profileUpdate.gender && !['Woman', 'Man'].includes(profileUpdate.gender)) throw new HttpsError('invalid-argument', 'Choose a valid gender.');
  const enumOptions = {
    maritalStatus: ['Never Married', 'Divorced', 'Widowed', 'Separated', 'Awaiting Divorce', 'Nikah Divorced / Talaq'],
    bodyType: ['Slim', 'Average', 'Athletic', 'Heavy', 'Prefer not to say'],
    bodyColour: ['Fair', 'Wheatish', 'Medium', 'Dark', 'Prefer not to say'],
    financialStatus: ['Lower income', 'Middle income', 'Upper-middle income', 'High income', 'Prefer not to say'],
    childrenStatus: ['No children', 'Have children', 'Prefer not to say'],
    employedIn: ['Private', 'Government', 'Business', 'Self Employed', 'Not Working'],
    familyStatus: ['Lower Middle Class', 'Middle Class', 'Upper Middle Class', 'Affluent', 'Prefer not to say'],
    familyType: ['Nuclear Family', 'Joint Family', 'Prefer not to say']
  };
  for (const [key, options] of Object.entries(enumOptions)) if (profileUpdate[key] && !options.includes(profileUpdate[key])) throw new HttpsError('invalid-argument', `Choose a valid ${key}.`);
  if (profileUpdate.disability && profileUpdate.disability.length > 120) throw new HttpsError('invalid-argument', 'Choose a valid disability option.');
  if (profileUpdate.place || profileUpdate.district || profileUpdate.state) {
    const existing = await db.collection('profiles').doc(uid).get();
    if (!existing.exists) throw new HttpsError('not-found', 'Member profile was not found.');
    const data = existing.data();
    profileUpdate.location = [profileUpdate.place ?? data.place, profileUpdate.district ?? data.district, profileUpdate.state ?? data.state].filter(Boolean).join(', ');
  }
  profileUpdate.updatedAt = Timestamp.now();
  privateUpdate.updatedAt = Timestamp.now();
  await db.runTransaction(async tx => {
    const profileRef = db.collection('profiles').doc(uid), privateRef = db.collection('privateProfiles').doc(uid);
    const [profileSnap, privateSnap] = await Promise.all([tx.get(profileRef), tx.get(privateRef)]);
    if (!profileSnap.exists || !privateSnap.exists) throw new HttpsError('not-found', 'Member account was not found.');
    if (privateUpdate.phone && privateUpdate.phone !== privateSnap.data().phone) {
      const oldPhone = privateSnap.data().phone || '';
      const oldAccountRef = oldPhone ? db.collection('phoneAccounts').doc(createHash('sha256').update(oldPhone).digest('hex')) : null;
      const newAccountRef = db.collection('phoneAccounts').doc(createHash('sha256').update(privateUpdate.phone).digest('hex'));
      const [oldAccountSnap, newAccountSnap] = await Promise.all([
        oldAccountRef ? tx.get(oldAccountRef) : Promise.resolve(null), tx.get(newAccountRef)
      ]);
      if (newAccountSnap.exists && newAccountSnap.data().uid !== uid) throw new HttpsError('already-exists', 'That registered phone number belongs to another account.');
      if (oldAccountRef && oldAccountSnap?.exists && oldAccountSnap.data().uid === uid && oldAccountRef.path !== newAccountRef.path) tx.delete(oldAccountRef);
      if (!newAccountSnap.exists) tx.create(newAccountRef, { uid, createdAt: Timestamp.now() });
    }
    tx.update(profileRef, profileUpdate);
    tx.update(privateRef, privateUpdate);
  });
  return { updated: true };
});

exports.adminSetMemberBlocked = onCall({ secrets: [ADMIN_PASSWORD], maxInstances: 5 }, async request => {
  requireAdmin(request);
  const uid = String(request.data?.uid || ''), blocked = request.data?.blocked;
  if (!uid || uid.length > 128 || uid.includes('/') || typeof blocked !== 'boolean') throw new HttpsError('invalid-argument', 'Choose a member and block status.');
  const profileRef = db.collection('profiles').doc(uid);
  const profileSnap = await profileRef.get();
  if (!profileSnap.exists) throw new HttpsError('not-found', 'Member profile was not found.');
  if (blocked) {
    await profileRef.update({ blocked: true, updatedAt: Timestamp.now() });
    await getAuth().updateUser(uid, { disabled: true });
  } else {
    await getAuth().updateUser(uid, { disabled: false });
    await profileRef.update({ blocked: false, updatedAt: Timestamp.now() });
  }
  return { blocked };
});

exports.adminDeleteMember = onCall({ secrets: [ADMIN_PASSWORD], maxInstances: 3 }, async request => {
  requireAdmin(request);
  const uid = String(request.data?.uid || '');
  if (!uid || uid.length > 128 || uid.includes('/')) throw new HttpsError('invalid-argument', 'Choose a valid member.');
  await deleteMemberData(uid);
  return { deleted: true };
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
  const paymentRef = db.collection('premiumPayments').doc();
  const legacyPaymentRef = db.collection('premiumPayments').doc(`legacy_${uid}`);
  const now = Timestamp.now();
  const activated = await db.runTransaction(async tx => {
    const [profileSnap, subscriptionSnap, premiumRequestSnap, legacyPaymentSnap] = await Promise.all([
      tx.get(profileRef), tx.get(subscriptionRef), tx.get(requestRef), tx.get(legacyPaymentRef)
    ]);
    if (!profileSnap.exists || !requiresPremium(profileSnap.data())) throw new HttpsError('not-found', 'Premium eligible member profile was not found.');
    const previous = subscriptionSnap.data()?.activeUntil;
    const start = previous && previous.toMillis() > now.toMillis() ? previous.toDate() : now.toDate();
    const activeUntil = addMonthsUtc(start, months);
    if (!legacyPaymentSnap.exists) {
      const requestData = premiumRequestSnap.data() || {}, subscriptionData = subscriptionSnap.data() || {};
      const legacy = requestData.status === 'activated'
        ? (!requestData.paymentLedgerId ? { amountInr: requestData.amountInr, planMonths: requestData.activatedPlanMonths || requestData.planMonths, paidAt: requestData.activatedAt } : null)
        : subscriptionSnap.exists
          ? { amountInr: subscriptionData.amountInr, planMonths: subscriptionData.planMonths, paidAt: subscriptionData.activatedAt }
          : null;
      if (legacy && Number(legacy.amountInr) > 0) tx.create(legacyPaymentRef, {
        uid, amountInr: Number(legacy.amountInr), planMonths: Number(legacy.planMonths) || null,
        paidAt: legacy.paidAt || now, source: 'legacy_migration', recordedBy: adminEmail
      });
    }
    tx.set(subscriptionRef, {
      uid, planMonths: months, amountInr: PREMIUM_PLANS[months], activeUntil,
      activatedAt: now, activatedBy: adminEmail, updatedAt: now
    });
    tx.create(paymentRef, {
      uid, planMonths: months, amountInr: PREMIUM_PLANS[months], paidAt: now,
      recordedBy: adminEmail, source: premiumRequestSnap.exists ? 'payment_request' : 'manual_activation'
    });
    if (premiumRequestSnap.exists) tx.update(requestRef, {
      status: 'activated', activatedAt: now, activatedBy: adminEmail,
      activatedPlanMonths: months, paymentLedgerId: paymentRef.id, updatedAt: now
    });
    return activeUntil.toMillis();
  });
  return { activeUntilMillis: activated };
});
