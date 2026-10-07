# Production setup

## Admin account

- Admin sign-in is separate from Firebase Authentication. The administrator enters `muzellamedia@gmail.com` and a password; the `adminLogin` Cloud Function checks them against the `ADMIN_PASSWORD` Secret Manager value and returns a signed session that expires after one hour. Admin member listing and premium activation verify that signed session server-side on every call.
- Set a new, strong password (do not reuse the password previously shared in chat) from the repository root with `firebase functions:secrets:set ADMIN_PASSWORD`. Enter the password only at the CLI prompt; never put it in source code, a command argument, GitHub, or a screenshot. The secret is required by `adminLogin`, `adminListMembers`, and `adminActivatePremium`.
- After setting the secret, deploy the functions with `firebase deploy --only functions`. Firebase Authentication remains in use for member phone/date-of-birth accounts, but the admin path does not use Firebase Authentication.
- Admin login attempts are limited by IP using hashed identifiers in Firestore. A browser session token is held in session storage and expires after one hour; signing out clears it.

## Premium payments

- Registration stores the sign-in phone and profile contact phone separately in each private profile. The contact phone is returned only after the accepted-interest and gender/premium checks in Firestore rules. Existing accounts continue to use their stored phone as a fallback contact.
- Confirm both Razorpay Payment Buttons are live, in INR, and configured for exactly ₹599 (6 months) and ₹1,199 (12 months). The site records a member's plan selection before loading the supplied Razorpay button.
- A recorded selection means the member chose a plan; it does not prove checkout or payment completed. Check Razorpay Dashboard and activate only transactions shown as captured. The admin dashboard's payment-request filter provides the member and selected plan.
- Admin activation writes the entitlement on the server. Firestore rules hide private contact data from men without an active entitlement, even if the page UI is bypassed. Women and non-male profiles retain free contact access after mutual interest acceptance. Only profiles declared as Man require Premium; this does not independently verify gender.
- The UI promises activation within 24 hours after payment verification. Operations must review the payment-request list within that period.

## Deploy

After merging the website PR (GitHub Pages publishes the static website), deploy the Firebase backend from the repository root:

```sh
firebase deploy --only functions,firestore:rules
```

The repository's `.firebaserc` selects production project `kmarry-5ce8a`. Confirm the Firebase CLI is signed in to an account authorized to deploy that project before running the command. Verify admin login, both payment buttons, payment-request listing, manual activation, and the female-free/male-premium contact rules in production.
