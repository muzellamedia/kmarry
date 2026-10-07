# Production setup

## Admin account

- In Firebase Console, enable **Authentication → Sign-in method → Email/Password**.
- Create the administrator account `muzellamedia@gmail.com`, verify that email, and use a fresh password managed in Firebase Auth. Admin credentials are never stored in site code. The server only grants admin callables to that verified email.
- The password previously shared in chat must be rotated before production use.

## Premium payments

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
